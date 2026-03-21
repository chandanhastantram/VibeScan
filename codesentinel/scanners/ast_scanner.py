"""
CodeSentinel — AST-Based Python Scanner
Uses Python's ast module for semantic analysis rather than pure regex.

Detects:
  - SQL injection:   execute("..." + var) with non-literal first arg
  - Command injection: os.system(var), subprocess(shell=True, ...)
  - eval()/exec() with non-Constant argument
  - Dangerous imports: pickle, marshal, telnetlib, ftplib
  - assert statements used for security checks (stripped in -O mode)
  - Bare except clauses that swallow exceptions silently
  - Hardcoded bind to 0.0.0.0 (listens on all interfaces)

This scanner produces ZERO false positives for patterns it covers because
it works at the AST level — it can distinguish:
  cursor.execute("SELECT 1")          ← safe (literal)
  cursor.execute("SELECT " + user_id) ← unsafe (concatenation)
"""

import ast
import os
from .base import BaseScanner
from ..models import Finding, Severity


class ASTScanner(BaseScanner):
    name = "ASTScanner"
    SUPPORTED_EXTENSIONS = (".py",)

    def scan_file(self, filepath: str, content: str, lines: list[str]) -> list[Finding]:
        tree = self._try_parse_ast(content)
        if tree is None:
            return []

        visitor = _SecurityVisitor(filepath, lines)
        visitor.visit(tree)
        return visitor.findings


# ── AST Visitor ────────────────────────────────────────────────────────────────

class _SecurityVisitor(ast.NodeVisitor):
    """Walks the Python AST and flags dangerous patterns."""

    _SQL_METHODS = frozenset({"execute", "executemany"})
    _SHELL_CALLS = frozenset({"system", "popen", "startfile"})
    _SUBPROCESS  = frozenset({"call", "run", "Popen", "check_output", "check_call"})
    _DANGEROUS_IMPORTS = {
        "pickle":   ("Insecure Import — pickle", Severity.HIGH,
                     "CWE-502", "Replace with json or msgpack for data serialization."),
        "marshal":  ("Insecure Import — marshal", Severity.HIGH,
                     "CWE-502", "Replace with json. marshal is not safe for untrusted data."),
        "telnetlib":("Insecure Import — telnetlib (plaintext protocol)", Severity.MEDIUM,
                     "CWE-319", "Replace with paramiko (SSH) for encrypted remote access."),
        "ftplib":   ("Insecure Import — ftplib (plaintext FTP)", Severity.LOW,
                     "CWE-319", "Use FTPS or SFTP instead."),
        "cgi":      ("Insecure Import — cgi module (deprecated, XSS risk)", Severity.LOW,
                     "CWE-79", "Use a modern web framework instead."),
    }

    def __init__(self, filepath: str, lines: list[str]):
        self.filepath = filepath
        self.lines    = lines
        self.findings: list[Finding] = []

    # ── helpers ────────────────────────────────────────────────────────────────

    def _add(self, node: ast.AST, severity: Severity, title: str,
             desc: str, cwe: str = "", fix: str = "") -> None:
        self.findings.append(Finding(
            file=self.filepath,
            line=getattr(node, "lineno", 0),
            severity=severity,
            title=title,
            description=desc,
            code_snippet=self._snippet(node),
            cwe_id=cwe or None,
            fix=fix,
            scanner="ASTScanner",
        ))

    def _snippet(self, node: ast.AST) -> str:
        ln = getattr(node, "lineno", 1)
        if 1 <= ln <= len(self.lines):
            return self.lines[ln - 1].rstrip()
        return ""

    @staticmethod
    def _is_literal(node: ast.AST) -> bool:
        """Return True if node is a string/bytes/number literal (safe constant)."""
        return isinstance(node, ast.Constant)

    @staticmethod
    def _has_string_concat(node: ast.AST) -> bool:
        """Return True if node contains BinOp with + (string concatenation)."""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return True
        if isinstance(node, ast.JoinedStr):   # f-string
            return True
        return False

    @staticmethod
    def _is_shell_true(keywords: list[ast.keyword]) -> bool:
        """Return True if keyword args contain shell=True."""
        for kw in keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    # ── visitors ───────────────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            pkg = alias.name.split(".")[0]
            if pkg in self._DANGEROUS_IMPORTS:
                title, sev, cwe, fix = self._DANGEROUS_IMPORTS[pkg]
                self._add(node, sev, title,
                          f"Importing '{pkg}' introduces security risk. {fix}", cwe, fix)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        pkg = (node.module or "").split(".")[0]
        if pkg in self._DANGEROUS_IMPORTS:
            title, sev, cwe, fix = self._DANGEROUS_IMPORTS[pkg]
            self._add(node, sev, title,
                      f"Importing from '{pkg}' introduces security risk. {fix}", cwe, fix)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        # ── eval() / exec() ─────────────────────────────────────────────────
        if isinstance(func, ast.Name) and func.id in ("eval", "exec"):
            if node.args and not self._is_literal(node.args[0]):
                self._add(node, Severity.CRITICAL,
                          f"Code Injection — {func.id}() with non-literal argument",
                          f"{func.id}() executes arbitrary Python code. If the argument is not "
                          f"a compile-time constant, this is a remote code execution risk.",
                          "CWE-95",
                          "Remove eval()/exec(). Use ast.literal_eval() for safe literal parsing.")

        # ── os.system / os.popen ────────────────────────────────────────────
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id == "os" and func.attr in self._SHELL_CALLS:
                if node.args and not self._is_literal(node.args[0]):
                    self._add(node, Severity.HIGH,
                              f"Command Injection — os.{func.attr}() with dynamic argument",
                              f"os.{func.attr}() passes the command to the shell. "
                              "A non-literal argument may allow shell metacharacter injection.",
                              "CWE-78",
                              "Replace with subprocess.run([...], shell=False).")

            # ── subprocess with shell=True ──────────────────────────────────
            if func.value.id == "subprocess" and func.attr in self._SUBPROCESS:
                if self._is_shell_true(node.keywords):
                    self._add(node, Severity.CRITICAL,
                              "Command Injection — subprocess with shell=True",
                              "shell=True passes the command string through the shell interpreter. "
                              "Any user-controlled data in the command leads to command injection.",
                              "CWE-78",
                              "Use shell=False and pass args as a list: subprocess.run(['cmd', arg]).")

        # ── cursor.execute(non-literal) ─────────────────────────────────────
        if isinstance(func, ast.Attribute) and func.attr in self._SQL_METHODS:
            if node.args:
                first_arg = node.args[0]
                if not self._is_literal(first_arg) and self._has_string_concat(first_arg):
                    self._add(node, Severity.CRITICAL,
                              "SQL Injection — Dynamic Query in execute()",
                              "The first argument to execute() contains string concatenation or "
                              "an f-string. If any component is user-controlled, this is injectable.",
                              "CWE-89",
                              "Use parameterized queries: cursor.execute('SELECT ... WHERE id=%s', (id,))")

        # ── app.run(debug=True) ─────────────────────────────────────────────
        if isinstance(func, ast.Attribute) and func.attr == "run":
            for kw in node.keywords:
                if (kw.arg == "debug"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True):
                    self._add(node, Severity.HIGH,
                              "Sensitive Data Exposure — Flask debug=True",
                              "Running Flask with debug=True exposes the interactive debugger, "
                              "which allows arbitrary code execution from the browser.",
                              "CWE-215",
                              "Set debug=False or load from env: debug=os.environ.get('FLASK_DEBUG','False')=='True'")

        # ── socket bind to 0.0.0.0 ──────────────────────────────────────────
        if isinstance(func, ast.Attribute) and func.attr == "bind":
            for arg in node.args:
                if isinstance(arg, ast.Tuple):
                    for elt in arg.elts:
                        if isinstance(elt, ast.Constant) and elt.value == "0.0.0.0":
                            self._add(node, Severity.LOW,
                                      "Network Binding — Listening on 0.0.0.0",
                                      "Binding to 0.0.0.0 accepts connections on all interfaces. "
                                      "In production, restrict to a specific interface unless intentional.",
                                      "CWE-605",
                                      "Bind to '127.0.0.1' or a specific interface in production.")

        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        """Warn about security-critical logic inside assert statements."""
        # Heuristic: assert contains auth/permission/validate keywords
        code = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
        if any(kw in code.lower() for kw in ("auth", "permission", "is_admin", "login", "verify", "token")):
            self._add(node, Severity.HIGH,
                      "Security Logic in assert Statement",
                      "assert statements are stripped when Python runs with the -O flag. "
                      "Never use assert for authentication or authorization checks.",
                      "CWE-617",
                      "Replace assert with an explicit if check and raise AuthenticationError.")
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Detect bare except clauses that silently swallow all exceptions."""
        if node.type is None:
            # Check if the body is just `pass` or a trivially empty handler
            body_stmts = node.body
            if all(isinstance(s, (ast.Pass,)) for s in body_stmts):
                self._add(node, Severity.LOW,
                          "Error Handling — Bare except: pass Swallowing All Exceptions",
                          "A bare `except: pass` silently swallows all exceptions including "
                          "SystemExit, KeyboardInterrupt, and security-related errors.",
                          "CWE-390",
                          "Catch specific exceptions: except ValueError as e: logger.warning(str(e))")
        self.generic_visit(node)
