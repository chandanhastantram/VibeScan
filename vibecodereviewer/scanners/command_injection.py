"""
VibeCodeReviewer — Command Injection Scanner
Detects dangerous shell execution patterns: os.system, subprocess with shell=True,
eval(), exec(), and similar code execution sinks that may receive user input.
"""

import re
import ast
from .base import BaseScanner
from ..models import Finding, Severity


# Catches os.system(...), os.popen(...) with any argument
_OS_SYSTEM_RE = re.compile(r"os\.(system|popen|startfile)\s*\(")

# subprocess with shell=True
_SUBPROCESS_SHELL_RE = re.compile(
    r"subprocess\.(call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True"
)

# eval() and exec() with non-literal arguments
_EVAL_RE = re.compile(r"\beval\s*\((?!\s*['\"])")
_EXEC_RE = re.compile(r"\bexec\s*\((?!\s*['\"])")

# Template rendering with user input (Jinja2 / Mako)
_TEMPLATE_RENDER_RE = re.compile(
    r"(?i)(Environment|Template)\s*\(.*?\).*?render|jinja2\.Template\s*\("
)

# Node.js / JS equivalents
_JS_EXEC_RE = re.compile(
    r"(?i)(child_process\.(exec|execSync|spawn|spawnSync)|eval\s*\(|new Function\s*\()"
)

# PHP
_PHP_EXEC_RE = re.compile(
    r"(?i)\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\("
)


class CommandInjectionScanner(BaseScanner):
    name = "CommandInjectionScanner"
    SUPPORTED_EXTENSIONS = (".py", ".js", ".ts", ".php", ".rb", ".sh")

    def scan_file(self, filepath: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []

        if filepath.endswith(".py"):
            findings += self._regex_findings(
                filepath, lines, _OS_SYSTEM_RE,
                Severity.HIGH,
                "Command Injection — os.system / os.popen",
                "os.system() and os.popen() pass the command directly to the shell. "
                "If any part of the command is user-controlled, this is exploitable.",
                cwe_id="CWE-78",
                fix=(
                    "Replace with subprocess.run([...], shell=False) and pass arguments as a list:\n"
                    "  subprocess.run(['ls', '-la', user_path], shell=False, check=True)"
                ),
            )
            findings += self._regex_findings(
                filepath, lines, _SUBPROCESS_SHELL_RE,
                Severity.CRITICAL,
                "Command Injection — subprocess with shell=True",
                "subprocess called with shell=True allows shell metacharacters in any "
                "string argument to execute arbitrary commands.",
                cwe_id="CWE-78",
                fix=(
                    "Set shell=False and pass the command as a list:\n"
                    "  subprocess.run(['cmd', arg1, arg2], shell=False)"
                ),
            )
            findings += self._regex_findings(
                filepath, lines, _EVAL_RE,
                Severity.CRITICAL,
                "Code Injection — eval() with dynamic argument",
                "eval() on a non-literal expression executes arbitrary Python code. "
                "If the argument can be influenced by user input, this is a critical RCE vector.",
                cwe_id="CWE-95",
                fix=(
                    "Remove eval(). Use ast.literal_eval() for safe literal parsing, "
                    "or redesign to avoid dynamic code execution entirely."
                ),
            )
            findings += self._regex_findings(
                filepath, lines, _EXEC_RE,
                Severity.CRITICAL,
                "Code Injection — exec() with dynamic argument",
                "exec() executes arbitrary Python code. Never pass user-controlled data to exec().",
                cwe_id="CWE-95",
                fix="Remove exec(). Redesign to avoid dynamic code execution.",
            )

        if filepath.endswith((".js", ".ts")):
            findings += self._regex_findings(
                filepath, lines, _JS_EXEC_RE,
                Severity.CRITICAL,
                "Command/Code Injection — Dangerous JS Execution",
                "child_process.exec or eval() in JavaScript can lead to RCE if user input reaches it.",
                cwe_id="CWE-78",
                fix=(
                    "Use child_process.execFile() or spawn() with argument arrays instead of exec(). "
                    "Never pass user input directly. Avoid eval() and new Function()."
                ),
            )

        if filepath.endswith(".php"):
            findings += self._regex_findings(
                filepath, lines, _PHP_EXEC_RE,
                Severity.CRITICAL,
                "Command Injection — PHP Shell Execution Function",
                "PHP functions like system(), exec(), shell_exec() execute OS commands. "
                "User input in these calls leads to remote code execution.",
                cwe_id="CWE-78",
                fix=(
                    "Avoid these functions entirely. If required, use escapeshellarg() "
                    "and escapeshellcmd() to sanitize all arguments."
                ),
            )

        return findings
