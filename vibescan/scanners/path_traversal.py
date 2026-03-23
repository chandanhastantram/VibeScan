"""
VibeScan — Path Traversal Scanner
Detects user-controlled paths passed to file system operations without validation.
"""

import re
from .base import BaseScanner
from ..models import Finding, Severity


# open() with variable (not a pure string literal)
_OPEN_VAR_RE = re.compile(
    r"\bopen\s*\(\s*(?![\'\"](?!\s*[\'\"]))[^\"'][^)]*\)"
)

# os.path.join with potential user input (variable as first or second arg)
_OSPATH_JOIN_RE = re.compile(
    r"os\.path\.join\s*\([^)]*\b(request|user|param|input|filename|path|name)\b"
)

# send_file / send_from_directory in Flask with variable
_FLASK_SEND_RE = re.compile(
    r"send_file\s*\([^)]*\b(request|user|param|filename|path)\b"
)

# Direct string concatenation with user-provided path segments
_PATH_CONCAT_RE = re.compile(
    r"""(?ix)
    (BASE_DIR|ROOT_DIR|UPLOAD_DIR|app\.(root_path|static_folder))\s*[+]\s*
    \b(request|user|param|filename|path|name)\b
    |
    \b(request|user|param|filename|path|name)\b\s*[+]\s*
    (BASE_DIR|ROOT_DIR|UPLOAD_DIR)
    """
)

# Double-dot traversal in user input (sometimes found in test code or logs)
_DOTDOT_INPUT_RE = re.compile(r"['\"]\.\.[\\/]")


class PathTraversalScanner(BaseScanner):
    name = "PathTraversalScanner"
    SUPPORTED_EXTENSIONS = (".py", ".js", ".ts", ".php", ".rb", ".java")

    def scan_file(self, filepath: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []

        if filepath.endswith(".py"):
            findings += self._regex_findings(
                filepath, lines, _OSPATH_JOIN_RE,
                Severity.HIGH,
                "Path Traversal — os.path.join with User Input",
                "os.path.join() with a user-controlled component can produce paths "
                "outside the intended directory (e.g. ../../etc/passwd).",
                cwe_id="CWE-22",
                fix=(
                    "Validate the resolved path stays within the safe base directory:\n"
                    "  safe_root = Path('/uploads').resolve()\n"
                    "  target = (safe_root / filename).resolve()\n"
                    "  if not str(target).startswith(str(safe_root)):\n"
                    "      raise ValueError('Path traversal detected')"
                ),
            )
            findings += self._regex_findings(
                filepath, lines, _FLASK_SEND_RE,
                Severity.HIGH,
                "Path Traversal — Flask send_file with User Input",
                "Passing user-controlled paths to Flask's send_file can expose "
                "arbitrary files on the server.",
                cwe_id="CWE-22",
                fix=(
                    "Use send_from_directory() with a fixed directory:\n"
                    "  send_from_directory('/safe/upload/dir', secure_filename(user_filename))"
                ),
            )
            findings += self._regex_findings(
                filepath, lines, _PATH_CONCAT_RE,
                Severity.HIGH,
                "Path Traversal — String Concatenation with User-Controlled Path",
                "Concatenating user input with a base directory path without validation "
                "enables directory traversal attacks.",
                cwe_id="CWE-22",
                fix=(
                    "Use werkzeug.utils.secure_filename() to sanitize filenames, "
                    "then verify the resolved path is within the base directory."
                ),
            )

        findings += self._regex_findings(
            filepath, lines, _DOTDOT_INPUT_RE,
            Severity.MEDIUM,
            "Path Traversal — Literal ../ Sequence in Code",
            "A hardcoded '../' or '..\\\\' sequence was found. While not always "
            "exploitable, verify this is not derived from user input.",
            cwe_id="CWE-22",
            fix="Audit all paths containing '../' to ensure they cannot be influenced by user input.",
        )

        return findings
