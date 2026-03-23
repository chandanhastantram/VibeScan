"""
VibeScan — SQL Injection Scanner
Detects SQL injection vectors: string concatenation, f-strings, and
.format() calls being passed to database execute() methods.
"""

import re
import ast
from .base import BaseScanner
from ..models import Finding, Severity


# Regex: SQL keywords followed by string concat or f-string interpolation
_SQL_CONCAT_RE = re.compile(
    r"""(?ix)
    (execute|executemany|raw|cursor\.execute)\s*\(
    \s*
    (
      f['"]{1,3}.*?(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|WHERE).*?['"]{1,3}
      |
      ['"]\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|WHERE).*?['"]\s*[+%]
      |
      (SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION)\s+.*?%\s*
    )
    """,
)

_SQL_FORMAT_RE = re.compile(
    r"""(?ix)
    (SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)
    .*?
    (\.format\(|\s*%\s*[\(\[]|f["\'])
    """,
)

# ORM raw() / extra() calls are sometimes used unsafely
_ORM_RAW_RE = re.compile(
    r"""(?ix)
    \.(raw|extra|RawSQL)\s*\(\s*(f['"\"]+|['"\"]+.*?[+%]|.*?\.format)
    """,
)


class SQLInjectionScanner(BaseScanner):
    name = "SQLInjectionScanner"
    SUPPORTED_EXTENSIONS = (".py", ".php", ".js", ".ts", ".java", ".rb", ".go")

    def scan_file(self, filepath: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []
        findings += self._regex_findings(
            filepath, lines, _SQL_CONCAT_RE,
            Severity.CRITICAL,
            "SQL Injection — String Concatenation in Query",
            "User-controlled data appears to be concatenated directly into a SQL query. "
            "This allows an attacker to manipulate the query structure.",
            cwe_id="CWE-89",
            fix=(
                "Use parameterized queries / prepared statements:\n"
                "  cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
                "Never build SQL strings with f-strings, %, or .format()."
            ),
        )
        findings += self._regex_findings(
            filepath, lines, _SQL_FORMAT_RE,
            Severity.HIGH,
            "SQL Injection — Potential Dynamic Query Construction",
            "SQL keyword found adjacent to string formatting. "
            "If any variable originates from user input, this is injectable.",
            cwe_id="CWE-89",
            fix=(
                "Replace dynamic query construction with parameterized queries. "
                "Use an ORM query builder for dynamic filters."
            ),
        )
        if filepath.endswith(".py"):
            findings += self._regex_findings(
                filepath, lines, _ORM_RAW_RE,
                Severity.HIGH,
                "SQL Injection — ORM raw() with Dynamic Input",
                "Django/SQLAlchemy raw query called with possible string interpolation.",
                cwe_id="CWE-89",
                fix=(
                    "Pass parameters separately:\n"
                    "  MyModel.objects.raw('SELECT * FROM t WHERE id = %s', [user_id])"
                ),
            )
        return findings
