"""
VibeCodeReviewer — XSS Scanner
Detects cross-site scripting vectors in server-side template rendering,
innerHTML assignments, and unsanitized output in HTML/JS/Python templates.
"""

import re
from .base import BaseScanner
from ..models import Finding, Severity


# Python: Jinja2/Django template bypasses (|safe filter, mark_safe)
_JINJA_SAFE_RE   = re.compile(r"\|\s*safe\b")
_MARK_SAFE_RE    = re.compile(r"\bmark_safe\s*\(")
_FORMAT_HTML_RE  = re.compile(r"\bformat_html\s*\([^)]*%[sd]")

# JavaScript: innerHTML, document.write, outerHTML with a variable
_INNER_HTML_RE   = re.compile(r"\.innerHTML\s*=(?!=)\s*(?!['\"`])")
_DOC_WRITE_RE    = re.compile(r"document\.write\s*\([^'\"`]")
_OUTER_HTML_RE   = re.compile(r"\.outerHTML\s*=(?!=)\s*(?!['\"`])")

# React dangerouslySetInnerHTML
_DANGEROUS_HTML_RE = re.compile(r"dangerouslySetInnerHTML\s*=\s*\{")

# PHP: echo with $_GET/$_POST without escaping
_PHP_ECHO_RE = re.compile(r"echo\s+.*?\$_(GET|POST|REQUEST|COOKIE)\s*\[", re.IGNORECASE)


class XSSScanner(BaseScanner):
    name = "XSSScanner"
    SUPPORTED_EXTENSIONS = (".py", ".html", ".js", ".ts", ".jsx", ".tsx", ".php")

    def scan_file(self, filepath: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []

        if filepath.endswith(".py"):
            findings += self._regex_findings(
                filepath, lines, _MARK_SAFE_RE,
                Severity.HIGH,
                "XSS — mark_safe() with Potentially Unsanitized Data",
                "mark_safe() disables Django's auto-escaping. If passed user-controlled data, "
                "it renders raw HTML which can execute attacker scripts.",
                cwe_id="CWE-79",
                fix=(
                    "Use format_html() instead of mark_safe() + string formatting:\n"
                    "  format_html('<a href=\"{}\">{}</a>', url, text)"
                ),
            )
            findings += self._regex_findings(
                filepath, lines, _JINJA_SAFE_RE,
                Severity.HIGH,
                "XSS — Jinja2 |safe Filter Disables Escaping",
                "The |safe filter marks a value as safe from escaping. "
                "If applied to user-controlled data, XSS is possible.",
                cwe_id="CWE-79",
                fix=(
                    "Remove |safe from user-controlled variables. "
                    "Sanitize with bleach.clean() before marking safe."
                ),
            )

        if filepath.endswith((".js", ".ts", ".jsx", ".tsx", ".html")):
            findings += self._regex_findings(
                filepath, lines, _INNER_HTML_RE,
                Severity.HIGH,
                "XSS — innerHTML Assignment with Non-Literal Value",
                "Assigning a variable to innerHTML executes any script tags in the value. "
                "An attacker who controls that value can inject arbitrary JavaScript.",
                cwe_id="CWE-79",
                fix=(
                    "Use textContent for plain text, or sanitize with DOMPurify:\n"
                    "  element.textContent = userValue;\n"
                    "  // or\n"
                    "  element.innerHTML = DOMPurify.sanitize(userValue);"
                ),
            )
            findings += self._regex_findings(
                filepath, lines, _DOC_WRITE_RE,
                Severity.HIGH,
                "XSS — document.write() with Dynamic Argument",
                "document.write() with a variable can inject script elements. "
                "Avoid document.write entirely in modern applications.",
                cwe_id="CWE-79",
                fix="Replace document.write() with DOM manipulation (createElement, appendChild).",
            )
            findings += self._regex_findings(
                filepath, lines, _DANGEROUS_HTML_RE,
                Severity.MEDIUM,
                "XSS — React dangerouslySetInnerHTML",
                "dangerouslySetInnerHTML bypasses React's XSS protection. "
                "Use it only with fully trusted, sanitized content.",
                cwe_id="CWE-79",
                fix=(
                    "Sanitize the value with DOMPurify before passing it:\n"
                    "  dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}"
                ),
            )

        if filepath.endswith(".php"):
            findings += self._regex_findings(
                filepath, lines, _PHP_ECHO_RE,
                Severity.CRITICAL,
                "XSS — PHP echo with Unsanitized Superglobal",
                "Echoing $_GET/$_POST/$_REQUEST directly renders raw user input as HTML.",
                cwe_id="CWE-79",
                fix=(
                    "Always escape output:\n"
                    "  echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');"
                ),
            )

        return findings
