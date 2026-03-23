"""
VibeScan — Sensitive Data Exposure Scanner
Detects logging or printing of sensitive fields, verbose error messages,
stack traces in API responses, and debug mode enabled in production.
"""

import re
from .base import BaseScanner
from ..models import Finding, Severity


# Logging or printing sensitive field names
_SENSITIVE_LOG_RE = re.compile(
    r"(?i)(log|print|console\.log|fmt\.Print)\s*[\w.]*\s*[\(,+]\s*"
    r"[^)]*\b(password|passwd|pwd|secret|token|api_key|credit_card|ssn|cvv|pin|auth)\b",
)

# Stack trace in HTTP response (Flask/Django)
_STACK_TRACE_RESPONSE_RE = re.compile(
    r"(?i)(traceback|stack.?trace|exception|error)\b.*\b(response|jsonify|json\.dumps|return)\b"
    r"|"
    r"\b(jsonify|json\.dumps)\s*\([^)]*\b(traceback|exception|error|stack)\b",
)

# DEBUG = True in settings
_DEBUG_TRUE_RE = re.compile(r"\bDEBUG\s*=\s*True\b")

# Flask debug=True
_FLASK_DEBUG_RE = re.compile(r"app\.run\s*\([^)]*debug\s*=\s*True")

# Django ALLOWED_HOSTS = [] (empty — security misconfiguration)
_EMPTY_ALLOWED_HOSTS_RE = re.compile(r"ALLOWED_HOSTS\s*=\s*\[\s*\]")

# Django/Flask SECRET_KEY with weak/default value
_WEAK_SECRET_KEY_RE = re.compile(
    r"SECRET_KEY\s*=\s*['\"]"
    r"(django-insecure|secret|changeme|dev|development|test|example|your[_-]?secret|"
    r"[a-z]{5,30})['\"]",
    re.IGNORECASE,
)

# Exposing internal paths or configurations in error messages
_VERBOSE_ERROR_RE = re.compile(
    r"(?i)(raise|except.*Exception).*\b(traceback\.format_exc|__file__|sys\.path|os\.environ)\b",
)

# Direct exposure of environment variables in response
_ENV_IN_RESPONSE_RE = re.compile(
    r"(?i)(os\.environ|os\.getenv)\s*.*\b(jsonify|json\.dumps|Response|render)\b"
    r"|"
    r"\b(jsonify|json\.dumps|render)\s*\([^)]*os\.environ",
)


class SensitiveDataScanner(BaseScanner):
    name = "SensitiveDataScanner"
    SUPPORTED_EXTENSIONS = (".py", ".js", ".ts", ".php", ".java")

    def scan_file(self, filepath: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []

        findings += self._regex_findings(
            filepath, lines, _SENSITIVE_LOG_RE,
            Severity.HIGH,
            "Sensitive Data Exposure — Logging Sensitive Field",
            "A sensitive field (password, token, secret, etc.) appears to be passed to a "
            "log or print statement. This writes credentials to log files, which may be "
            "accessible to attackers or exposing in log aggregation systems.",
            cwe_id="CWE-532",
            fix=(
                "Exclude sensitive fields from logging. If you must log, mask the value:\n"
                "  logger.info('User login attempt for: %s', username)  # NOT password\n"
                "  logger.debug('Token: %s...', token[:6])  # partial only"
            ),
        )

        if filepath.endswith(".py"):
            findings += self._regex_findings(
                filepath, lines, _DEBUG_TRUE_RE,
                Severity.HIGH,
                "Sensitive Data Exposure — DEBUG = True",
                "DEBUG mode exposes full stack traces, local variable values, and internal "
                "settings to anyone who triggers an error. Never use in production.",
                cwe_id="CWE-215",
                fix=(
                    "Set DEBUG = False in production settings. "
                    "Use environment variables:\n"
                    "  DEBUG = os.environ.get('DEBUG', 'False') == 'True'"
                ),
            )
            findings += self._regex_findings(
                filepath, lines, _FLASK_DEBUG_RE,
                Severity.HIGH,
                "Sensitive Data Exposure — Flask debug=True in app.run()",
                "Running Flask with debug=True enables the Werkzeug debugger, which allows "
                "arbitrary code execution from the browser via the debug console PIN.",
                cwe_id="CWE-215",
                fix=(
                    "Remove debug=True from production code:\n"
                    "  app.run(debug=os.environ.get('FLASK_DEBUG', False))"
                ),
            )
            findings += self._regex_findings(
                filepath, lines, _EMPTY_ALLOWED_HOSTS_RE,
                Severity.HIGH,
                "Security Misconfiguration — Django ALLOWED_HOSTS = []",
                "An empty ALLOWED_HOSTS in production allows HTTP Host header injection. "
                "Django should reject requests with unrecognized Host headers.",
                cwe_id="CWE-16",
                fix=(
                    "Set ALLOWED_HOSTS to your actual domain(s):\n"
                    "  ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']"
                ),
            )
            findings += self._regex_findings(
                filepath, lines, _WEAK_SECRET_KEY_RE,
                Severity.CRITICAL,
                "Sensitive Data Exposure — Weak or Default SECRET_KEY",
                "A weak, default, or recognizable SECRET_KEY was detected. "
                "Django's SECRET_KEY is used for session signing, CSRF tokens, and password reset links. "
                "A known key allows these to be forged.",
                cwe_id="CWE-798",
                fix=(
                    "Generate a strong random key and load from environment:\n"
                    "  python -c \"import secrets; print(secrets.token_urlsafe(50))\"\n"
                    "  SECRET_KEY = os.environ['DJANGO_SECRET_KEY']"
                ),
            )
            findings += self._regex_findings(
                filepath, lines, _ENV_IN_RESPONSE_RE,
                Severity.HIGH,
                "Sensitive Data Exposure — Environment Variables in HTTP Response",
                "os.environ or os.getenv values appear to be included in an HTTP response. "
                "Environment variables often contain secrets, database URLs, and API keys.",
                cwe_id="CWE-200",
                fix="Never return os.environ or internal configuration values in API responses.",
            )

        return findings
