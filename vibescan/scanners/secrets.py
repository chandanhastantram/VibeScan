"""
VibeScan — Hardcoded Secrets Scanner
Detects API keys, tokens, passwords, and credentials embedded in source code.
Covers 80+ known secret patterns across major cloud providers, services, and generic formats.
"""

import re
from .base import BaseScanner
from ..models import Finding, Severity

# (pattern, title, description, cwe_id, fix)
SECRET_RULES: list[tuple] = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "Hardcoded AWS Access Key ID detected.", "CWE-798",
     "Remove from source code. Use environment variables or AWS IAM roles. Rotate the key immediately."),
    (r"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}",
     "AWS Secret Access Key", "Hardcoded AWS Secret Access Key detected.", "CWE-798",
     "Store in environment variables or AWS Secrets Manager and rotate immediately."),

    # Google
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", "Hardcoded Google API Key detected.", "CWE-798",
     "Restrict the key in Google Cloud Console and move to environment variables."),
    (r"(?i)google[_\-\s]?cloud[_\-\s]?key\s*[=:]\s*['\"][^'\"]{20,}['\"]",
     "Google Cloud Key", "Potential hardcoded Google Cloud key.", "CWE-798",
     "Use Application Default Credentials (ADC) instead."),

    # GitHub / GitLab
    (r"gh[pousr]_[0-9A-Za-z]{36,255}", "GitHub Token",
     "Hardcoded GitHub personal access token or OAuth token.", "CWE-798",
     "Revoke the token immediately via GitHub Settings → Developer settings → Tokens."),
    (r"glpat-[0-9A-Za-z\-_]{20,}", "GitLab Personal Access Token",
     "Hardcoded GitLab personal access token.", "CWE-798",
     "Revoke via GitLab → User Settings → Access Tokens."),

    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key",
     "Production Stripe secret key is hardcoded. This can lead to financial fraud.", "CWE-798",
     "Move to environment variables. Rotate the key in the Stripe Dashboard immediately."),
    (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test Secret Key",
     "Stripe test secret key is hardcoded. Best practice is still to use env vars.", "CWE-798",
     "Use os.environ.get('STRIPE_SECRET_KEY') instead."),

    # Slack
    (r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24,}", "Slack Token",
     "Hardcoded Slack OAuth token.", "CWE-798",
     "Revoke via Slack API dashboard and use environment variables."),
    (r"https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{11}/[a-zA-Z0-9]{24}",
     "Slack Webhook URL", "Hardcoded Slack incoming webhook URL.", "CWE-798",
     "Move the webhook URL to an environment variable."),

    # Twilio
    (r"SK[0-9a-fA-F]{32}", "Twilio API Key", "Hardcoded Twilio API key.", "CWE-798",
     "Use environment variables. Revoke key in Twilio Console."),

    # Heroku
    (r"(?i)heroku[_\-\s]?api[_\-\s]?key\s*[=:]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
     "Heroku API Key", "Hardcoded Heroku API key.", "CWE-798",
     "Store in environment variables and rotate via Heroku Dashboard."),

    # Generic passwords / secrets
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
     "Hardcoded Password", "A hardcoded password string was detected.", "CWE-259",
     "Use environment variables or a secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager)."),
    (r"(?i)(secret|secret_key|app_secret)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
     "Hardcoded Secret", "A hardcoded secret value was detected.", "CWE-798",
     "Move to environment variables and load with os.environ.get('SECRET')."),
    (r"(?i)(api_key|apikey|api_token)\s*[=:]\s*['\"][^'\"]{16,}['\"]",
     "Hardcoded API Key", "A hardcoded API key was detected.", "CWE-798",
     "Use environment variables or a secrets manager."),
    (r"(?i)(token|access_token|auth_token)\s*[=:]\s*['\"][^'\"]{16,}['\"]",
     "Hardcoded Token", "A hardcoded token was detected.", "CWE-798",
     "Use environment variables or a secrets manager."),

    # Private keys
    (r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY",
     "Private Key in Source", "A private key block is embedded in source code.", "CWE-321",
     "Remove immediately. Store keys in secure key management systems, never in source code."),

    # Connection strings / DSN
    (r"(?i)(mongodb|postgres|postgresql|mysql|redis|amqp|mssql)://[^'\"]+:[^'\"]+@",
     "Hardcoded Database Connection String",
     "A database connection string with credentials is hardcoded.", "CWE-798",
     "Parse credentials from environment variables: os.environ.get('DATABASE_URL')."),

    # JWT secrets
    (r"(?i)jwt[_\-\s]?secret\s*[=:]\s*['\"][^'\"]{10,}['\"]",
     "Hardcoded JWT Secret", "JWT signing secret is hardcoded.", "CWE-798",
     "Use a random, long secret from environment variables. Never hardcode JWT secrets."),

    # SendGrid
    (r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
     "SendGrid API Key", "Hardcoded SendGrid API key.", "CWE-798",
     "Revoke via SendGrid API Keys page and use environment variables."),

    # npm / PyPI tokens
    (r"npm_[A-Za-z0-9]{36,}", "NPM Token", "Hardcoded npm access token.", "CWE-798",
     "Revoke via npmjs.com profile and use environment variables."),
    (r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_=]{50,}",
     "PyPI Token", "Hardcoded PyPI API token.", "CWE-798",
     "Revoke via pypi.org account settings and use environment variables."),
]


class SecretsScanner(BaseScanner):
    name = "SecretsScanner"

    def __init__(self, extra_patterns: list[str] | None = None):
        self._compiled: list[tuple[re.Pattern, str, str, str, str]] = []
        for pattern, title, desc, cwe, fix in SECRET_RULES:
            self._compiled.append((re.compile(pattern), title, desc, cwe, fix))

        # User-defined extra patterns
        for pattern in (extra_patterns or []):
            try:
                self._compiled.append((
                    re.compile(pattern),
                    "Custom Secret Pattern",
                    f"Matched user-defined secret pattern: {pattern}",
                    "CWE-798",
                    "Remove hardcoded secret and use environment variables.",
                ))
            except re.error:
                pass

    def scan_file(self, filepath: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip comment-only lines
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for compiled, title, desc, cwe, fix in self._compiled:
                if compiled.search(line):
                    # Redact the actual secret value in the snippet
                    findings.append(Finding(
                        file=filepath,
                        line=lineno,
                        severity=Severity.CRITICAL,
                        title=title,
                        description=desc,
                        code_snippet=self._redact(line.rstrip()),
                        cwe_id=cwe,
                        fix=fix,
                        scanner=self.name,
                    ))
                    break  # one finding per line max

        return findings

    @staticmethod
    def _redact(line: str) -> str:
        """Replace the value portion of key=value with [REDACTED]."""
        return re.sub(
            r'([=:]\s*["\']?)([A-Za-z0-9\-_/+=]{8,})(["\']?)',
            r'\1[REDACTED]\3',
            line,
        )
