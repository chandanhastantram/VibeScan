"""
VibeScan — Dependency Vulnerability Scanner
Parses requirements.txt and package.json for known vulnerable package versions.
Uses a bundled vulnerability database (CVE/GHSA data, updated regularly).

This is a lightweight, offline-capable scanner. For production use,
integrate with pip-audit, safety, or npm audit.
"""

import re
import json
import os
from .base import BaseScanner
from ..models import Finding, Severity

# ──────────────────────────────────────────────────────────────────────────────
# Bundled vulnerability database (a curated subset of well-known high-impact CVEs)
# Format: { "package_name": [ {"max_version": "x.y.z", "cve": "CVE-XXXX", "severity":..., "desc":.., "fix":..} ] }
# ──────────────────────────────────────────────────────────────────────────────
VULN_DB: dict[str, list[dict]] = {
    # Python packages
    "django": [
        {"max_version": "2.2.27", "cve": "CVE-2022-28346", "severity": "CRITICAL",
         "desc": "SQL injection via QuerySet.annotate(), aggregate(), extra() in Django <= 2.2.27.",
         "fix": "Upgrade to Django >= 3.2.13 or >= 4.0.4."},
        {"max_version": "3.2.12", "cve": "CVE-2022-28346", "severity": "CRITICAL",
         "desc": "SQL injection via QuerySet.annotate(), aggregate(), extra() in Django <= 3.2.12.",
         "fix": "Upgrade to Django >= 3.2.13 or >= 4.0.4."},
    ],
    "flask": [
        {"max_version": "0.12.4", "cve": "CVE-2018-1000656", "severity": "HIGH",
         "desc": "Denial of service via large amount of JSON data (Flask <= 0.12.4).",
         "fix": "Upgrade to Flask >= 1.0."},
    ],
    "pillow": [
        {"max_version": "9.0.1", "cve": "CVE-2022-22815", "severity": "HIGH",
         "desc": "Path traversal in Pillow <= 9.0.1 via crafted image files.",
         "fix": "Upgrade to Pillow >= 9.1.0."},
    ],
    "requests": [
        {"max_version": "2.19.1", "cve": "CVE-2018-18074", "severity": "MEDIUM",
         "desc": "Requests <= 2.19.1 sends HTTP Authorization header to redirect targets.",
         "fix": "Upgrade to requests >= 2.20.0."},
    ],
    "pyyaml": [
        {"max_version": "5.3.1", "cve": "CVE-2020-14343", "severity": "CRITICAL",
         "desc": "Arbitrary code execution via yaml.load() in PyYAML <= 5.3.1.",
         "fix": "Upgrade to PyYAML >= 5.4 and use yaml.safe_load()."},
    ],
    "cryptography": [
        {"max_version": "41.0.0", "cve": "CVE-2023-38325", "severity": "HIGH",
         "desc": "NULL pointer dereference in cryptography <= 41.0.0.",
         "fix": "Upgrade to cryptography >= 41.0.1."},
    ],
    "paramiko": [
        {"max_version": "2.9.5", "cve": "CVE-2022-24302", "severity": "MEDIUM",
         "desc": "Race condition in Paramiko <= 2.9.5 during private key file creation.",
         "fix": "Upgrade to paramiko >= 2.10.1."},
    ],
    "sqlalchemy": [
        {"max_version": "1.4.45", "cve": "CVE-2023-30534", "severity": "HIGH",
         "desc": "SQL injection in SQLAlchemy <= 1.4.45 via crafted filter expressions.",
         "fix": "Upgrade to SQLAlchemy >= 1.4.46 or >= 2.0."},
    ],
    "urllib3": [
        {"max_version": "1.26.4", "cve": "CVE-2021-33503", "severity": "HIGH",
         "desc": "ReDoS in urllib3 <= 1.26.4 via malformed URL.",
         "fix": "Upgrade to urllib3 >= 1.26.5."},
    ],
    "celery": [
        {"max_version": "4.4.6", "cve": "CVE-2021-23727", "severity": "HIGH",
         "desc": "JWT algorithm confusion in Celery <= 4.4.6.",
         "fix": "Upgrade to Celery >= 5.2.2."},
    ],
    # Node.js packages
    "lodash": [
        {"max_version": "4.17.20", "cve": "CVE-2021-23337", "severity": "HIGH",
         "desc": "Command injection in lodash <= 4.17.20 via template() function.",
         "fix": "Upgrade to lodash >= 4.17.21."},
    ],
    "express": [
        {"max_version": "4.17.2", "cve": "CVE-2022-24999", "severity": "HIGH",
         "desc": "Open redirect via Host header in express <= 4.17.2.",
         "fix": "Upgrade to express >= 4.18.2."},
    ],
    "axios": [
        {"max_version": "0.21.1", "cve": "CVE-2021-3749", "severity": "HIGH",
         "desc": "Server-side request forgery (SSRF) in axios <= 0.21.1.",
         "fix": "Upgrade to axios >= 0.21.2."},
    ],
    "node-fetch": [
        {"max_version": "2.6.6", "cve": "CVE-2022-0235", "severity": "HIGH",
         "desc": "Exposure of sensitive information via redirect in node-fetch <= 2.6.6.",
         "fix": "Upgrade to node-fetch >= 2.6.7 or >= 3.1.1."},
    ],
    "minimist": [
        {"max_version": "1.2.5", "cve": "CVE-2021-44906", "severity": "CRITICAL",
         "desc": "Prototype pollution in minimist <= 1.2.5.",
         "fix": "Upgrade to minimist >= 1.2.6."},
    ],
    "jsonwebtoken": [
        {"max_version": "8.5.1", "cve": "CVE-2022-23529", "severity": "HIGH",
         "desc": "JWT algorithm confusion + improper key handling in jsonwebtoken <= 8.5.1.",
         "fix": "Upgrade to jsonwebtoken >= 9.0.0."},
    ],
}


def _parse_version(v: str) -> tuple[int, ...]:
    """Convert '1.2.3' to (1, 2, 3). Non-numeric parts become 0."""
    parts = re.split(r"[.\-]", v)
    result = []
    for p in parts[:4]:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    while len(result) < 4:
        result.append(0)
    return tuple(result)


def _version_lte(v: str, max_v: str) -> bool:
    """Return True if v <= max_v."""
    try:
        return _parse_version(v) <= _parse_version(max_v)
    except Exception:
        return False


_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
}


class DependencyScanner(BaseScanner):
    name = "DependencyScanner"
    SUPPORTED_EXTENSIONS = (".txt", ".json")

    def scan_file(self, filepath: str, content: str, lines: list[str]) -> list[Finding]:
        findings = []
        basename = os.path.basename(filepath).lower()

        if basename == "requirements.txt":
            findings += self._scan_requirements(filepath, lines)
        elif basename == "package.json":
            findings += self._scan_package_json(filepath, content)

        return findings

    # ------------------------------------------------------------------ Python

    def _scan_requirements(self, filepath: str, lines: list[str]) -> list[Finding]:
        findings = []
        # Matches: package==1.2.3, package>=1.0, package~=2.0, etc.
        req_re = re.compile(
            r"^\s*([A-Za-z0-9_\-]+)\s*(?:==|>=|<=|~=|!=)\s*([^\s;#]+)", re.IGNORECASE
        )
        for lineno, line in enumerate(lines, start=1):
            m = req_re.match(line)
            if not m:
                continue
            pkg  = m.group(1).lower()
            ver  = m.group(2).strip()
            vulns = VULN_DB.get(pkg, [])
            for vuln in vulns:
                if _version_lte(ver, vuln["max_version"]):
                    findings.append(Finding(
                        file=filepath,
                        line=lineno,
                        severity=_SEVERITY_MAP.get(vuln["severity"], Severity.MEDIUM),
                        title=f"Vulnerable Dependency — {pkg} {ver} ({vuln['cve']})",
                        description=vuln["desc"],
                        code_snippet=line.rstrip(),
                        cwe_id="CWE-1035",
                        fix=vuln["fix"],
                        scanner=self.name,
                    ))
        return findings

    # ---------------------------------------------------------------- Node.js

    def _scan_package_json(self, filepath: str, content: str) -> list[Finding]:
        findings = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return findings

        all_deps: dict[str, str] = {}
        all_deps.update(data.get("dependencies", {}))
        all_deps.update(data.get("devDependencies", {}))

        for pkg, ver_spec in all_deps.items():
            pkg_lower = pkg.lower()
            # Strip npm semver prefix symbols: ^, ~, >=
            ver = re.sub(r"^[\^~>=<\s]+", "", ver_spec).strip()
            vulns = VULN_DB.get(pkg_lower, [])
            for vuln in vulns:
                if _version_lte(ver, vuln["max_version"]):
                    findings.append(Finding(
                        file=filepath,
                        line=1,
                        severity=_SEVERITY_MAP.get(vuln["severity"], Severity.MEDIUM),
                        title=f"Vulnerable Dependency — {pkg} {ver} ({vuln['cve']})",
                        description=vuln["desc"],
                        code_snippet=f'"{pkg}": "{ver_spec}"',
                        cwe_id="CWE-1035",
                        fix=vuln["fix"],
                        scanner=self.name,
                    ))
        return findings
