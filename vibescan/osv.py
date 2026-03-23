"""
VibeScan — Live CVE / OSV Database Integration
Queries the Open Source Vulnerabilities API (api.osv.dev) for real-time
vulnerability data, with transparent fallback to the bundled offline database.

OSV API docs: https://google.github.io/osv.dev/api/
"""

import json
import os
import urllib.request
import urllib.error
from .scanners.dependencies import VULN_DB, _version_lte, _SEVERITY_MAP
from .models import Finding, Severity

OSV_API_URL = "https://api.osv.dev/v1/query"
_CACHE_FILE  = os.path.join(os.path.expanduser("~"), ".vibescan_osv_cache.json")
_CACHE_TTL   = 86_400  # 24 hours


def _load_cache() -> dict:
    if not os.path.isfile(_CACHE_FILE):
        return {}
    try:
        mtime = os.path.getmtime(_CACHE_FILE)
        if (os.path.getmtime(_CACHE_FILE) + _CACHE_TTL) < __import__("time").time():
            return {}
        with open(_CACHE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save_cache(cache: dict) -> None:
    try:
        with open(_CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(cache, fh)
    except Exception:
        pass


def _query_osv(package: str, version: str, ecosystem: str = "PyPI") -> list[dict]:
    """
    Query OSV API for vulnerabilities affecting package@version.
    Returns list of OSV vulnerability dicts, or [] on error.
    """
    cache = _load_cache()
    cache_key = f"{ecosystem}:{package}:{version}"
    if cache_key in cache:
        return cache[cache_key]

    payload = json.dumps({
        "version": version,
        "package": {"name": package, "ecosystem": ecosystem},
    }).encode()

    try:
        req = urllib.request.Request(
            OSV_API_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            vulns = data.get("vulns", [])
            cache[cache_key] = vulns
            _save_cache(cache)
            return vulns
    except Exception:
        cache[cache_key] = []
        _save_cache(cache)
        return []


def _osv_severity(vuln: dict) -> Severity:
    """Map OSV severity rating to our Severity enum."""
    for sev_entry in vuln.get("severity", []):
        score_str = sev_entry.get("score", "")
        try:
            score = float(score_str)
            if score >= 9.0:  return Severity.CRITICAL
            if score >= 7.0:  return Severity.HIGH
            if score >= 4.0:  return Severity.MEDIUM
            return Severity.LOW
        except ValueError:
            rating = sev_entry.get("score", "").upper()
            if "CRITICAL" in rating: return Severity.CRITICAL
            if "HIGH"     in rating: return Severity.HIGH
            if "MEDIUM"   in rating: return Severity.MEDIUM
            return Severity.LOW
    return Severity.HIGH  # default if no severity info


def query_vulnerabilities(
    package: str,
    version: str,
    filepath: str,
    lineno: int,
    code_snippet: str,
    ecosystem: str = "PyPI",
    use_live: bool = True,
) -> list[Finding]:
    """
    Look up vulnerabilities for a package@version.
    Tries OSV live API first, falls back to bundled DB on error.
    """
    findings = []

    if use_live:
        osv_vulns = _query_osv(package, version, ecosystem)
        for vuln in osv_vulns:
            vuln_id   = vuln.get("id", "UNKNOWN")
            summary   = vuln.get("summary", f"Vulnerability in {package} {version}")
            details   = vuln.get("details", summary)[:300]
            severity  = _osv_severity(vuln)

            # Extract fix version from affected ranges
            fix_version = "latest"
            for affected in vuln.get("affected", []):
                for rng in affected.get("ranges", []):
                    for evt in rng.get("events", []):
                        if "fixed" in evt:
                            fix_version = evt["fixed"]
                            break

            findings.append(Finding(
                file=filepath,
                line=lineno,
                severity=severity,
                title=f"Vulnerable Dependency — {package} {version} ({vuln_id})",
                description=details,
                code_snippet=code_snippet,
                cwe_id="CWE-1035",
                fix=f"Upgrade {package} to >= {fix_version}. See: https://osv.dev/vulnerability/{vuln_id}",
                scanner="OSVScanner",
            ))

        if findings:
            return findings  # OSV results take priority

    # ── Fallback: bundled DB ──────────────────────────────────────────────────
    pkg_lower = package.lower()
    for vuln in VULN_DB.get(pkg_lower, []):
        if _version_lte(version, vuln["max_version"]):
            findings.append(Finding(
                file=filepath,
                line=lineno,
                severity=_SEVERITY_MAP.get(vuln["severity"], Severity.MEDIUM),
                title=f"Vulnerable Dependency — {package} {version} ({vuln['cve']})",
                description=vuln["desc"],
                code_snippet=code_snippet,
                cwe_id="CWE-1035",
                fix=vuln["fix"],
                scanner="DependencyScanner(bundled)",
            ))
    return findings
