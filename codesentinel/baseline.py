"""
CodeSentinel — Baseline Manager
Saves a scan result as a JSON baseline and computes the diff on subsequent runs.

Usage:
  # First run — establish baseline
  codesentinel scan . --save-baseline baseline.json

  # Subsequent runs — only report new findings
  codesentinel scan . --baseline baseline.json

How it works:
  A finding is considered "seen before" if a baseline entry matches on
  (relative_file_path, line, title). Line numbers shift when code is edited,
  so an optional --fuzzy-lines N flag allows a ±N line tolerance.
"""

import json
import os
from dataclasses import asdict
from .models import Finding, ScanResult, Severity


# ── Serialization helpers ─────────────────────────────────────────────────────

def save_baseline(result: ScanResult, baseline_path: str) -> None:
    """Persist the current scan's findings as a baseline JSON file."""
    entries = []
    for f in result.findings:
        try:
            rel = os.path.relpath(f.file, result.target_path)
        except ValueError:
            rel = f.file
        entries.append({
            "file":     rel.replace("\\", "/"),
            "line":     f.line,
            "title":    f.title,
            "severity": f.severity.label,
            "scanner":  f.scanner,
        })

    payload = {
        "target_path":    result.target_path,
        "total_findings": result.total,
        "findings":       entries,
    }
    with open(baseline_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def load_baseline(baseline_path: str) -> list[dict]:
    """Load baseline entries from a JSON file. Returns [] if file missing."""
    if not os.path.isfile(baseline_path):
        return []
    try:
        with open(baseline_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("findings", [])
    except (json.JSONDecodeError, KeyError):
        return []


# ── Diff computation ──────────────────────────────────────────────────────────

def _finding_key(rel_file: str, line: int, title: str) -> tuple:
    return (rel_file.replace("\\", "/").lower(), line, title.lower())


def _finding_key_fuzzy(rel_file: str, line: int, title: str, tolerance: int) -> set:
    base = rel_file.replace("\\", "/").lower()
    title_l = title.lower()
    return {(base, l, title_l) for l in range(max(1, line - tolerance), line + tolerance + 1)}


def diff_against_baseline(
    result: ScanResult,
    baseline_entries: list[dict],
    fuzzy_lines: int = 3,
) -> tuple[list[Finding], list[Finding]]:
    """
    Compare current findings against baseline.

    Returns:
        (new_findings, suppressed_findings)
        - new_findings:        findings NOT present in baseline (should be reported)
        - suppressed_findings: findings that match a baseline entry (previously known)
    """
    # Build a flat set of fuzzy keys from baseline
    baseline_keys: set[tuple] = set()
    for entry in baseline_entries:
        keys = _finding_key_fuzzy(
            entry.get("file", ""),
            entry.get("line", 0),
            entry.get("title", ""),
            fuzzy_lines,
        )
        baseline_keys.update(keys)

    new_findings = []
    suppressed_findings = []

    for finding in result.findings:
        try:
            rel = os.path.relpath(finding.file, result.target_path)
        except ValueError:
            rel = finding.file

        key = _finding_key(rel, finding.line, finding.title)
        if key in baseline_keys:
            suppressed_findings.append(finding)
        else:
            new_findings.append(finding)

    return new_findings, suppressed_findings
