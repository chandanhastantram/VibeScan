"""
VibeScan — Suppression Handler
Reads inline suppression comments and removes matching findings.

Supported formats (case-insensitive):
  # nosec
  # nosec: SQL Injection
  # vibescan: ignore
  # vibescan: ignore SQL Injection, Hardcoded Password
  # noqa (generic, suppresses all findings on the line)
  // nosec                  (JS/TS/Java/Go)
  // vibescan: ignore   (JS/TS/Java/Go)
"""

import re
from .models import Finding

# Matches any suppression annotation on a line
_SUPPRESSION_RE = re.compile(
    r"(?:#|//)\s*(?:nosec|noqa|vibescan\s*:\s*ignore)(?:\s*:?\s*(.+))?$",
    re.IGNORECASE,
)


def _parse_suppression(line: str) -> tuple[bool, list[str]]:
    """
    Parse a source line for suppression annotations.

    Returns:
        (is_suppressed: bool, specific_rules: list[str])
        If specific_rules is empty and is_suppressed is True → suppress ALL findings on this line.
        If specific_rules is non-empty → suppress only findings whose title contains one of the rules.
    """
    m = _SUPPRESSION_RE.search(line)
    if not m:
        return False, []

    rule_text = m.group(1)
    if not rule_text or not rule_text.strip():
        return True, []  # blanket suppression

    rules = [r.strip().lower() for r in rule_text.split(",") if r.strip()]
    return True, rules


def apply_suppressions(findings: list[Finding], file_lines: dict[str, list[str]]) -> tuple[list[Finding], int]:
    """
    Filter out findings that have a suppression comment on their source line.

    Args:
        findings:   All raw findings from the scan.
        file_lines: Dict mapping filepath → list of source lines (1-indexed content).

    Returns:
        (kept_findings, suppressed_count)
    """
    kept = []
    suppressed_count = 0

    for finding in findings:
        lines = file_lines.get(finding.file, [])
        if not lines or finding.line < 1 or finding.line > len(lines):
            kept.append(finding)
            continue

        line_content = lines[finding.line - 1]  # convert to 0-indexed
        is_suppressed, specific_rules = _parse_suppression(line_content)

        if not is_suppressed:
            kept.append(finding)
            continue

        if not specific_rules:
            # Blanket suppress — drop this finding
            suppressed_count += 1
            continue

        # Check if any specific rule matches this finding's title
        title_lower = finding.title.lower()
        if any(rule in title_lower for rule in specific_rules):
            suppressed_count += 1
        else:
            kept.append(finding)

    return kept, suppressed_count
