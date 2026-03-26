"""
VibeScan — Report Generator
Produces rich Markdown and JSON reports from a ScanResult.
"""

import json
import os
from datetime import datetime
from .models import ScanResult, Severity


def _severity_icon(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "🔴",
        Severity.HIGH:     "🟠",
        Severity.MEDIUM:   "🟡",
        Severity.LOW:      "🔵",
        Severity.INFO:     "⚪",
    }.get(severity, "⚪")


def generate_markdown(result: ScanResult) -> str:
    """Generate a full Markdown report from a ScanResult."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines += [
        "# 🛡️ VibeScan Security Report",
        "",
        f"**Generated:** {now}  ",
        f"**Target:** `{result.target_path}`  ",
        f"**Files Scanned:** {result.files_scanned}  ",
        f"**Files Skipped:** {result.files_skipped}  ",
        f"**Scan Duration:** {result.scan_duration:.2f}s  ",
        "",
    ]

    # ── Executive Summary ─────────────────────────────────────────────────────
    lines += [
        "## 📊 Executive Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 Critical | {result.critical_count} |",
        f"| 🟠 High     | {result.high_count} |",
        f"| 🟡 Medium   | {result.medium_count} |",
        f"| 🔵 Low      | {result.low_count} |",
        f"| ⚪ Info     | {result.info_count} |",
        f"| **Total**   | **{result.total}** |",
        "",
    ]

    # ── Overall verdict ───────────────────────────────────────────────────────
    if result.critical_count > 0:
        verdict_line = "❌ **VERDICT: REQUEST_CHANGES** — Critical vulnerabilities must be resolved before deployment."
    elif result.high_count > 0:
        verdict_line = "⚠️ **VERDICT: COMMENT** — High-severity issues should be addressed before production deployment."
    elif result.total > 0:
        verdict_line = "🔶 **VERDICT: COMMENT** — Minor issues found. Review before merging."
    else:
        verdict_line = "✅ **VERDICT: APPROVE** — No security vulnerabilities detected."

    lines += [verdict_line, ""]

    # ── Findings ──────────────────────────────────────────────────────────────
    if result.findings:
        lines += ["---", "", "## 🔍 Findings", ""]

        sorted_findings = result.sorted_findings()
        current_sev = None
        for finding in sorted_findings:
            if finding.severity != current_sev:
                current_sev = finding.severity
                lines += [
                    f"### {_severity_icon(finding.severity)} {finding.severity.label} Severity",
                    "",
                ]

            rel_path = os.path.relpath(finding.file, result.target_path)
            lines += [
                f"#### [{finding.severity.label}] {finding.title}",
                "",
                f"- **File:** `{rel_path}`",
                f"- **Line:** {finding.line}",
            ]
            if finding.cwe_id:
                lines.append(f"- **CWE:** [{finding.cwe_id}](https://cwe.mitre.org/data/definitions/{finding.cwe_id.split('-')[-1]}.html)")
            lines += [
                f"- **Scanner:** `{finding.scanner}`",
                "",
                f"**Problem:** {finding.description}",
                "",
            ]
            if finding.code_snippet:
                lines += [
                    "**Code:**",
                    "```",
                    finding.code_snippet,
                    "```",
                    "",
                ]
            if finding.fix:
                lines += [
                    "**Fix:**",
                    f"{finding.fix}",
                    "",
                ]
            lines.append("---")
            lines.append("")
    else:
        lines += ["## ✅ No Issues Found", "", "The scanner found no security vulnerabilities in this codebase.", ""]

    # ── Security Assessment ───────────────────────────────────────────────────
    lines += ["## 🔒 Security Assessment", ""]
    if result.critical_count == 0 and result.high_count == 0:
        lines.append("No critical or high-severity security vulnerabilities were identified in this scan.")
    else:
        lines.append(
            f"**{result.critical_count} critical** and **{result.high_count} high**-severity security "
            "vulnerabilities were identified. These must be addressed before deploying to production. "
            "See the findings above for detailed remediation guidance."
        )
    lines += [""]

    # ── JSON Summary Block ────────────────────────────────────────────────────
    lines += [
        "---",
        "",
        "## 📦 Machine-Readable Summary",
        "",
        "```json",
        json.dumps(result.to_dict()["summary"] | {
            "verdict":               ("REQUEST_CHANGES" if result.critical_count > 0
                                      else "COMMENT" if result.total > 0
                                      else "APPROVE"),
            "security_issues_found": result.critical_count > 0 or result.high_count > 0,
            "files_scanned":         result.files_scanned,
            "scan_duration_seconds": round(result.scan_duration, 3),
        }, indent=2),
        "```",
        "",
    ]

    return "\n".join(lines)


def generate_json(result: ScanResult) -> str:
    """Generate a standalone JSON report."""
    return json.dumps(result.to_dict(), indent=2)


def write_report(result: ScanResult, output_path: str, fmt: str = "md") -> None:
    """Write the report to a file. fmt: 'md' | 'json' | 'html' | 'pdf'"""
    if fmt == "pdf":
        from .pdf_report import write_pdf
        write_pdf(result, output_path)
        return

    if fmt == "json":
        content = generate_json(result)
    elif fmt == "html":
        from .html_report import generate_html          # lazy import — optional dep
        content = generate_html(result)
    else:
        content = generate_markdown(result)

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)
