"""
VibeScan — PDF Report Generator
Generates a print-ready HTML file with @media print CSS that can be saved as PDF.
If weasyprint is installed, auto-generates a PDF file directly.
Falls back to a styled printable HTML file otherwise.
"""

import os
from datetime import datetime
from .models import ScanResult, Severity


def _sev_color(label: str) -> str:
    return {
        "CRITICAL": "#E24B4A", "HIGH": "#EF9F27", "MEDIUM": "#D4B84A",
        "LOW": "#4A9EE8", "INFO": "#888780",
    }.get(label, "#888780")


def generate_pdf_html(result: ScanResult) -> str:
    """Generate a self-contained, print-optimized HTML report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    project = os.path.basename(result.target_path)

    # Build findings rows
    rows = ""
    for f in result.sorted_findings():
        col = _sev_color(f.severity.label)
        rel = os.path.relpath(f.file, result.target_path)
        cwe = f.cwe_id or "—"
        fix_html = f"<div class='fix'>{_esc(f.fix)}</div>" if f.fix else ""
        rows += f"""
        <div class="finding">
          <div class="finding-head">
            <span class="sev" style="background:{col}">{_esc(f.severity.label)}</span>
            <span class="ftitle">{_esc(f.title)}</span>
            <span class="floc">{_esc(rel)}:{f.line}</span>
          </div>
          <div class="finding-body">
            <p class="meta-row">CWE: {_esc(cwe)} &middot; Scanner: {_esc(f.scanner)}</p>
            <p class="desc">{_esc(f.description)}</p>
            {f'<pre class="code">{_esc(f.code_snippet)}</pre>' if f.code_snippet else ''}
            {fix_html}
          </div>
        </div>"""

    if result.critical_count > 0:
        verdict = "CRITICAL — Immediate action required"
        verdict_color = "#E24B4A"
    elif result.high_count > 0:
        verdict = "HIGH — Review before production"
        verdict_color = "#EF9F27"
    elif result.total > 0:
        verdict = "MINOR — Issues found, review recommended"
        verdict_color = "#D4B84A"
    else:
        verdict = "CLEAN — No vulnerabilities detected"
        verdict_color = "#4AC88C"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VibeScan Security Report — {_esc(project)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'IBM Plex Sans', sans-serif; font-size: 11px; color: #1a1a1a; padding: 32px; line-height: 1.5; }}
  .header {{ border-bottom: 2px solid #111; padding-bottom: 12px; margin-bottom: 20px; }}
  .logo {{ font-family: 'IBM Plex Mono', monospace; font-size: 9px; color: #888; text-transform: uppercase; letter-spacing: 0.1em; }}
  h1 {{ font-size: 20px; font-weight: 600; margin: 4px 0; }}
  .meta {{ font-size: 10px; color: #666; font-family: 'IBM Plex Mono', monospace; }}
  .verdict {{ display: inline-block; padding: 6px 14px; border-radius: 4px; font-size: 11px; font-weight: 500; color: white; background: {verdict_color}; margin: 12px 0 16px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin-bottom: 20px; }}
  .summary-card {{ border: 1px solid #ddd; border-radius: 6px; padding: 10px; text-align: center; }}
  .summary-card .num {{ font-size: 20px; font-weight: 600; font-family: 'IBM Plex Mono', monospace; }}
  .summary-card .lbl {{ font-size: 9px; color: #888; text-transform: uppercase; letter-spacing: 0.06em; }}
  .finding {{ border: 1px solid #ddd; border-radius: 6px; margin-bottom: 8px; overflow: hidden; page-break-inside: avoid; }}
  .finding-head {{ display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: #f8f8f8; }}
  .sev {{ font-family: 'IBM Plex Mono', monospace; font-size: 9px; padding: 2px 8px; border-radius: 3px; color: white; font-weight: 500; }}
  .ftitle {{ font-weight: 500; font-size: 12px; flex: 1; }}
  .floc {{ font-family: 'IBM Plex Mono', monospace; font-size: 10px; color: #888; }}
  .finding-body {{ padding: 8px 12px; }}
  .meta-row {{ font-size: 10px; color: #888; font-family: 'IBM Plex Mono', monospace; margin-bottom: 4px; }}
  .desc {{ font-size: 11px; color: #444; margin-bottom: 6px; }}
  .code {{ background: #f4f4f4; border: 1px solid #e0e0e0; border-radius: 4px; padding: 6px 10px; font-family: 'IBM Plex Mono', monospace; font-size: 10px; overflow-x: auto; white-space: pre; margin-bottom: 6px; }}
  .fix {{ background: #eef9f3; border: 1px solid #c3e6d5; border-radius: 4px; padding: 6px 10px; font-size: 10px; color: #2d8659; }}
  .footer {{ margin-top: 24px; padding-top: 12px; border-top: 1px solid #ddd; font-size: 9px; color: #888; font-family: 'IBM Plex Mono', monospace; display: flex; justify-content: space-between; }}
  @media print {{
    body {{ padding: 16px; }}
    .finding {{ page-break-inside: avoid; }}
  }}
</style>
</head>
<body>
  <div class="header">
    <div class="logo">&#9635; VibeScan Security Report</div>
    <h1>{_esc(project)}</h1>
    <div class="meta">
      Generated: {now} &middot; Target: {_esc(result.target_path)} &middot;
      {result.files_scanned} files scanned &middot; {result.scan_duration:.2f}s
    </div>
  </div>
  <div class="verdict">{verdict}</div>
  <div class="summary-grid">
    <div class="summary-card"><div class="num" style="color:#E24B4A">{result.critical_count}</div><div class="lbl">Critical</div></div>
    <div class="summary-card"><div class="num" style="color:#EF9F27">{result.high_count}</div><div class="lbl">High</div></div>
    <div class="summary-card"><div class="num" style="color:#D4B84A">{result.medium_count}</div><div class="lbl">Medium</div></div>
    <div class="summary-card"><div class="num" style="color:#4A9EE8">{result.low_count}</div><div class="lbl">Low</div></div>
    <div class="summary-card"><div class="num" style="color:#888">{result.info_count}</div><div class="lbl">Info</div></div>
  </div>
  {rows}
  <div class="footer">
    <span>VibeScan v2.1.0</span>
    <span>{now}</span>
  </div>
</body>
</html>"""


def _esc(s: str) -> str:
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def write_pdf(result: ScanResult, output_path: str) -> None:
    """
    Write a PDF report. Uses weasyprint if available, otherwise
    generates a printable HTML file the user can open and print to PDF.
    """
    html = generate_pdf_html(result)

    try:
        from weasyprint import HTML as WeasyprintHTML
        WeasyprintHTML(string=html).write_pdf(output_path)
        return
    except ImportError:
        pass

    # Fallback: write printable HTML
    html_path = output_path
    if output_path.endswith(".pdf"):
        html_path = output_path.replace(".pdf", ".html")

    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    if html_path != output_path:
        print(f"  Note: weasyprint not installed. Printable HTML saved to: {html_path}")
        print(f"        Open in browser and use Ctrl+P / File > Print to save as PDF.")
        print(f"        Install weasyprint for direct PDF: pip install weasyprint")
