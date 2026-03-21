# ── Integration patch for report.py ────────────────────────────────────────────
#
# 1. Copy html_report.py into codesentinel/ (alongside report.py).
#
# 2. In report.py, add this import at the top:
#
#      from .html_report import generate_html
#
# 3. Replace the write_report() function at the bottom of report.py with this:

def write_report(result, output_path: str, fmt: str = "md") -> None:
    """Write the report to a file. fmt: 'md' | 'json' | 'html'"""
    if fmt == "json":
        content = generate_json(result)
    elif fmt == "html":
        from .html_report import generate_html
        content = generate_html(result)
    else:
        content = generate_markdown(result)

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)


# 4. In cli.py, extend the --format argument choices:
#
#    BEFORE:
#      choices=["md", "json"]
#
#    AFTER:
#      choices=["md", "json", "html"]
#
# 5. Usage:
#      python -m codesentinel.cli scan ./my_project --output report.html --format html
#
# That's it. The HTML report is self-contained (no CDN dependencies at runtime),
# dark-themed, filterable by severity, searchable by keyword, and auto-expands
# all CRITICAL findings on load.