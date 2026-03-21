"""
CodeSentinel — CLI Entry Point (v2)
All new flags: --sarif, --baseline, --save-baseline, --plugins, --live-cve, --workers
"""

import os
import sys
import argparse
import time

# ── Windows: force UTF-8 output so the ASCII banner renders without PYTHONIOENCODING ──
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass  # Python < 3.7 — ignore

try:
    import colorama
    colorama.init(autoreset=True)
    _USE_COLOR = True
except ImportError:
    _USE_COLOR = False

RESET  = "\033[0m"   if _USE_COLOR else ""
BOLD   = "\033[1m"   if _USE_COLOR else ""
DIM    = "\033[2m"   if _USE_COLOR else ""
RED    = "\033[91m"  if _USE_COLOR else ""
ORANGE = "\033[33m"  if _USE_COLOR else ""
YELLOW = "\033[93m"  if _USE_COLOR else ""
CYAN   = "\033[96m"  if _USE_COLOR else ""
GREEN  = "\033[92m"  if _USE_COLOR else ""
WHITE  = "\033[97m"  if _USE_COLOR else ""
GRAY   = "\033[90m"  if _USE_COLOR else ""

BANNER = f"""{RED}{BOLD}
  ================================================================
   CodeSentinel  --  Autonomous Security Vulnerability Scanner
   v2.0.0
  ================================================================
{RESET}"""

def _sev_color(label: str) -> str:
    return {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": CYAN, "INFO": WHITE}.get(label, WHITE)


def _print_finding(finding, target_path: str) -> None:
    col  = _sev_color(finding.severity.label)
    rel  = os.path.relpath(finding.file, target_path)
    print(f"\n  {col}{BOLD}[{finding.severity.label}]{RESET} {BOLD}{finding.title}{RESET}")
    print(f"  {GRAY}┌─{RESET} {CYAN}{rel}{RESET}:{YELLOW}line {finding.line}{RESET}")
    if finding.cwe_id:
        print(f"  {GRAY}├─{RESET} CWE: {finding.cwe_id}  •  Scanner: {finding.scanner}")
    print(f"  {GRAY}├─{RESET} {DIM}{finding.description[:120]}{'...' if len(finding.description) > 120 else ''}{RESET}")
    if finding.code_snippet:
        print(f"  {GRAY}├─{RESET} {GRAY}Code:{RESET} {finding.code_snippet[:120].strip()}")
    if finding.fix:
        print(f"  {GRAY}└─{RESET} {GREEN}Fix:{RESET} {finding.fix.splitlines()[0][:110]}")


def _print_summary(result, new_only: bool = False, suppressed: int = 0) -> None:
    cc, hc, mc, lc = result.critical_count, result.high_count, result.medium_count, result.low_count
    label = "NEW findings" if new_only else "findings"
    sep = "-" * 70
    print(f"\n{BOLD}{sep}{RESET}")
    print(f" {BOLD}SCAN COMPLETE{RESET}  |  {result.files_scanned} files  |  {result.scan_duration:.2f}s")
    if suppressed:
        print(f" {GRAY}Suppressed by inline comments: {suppressed}{RESET}")
    print(sep)
    print(f"  {RED}{BOLD}CRITICAL {cc:>4}{RESET}  |  {ORANGE}HIGH {hc:>4}{RESET}  |  {YELLOW}MEDIUM {mc:>4}{RESET}  |  {CYAN}LOW {lc:>4}{RESET}")
    print(sep)
    if cc > 0:
        print(f"  {RED}{BOLD}[!!] {result.total} {label} -- CRITICAL issues must be fixed before deployment.{RESET}")
    elif hc > 0:
        print(f"  {ORANGE}[!]  {result.total} {label} -- HIGH issues should be resolved.{RESET}")
    elif result.total > 0:
        print(f"  {YELLOW}[~]  {result.total} {label} -- Review before merging.{RESET}")
    else:
        print(f"  {GREEN}[OK] No {'new ' if new_only else ''}security vulnerabilities found.{RESET}")
    print(f"{sep}\n")


def cmd_scan(args) -> int:
    from .config   import load_config
    from .engine   import run_scan
    from .report   import write_report
    from .sarif    import write_sarif
    from .baseline import save_baseline, load_baseline, diff_against_baseline
    from .plugins  import discover_plugins

    target = os.path.abspath(args.path)
    if not os.path.isdir(target):
        print(f"{RED}Error: '{target}' is not a valid directory.{RESET}")
        return 1

    print(BANNER)
    print(f"  {BOLD}Scanning:{RESET} {target}")
    print(f"  {BOLD}Workers: {RESET} {args.workers}  (parallel file scanning)")

    config = load_config(target)
    config.min_severity = args.severity.upper()

    # Plugin discovery
    extra_scanners = []
    if args.plugins:
        plugins_dir = os.path.abspath(args.plugins)
        print(f"  {BOLD}Plugins: {RESET} {plugins_dir}")
        extra_scanners = discover_plugins(plugins_dir)

    print(f"\n  {DIM}Running scanners...{RESET}", flush=True)

    result = run_scan(target, config, extra_scanners=extra_scanners, max_workers=args.workers)

    # ── Baseline diff ─────────────────────────────────────────────────────────
    new_findings = result.findings
    suppressed_by_baseline = 0
    baseline_mode = False

    if args.baseline and os.path.isfile(args.baseline):
        baseline_entries = load_baseline(args.baseline)
        new_findings, known_findings = diff_against_baseline(result, baseline_entries)
        suppressed_by_baseline = len(known_findings)
        baseline_mode = True
        # Replace result.findings with new-only for display/reporting
        result.findings = new_findings
        print(f"  {CYAN}Baseline mode:{RESET} {suppressed_by_baseline} previously known findings suppressed.")

    if args.save_baseline:
        save_baseline(result, args.save_baseline)
        print(f"  {GREEN}✔ Baseline saved to:{RESET} {args.save_baseline}")

    # ── Print findings ────────────────────────────────────────────────────────
    if result.findings:
        print(f"\n  {BOLD}Findings ({result.total} total):{RESET}")
        for finding in result.sorted_findings():
            _print_finding(finding, target)

    _print_summary(result, new_only=baseline_mode, suppressed=suppressed_by_baseline)

    # ── Write reports ─────────────────────────────────────────────────────────
    if args.output:
        write_report(result, args.output, fmt=args.format)
        print(f"  {GREEN}✔ Report written to:{RESET} {args.output}")

    if args.sarif:
        write_sarif(result, args.sarif)
        print(f"  {GREEN}✔ SARIF report written to:{RESET} {args.sarif}")
        print(f"  {GRAY}  → Upload to GitHub: actions/upload-sarif@v3{RESET}")

    if args.output or args.sarif:
        print()

    return 1 if result.critical_count > 0 else 0


def cmd_list_plugins(args) -> int:
    from .plugins import list_plugin_info
    plugins_dir = os.path.abspath(args.plugins_dir)
    plugins = list_plugin_info(plugins_dir)
    if not plugins:
        print(f"No plugins found in: {plugins_dir}")
        return 0
    print(f"\nPlugins in {plugins_dir}:")
    for p in plugins:
        exts = ", ".join(p["extensions"]) or "all files"
        print(f"  • {p['name']} ({p['class']}) — extensions: {exts}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="codesentinel",
        description="CodeSentinel v2 — Autonomous Security Vulnerability Scanner",
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── scan ──────────────────────────────────────────────────────────────────
    sp = subparsers.add_parser("scan", help="Scan a directory for security vulnerabilities")
    sp.add_argument("path",                     help="Directory to scan")
    sp.add_argument("--output",     "-o",       help="Report output path (e.g. report.md)")
    sp.add_argument("--format",     "-f",       default="md", choices=["md", "json", "html"],
                    help="Report format: md, json, or html (default: md)")
    sp.add_argument("--sarif",                  help="Write SARIF 2.1.0 output to this path (e.g. results.sarif)")
    sp.add_argument("--severity",   "-s",       default="INFO",
                    choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    help="Minimum severity to report (default: INFO)")
    sp.add_argument("--baseline",               help="Baseline JSON to diff against (only report new findings)")
    sp.add_argument("--save-baseline",          help="Save current scan as baseline JSON")
    sp.add_argument("--plugins",                help="Path to plugins directory (auto-discovered scanners)")
    sp.add_argument("--workers",    "-w",       type=int, default=8,
                    help="Number of parallel worker threads (default: 8)")

    # ── list-plugins ──────────────────────────────────────────────────────────
    lp = subparsers.add_parser("list-plugins", help="List discovered plugins in a directory")
    lp.add_argument("plugins_dir", help="Path to plugins directory")

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "list-plugins":
        sys.exit(cmd_list_plugins(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
