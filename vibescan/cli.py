"""
VibeScan — CLI Entry Point (v2)
All new flags: --sarif, --baseline, --save-baseline, --plugins, --live-cve, --workers,
               --staged-only, --fix, --rules, --format pdf
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
   VibeScan  --  Autonomous Security Vulnerability Scanner
   v2.1.0
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

    # YAML custom rules
    yaml_rule_scanner = None
    if args.rules:
        from .yaml_rules import load_yaml_rules, YAMLRuleScanner
        rules_path = os.path.abspath(args.rules)
        print(f"  {BOLD}Rules:  {RESET} {rules_path}")
        rules = load_yaml_rules(rules_path)
        if rules:
            yaml_rule_scanner = YAMLRuleScanner(rules)
            extra_scanners.append(yaml_rule_scanner)
            print(f"  {GREEN}✔ Loaded {len(rules)} custom rule(s){RESET}")

    print(f"\n  {DIM}Running scanners...{RESET}", flush=True)

    # Staged-only mode for pre-commit
    staged_files = None
    if getattr(args, 'staged_only', False):
        import subprocess as _sp
        try:
            out = _sp.check_output(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                cwd=target, text=True
            )
            staged_files = [os.path.join(target, f.strip()) for f in out.strip().splitlines() if f.strip()]
            print(f"  {CYAN}Pre-commit mode:{RESET} scanning {len(staged_files)} staged file(s)")
        except Exception:
            print(f"  {YELLOW}Warning:{RESET} Could not get staged files, scanning full directory.")

    result = run_scan(target, config, extra_scanners=extra_scanners,
                      max_workers=args.workers, staged_files=staged_files)

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

    # ── Show auto-fix diffs (--fix mode) ─────────────────────────────────────
    if getattr(args, 'fix', False) and result.findings:
        print(f"  {BOLD}Auto-Remediation Suggestions:{RESET}")
        has_fix = False
        for finding in result.sorted_findings():
            if finding.fix and '\n' in finding.fix:
                has_fix = True
                rel = os.path.relpath(finding.file, target)
                print(f"\n  {CYAN}{rel}{RESET}:{YELLOW}line {finding.line}{RESET} — {finding.title}")
                for fix_line in finding.fix.splitlines():
                    if fix_line.strip().startswith('Before:'):
                        print(f"    {RED}- {fix_line.strip()}{RESET}")
                    elif fix_line.strip().startswith('After:'):
                        print(f"    {GREEN}+ {fix_line.strip()}{RESET}")
                    else:
                        print(f"    {DIM}{fix_line}{RESET}")
        if not has_fix:
            print(f"  {DIM}No auto-fix suggestions available for current findings.{RESET}")
        print()

    # ── Auto-save to history DB ───────────────────────────────────────────────
    if not getattr(args, "no_save", False):
        try:
            from .storage import ScanStore
            scan_id = ScanStore().save_scan(result)
            print(f"  {DIM}\u270e Scan saved to history (id={scan_id}). "
                  f"Run {RESET}{CYAN}vibescan serve{RESET}{DIM} to view.{RESET}\n")
        except Exception:
            pass  # never let storage failure break a scan

    return 1 if result.critical_count > 0 else 0


def cmd_serve(args) -> int:
    from .serve import start_server
    start_server(
        port=args.port,
        db_path=args.db or None,
        open_browser=not args.no_browser,
    )
    return 0


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


SNIPPETS = [
    {
        "id": "1a",
        "title": "Discount Pricing (if-elif-else)",
        "code": """a = int(input())

if a < 1000:
    f = a
elif a < 5000:
    f = a*0.9
elif a < 10000:
    f = a*0.8
else:
    f = a*0.75 - 500

print(int(f))""",
        "input": "12000",
    },
    {
        "id": "1b",
        "title": "Shopping Cart Discount",
        "code": """n = int(input())
t = 0

for i in range(n):
    p, d = map(int, input().split())
    t += p - p*d/100

if t > 1000:
    t -= 150
elif t > 500:
    t -= t*0.10

print(int(t))""",
        "input": "2\n600 10\n500 20",
    },
    {
        "id": "2a",
        "title": "Sum Modulo M",
        "code": """n,m = map(int,input().split())
a = list(map(int,input().split()))

s = 0
for i in a:
    s = (s+i)%m

print(s)""",
        "input": "5 7\n10 20 30 40 50",
    },
    {
        "id": "2b",
        "title": "Modular Exponentiation",
        "code": """a,m,p = map(int,input().split())

r = 1
a %= p

while m > 0:
    if m%2:
        r = (r*a)%p
    a = (a*a)%p
    m //= 2

print(r)""",
        "input": "2 5 13",
    },
    {
        "id": "3a",
        "title": "Sum of Modular Powers",
        "code": """def f(a,m,p):
 r=1
 while m:
  if m%2:r=r*a%p
  a=a*a%p
  m//=2
 return r

n,p=map(int,input().split())
t=0

for i in range(n):
 a,m=map(int,input().split())
 t=(t+f(a,m,p))%p

print(t)""",
        "input": "2 100\n2 5\n3 4",
    },
    {
        "id": "3b",
        "title": "Modular Product Divisibility",
        "code": """a,b,p,k = map(int,input().split())

m = (a*b)%p

if m%k==0:
    print(\"Divisible\")
else:
    print(\"Not Divisible\")""",
        "input": "100000 200000 1000000 4",
    },
    {
        "id": "4a",
        "title": "nCr — Optimised",
        "code": """n,k = map(int,input().split())

r = 1
k = min(k,n-k)

for i in range(1,k+1):
    r = r*(n-i+1)//i

print(r)""",
        "input": "5 2",
    },
    {
        "id": "4b",
        "title": "nCr — Factorial Method",
        "code": """n,k = map(int,input().split())

f = 1
for i in range(1,n+1):
    f *= i

a = 1
for i in range(1,k+1):
    a *= i

b = 1
for i in range(1,n-k+1):
    b *= i

print(f//(a*b))""",
        "input": "6 3",
    },
    {
        "id": "5a",
        "title": "Card Probability",
        "code": """def c(n,r):
 f=1
 for i in range(r):
  f=f*(n-i)//(i+1)
 return f

k,r=map(int,input().split())

a=c(13,r)*c(39,k-r)
b=c(52,k)

print(round(a/b,6))""",
        "input": "5 2",
    },
    {
        "id": "5b",
        "title": "Hypergeometric Probability",
        "code": """def c(n,r):
 t=1
 for i in range(r):
  t=t*(n-i)/(i+1)
 return t

n,d,k,r=map(int,input().split())

print(f\"{c(d,r)*c(n-d,k-r)/c(n,k):.6f}\")""",
        "input": "100 10 8 2",
    },
    {
        "id": "6a",
        "title": "XOR of Array",
        "code": """n=int(input())
a=map(int,input().split())

x=0
for i in a:
 x^=i

print(x)""",
        "input": "5\n1 2 3 2 1",
    },
    {
        "id": "6b",
        "title": "XOR Checksum Anomaly Detector",
        "code": """n=int(input())
a=map(int,input().split())
c=int(input())

x=0
for i in a:x^=i

print(\"OK\" if x==c else \"ANOMALY\")""",
        "input": "5\n12 5 7 12 5\n7",
    },
    {
        "id": "7a",
        "title": "Print Array Elements",
        "code": """n=int(input())
a=input().split()

for i in a:
 print(i,end=\" \")""",
        "input": "5\n12 15 10 18 14",
    },
    {
        "id": "7b",
        "title": "Bubble Sort — 3rd Smallest",
        "code": """n=int(input())
a=list(map(int,input().split()))

for i in range(n):
 for j in range(i+1,n):
  if a[i]>a[j]:
   a[i],a[j]=a[j],a[i]

print(a[2])""",
        "input": "5\n12 15 10 18 14",
    },
    {
        "id": "8a",
        "title": "Sort & Print",
        "code": """n=int(input())
a=list(map(int,input().split()))

a.sort()

for i in a:
 print(i,end=\" \")""",
        "input": "6\n45 78 12 90 56 34",
    },
    {
        "id": "8b",
        "title": "Sort Tuples — Top 10",
        "code": """n=int(input())
a=[tuple(map(int,input().split())) for i in range(n)]

a.sort()

for i in a[:10]:
 print(*i)""",
        "input": "12\n120 101\n115 102\n130 103\n110 104\n118 105\n125 106\n112 107\n119 108\n117 109\n114 110\n116 111\n113 112",
    },
    {
        "id": "9a",
        "title": "Linear Search",
        "code": """n=int(input())
a=list(map(int,input().split()))
x=int(input())

if x in a:
 print(a.index(x))
else:
 print(\"Not Found\")""",
        "input": "6\n15 22 30 45 10 18\n45",
    },
    {
        "id": "9b",
        "title": "Access Control — Position Check",
        "code": """n=int(input())
a=list(map(int,input().split()))
x,k=map(int,input().split())

if x in a:
 print(\"Valid Access\" if a.index(x)<k else \"Late Access\")
else:
 print(\"Access ID Not Found\")""",
        "input": "8\n1012 2050 3091 4120 1503 5220 6101 7099\n3091 3",
    },
    {
        "id": "10a",
        "title": "Set Membership Check",
        "code": """s={input() for i in range(int(input()))}

for i in range(int(input())):
 print(\"Found\" if input() in s else \"Not Found\")""",
        "input": "5\napple\nbanana\ngrape\norange\nmango\n3\napple\npear\nmango",
    },
    {
        "id": "10b",
        "title": "Book Catalogue (Dictionary)",
        "code": """b=dict(input().split() for i in range(int(input())))

for i in range(int(input())):
 q=input()
 print(b[q] if q in b else \"Book Not Found\")""",
        "input": "4\nDataStructures 101\nAlgorithms 102\nOperatingSystems 103\nDatabaseSystems 104\n3\nAlgorithms\nNetworks\nDatabaseSystems",
    },
]


def cmd_snippets(args) -> int:
    """Print all code snippets to the terminal."""
    filter_id = args.filter.lower() if args.filter else None
    sep = "=" * 65
    thin = "-" * 65

    matches = [
        s for s in SNIPPETS
        if filter_id is None or s["id"].lower() == filter_id
    ]

    if not matches:
        print(f"{RED}No snippet found with id '{args.filter}'.{RESET}")
        print(f"{DIM}Available ids: {', '.join(s['id'] for s in SNIPPETS)}{RESET}")
        return 1

    print(BANNER)
    print(f"{BOLD}{CYAN}  VibeScan — Code Snippets  ({len(matches)} of {len(SNIPPETS)} shown){RESET}\n")

    for snippet in matches:
        print(f"{CYAN}{sep}{RESET}")
        print(f"  {BOLD}{YELLOW}[{snippet['id']}]{RESET}  {BOLD}{snippet['title']}{RESET}")
        print(f"{CYAN}{thin}{RESET}")
        # Print code with line numbers
        for lineno, line in enumerate(snippet["code"].splitlines(), 1):
            print(f"  {GRAY}{lineno:>3} |{RESET}  {GREEN}{line}{RESET}")
        print(f"{CYAN}{thin}{RESET}")
        print(f"  {BOLD}Input:{RESET}")
        for inp_line in snippet["input"].splitlines():
            print(f"    {YELLOW}{inp_line}{RESET}")
        print()

    print(f"{CYAN}{sep}{RESET}")
    print(f"  {DIM}Tip: use  vibescan snippets --filter 3a  to show a single snippet.{RESET}\n")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="vibescan",
        description="VibeScan v2 — Autonomous Security Vulnerability Scanner",
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── scan ──────────────────────────────────────────────────────────────────
    sp = subparsers.add_parser("scan", help="Scan a directory for security vulnerabilities")
    sp.add_argument("path",                     help="Directory to scan")
    sp.add_argument("--output",     "-o",       help="Report output path (e.g. report.md)")
    sp.add_argument("--format",     "-f",       default="md", choices=["md", "json", "html", "pdf"],
                    help="Report format: md, json, html, or pdf (default: md)")
    sp.add_argument("--sarif",                  help="Write SARIF 2.1.0 output to this path (e.g. results.sarif)")
    sp.add_argument("--severity",   "-s",       default="INFO",
                    choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    help="Minimum severity to report (default: INFO)")
    sp.add_argument("--baseline",               help="Baseline JSON to diff against (only report new findings)")
    sp.add_argument("--save-baseline",          help="Save current scan as baseline JSON")
    sp.add_argument("--plugins",                help="Path to plugins directory (auto-discovered scanners)")
    sp.add_argument("--workers",    "-w",       type=int, default=8,
                    help="Number of parallel worker threads (default: 8)")
    sp.add_argument("--no-save",                action="store_true",
                     help="Don't save this scan to the history database")
    sp.add_argument("--staged-only",             action="store_true",
                     help="Scan only git-staged files (for pre-commit hooks)")
    sp.add_argument("--fix",                     action="store_true",
                     help="Show auto-remediation suggestions with before/after diffs")
    sp.add_argument("--rules",                   default=None,
                     help="Path to a .vibescan-rules.yml custom rule file")

    # ── serve ─────────────────────────────────────────────────────────────────
    srv = subparsers.add_parser("serve", help="Launch the local web dashboard")
    srv.add_argument("--port", "-p", type=int, default=8080,
                     help="Port to listen on (default: 8080)")
    srv.add_argument("--db", default=None,
                     help="Path to the SQLite history database")
    srv.add_argument("--no-browser", action="store_true",
                     help="Don't open a browser tab automatically")

    # ── list-plugins ──────────────────────────────────────────────────────────
    lp = subparsers.add_parser("list-plugins", help="List discovered plugins in a directory")
    lp.add_argument("plugins_dir", help="Path to plugins directory")

    # ── snippets ──────────────────────────────────────────────────────────────
    snp = subparsers.add_parser("snippets", help="Display all built-in code snippets in the terminal")
    snp.add_argument("--filter", "-f", default=None, metavar="ID",
                     help="Show only the snippet with this id (e.g. 3a, 10b)")

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "serve":
        sys.exit(cmd_serve(args))
    elif args.command == "list-plugins":
        sys.exit(cmd_list_plugins(args))
    elif args.command == "snippets":
        sys.exit(cmd_snippets(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
