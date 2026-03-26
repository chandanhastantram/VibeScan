"""
VibeScan — Auto-Remediation Engine
Maps common vulnerability patterns to suggested code fixes.
Applied as a post-processing step to enhance Finding.fix fields.
"""

import re
from .models import Finding

# ── Remediation rules ─────────────────────────────────────────────────────────
# Each rule: (scanner_pattern, code_regex, before_snippet, after_snippet, note)

_REMEDIATION_MAP: list[dict] = [
    # SQL Injection — f-string / format / concat → parameterized
    {
        "title_match": re.compile(r"sql injection", re.IGNORECASE),
        "patterns": [
            {
                "detect": re.compile(r"""(cursor\.\w+|\.execute)\s*\(\s*f["']"""),
                "before": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                "after":  'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                "note": "Use parameterized queries instead of f-strings in SQL.",
            },
            {
                "detect": re.compile(r"""(cursor\.\w+|\.execute)\s*\(\s*["'].*%s.*["']\s*%"""),
                "before": 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
                "after":  'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                "note": "Use parameterized queries instead of string interpolation.",
            },
        ],
    },
    # Command Injection — os.system / subprocess shell=True
    {
        "title_match": re.compile(r"command injection|os\.system|shell.?true", re.IGNORECASE),
        "patterns": [
            {
                "detect": re.compile(r"os\.system\s*\("),
                "before": 'os.system(f"rm -rf {user_input}")',
                "after":  'subprocess.run(["rm", "-rf", user_input], check=True)',
                "note": "Replace os.system() with subprocess.run() using a list of arguments (no shell).",
            },
            {
                "detect": re.compile(r"subprocess\.\w+\(.*shell\s*=\s*True"),
                "before": 'subprocess.run(cmd, shell=True)',
                "after":  'subprocess.run(shlex.split(cmd), shell=False)',
                "note": "Set shell=False and pass arguments as a list.",
            },
        ],
    },
    # eval / exec
    {
        "title_match": re.compile(r"eval|exec|code execution", re.IGNORECASE),
        "patterns": [
            {
                "detect": re.compile(r"\beval\s*\("),
                "before": 'result = eval(user_input)',
                "after":  'import ast\nresult = ast.literal_eval(user_input)',
                "note": "Use ast.literal_eval() for safe evaluation of string literals.",
            },
        ],
    },
    # Insecure Deserialization — pickle → json
    {
        "title_match": re.compile(r"pickle|deserialization", re.IGNORECASE),
        "patterns": [
            {
                "detect": re.compile(r"pickle\.load\s*\("),
                "before": 'data = pickle.load(file)',
                "after":  'import json\ndata = json.load(file)',
                "note": "Replace pickle with json for untrusted data. If you need pickle, only load trusted data.",
            },
        ],
    },
    # yaml.load → yaml.safe_load
    {
        "title_match": re.compile(r"yaml\.load|deserialization", re.IGNORECASE),
        "patterns": [
            {
                "detect": re.compile(r"yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)"),
                "before": 'data = yaml.load(content)',
                "after":  'data = yaml.safe_load(content)',
                "note": "Use yaml.safe_load() to prevent arbitrary code execution.",
            },
        ],
    },
    # Weak crypto — md5/sha1 → sha256
    {
        "title_match": re.compile(r"md5|sha1|weak.*crypt|hash", re.IGNORECASE),
        "patterns": [
            {
                "detect": re.compile(r"hashlib\.md5\s*\("),
                "before": 'digest = hashlib.md5(data).hexdigest()',
                "after":  'digest = hashlib.sha256(data).hexdigest()',
                "note": "MD5 is cryptographically broken. Use SHA-256 or SHA-3.",
            },
            {
                "detect": re.compile(r"hashlib\.sha1\s*\("),
                "before": 'digest = hashlib.sha1(data).hexdigest()',
                "after":  'digest = hashlib.sha256(data).hexdigest()',
                "note": "SHA-1 is deprecated. Use SHA-256 or SHA-3.",
            },
        ],
    },
    # DEBUG = True
    {
        "title_match": re.compile(r"debug.*true|sensitive.*data", re.IGNORECASE),
        "patterns": [
            {
                "detect": re.compile(r"DEBUG\s*=\s*True\b"),
                "before": 'DEBUG = True',
                "after":  'DEBUG = os.environ.get("DEBUG", "False").lower() == "true"',
                "note": "Never hardcode DEBUG=True. Use environment variables for production safety.",
            },
        ],
    },
    # XSS — mark_safe / dangerouslySetInnerHTML
    {
        "title_match": re.compile(r"xss|cross.?site|mark_safe|innerHTML", re.IGNORECASE),
        "patterns": [
            {
                "detect": re.compile(r"mark_safe\s*\("),
                "before": 'return mark_safe(user_content)',
                "after":  'from django.utils.html import escape\nreturn mark_safe(escape(user_content))',
                "note": "Always escape user input before passing to mark_safe().",
            },
            {
                "detect": re.compile(r"dangerouslySetInnerHTML"),
                "before": '<div dangerouslySetInnerHTML={{__html: userInput}} />',
                "after":  'import DOMPurify from "dompurify";\n<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />',
                "note": "Sanitize input with DOMPurify before using dangerouslySetInnerHTML.",
            },
        ],
    },
]


def enhance_findings_with_remediation(findings: list[Finding]) -> list[Finding]:
    """
    Post-process findings to add detailed remediation suggestions.
    Enhances the 'fix' field with before/after code examples when available.
    """
    for finding in findings:
        for rule in _REMEDIATION_MAP:
            if not rule["title_match"].search(finding.title):
                continue
            for pat in rule["patterns"]:
                if finding.code_snippet and pat["detect"].search(finding.code_snippet):
                    # Build enhanced fix with before/after diff
                    fix_text = pat["note"]
                    fix_text += f"\n\n  Before: {pat['before']}"
                    fix_text += f"\n  After:  {pat['after']}"
                    finding.fix = fix_text
                    break
            else:
                continue
            break  # matched — stop checking more rules

    return findings
