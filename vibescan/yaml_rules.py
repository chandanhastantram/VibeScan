"""
VibeScan — YAML Custom Rule Engine
Lets users define security rules in .vibescan-rules.yml instead of writing Python.

Rule format:
  rules:
    - id: no-console-log
      pattern: "console\\.log\\("
      file_extensions: [".js", ".ts"]
      severity: LOW
      title: "Console.log left in code"
      description: "Remove console.log statements before production deployment."
      fix: "Replace with a proper logger or remove entirely."
      cwe_id: null
"""

import re
import os
from .scanners.base import BaseScanner
from .models import Finding, Severity

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
    "INFO":     Severity.INFO,
}


class YAMLRule:
    """A single compiled rule from the YAML file."""

    def __init__(self, data: dict):
        self.id = data.get("id", "custom-rule")
        self.pattern = re.compile(data["pattern"])
        self.extensions = tuple(data.get("file_extensions", []))
        self.severity = _SEV_MAP.get(
            str(data.get("severity", "MEDIUM")).upper(), Severity.MEDIUM
        )
        self.title = data.get("title", self.id)
        self.description = data.get("description", "")
        self.fix = data.get("fix", "")
        self.cwe_id = data.get("cwe_id")


class YAMLRuleScanner(BaseScanner):
    """Scanner that applies user-defined YAML rules."""

    name = "YAMLRuleScanner"
    SUPPORTED_EXTENSIONS = ()  # will be determined dynamically

    def __init__(self, rules: list[YAMLRule] | None = None):
        self.rules = rules or []
        # Dynamically compute supported extensions from all rules
        all_exts: set[str] = set()
        for r in self.rules:
            all_exts.update(r.extensions)
        # If any rule has no extension filter, support all files
        if not all_exts or any(not r.extensions for r in self.rules):
            self.SUPPORTED_EXTENSIONS = ()
        else:
            self.SUPPORTED_EXTENSIONS = tuple(all_exts)

    def scan_file(self, filepath: str, content: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            # Skip if rule has extension filter and file doesn't match
            if rule.extensions and not any(filepath.endswith(e) for e in rule.extensions):
                continue
            for lineno, line in enumerate(lines, start=1):
                if rule.pattern.search(line):
                    findings.append(Finding(
                        file=filepath,
                        line=lineno,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        code_snippet=line.rstrip(),
                        cwe_id=rule.cwe_id,
                        fix=rule.fix,
                        scanner=f"{self.name}:{rule.id}",
                    ))
        return findings


def load_yaml_rules(rules_path: str) -> list[YAMLRule]:
    """Load and compile rules from a YAML file."""
    if not _YAML_AVAILABLE:
        print("  Warning: PyYAML required for custom rules. pip install pyyaml")
        return []

    if not os.path.isfile(rules_path):
        print(f"  Warning: Rules file not found: {rules_path}")
        return []

    try:
        with open(rules_path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception as e:
        print(f"  Warning: Failed to load rules file: {e}")
        return []

    raw_rules = data.get("rules", [])
    compiled: list[YAMLRule] = []
    for item in raw_rules:
        if "pattern" not in item:
            continue
        try:
            compiled.append(YAMLRule(item))
        except re.error as e:
            print(f"  Warning: Invalid regex in rule '{item.get('id', '?')}': {e}")

    return compiled
