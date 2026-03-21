"""
VibeCodeReviewer — SARIF Output Generator
Produces a Static Analysis Results Interchange Format (SARIF) 2.1.0 JSON file.

SARIF enables:
  - GitHub Code Scanning PR annotations (upload via actions/upload-sarif)
  - VS Code inline warnings (via SARIF Viewer extension)
  - Integration with any SARIF-compatible tooling

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
import os
from datetime import datetime, timezone
from .models import ScanResult, Severity

# Map our severity to SARIF level + security-severity score
_SEVERITY_MAP = {
    Severity.CRITICAL: ("error",   "9.0"),
    Severity.HIGH:     ("error",   "7.0"),
    Severity.MEDIUM:   ("warning", "5.0"),
    Severity.LOW:      ("note",    "3.0"),
    Severity.INFO:     ("none",    "1.0"),
}

TOOL_NAME    = "VibeCodeReviewer"
TOOL_VERSION = "1.0.0"
TOOL_URI     = "https://github.com/vibecodereviewer/vibecodereviewer"


def _make_rule(finding) -> dict:
    """Build a SARIF reportingDescriptor for a unique finding title."""
    level, score = _SEVERITY_MAP.get(finding.severity, ("warning", "5.0"))
    rule_id = finding.title.replace(" ", "_").replace("—", "").replace("/", "_")[:64]
    rule = {
        "id": rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription":  {"text": finding.description},
        "defaultConfiguration": {"level": level},
        "properties": {
            "security-severity": score,
            "tags": ["security"],
        },
    }
    if finding.cwe_id:
        rule["relationships"] = [{
            "target": {
                "id": finding.cwe_id,
                "toolComponent": {"name": "CWE"},
            },
        }]
    if finding.fix:
        rule["help"] = {"text": finding.fix, "markdown": f"**Fix:** {finding.fix}"}
    return rule


def _make_result(finding, target_path: str, rule_id: str) -> dict:
    """Build a SARIF result object from a Finding."""
    level, _ = _SEVERITY_MAP.get(finding.severity, ("warning", "5.0"))

    # Prefer relative paths in SARIF for portability
    try:
        rel = os.path.relpath(finding.file, target_path).replace("\\", "/")
    except ValueError:
        rel = finding.file.replace("\\", "/")

    result = {
        "ruleId":  rule_id,
        "level":   level,
        "message": {
            "text": finding.description,
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri":       rel,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": finding.line,
                    "startColumn": 1,
                },
            },
        }],
        "properties": {
            "severity": finding.severity.label,
            "scanner":  finding.scanner,
        },
    }

    if finding.code_snippet:
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": finding.code_snippet,
        }

    if finding.fix:
        result["fixes"] = [{
            "description": {"text": finding.fix},
        }]

    return result


def generate_sarif(result: ScanResult) -> str:
    """
    Generate a SARIF 2.1.0 document from a ScanResult.
    Returns the JSON string.
    """
    # Deduplicate rules by normalised title → rule_id
    rules: dict[str, dict] = {}
    results_list = []

    for finding in result.sorted_findings():
        rule_id = finding.title.replace(" ", "_").replace("—", "").replace("/", "_")[:64]

        if rule_id not in rules:
            rules[rule_id] = _make_rule(finding)
            rules[rule_id]["id"] = rule_id  # ensure id field set correctly

        results_list.append(_make_result(finding, result.target_path, rule_id))

    sarif_doc = {
        "$schema":  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version":  "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name":            TOOL_NAME,
                    "version":         TOOL_VERSION,
                    "informationUri":  TOOL_URI,
                    "semanticVersion": TOOL_VERSION,
                    "rules":           list(rules.values()),
                },
            },
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                "toolExecutionNotifications": [],
            }],
            "results":   results_list,
            "artifacts": [
                {
                    "location": {
                        "uri":       os.path.relpath(finding.file, result.target_path).replace("\\", "/"),
                        "uriBaseId": "%SRCROOT%",
                    },
                }
                for finding in result.sorted_findings()
            ],
            "originalUriBaseIds": {
                "%SRCROOT%": {
                    "uri": result.target_path.replace("\\", "/").rstrip("/") + "/",
                },
            },
            "properties": {
                "metrics": {
                    "critical": result.critical_count,
                    "high":     result.high_count,
                    "medium":   result.medium_count,
                    "low":      result.low_count,
                    "total":    result.total,
                },
            },
        }],
    }

    return json.dumps(sarif_doc, indent=2)


def write_sarif(result: ScanResult, output_path: str) -> None:
    """Write a SARIF file to disk."""
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(generate_sarif(result))
