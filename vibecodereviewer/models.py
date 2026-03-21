"""
VibeCodeReviewer - Data Models
Defines the core data structures used across the scanner.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


class Severity(Enum):
    CRITICAL = ("CRITICAL", 5, "\033[91m")   # Bright Red
    HIGH     = ("HIGH",     4, "\033[31m")    # Red
    MEDIUM   = ("MEDIUM",   3, "\033[33m")    # Yellow
    LOW      = ("LOW",      2, "\033[36m")    # Cyan
    INFO     = ("INFO",     1, "\033[37m")    # White

    def __init__(self, label: str, weight: int, color: str):
        self.label = label
        self.weight = weight
        self.color = color

    def __lt__(self, other):
        return self.weight < other.weight

    def __le__(self, other):
        return self.weight <= other.weight

    def __gt__(self, other):
        return self.weight > other.weight

    def __ge__(self, other):
        return self.weight >= other.weight

    def colored(self) -> str:
        reset = "\033[0m"
        return f"{self.color}{self.label}{reset}"


@dataclass
class Finding:
    """Represents a single security vulnerability finding."""
    file:         str
    line:         int
    severity:     Severity
    title:        str
    description:  str
    code_snippet: str           = ""
    cwe_id:       Optional[str] = None   # e.g. "CWE-89"
    fix:          str           = ""
    scanner:      str           = ""

    def to_dict(self) -> dict:
        return {
            "file":         self.file,
            "line":         self.line,
            "severity":     self.severity.label,
            "title":        self.title,
            "description":  self.description,
            "code_snippet": self.code_snippet,
            "cwe_id":       self.cwe_id,
            "fix":          self.fix,
            "scanner":      self.scanner,
        }


@dataclass
class ScanResult:
    """Aggregated results of a full codebase scan."""
    findings:      list[Finding]  = field(default_factory=list)
    files_scanned: int            = 0
    files_skipped: int            = 0
    scan_duration: float          = 0.0
    target_path:   str            = ""

    def count_by_severity(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    @property
    def critical_count(self) -> int:
        return self.count_by_severity(Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return self.count_by_severity(Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return self.count_by_severity(Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return self.count_by_severity(Severity.LOW)

    @property
    def info_count(self) -> int:
        return self.count_by_severity(Severity.INFO)

    @property
    def total(self) -> int:
        return len(self.findings)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity, reverse=True)

    def to_dict(self) -> dict:
        return {
            "target_path":   self.target_path,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "scan_duration": round(self.scan_duration, 3),
            "summary": {
                "critical": self.critical_count,
                "high":     self.high_count,
                "medium":   self.medium_count,
                "low":      self.low_count,
                "info":     self.info_count,
                "total":    self.total,
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
