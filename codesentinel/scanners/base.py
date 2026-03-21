"""
CodeSentinel — Base Scanner
Abstract base class that all scanners inherit from.
"""

import re
import ast
from abc import ABC, abstractmethod
from typing import Optional
from ..models import Finding, Severity


class BaseScanner(ABC):
    """Abstract base for all security scanners."""

    name: str = "BaseScanner"

    # File extensions this scanner applies to (empty = all text files)
    SUPPORTED_EXTENSIONS: tuple[str, ...] = ()

    def supports_file(self, filepath: str) -> bool:
        if not self.SUPPORTED_EXTENSIONS:
            return True
        return any(filepath.endswith(ext) for ext in self.SUPPORTED_EXTENSIONS)

    @abstractmethod
    def scan_file(self, filepath: str, content: str, lines: list[str]) -> list[Finding]:
        """Scan a single file and return a list of findings."""
        ...

    # ------------------------------------------------------------------ helpers

    def _regex_findings(
        self,
        filepath: str,
        lines: list[str],
        pattern: re.Pattern,
        severity: Severity,
        title: str,
        description: str,
        cwe_id: Optional[str] = None,
        fix: str = "",
    ) -> list[Finding]:
        """Run a compiled regex against every line, emit a Finding on match."""
        results = []
        for lineno, line in enumerate(lines, start=1):
            if pattern.search(line):
                results.append(Finding(
                    file=filepath,
                    line=lineno,
                    severity=severity,
                    title=title,
                    description=description,
                    code_snippet=line.rstrip(),
                    cwe_id=cwe_id,
                    fix=fix,
                    scanner=self.name,
                ))
        return results

    def _try_parse_ast(self, content: str):
        """Parse Python source to an AST, return None on syntax error."""
        try:
            return ast.parse(content)
        except SyntaxError:
            return None

    def _is_python(self, filepath: str) -> bool:
        return filepath.endswith(".py")

    def _get_snippet(self, lines: list[str], lineno: int, context: int = 0) -> str:
        """Return a code snippet around the given line number (1-indexed)."""
        start = max(0, lineno - 1 - context)
        end   = min(len(lines), lineno + context)
        return "\n".join(lines[start:end]).rstrip()
