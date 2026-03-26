"""
VibeScan — Scan Engine (v2)
Parallel file scanning with ThreadPoolExecutor + suppression support.
Dispatches files to all registered scanners; collects, deduplicates, and
filters findings. Integrated AST scanner, plugin support, and suppressions.
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from .models import Finding, ScanResult, Severity
from .config import ScanConfig
from .suppression import apply_suppressions
from .scanners.secrets          import SecretsScanner
from .scanners.sql_injection    import SQLInjectionScanner
from .scanners.command_injection import CommandInjectionScanner
from .scanners.xss              import XSSScanner
from .scanners.path_traversal   import PathTraversalScanner
from .scanners.deserialization  import DeserializationScanner
from .scanners.weak_crypto      import WeakCryptoScanner
from .scanners.sensitive_data   import SensitiveDataScanner
from .scanners.dependencies     import DependencyScanner
from .scanners.ast_scanner      import ASTScanner
from .scanners.iac_scanner      import IaCScanner
from .remediation               import enhance_findings_with_remediation


_SEVERITY_ORDER = {
    "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1,
}


def _build_scanners(config: ScanConfig, extra_scanners: list | None = None):
    """Instantiate all built-in + plugin scanners."""
    all_scanners = {
        "secrets":           SecretsScanner(extra_patterns=config.extra_secret_patterns),
        "sql_injection":     SQLInjectionScanner(),
        "command_injection": CommandInjectionScanner(),
        "xss":               XSSScanner(),
        "path_traversal":    PathTraversalScanner(),
        "deserialization":   DeserializationScanner(),
        "weak_crypto":       WeakCryptoScanner(),
        "sensitive_data":    SensitiveDataScanner(),
        "dependencies":      DependencyScanner(),
        "ast_scanner":       ASTScanner(),
        "iac":               IaCScanner(),
    }
    if config.enabled_scanners:
        scanners = [v for k, v in all_scanners.items() if k in config.enabled_scanners]
    else:
        scanners = list(all_scanners.values())

    # Append plugin scanners
    if extra_scanners:
        scanners.extend(extra_scanners)

    return scanners


def _is_binary(content: bytes) -> bool:
    sample = content[:8192]
    if not sample:
        return False
    non_text = sum(b < 9 or (14 <= b < 32) or b == 127 for b in sample)
    return non_text / len(sample) > 0.30


def _should_skip_file(filepath: str, config: ScanConfig) -> bool:
    if config.include_extensions:
        return not any(filepath.endswith(ext) for ext in config.include_extensions)
    return False


def _should_skip_dir(dirname: str, config: ScanConfig) -> bool:
    return dirname in config.exclude_dirs or dirname.startswith(".")


def _read_file(filepath: str, config: ScanConfig) -> tuple[str | None, list[str]]:
    """Read a file and return (content, lines) or (None, []) if unreadable/skipped."""
    try:
        size = os.path.getsize(filepath)
    except OSError:
        return None, []

    if size > config.max_file_size:
        return None, []

    try:
        raw = open(filepath, "rb").read()
    except OSError:
        return None, []

    if not config.scan_binary and _is_binary(raw):
        return None, []

    try:
        content = raw.decode("utf-8", errors="replace")
    except Exception:
        return None, []

    return content, content.splitlines()


def _scan_single_file(
    filepath: str,
    scanners: list,
    config: ScanConfig,
    min_weight: int,
) -> tuple[list[Finding], list[str], bool]:
    """
    Scan one file with all applicable scanners.

    Returns:
        (findings, lines, was_scanned)
    """
    content, lines = _read_file(filepath, config)
    if content is None:
        return [], [], False

    findings: list[Finding] = []
    for scanner in scanners:
        if not scanner.supports_file(filepath):
            continue
        try:
            results = scanner.scan_file(filepath, content, lines)
            for f in results:
                if _SEVERITY_ORDER.get(f.severity.label, 0) >= min_weight:
                    findings.append(f)
        except Exception:
            pass

    return findings, lines, True


def _collect_files(target_path: str, config: ScanConfig) -> list[str]:
    """Walk target_path and return eligible file paths."""
    eligible = []
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if not _should_skip_dir(d, config)]
        for filename in files:
            fp = os.path.join(root, filename)
            if not _should_skip_file(fp, config):
                eligible.append(fp)
    return eligible


def run_scan(
    target_path: str,
    config: ScanConfig,
    extra_scanners: list | None = None,
    max_workers: int = 8,
    staged_files: list[str] | None = None,
) -> ScanResult:
    """
    Walk target_path, scan all eligible files in parallel,
    apply suppressions, deduplicate, and return aggregated ScanResult.

    Args:
        target_path:    Directory to scan.
        config:         ScanConfig (from load_config or defaults).
        extra_scanners: Additional plugin scanner instances.
        max_workers:    ThreadPoolExecutor concurrency (default 8).
        staged_files:   If provided, only scan these files (for pre-commit mode).
    """
    result = ScanResult(target_path=target_path)
    scanners = _build_scanners(config, extra_scanners)
    min_weight = _SEVERITY_ORDER.get(config.min_severity, 1)

    start = time.perf_counter()

    # Phase 1: collect all eligible files
    if staged_files:
        filepaths = [os.path.abspath(f) for f in staged_files if os.path.isfile(f)]
    else:
        filepaths = _collect_files(target_path, config)

    # Phase 2: scan in parallel
    all_findings: list[Finding] = []
    file_lines_cache: dict[str, list[str]] = {}   # used for suppression lookups

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {
            pool.submit(_scan_single_file, fp, scanners, config, min_weight): fp
            for fp in filepaths
        }
        for future in as_completed(future_map):
            fp = future_map[future]
            try:
                findings, lines, was_scanned = future.result()
            except Exception:
                result.files_skipped += 1
                continue

            if was_scanned:
                result.files_scanned += 1
                all_findings.extend(findings)
                if lines:
                    file_lines_cache[fp] = lines
            else:
                result.files_skipped += 1

    # Phase 3: apply inline suppressions (# nosec / # vibescan: ignore)
    all_findings, suppressed_count = apply_suppressions(all_findings, file_lines_cache)
    result.files_skipped += 0   # suppressed findings are not skipped files

    # Phase 4: deduplicate (same file + line + title)
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in all_findings:
        key = (f.file, f.line, f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Phase 5: enhance with auto-remediation suggestions
    unique = enhance_findings_with_remediation(unique)

    result.findings = unique
    result.scan_duration = time.perf_counter() - start

    return result
