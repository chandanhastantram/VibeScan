"""
VibeCodeReviewer — Config Loader
Loads .vibecodereviewer.yml from the target directory (optional).
"""

import os
from dataclasses import dataclass, field
from typing import Optional

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


@dataclass
class ScanConfig:
    """Runtime configuration for a scan."""
    # Minimum severity to report (INFO = report everything)
    min_severity: str = "INFO"

    # Directories to exclude from scanning
    exclude_dirs: list[str] = field(default_factory=lambda: [
        ".git", "__pycache__", "node_modules", ".venv", "venv",
        ".env", "dist", "build", ".tox", ".mypy_cache",
    ])

    # File extensions to include (empty = all text files)
    include_extensions: list[str] = field(default_factory=lambda: [
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".rb",
        ".go", ".cs", ".cpp", ".c", ".h", ".sh", ".env", ".yml",
        ".yaml", ".json", ".xml", ".html", ".cfg", ".ini", ".conf",
        ".toml", ".txt",
    ])

    # Scanners to enable (empty = all)
    enabled_scanners: list[str] = field(default_factory=list)

    # Extra secret regex patterns (user-defined)
    extra_secret_patterns: list[str] = field(default_factory=list)

    # Max file size in bytes (skip larger files)
    max_file_size: int = 1_000_000  # 1 MB

    # Whether to scan binary files
    scan_binary: bool = False


def load_config(target_path: str) -> ScanConfig:
    """
    Try to load .vibecodereviewer.yml from target_path.
    Falls back to defaults if not found or yaml not installed.
    """
    config = ScanConfig()
    config_file = os.path.join(target_path, ".vibecodereviewer.yml")

    if not _YAML_AVAILABLE or not os.path.isfile(config_file):
        return config

    try:
        with open(config_file, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}

        if "min_severity" in data:
            config.min_severity = str(data["min_severity"]).upper()
        if "exclude_dirs" in data:
            config.exclude_dirs = list(data["exclude_dirs"])
        if "include_extensions" in data:
            config.include_extensions = list(data["include_extensions"])
        if "enabled_scanners" in data:
            config.enabled_scanners = list(data["enabled_scanners"])
        if "extra_secret_patterns" in data:
            config.extra_secret_patterns = list(data["extra_secret_patterns"])
        if "max_file_size" in data:
            config.max_file_size = int(data["max_file_size"])

    except Exception:
        pass  # silently fall back to defaults

    return config
