"""
VibeScan — Plugin / Custom Scanner API
Auto-discovers user scanners dropped into a plugins/ directory.

Usage:
  1. Create a file in your project's plugins/ directory:
     my_project/plugins/my_scanner.py

  2. Define a class that inherits from BaseScanner:
     from vibescan.scanners.base import BaseScanner
     from vibescan.models import Finding, Severity

     class MySQLPatternScanner(BaseScanner):
         name = \"MySQLPatternScanner\"
         SUPPORTED_EXTENSIONS = (\".php\",)

         def scan_file(self, filepath, content, lines):
             # your logic here
             return []

  3. Run vibescan with --plugins ./plugins
     vibescan scan . --plugins ./plugins

VibeScan will auto-discover and register all BaseScanner subclasses
found in .py files within the plugins directory.
"""

import os
import sys
import importlib.util
from .scanners.base import BaseScanner


def discover_plugins(plugins_dir: str) -> list[BaseScanner]:
    """
    Scan plugins_dir for .py files and return instantiated scanner objects
    for any BaseScanner subclass found.

    Args:
        plugins_dir: Absolute or relative path to the plugins directory.

    Returns:
        List of instantiated scanner objects.
    """
    discovered: list[BaseScanner] = []

    if not os.path.isdir(plugins_dir):
        return discovered

    for filename in os.listdir(plugins_dir):
        if not filename.endswith(".py") or filename.startswith("_"):
            continue

        filepath = os.path.join(plugins_dir, filename)
        module_name = f"_vibescan_plugin_{filename[:-3]}"

        try:
            spec   = importlib.util.spec_from_file_location(module_name, filepath)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        except Exception as e:
            print(f"  [PLUGIN] Warning: failed to load {filename}: {e}")
            continue

        # Find all BaseScanner subclasses defined in this module
        for attr_name in dir(module):
            obj = getattr(module, attr_name)
            try:
                if (
                    isinstance(obj, type)
                    and issubclass(obj, BaseScanner)
                    and obj is not BaseScanner
                    and obj.__module__ == module_name
                ):
                    instance = obj()
                    discovered.append(instance)
                    print(f"  [PLUGIN] Loaded scanner: {obj.name} from {filename}")
            except Exception:
                continue

    return discovered


def list_plugin_info(plugins_dir: str) -> list[dict]:
    """
    Return metadata about loaded plugins without instantiating.
    Used by the --list-plugins CLI flag.
    """
    plugins = discover_plugins(plugins_dir)
    return [
        {
            "name":       p.name,
            "extensions": list(p.SUPPORTED_EXTENSIONS),
            "class":      type(p).__name__,
        }
        for p in plugins
    ]
