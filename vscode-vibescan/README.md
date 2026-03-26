# VibeScan — VS Code Extension

Real-time security vulnerability detection for VS Code, powered by the VibeScan scanner engine.

## Features

- **Inline Diagnostics** — Security findings appear as red/yellow squiggles directly in your code
- **Quick Fixes** — Lightbulb actions to apply fixes, suppress with `# nosec`, or disable file scanning  
- **Auto-scan on Save** — Automatically scans files when you save (configurable)
- **Status Bar** — Shows scan status and finding count at a glance
- **Workspace Scanning** — Scan your entire workspace from the command palette

## Requirements

- **VibeScan** must be installed: `pip install chandan-vibescan`
- **Python 3.10+** must be available in your PATH

## Getting Started

1. Install vibescan: `pip install chandan-vibescan`
2. Open a project in VS Code
3. Press `Ctrl+Shift+P` → `VibeScan: Scan Workspace`
4. View findings as inline diagnostics with quick-fix suggestions

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `vibescan.scanOnSave` | `true` | Scan files automatically on save |
| `vibescan.severity` | `INFO` | Minimum severity level to report |
| `vibescan.pythonPath` | `python` | Path to Python interpreter |

## Commands

- **VibeScan: Scan Workspace** — Scan all files in the workspace
- **VibeScan: Scan Current File** — Scan only the active file
- **VibeScan: Clear All Diagnostics** — Remove all VibeScan diagnostics

## Development

```bash
cd vscode-vibescan
npm install
npm run compile
# Press F5 in VS Code to launch Extension Development Host
```
