# 🛡️ VibeScan

**Autonomous Security Vulnerability Scanner** — scan any codebase for security bugs using static analysis and get a rich, actionable report. Now available on PyPI and runnable in CI/CD pipelines.

[![PyPI](https://img.shields.io/badge/PyPI-chandan--vibescan-blue)](https://pypi.org/project/chandan-vibescan/)
[![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

---

## ✨ Features

| Scanner | Detects |
|---|---|
| 🔑 **Secrets** | 80+ patterns — AWS keys, GitHub tokens, Stripe keys, JWT secrets, private keys, DB connection strings |
| 💉 **SQL Injection** | String concat / f-strings / `.format()` in SQL queries; ORM `raw()` calls |
| 💻 **Command Injection** | `os.system`, `subprocess(shell=True)`, `eval()`, `exec()`, JS `child_process.exec`, PHP `system()` |
| 🌐 **XSS** | `mark_safe()`, Jinja2 `\|safe`, `innerHTML`, `document.write`, React `dangerouslySetInnerHTML` |
| 📁 **Path Traversal** | User input in `os.path.join`, `open()`, Flask `send_file` |
| 📦 **Insecure Deserialization** | `pickle.load`, `yaml.load` without SafeLoader, `marshal`, `shelve`, PHP `unserialize` |
| 🔐 **Weak Crypto** | MD5/SHA1, DES/RC4, ECB mode, small RSA keys, `random` for security, hardcoded IVs |
| 📢 **Sensitive Data Exposure** | Logging passwords, `DEBUG=True`, Flask `debug=True`, weak `SECRET_KEY` |
| 📋 **Dependencies** | Known CVEs in `requirements.txt` and `package.json` (live OSV API + bundled offline DB) |
| 🧠 **AST Analysis** | Deep Python analysis via Abstract Syntax Tree — catches obfuscated patterns |

---

## 🚀 Installation

```bash
pip install chandan-vibescan
```

Or run directly from source:

```bash
git clone https://github.com/chandanhastantram/VibeScan.git
cd VibeScan
pip install -e .
```

---

## 🖥️ Usage

### Scan a project
```bash
vibescan scan /path/to/your/project
```

### Generate a Markdown report
```bash
vibescan scan . --output report.md
```

### Generate an interactive HTML report
```bash
vibescan scan . --output report.html --format html
```

### Generate a SARIF report (for GitHub Security tab)
```bash
vibescan scan . --output results.sarif --format sarif
```

### Filter by minimum severity
```bash
vibescan scan . --severity HIGH
```

### Skip saving to history
```bash
vibescan scan . --no-save
```

---

## 🌐 Web Dashboard

VibeScan includes a local web dashboard to browse your full scan history.

```bash
vibescan serve
```

Then open your browser to **[http://localhost:8080](http://localhost:8080)**

```bash
# Custom port
vibescan serve --port 9000

# Headless (no browser auto-open)
vibescan serve --no-browser
```

> Scan history is saved automatically to `~/.vibescan/history.db` (SQLite).

---

## ⚙️ CI/CD Integration (GitHub Actions)

Add VibeScan to your pipeline by creating `.github/workflows/security-scan.yml`:

```yaml
name: VibeScan Security Check

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-python@v4
      with:
        python-version: '3.10'
    - run: pip install chandan-vibescan
    - run: vibescan scan . --severity HIGH
```

VibeScan exits with code `1` on CRITICAL findings, automatically blocking unsafe pull requests.

---

## 🔧 Configuration (optional)

Create `.vibescan.yml` in your project root:

```yaml
min_severity: HIGH
exclude_dirs:
  - vendor
  - migrations
  - __pycache__
enabled_scanners:
  - secrets
  - sql_injection
  - command_injection
extra_secret_patterns:
  - "MY_INTERNAL_TOKEN_[A-Z0-9]{20}"
```

---

## 🧩 Plugin System

Drop custom scanner plugins into a folder and auto-discover them:

```bash
vibescan scan . --plugins ./my_plugins
```

Each plugin is a Python file that subclasses `BaseScanner`. See `vibescan/plugins.py` for the API.

---

## 📊 Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan complete — no CRITICAL findings |
| `1` | CRITICAL findings detected |

---

## 📁 Project Structure

```
vibescan/
├── vibescan/
│   ├── cli.py              # CLI entry point
│   ├── engine.py           # Parallel file walker + dispatcher
│   ├── config.py           # .vibescan.yml loader
│   ├── models.py           # Finding, ScanResult, Severity
│   ├── report.py           # Markdown + JSON report generator
│   ├── html_report.py      # Interactive HTML report
│   ├── sarif.py            # SARIF 2.1.0 report generator
│   ├── storage.py          # SQLite scan history
│   ├── serve.py            # Local web dashboard server
│   ├── baseline.py         # Baseline & diff mode
│   ├── suppression.py      # Inline suppression (# nosec)
│   ├── plugins.py          # Plugin discovery system
│   ├── osv.py              # Live CVE lookup via OSV API
│   └── scanners/
│       ├── ast_scanner.py
│       ├── secrets.py
│       ├── sql_injection.py
│       ├── command_injection.py
│       ├── xss.py
│       ├── path_traversal.py
│       ├── deserialization.py
│       ├── weak_crypto.py
│       ├── sensitive_data.py
│       └── dependencies.py
└── sample_vulnerable/      # Deliberately vulnerable test project
```

---

> ⚠️ **Do not deploy `sample_vulnerable/`** — it contains intentional security flaws for testing purposes only.
