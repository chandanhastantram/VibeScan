# 🛡️ CodeSentinel

**Autonomous Security Vulnerability Scanner** — scans any codebase for security bugs using static analysis and returns a rich, actionable report.

---

## Features

| Scanner | Detects |
|---|---|
| 🔑 **Secrets** | 80+ patterns — AWS keys, GitHub tokens, Stripe keys, JWT secrets, private keys, DB connection strings |
| 💉 **SQL Injection** | String concat / f-strings / `.format()` in SQL queries; ORM `raw()` calls |
| 💻 **Command Injection** | `os.system`, `subprocess(shell=True)`, `eval()`, `exec()`, JS `child_process.exec`, PHP `system()` |
| 🌐 **XSS** | `mark_safe()`, Jinja2 `\|safe`, `innerHTML`, `document.write`, React `dangerouslySetInnerHTML`, PHP `echo $_GET` |
| 📁 **Path Traversal** | User input in `os.path.join`, `open()`, Flask `send_file` |
| 📦 **Insecure Deserialization** | `pickle.load`, `yaml.load` without SafeLoader, `marshal`, `shelve`, PHP `unserialize`, Java `ObjectInputStream` |
| 🔐 **Weak Crypto** | MD5/SHA1, DES/RC4, ECB mode, small RSA keys, `random` for security, disabled SSL, hardcoded IVs |
| 📢 **Sensitive Data Exposure** | Logging passwords, `DEBUG=True`, Flask `debug=True`, weak `SECRET_KEY`, env vars in responses |
| 📋 **Dependencies** | Known CVEs in `requirements.txt` and `package.json` (offline, bundled DB of 16 high-impact CVEs) |

---

## Installation

```bash
cd codesentinel
pip install -e .
```

Or without installing (run directly):

```bash
pip install colorama pyyaml
```

---

## Usage

### Basic scan (terminal output only)
```
python -m codesentinel.cli scan /path/to/your/project
```

### Generate a Markdown report
```
python -m codesentinel.cli scan /path/to/your/project --output report.md
```

### Generate a JSON report
```
python -m codesentinel.cli scan /path/to/your/project --output report.json --format json
```

### Filter by minimum severity
```
python -m codesentinel.cli scan /path/to/your/project --severity HIGH
```

### Scan the included sample vulnerable project
```
python -m codesentinel.cli scan ./sample_vulnerable --output report.md
```

---

## Output

**Terminal** — Colorized, severity-tagged findings with file:line references and one-line fix previews:

```
  [CRITICAL] Hardcoded AWS Access Key ID
  ┌─ sample_vulnerable/app.py : line 14
  ├─ CWE: CWE-798  •  Scanner: SecretsScanner
  ├─ Hardcoded AWS Access Key ID detected.
  └─ Fix: Remove from source code. Use environment variables or AWS IAM roles.
```

**Markdown Report** — Full report with severity tables, CWE links, code snippets, fix guidance, and a JSON summary block.

---

## Configuration (optional)

Create `.codesentinel.yml` in your project root:

```yaml
min_severity: HIGH           # Only report HIGH and CRITICAL
exclude_dirs:
  - vendor
  - migrations
  - __pycache__
enabled_scanners:             # Leave empty to run all 9
  - secrets
  - sql_injection
  - command_injection
extra_secret_patterns:        # Your own regex patterns
  - "MY_INTERNAL_TOKEN_[A-Z0-9]{20}"
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan complete, no CRITICAL findings |
| `1` | CRITICAL findings detected |

Use in CI/CD:
```bash
python -m codesentinel.cli scan . --severity HIGH || exit 1
```

---

## Project Structure

```
codesentinel/
├── codesentinel/
│   ├── cli.py              # CLI entry point
│   ├── engine.py           # File walker + dispatcher
│   ├── config.py           # .codesentinel.yml loader
│   ├── models.py           # Finding, ScanResult, Severity
│   ├── report.py           # Markdown + JSON report generator
│   └── scanners/
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
