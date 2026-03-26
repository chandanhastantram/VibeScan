<div align="center">
  <img src="https://raw.githubusercontent.com/chandanhastantram/vibecodereviewer/main/vscode-vibescan/icon.png" alt="VibeScan Logo" width="120" />
</div>

<h1 align="center">🛡️ VibeScan v2.1.0</h1>
<p align="center">
  <b>The Autonomous Security Vulnerability Scanner & Remediation Engine</b><br>
  Catch security flaws, hardcoded secrets, and misconfigurations locally before they ever reach production.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PyPI-chandan--vibescan-blue" alt="PyPI" />
  <img src="https://img.shields.io/badge/python-3.10%2B-brightgreen" alt="Python Version" />
  <img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="License" />
  <img src="https://img.shields.io/badge/security-First-red" alt="Security First" />
</p>

---

## ⚡ Instant Installation

You **do not** need to clone the repository to use VibeScan! Simply install it directly from your command prompt globally via PyPI.

```bash
pip install chandan-vibescan
```

Once installed, the `vibescan` command is instantly available in your terminal.

> **Optional**: If you wish to contribute to the source, you can clone the repository `git clone https://github.com/chandanhastantram/vibecodereviewer.git` and run `pip install -e .`.

---

## 🚀 Quick Start

Scan your current directory and output the results directly to the terminal:

```bash
vibescan scan .
```

Scan a specific project directory with a minimum severity threshold:

```bash
vibescan scan /path/to/project --severity HIGH
```

---

## 💎 Advanced Feature Suite (New in v2.1.0)

VibeScan has evolved from a simple Python AST scanner into a comprehensive DevSecOps suite. Here is an in-depth look at what it can detect and do.

### 1. 🔍 Comprehensive Vulnerability Detection (AST & Regex)
- **Injection Attacks:** SQL Injection (string formatting/f-strings in queries), Command Injection (`subprocess(shell=True)`, `eval`, `exec`).
- **Web Vulnerabilities:** Cross-Site Scripting (XSS) via `innerHTML`, `mark_safe`, React's `dangerouslySetInnerHTML`.
- **Insecure Deserialization:** `pickle.load`, `yaml.load` (without SafeLoader), `marshal`.
- **Cryptography:** Weak algorithms (MD5/SHA1, DES/RC4, ECB mode), weak RNG (`random` module for secrets), hardcoded IVs.
- **Path Traversal:** Unsanitized user inputs in open/read functions.

### 2. 🔑 Secrets Engine
Scans over **80+ patterns** to catch hardcoded secrets before they are committed. Detects AWS Keys, Stripe Tokens, GitHub PATs, JWT Secrets, Private RSA Keys, Database Connection Strings, and Slack Webhooks.

### 3. 🏗️ Infrastructure as Code (IaC) Scanning
Scans your deployment configurations for best-practice security violations:
- **Dockerfiles:** Root user execution, `latest` tags, plaintext secrets in `ENV`, `curl \| sh`.
- **Docker Compose:** Privileged containers, host networking, host PID namespaces.
- **Terraform:** Open CIDRs (`0.0.0.0/0`), public S3 buckets, disabled TLS/encryption.
- **Kubernetes:** Privileged pods, `runAsRoot`, PrivilegeEscalation, HostPath mounts.

### 4. 📋 Software Composition Analysis (SCA) & Lockfiles
VibeScan parses your dependency trees to identify known CVEs using the live OSV API and an offline embedded database. Supports:
- `requirements.txt`
- `package.json`
- `poetry.lock`
- `Pipfile.lock`
- `yarn.lock`
- `package-lock.json`

### 5. 🩹 Auto-Remediation Engine (`--fix`)
Don't just detect vulnerabilities – fix them. Running the scan with `--fix` generates exact before/after inline code diffs to patch the vulnerability instantly.
```bash
vibescan scan . --fix
```

### 6. 🛠️ Custom YAML Rule Engine
Define your company's proprietary security policies without writing Python code using `<root>/.vibescan-rules.yml`.
```yaml
rules:
  - id: no-console-log
    pattern: "console\\.log\\("
    severity: LOW
    title: "Console.log exposure"
    fix: "Use the internal logging module."
```

### 7. 💻 Official VS Code Extension
VibeScan features a bundled VS Code extension (found in `/vscode-vibescan`). It provides:
- **Red/Yellow squiggles** directly in your editor.
- **Quick-Fix Lightbulbs** to instantly apply VibeScan patches.
- **Status Bar Integration** counting live findings.
- **Auto-Scan on Save**.

### 8. 🌐 Interactive Web Dashboard
Explore an interactive UI to triage alerts, visualize data, and manage false positives.

```bash
vibescan serve
```
- **Analytics:** Severity Doughnut Charts & Top Vulnerabilities Bar Charts.
- **Triaging:** Click "Suppress" directly in the dashboard to mark findings as false positives (saved in SQLite).

---

## 📊 Rich Reporting Formats

VibeScan seamlessly integrates into any compliance workflow by exporting to multiple formats:

| Format | Command | Use Case |
|---|---|---|
| **Terminal** | `vibescan scan .` | Live developer feedback |
| **Markdown** | `vibescan scan . -o report.md -f md` | PR comments, simple documentation |
| **JSON** | `vibescan scan . -o report.json -f json` | Custom dashboards, data pipelines |
| **HTML** | `vibescan scan . -o report.html -f html` | Exec summaries, interactive tables |
| **PDF** | `vibescan scan . -o report.pdf -f pdf` | Auditor compliance, print-ready reports |
| **SARIF** | `vibescan scan . --sarif out.sarif` | Native GitHub Security tab integration |

---

## 🔗 Developer Experience (DevEx) & CI/CD

### Git Pre-Commit Hook
Prevent insecure code from ever making it to GitHub. Run the scanner strictly on modified, staged files using the `--staged-only` flag, or hook it into your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/chandanhastantram/vibecodereviewer
    rev: main
    hooks:
      - id: vibescan
```

### GitHub Actions Integration
Fail builds automatically if Critical/High vulnerabilities are merged using `/actions/setup-python@v4`.
```yaml
- run: pip install chandan-vibescan
- run: vibescan scan . --severity HIGH
```
*VibeScan exits with code `1` automatically if findings meet or exceed the severity threshold.*

---

## ⚙️ Configuration (`.vibescan.yml`)

Tune the engine locally to reduce noise:

```yaml
min_severity: HIGH
exclude_dirs:
  - vendor
  - tests
enabled_scanners:
  - secrets
  - sql_injection
  - iac_scanner
extra_secret_patterns:
  - "MY_INTERNAL_TOKEN_[A-Z0-9]{20}"
```

---

<p align="center">
  <i>Built to secure codebases from the first line of code to the final deployment.</i>
</p>
