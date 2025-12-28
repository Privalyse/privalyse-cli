<p align="center">
  <img src="https://raw.githubusercontent.com/Privalyse/privalyse-cli/main/public/github-privalyse-cli-readme-banner.png" alt="Privalyse Logo" width="100%"/>
</p>

<h1 align="center">The Linter for Privacy</h1>

<p align="center">
  <b>Catch PII leaks & secrets before they hit production.</b>
</p>

<p align="center">
  <a href="https://badge.fury.io/py/privalyse-cli"><img src="https://badge.fury.io/py/privalyse-cli.svg" alt="PyPI version"></a>
  <a href="https://pepy.tech/project/privalyse-cli"><img src="https://pepy.tech/badge/privalyse-cli/month" alt="Downloads"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://github.com/Privalyse/privalyse-cli/actions/workflows/test.yml"><img src="https://github.com/Privalyse/privalyse-cli/actions/workflows/test.yml/badge.svg" alt="Tests"></a>
  <a href="https://pypi.org/project/privalyse-cli/"><img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python Versions"></a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/Privalyse/privalyse-cli/main/public/github-privalyse-cli-demo.gif" alt="Privalyse Demo" width="100%"/>
</p>

---

**Privalyse** is a static analysis tool that builds a **Semantic Data Flow Graph** of your application. It traces data from source to sink to detect privacy violations that regex-based tools miss.

*   ❌ *Traditional Linter:* "Variable `user_email` used in line 42."
*   ✅ *Privalyse:* "User Email (Source) → Prompt Template → OpenAI API (Sink) → Logs (Leak)."

---

## 📚 Documentation

Full documentation is available in the [docs/](docs/) directory:

-   [**Getting Started**](docs/getting_started.md)
-   [**Integration Guide**](docs/integration.md) (CI/CD, Pre-commit)
-   [**Configuration**](docs/configuration.md) (Rules, Policies)
-   [**Architecture**](docs/architecture.md)

---

## ⚡ Quick Start

### Local
Install and run in seconds. No config required.

```bash
pip install privalyse-cli
privalyse
# ✅ Done. Check scan_results.md
```

### GitHub Actions
Add to your CI pipeline in 30 seconds.

```yaml
# .github/workflows/privacy.yml
name: Privacy Scan
on: [push, pull_request]

jobs:
  privalyse:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Privalyse
        uses: privalyse/privalyse-cli@v0.3.1
```

### Pre-Commit Hook
Catch leaks before you commit.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: privalyse
        name: Privalyse Scan
        entry: privalyse
        language: system
        pass_filenames: false
```

### GitLab CI

```yaml
# .gitlab-ci.yml
privalyse_scan:
  script:
    - pip install privalyse-cli
    - privalyse --out report.md
  artifacts:
    paths: [report.md]
```

### GitHub Code Scanning (SARIF)
Integrate findings directly into GitHub Security tab.

```yaml
      - name: Run Privalyse
        uses: privalyse/privalyse-cli@v0.3.1
        with:
          format: 'sarif'
          out: 'results.sarif'

      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

---

## 🚀 Features

### 🕵️‍♂️ Secret Detection
Detects hardcoded API keys, tokens, and credentials before they are pushed.
*   *Supports:* AWS, Stripe, OpenAI, Slack, and generic high-entropy strings.

### 🗣️ PII Leak Prevention
Identifies Personal Identifiable Information (PII) leaking into logs, external APIs, or analytics.
*   *Detects:* Emails, Phone Numbers, Credit Cards, SSNs.
*   *Context Aware:* Understands variable names like `user_email` or `client_id`.

### ⚖️ GDPR & Data Sovereignty
Maps data flows to ensure compliance.
*   *Flags:* Data transfers to non-EU providers (e.g., OpenAI, AWS US-East).
*   *Verifies:* Usage of sanitization functions before data egress.

### 🤖 AI Guardrails
Specialized checks for LLM-integrated applications.
*   *Prevents:* Sending sensitive customer data to model prompts.
*   *Audits:* LangChain and OpenAI SDK usage.

---

## 🤖 For AI Agents & MCP Servers

Privalyse is designed to be **agent-friendly**. If you are building an AI coding agent or using an MCP (Model Context Protocol) server, Privalyse provides structured outputs that agents can understand.

```bash
privalyse --format json --out privalyse_report.json
```

Agents can read the JSON report to autonomously fix privacy leaks in the codebase.

---

## 🗺️ Roadmap

*   [x] **Python Support** (AST Analysis)
*   [x] **JavaScript/TypeScript Support** (AST & Regex)
*   [x] **Cross-File Taint Tracking**
*   [ ] **VS Code Extension** (Coming Soon)
*   [ ] **Custom Rule Engine**

## 🤝 Contributing

We love contributions! Check out [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
