<p align="center">
  <img src="https://raw.githubusercontent.com/Privalyse/privalyse-cli/main/public/github-privalyse-cli-readme-banner.png" alt="Privalyse Logo" width="100%"/>
</p>

<h1 align="center">Privacy Guardrails for AI Applications</h1>

<p align="center">
  <b>Catch PII leaks to LLMs before they hit production.</b>
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

**Privalyse CLI** is a static analysis tool that builds a **Semantic Data Flow Graph** of your AI application. It traces PII from source to AI sink—detecting privacy violations that regex-based tools miss.

*   ❌ *Traditional Linter:* "Variable `user_email` used in line 42."
*   ✅ *Privalyse:* "User Email (Source) → Prompt Template → OpenAI API (Sink) = **Privacy Leak**"

---

## 🤖 Built for AI Applications

Privalyse is purpose-built for **LLM-integrated applications**. It detects when sensitive user data is being sent to:

| Provider | Support |
|----------|---------|
| **OpenAI** (GPT-4, o1, Embeddings) | ✅ Full |
| **Anthropic** (Claude) | ✅ Full |
| **Google** (Gemini, Vertex AI) | ✅ Full |
| **Mistral AI** | ✅ Full |
| **Groq** | ✅ Full |
| **Cohere** | ✅ Full |
| **Ollama** (Local LLMs) | ✅ Full |
| **LangChain** / **LlamaIndex** | ✅ Full |
| **Hugging Face** | ✅ Full |
| **Generic HTTP to AI APIs** | ✅ Full |

---

## 🛡️ Works with privalyse-mask

**[privalyse-mask](https://github.com/privalyse/privalyse-mask)** is our companion library for masking PII before sending it to LLMs.

**Privalyse CLI automatically recognizes `privalyse-mask` usage and won't flag already-masked data as leaks.**

```python
from privalyse_mask import PrivalyseMasker
from openai import OpenAI

masker = PrivalyseMasker()
client = OpenAI()

# User input with PII
user_input = "My name is Peter and my email is peter@example.com"

# ✅ Mask before sending to LLM
masked_text, mapping = masker.mask(user_input)
# -> "My name is {Name_x92} and my email is {Email_abc123}"

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": masked_text}]  # ✅ Safe - masked data
)

# Restore original values in response
final_response = masker.unmask(response.choices[0].message.content, mapping)
```

**Privalyse CLI will:**
- ✅ **Not flag** the `masked_text` being sent to OpenAI (it's sanitized)
- ⚠️ **Flag** if you send `user_input` directly without masking

---

## ⚡ Quick Start

### Install & Run

```bash
pip install privalyse-cli
privalyse
# ✅ Done. Check scan_results.md
```

### GitHub Actions

```yaml
# .github/workflows/privacy.yml
name: AI Privacy Scan
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

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: privalyse
        name: Privalyse AI Privacy Scan
        entry: privalyse
        language: system
        pass_filenames: false
```

---

## 📚 Documentation

-   [**Getting Started**](docs/getting_started.md)
-   [**Integration Guide**](docs/integration.md) (CI/CD, Pre-commit)
-   [**Configuration**](docs/configuration.md) (Rules, Policies)
-   [**Architecture**](docs/architecture.md)

---

## 🚀 Features

### 🤖 AI Guardrails (Primary Focus)
Specialized checks for LLM-integrated applications.
*   **Prevents:** Sending sensitive customer data to model prompts
*   **Audits:** OpenAI, Anthropic, Google Gemini, LangChain, and more
*   **Recognizes:** `privalyse-mask` and other sanitization libraries
*   **Tracks:** Data flow from user input → prompt → AI API

### 🕵️‍♂️ Secret Detection
Detects hardcoded API keys, tokens, and credentials.
*   *Supports:* AWS, Stripe, OpenAI, Slack, Anthropic, and generic high-entropy strings

### 🗣️ PII Leak Prevention
Identifies PII leaking into logs, external APIs, or analytics.
*   *Detects:* Emails, Phone Numbers, Credit Cards, SSNs, Names, Addresses
*   *Context Aware:* Understands variable names like `user_email` or `customer_ssn`

### ⚖️ GDPR & Data Sovereignty
Maps data flows to ensure compliance.
*   *Flags:* Data transfers to non-EU AI providers
*   *Verifies:* Usage of sanitization/masking functions before data egress

---

## 🔧 Recognized Sanitizers

Privalyse automatically recognizes these sanitization patterns and won't flag sanitized data:

| Library/Pattern | Recognition |
|-----------------|-------------|
| `privalyse-mask` (`PrivalyseMasker.mask()`) | ✅ Full |
| `presidio` (Microsoft Presidio) | ✅ Full |
| `scrubadub` | ✅ Full |
| Custom functions with: `mask`, `anonymize`, `hash`, `encrypt`, `redact`, `sanitize` | ✅ Full |
| Masked text patterns: `{Name_xyz}`, `{Email_abc}` | ✅ Full |

---

## 🤖 For AI Agents & MCP Servers

Privalyse is **agent-friendly**. Get structured JSON output for autonomous remediation:

```bash
privalyse --format json --out privalyse_report.json
```

AI coding agents can read the report and automatically fix privacy leaks.

---

## 🗺️ Roadmap

*   [x] **Python Support** (Full AST Analysis)
*   [x] **JavaScript/TypeScript Support** (AST & Regex)
*   [x] **Cross-File Taint Tracking**
*   [x] **privalyse-mask Integration**
*   [ ] **VS Code Extension** (Coming Soon)
*   [ ] **Custom Rule Engine**

---

## 🤝 Contributing

We love contributions! Check out [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
