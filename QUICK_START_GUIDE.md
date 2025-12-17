# Quick Start Guide

**Get scanning in 60 seconds** ⚡

---

## Installation

```bash
pip install privalyse
```

That's it. No config files, no setup, no API keys.

---

## Your First Scan

```bash
# Scan current directory
privalyse --root . --out report.md

# Scan specific project
privalyse --root /path/to/your/project --out compliance_report.md
```

---

## Understanding the Output

### Console Summary
```
🔴 Compliance Score: 45/100 (critical)
📊 Findings: 8 total
🔴 Critical: 2
🟠 High: 3
🟡 Medium: 2
📄 Report: report.md
```

### Markdown Report Structure

1. **Executive Summary**
   - Overall compliance score
   - Critical findings count
   - Risk breakdown

2. **Findings by Severity**
   - Critical issues first
   - Each finding includes:
     - File location
     - Code snippet
     - GDPR article reference
     - Fix suggestion
     - Before/after example

3. **Compliance Mapping**
   - Which GDPR articles apply
   - Required technical measures
   - Data processing legal basis

---

## Common Findings Explained

### 🔴 CRITICAL: Hardcoded API Key
```python
# ❌ Bad
API_KEY = "sk_live_abc123xyz789"

# ✅ Good
import os
API_KEY = os.getenv("API_KEY")
```

**Why it matters:** Art. 32 GDPR requires "appropriate security measures"

---

### 🔴 CRITICAL: Plaintext Passwords
```python
# ❌ Bad
password = user_input

# ✅ Good
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

**Why it matters:** Art. 32 GDPR - passwords must be protected

---

### 🟠 HIGH: PII in Logs
```python
# ❌ Bad
logger.info(f"User {user.email} logged in")

# ✅ Good
logger.info(f"User {redact_email(user.email)} logged in")
# Output: "User u***@example.com logged in"
```

**Why it matters:** Art. 5 GDPR - data minimization

---

### 🟡 MEDIUM: HTTP Instead of HTTPS
```python
# ❌ Bad
requests.post("http://api.example.com/user", data=user_data)

# ✅ Good
requests.post("https://api.example.com/user", data=user_data)
```

**Why it matters:** Art. 32 GDPR - encryption in transit

---

## Interpreting Compliance Scores

| Score | Status | Meaning |
|-------|--------|---------|
| 90-100 | 🟢 Compliant | Ready for production |
| 70-89 | 🟡 Needs Work | Fix high-priority items |
| 50-69 | 🟠 At Risk | Significant issues present |
| 0-49 | 🔴 Critical | Major compliance gaps |

---

## What Gets Scanned

### Supported Languages
- ✅ Python (.py, .pyw)
- ✅ JavaScript (.js, .jsx, .mjs, .cjs)
- ✅ TypeScript (.ts, .tsx)

### Excluded by Default
- `node_modules/`
- `venv/`, `.venv/`, `env/`
- `dist/`, `build/`
- `__pycache__/`
- `.git/`

### What It Detects
- **PII Types:** email, password, phone, name, address, SSN, credit card, etc.
- **Secrets:** API keys, tokens, AWS credentials, database passwords
- **GDPR Issues:** missing consent, insecure transmission, data retention
- **Security:** plaintext passwords, hardcoded secrets, insecure protocols

---

## Advanced Usage

### JSON Output (for CI/CD)
```bash
privalyse --root . --format json --out results.json
```

### HTML Report (for sharing)
```bash
privalyse --root . --format html --out report.html
```

Opens in browser with interactive findings, charts, and GDPR mapping.

### Scan Specific Directory
```bash
# Only scan backend code
privalyse --root ./backend --out backend_report.md

# Only scan frontend
privalyse --root ./frontend --out frontend_report.md
```

### Limit Workers (for CI)
```bash
privalyse --root . --max-workers 2 --out report.md
```

### Limit Files (for testing)
```bash
privalyse --root . --max-files 100 --out sample_report.md
```

---

## Example Projects

### Try on the Included Examples

**Bad Practice App** (intentionally vulnerable - "kitchen sink" demo):
```bash
cd examples/bad-practice-app
privalyse --root . --out vulnerable_report.md
```

**Expected Result:** 71 findings (20 critical, 30 high), 5/100 compliance score

**Note:** This app contains every violation type we detect. Real projects have 3-10 findings.

---

**Best Practice App** (secure implementation):
```bash
cd examples/best-practice-app
privalyse --root . --out secure_report.md
```

**Expected Result:** 0 findings, 100/100 compliance score

---

## Troubleshooting

### "No findings detected"
✅ Great! Your code looks good. Cross-file taint tracking is already enabled by default.

### "Too many findings"
Start with critical issues first:
```bash
privalyse --root . --out report.md
# Then open report.md and scroll to "CRITICAL" section
```

### Scan is slow
Limit scope:
```bash
# Scan only Python files
privalyse --root ./src --out report.md

# Use fewer workers
privalyse --root . --max-workers 4 --out report.md
```

### False positive
Open an issue on GitHub with:
- Code snippet
- Why it's a false positive
- Expected behavior

---

## Next Steps

1. **Read the full README:** [README.md](README.md)
2. **Check examples:** [examples/README.md](examples/README.md)
3. **Contribute:** [CONTRIBUTING.md](CONTRIBUTING.md)
4. **Report issues:** [GitHub Issues](https://github.com/privalyse/privalyse-cli/issues)

---

## Quick Reference

```bash
# Basic scan
privalyse --root . --out report.md

# JSON output
privalyse --root . --format json --out results.json

# HTML report
privalyse --root . --format html --out report.html

# Limit workers for smaller machines
privalyse --root . --max-workers 2 --quiet --out results.json

# Help
privalyse --help
```

---

**Questions?** Open a [GitHub Discussion](https://github.com/privalyse/privalyse-cli/discussions) 💬
