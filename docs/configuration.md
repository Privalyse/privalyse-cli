# Configuration

Privalyse works out of the box with sensible defaults, but you can customize its behavior using a configuration file and ignore patterns.

## Configuration File (`privalyse.toml`)

Create a `privalyse.toml` file in your project root to configure policies, severity levels, and custom rules.

```toml
# privalyse.toml

[policy]
# Block data flows to specific countries (ISO 3166-1 alpha-2 codes)
blocked_countries = ["CN", "RU"]

# Block specific providers/sinks
# Options: "openai", "aws", "azure", "gcp", "anthropic", "cohere"
blocked_providers = ["openai"]

# Require sanitization before sending PII to AI models
# If true, sending raw PII to an AI sink is a CRITICAL finding.
require_sanitization_for_ai = true

[scanner]
# Ignore specific directories (glob patterns)
ignore_patterns = [
    "tests/**",
    "venv/**",
    "**/node_modules/**",
    "dist/**"
]

[severity]
# Customize severity levels for specific rules
HARDCODED_SECRET = "CRITICAL"
PII_LEAK = "HIGH"
AI_PII_LEAK = "CRITICAL"

# =============================================================================
# CUSTOM RULES
# =============================================================================

# Example: Detect internal company tokens
[[rules]]
id = "INTERNAL_TOKEN"
pattern = "ACME-[A-Z0-9]{10}"
severity = "critical"
message = "Internal ACME token detected"
category = "secret"
```

## Ignore File (`.privalyseignore`)

You can exclude specific files or directories from the scan using a `.privalyseignore` file. The syntax is similar to `.gitignore`.

```gitignore
# .privalyseignore

# Ignore dependencies
node_modules/
venv/
env/

# Ignore build artifacts
dist/
build/

# Ignore tests
tests/
*_test.py

# Ignore specific files
legacy_code.py
```

## Custom Rules

You can define custom regex-based rules in `privalyse.toml` under the `[[rules]]` section.
For a list of built-in rules, see [DETECTION_RULES.md](../DETECTION_RULES.md).

| Field | Description | Required |
|-------|-------------|----------|
| `id` | Unique identifier for the rule (e.g., `MY_RULE`) | Yes |
| `pattern` | Regex pattern to search for | Yes |
| `severity` | `critical`, `high`, `medium`, `low`, or `info` | Yes |
| `message` | Description of the finding | Yes |
| `category` | Category (e.g., `secret`, `pii`, `security`) | Yes |

### Example: Detect TODOs

```toml
[[rules]]
id = "TODO_CHECK"
pattern = "TODO:"
severity = "info"
message = "Found a TODO item"
category = "best_practice"
```
