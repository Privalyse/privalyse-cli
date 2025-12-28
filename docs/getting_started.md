# Getting Started with Privalyse

Privalyse is a static analysis tool designed to detect privacy violations, PII leaks, and security risks in your code by analyzing data flows.

## Installation

Privalyse is available as a Python package. You can install it using pip:

```bash
pip install privalyse-cli
```

## Basic Usage

To scan your current directory, simply run:

```bash
privalyse
```

This will:
1.  Scan the current directory recursively.
2.  Detect PII, secrets, and data flows to external sinks (AI models, APIs, etc.).
3.  Generate a report (`report.md` by default).

## Command Line Options

You can customize the scan using various flags:

```bash
privalyse [OPTIONS]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--root PATH` | Root directory to scan | `.` (Current directory) |
| `--out PATH` | Output file path | `report.md` |
| `--format TYPE` | Output format (`markdown`, `json`, `html`, `sarif`) | `markdown` |
| `--debug` | Enable debug logging | `False` |
| `--quiet` | Suppress console output (useful for CI) | `False` |

### Examples

**Scan a specific project folder:**
```bash
privalyse --root ./my-project
```

**Generate a JSON report for programmatic analysis:**
```bash
privalyse --out results.json --format json
```

**Generate a SARIF report for GitHub Security integration:**
```bash
privalyse --out results.sarif --format sarif
```

## Understanding the Output

Privalyse generates a report containing:
-   **Compliance Score**: A 0-100 score indicating your project's privacy posture.
-   **Findings**: Detailed list of detected issues, categorized by severity (Critical, High, Medium, Low).
-   **Data Flow Graph**: Visual representation of how data moves through your application (in HTML/JSON reports).
-   **Top Risks**: The most critical data flow paths detected.

### Severity Levels

-   **CRITICAL**: Immediate action required (e.g., Hardcoded secrets, PII sent to AI without sanitization).
-   **HIGH**: Significant privacy risk (e.g., PII logging, Unencrypted data storage).
-   **MEDIUM**: Compliance warning (e.g., Missing data retention policy).
-   **LOW**: Best practice suggestion.
