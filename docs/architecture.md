# Architecture & How It Works

Privalyse goes beyond simple regex matching by building a semantic understanding of your code.

## Core Concepts

### 1. Semantic Data Flow Graph
Privalyse parses your code (AST for Python, AST/Regex for JS) to build a graph where:
-   **Nodes** represent variables, functions, API calls, and data sources.
-   **Edges** represent data flow (assignments, function calls, return values).

This allows the scanner to trace data from a **Source** (e.g., user input) to a **Sink** (e.g., logging, external API).

### 2. Taint Tracking
The scanner identifies "tainted" data—variables containing PII or secrets. It then propagates this taint through the graph.

*Example:*
1.  `email = request.form['email']` -> `email` is tainted (Source: User Input).
2.  `log_msg = f"User: {email}"` -> `log_msg` is tainted (Propagation).
3.  `logging.info(log_msg)` -> **Leak Detected** (Sink: Logging).

### 3. Cross-File Analysis
Privalyse resolves imports to track data flow across multiple files. If a function in `utils.py` returns PII, and `main.py` logs the result of that function, Privalyse detects the leak.

## Scanner Pipeline

1.  **Discovery**: Find all relevant files in the project.
2.  **Import Resolution**: Build a dependency graph of modules.
3.  **Symbol Analysis**: Index functions, classes, and variables (Global Symbol Table).
4.  **Intra-file Analysis**:
    -   Parse code to AST.
    -   Identify Sources (PII, Secrets).
    -   Identify Sinks (APIs, Logs, DBs).
    -   Track data flow within the file.
5.  **Cross-file Propagation**: Connect flows between modules using the Import Graph.
6.  **Policy Check**: Verify findings against configured policies (e.g., GDPR compliance).
7.  **Reporting**: Generate output in the requested format.

## Supported Languages

-   **Python**: Full AST-based analysis with cross-file tracking.
-   **JavaScript/TypeScript**: Hybrid analysis (Regex + partial AST) for detecting common patterns in React/Node.js apps.
