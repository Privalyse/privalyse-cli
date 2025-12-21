# Changelog

## [0.2.0] - 2025-12-21 - Beta Release

Major update introducing "Flow Stories" and enhanced data flow visibility.

### Features
- **Data Flow Visualization**: CLI output now shows the full path of data (Source -> Sink) using tree structures.
- **Semantic Graph Core**: Improved taint tracking engine that captures full propagation paths across functions and files.
- **Refactored Finding Model**: Findings now include detailed source, sink, and flow path information.
- **New Demos**: Added `flow-story-demo` to showcase multi-step leak detection capabilities.
- **Enhanced Reporting**: Reports now include more context about the data flow.

### Improvements
- Better cross-file analysis for Python projects.
- Improved accuracy in detecting hardcoded secrets.

## [0.1.0] - 2025-12-17 - Alpha Release

First public release of Privalyse - The privacy scanner for modern devs.

### Features
- Python & JavaScript/TypeScript analysis
- Hardcoded secret detection (API keys, passwords)
- Cross-file taint tracking
- PII detection (15+ types)
- GDPR article mapping (Art. 6, 9, 32)
- Markdown & JSON export
- `.privalyseignore` support

---

For detailed release notes, see [GitHub Releases](https://github.com/privalyse/privalyse-cli/releases).
