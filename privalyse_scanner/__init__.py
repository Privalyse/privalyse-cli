"""
Privalyse Scanner - Modular Privacy & GDPR Compliance Scanner

A modular, extensible scanner for detecting privacy issues and GDPR compliance
violations in Python, JavaScript/TypeScript, and configuration files.

Package Structure:
- core: Core scanning engine and orchestration
- analyzers: Language-specific analyzers (Python, JS/TS)
- models: Data models and type definitions
- parsers: File parsers and AST utilities
- utils: Helper functions and utilities
"""

__version__ = "0.3.3"
__author__ = "Privalyse Team"

from .core.scanner import PrivalyseScanner
from .models.finding import Finding, Severity
from .models.config import ScanConfig

__all__ = [
    "PrivalyseScanner",
    "Finding",
    "Severity",
    "ScanConfig",
]
