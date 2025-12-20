"""
Base Analyzer Interface
=======================
Defines the contract for all language-specific analyzers.
Ensures 1:1 feature parity across languages.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass, field

from ..models.finding import Finding

@dataclass
class AnalyzedSymbol:
    """Represents a function, class, or variable definition."""
    name: str
    type: str  # 'function', 'class', 'variable'
    line: int
    is_exported: bool
    signature: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AnalyzedImport:
    """Represents an import statement."""
    source_module: str
    imported_names: List[str]  # ['User', 'AuthService']
    line: int

class BaseAnalyzer(ABC):
    """
    Abstract base class for all language analyzers.
    Enforces a unified structure for:
    1. Finding detection
    2. Symbol extraction (for cross-file analysis)
    3. Import resolution (for dependency graph)
    """
    
    @abstractmethod
    def analyze_file(self, file_path: Path, code: str, **kwargs) -> Tuple[List[Finding], List[Any]]:
        """
        Analyze a single file for privacy/security findings.
        Returns (findings, data_flows).
        """
        pass

    @abstractmethod
    def extract_symbols(self, code: str) -> List[AnalyzedSymbol]:
        """
        Extract definitions (functions, classes) for the Symbol Table.
        Essential for Phase 2.2 (Global Symbol Registry).
        """
        pass

    @abstractmethod
    def extract_imports(self, code: str) -> List[AnalyzedImport]:
        """
        Extract dependencies for the Import Resolver.
        Essential for Phase 2.1 (Dependency Graph).
        """
        pass
