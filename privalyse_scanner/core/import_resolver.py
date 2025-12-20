"""
Import Resolution Module
========================
Tracks imports and builds module dependency graphs for cross-file taint analysis.
Supports multiple languages via BaseAnalyzer interface.

Features:
- Resolves 'import X', 'from X import Y', 'import X as Z'
- Builds dependency graph showing which modules import from which
- Maps imported symbols to their source modules
- Supports relative imports (from .module import X)
- Handles package hierarchies
"""

import ast
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field

from ..analyzers.base_analyzer import BaseAnalyzer, AnalyzedImport


@dataclass
class ImportedSymbol:
    """Represents a symbol imported from another module."""
    name: str  # Symbol name as used in importing module
    source_module: str  # Module where symbol is defined
    original_name: str  # Original name in source module (different if 'import X as Y')
    import_type: str  # 'import', 'from_import', or 'relative_import'
    location: Tuple[int, int]  # (line, column) in importing module


@dataclass
class ModuleInfo:
    """Information about a module (Python, JS, etc.)."""
    path: Path  # Absolute path to module file
    package: str  # Qualified package name (e.g., 'privalyse.api.v1' or 'frontend/components/Button')
    imports: List[ImportedSymbol] = field(default_factory=list)
    exports: Set[str] = field(default_factory=set)  # Functions/classes defined in module
    dependencies: Set[str] = field(default_factory=set)  # Modules this module imports from


class ImportResolver:
    """
    Resolves imports and builds module dependency graphs.
    
    Usage:
        resolver = ImportResolver(root_path='/path/to/project')
        resolver.analyze_module('/path/to/module.py', analyzer)
        graph = resolver.build_dependency_graph()
    """
    
    def __init__(self, root_path: Path):
        self.root_path = Path(root_path)
        self.modules: Dict[str, ModuleInfo] = {}  # package_name -> ModuleInfo
        self.path_to_package: Dict[Path, str] = {}  # file_path -> package_name
        
    def analyze_module(self, file_path: Path, analyzer: Optional[BaseAnalyzer] = None) -> ModuleInfo:
        """
        Analyze a file and extract import information using the provided analyzer.
        
        Args:
            file_path: Path to file
            analyzer: Language-specific analyzer instance (must implement extract_imports)
            
        Returns:
            ModuleInfo object with imports and exports
        """
        file_path = Path(file_path).resolve()
        
        # Calculate package name
        package_name = self._path_to_package_name(file_path)
        
        # Skip if already analyzed
        if package_name in self.modules:
            return self.modules[package_name]
        
        module_info = ModuleInfo(path=file_path, package=package_name)
        
        # If no analyzer provided, return empty info (or fallback to legacy logic if needed)
        if not analyzer:
            self.modules[package_name] = module_info
            self.path_to_package[file_path] = package_name
            return module_info
            
        try:
            code = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # 1. Extract Imports
            analyzed_imports = analyzer.extract_imports(code)
            for imp in analyzed_imports:
                # Convert AnalyzedImport to ImportedSymbol
                # Note: AnalyzedImport is simpler, we map it to our internal structure
                
                # Handle "import X" vs "from X import Y"
                if imp.imported_names:
                    # from X import A, B
                    for name in imp.imported_names:
                        symbol = ImportedSymbol(
                            name=name,
                            source_module=imp.source_module,
                            original_name=name,
                            import_type='from_import',
                            location=(imp.line, 0)
                        )
                        module_info.imports.append(symbol)
                else:
                    # import X
                    symbol = ImportedSymbol(
                        name=imp.source_module,
                        source_module=imp.source_module,
                        original_name=imp.source_module,
                        import_type='import',
                        location=(imp.line, 0)
                    )
                    module_info.imports.append(symbol)
                
                module_info.dependencies.add(imp.source_module)
            
            # 2. Extract Exports (Symbols defined in this file)
            analyzed_symbols = analyzer.extract_symbols(code)
            for sym in analyzed_symbols:
                if sym.is_exported:
                    module_info.exports.add(sym.name)
                    
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Error analyzing module {file_path}: {e}")
        
        self.modules[package_name] = module_info
        self.path_to_package[file_path] = package_name
        return module_info
    
    def _path_to_package_name(self, file_path: Path) -> str:
        """Convert file path to dotted package name (Python) or relative path (JS)."""
        try:
            rel_path = file_path.relative_to(self.root_path)
            
            # Python style: a/b/c.py -> a.b.c
            if file_path.suffix == '.py':
                parts = list(rel_path.parts)
                parts[-1] = parts[-1][:-3]  # remove .py
                if parts[-1] == '__init__':
                    parts.pop()
                return '.'.join(parts)
            
            # JS/TS style: a/b/c.js -> a/b/c
            else:
                return str(rel_path)
                
        except ValueError:
            # File is outside root path
            return file_path.name

    def build_dependency_graph(self) -> Dict[str, Set[str]]:
        """
        Build a graph of module dependencies.
        Returns: dict {module_name: {imported_module_names}}
        """
        graph = {}
        for name, info in self.modules.items():
            graph[name] = info.dependencies
        return graph

    def resolve_symbol(self, symbol_name: str, current_module: str) -> Optional[str]:
        """
        Resolve a symbol to its defining module.
        
        Args:
            symbol_name: The symbol being used (e.g. 'createUser')
            current_module: The module where it is being used
            
        Returns:
            The name of the module defining the symbol, or None if not found.
        """
        if current_module not in self.modules:
            return None
            
        module_info = self.modules[current_module]
        
        # 1. Check if defined locally (exported)
        if symbol_name in module_info.exports:
            return current_module
            
        # 2. Check imports
        for imported in module_info.imports:
            if imported.name == symbol_name:
                # Found the import!
                source = imported.source_module
                
                # If it's a relative import (starts with .), resolve it relative to current module
                if source.startswith('.'):
                    resolved = self._resolve_relative_import(source, current_module)
                    return resolved if resolved else source
                
                return source
                
        return None

    def _resolve_relative_import(self, import_path: str, current_module: str) -> Optional[str]:
        """Resolve a relative import path (e.g. './utils') to a module name."""
        current_info = self.modules.get(current_module)
        if not current_info:
            return None
            
        current_dir = current_info.path.parent
        
        try:
            # Resolve path relative to current file's directory
            # Note: import_path might be '../utils' or './api'
            target_path = (current_dir / import_path).resolve()
            
            # Try to find the file with extensions
            extensions = ['.ts', '.tsx', '.js', '.jsx', '.py']
            
            # Helper to check if path matches a known module
            def check_path(p: Path) -> Optional[str]:
                if p in self.path_to_package:
                    return self.path_to_package[p]
                return None

            # 1. Exact match (unlikely for imports without extension)
            if res := check_path(target_path): return res
                
            # 2. Try extensions
            for ext in extensions:
                if res := check_path(target_path.with_suffix(ext)): return res
            
            # 3. Try index files
            for ext in extensions:
                if res := check_path(target_path / f"index{ext}"): return res
                    
        except Exception:
            pass
            
        return None
