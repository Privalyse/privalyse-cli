"""
Global Symbol Table
===================
Tracks functions, classes, and their signatures across all modules for cross-file analysis.

Features:
- Register functions with parameters, return types, and source location
- Register classes with attributes and methods
- Lookup symbols across modules
- Track which symbols handle PII or sensitive data
- Support for method resolution order (MRO) in class hierarchies
"""

import ast
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..utils.helpers import safe_unparse


class SymbolType(Enum):
    """Type of symbol in the symbol table."""
    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    VARIABLE = "variable"
    CONSTANT = "constant"


@dataclass
class Parameter:
    """Function/method parameter information."""
    name: str
    type_annotation: Optional[str] = None
    default_value: Optional[str] = None
    is_pii_related: bool = False  # True if name suggests PII (email, password, etc.)


@dataclass
class FunctionSignature:
    """Function or method signature."""
    name: str
    parameters: List[Parameter] = field(default_factory=list)
    return_type: Optional[str] = None
    is_async: bool = False
    decorators: List[str] = field(default_factory=list)
    docstring: Optional[str] = None
    returns_pii: bool = False # True if function is known to return PII
    
    # Taint tracking metadata
    pii_parameters: Set[str] = field(default_factory=set)  # Parameters that are PII
    returns_pii: bool = False  # True if function returns PII
    sensitive_operations: Set[str] = field(default_factory=set)  # 'db_write', 'logging', 'network'


@dataclass
class ClassInfo:
    """Class definition information."""
    name: str
    base_classes: List[str] = field(default_factory=list)
    attributes: Set[str] = field(default_factory=set)
    methods: Dict[str, FunctionSignature] = field(default_factory=dict)
    decorators: List[str] = field(default_factory=list)
    docstring: Optional[str] = None
    
    # Privacy metadata
    pii_attributes: Set[str] = field(default_factory=set)  # Attributes storing PII


@dataclass
class SymbolInfo:
    """Complete information about a symbol."""
    name: str
    symbol_type: SymbolType
    module: str  # Package name where symbol is defined
    file_path: Path
    location: Tuple[int, int]  # (line, column)
    
    # Type-specific data (only one will be populated)
    function_signature: Optional[FunctionSignature] = None
    class_info: Optional[ClassInfo] = None
    value: Optional[Any] = None  # For variables/constants


class GlobalSymbolTable:
    """
    Global symbol table tracking all functions, classes, and variables across modules.
    
    Usage:
        symbol_table = GlobalSymbolTable()
        symbol_table.register_module('/path/to/module.py', 'privalyse.api.v1.scans')
        func_info = symbol_table.lookup('create_scan', context='privalyse.api.v1.scans')
    """
    
    def __init__(self):
        # symbol_name -> List[SymbolInfo] (multiple definitions in different modules)
        self.symbols: Dict[str, List[SymbolInfo]] = {}
        
        # module -> {symbol_name -> SymbolInfo}
        self.module_symbols: Dict[str, Dict[str, SymbolInfo]] = {}
        
        # Track which functions perform sensitive operations
        self.sensitive_functions: Set[str] = set()  # Fully qualified names
        
    def register_module(self, file_path: Path, module_name: str, analyzer: Optional[Any] = None):
        """
        Analyze a module and register all symbols.
        
        Args:
            file_path: Path to file
            module_name: Qualified module name
            analyzer: Optional analyzer instance to extract symbols (generic)
        """
        if analyzer:
            try:
                code = file_path.read_text(encoding='utf-8', errors='ignore')
                symbols = analyzer.extract_symbols(code)
                
                module_syms = {}
                for sym in symbols:
                    # Map AnalyzedSymbol to SymbolInfo
                    symbol_type = SymbolType.FUNCTION if sym.type == 'function' else \
                                  SymbolType.CLASS if sym.type == 'class' else \
                                  SymbolType.VARIABLE
                    
                    info = SymbolInfo(
                        name=sym.name,
                        symbol_type=symbol_type,
                        module=module_name,
                        file_path=file_path,
                        location=(sym.line, 0)
                    )
                    
                    # Add to symbol table
                    module_syms[sym.name] = info
                    self._add_symbol(sym.name, info)
                    
                    # If it's a function, register signature (simplified for now)
                    if symbol_type == SymbolType.FUNCTION:
                        sig = FunctionSignature(name=sym.name)
                        
                        # Check metadata for PII return
                        if hasattr(sym, 'metadata') and sym.metadata.get('returns_pii'):
                            sig.returns_pii = True
                            self.sensitive_functions.add(f"{module_name}.{sym.name}")
                            
                        info.function_signature = sig
                        
                        # Check metadata for PII return
                        if hasattr(sym, 'metadata') and sym.metadata.get('returns_pii'):
                            self.sensitive_functions.add(f"{module_name}.{sym.name}")
                
                self.module_symbols[module_name] = module_syms
                return
            except Exception as e:
                import logging
                logging.getLogger(__name__).warning(f"Error registering symbols for {file_path}: {e}")
                return

        # Legacy Python-only fallback (if no analyzer provided)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read(), filename=str(file_path))
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Failed to parse {file_path} for symbol table: {e}")
            return
        
        module_syms = {}
        
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                sym_info = self._register_function(node, module_name, file_path)
                if sym_info:
                    module_syms[sym_info.name] = sym_info
                    self._add_symbol(sym_info.name, sym_info)
                    
            elif isinstance(node, ast.ClassDef):
                sym_info = self._register_class(node, module_name, file_path)
                if sym_info:
                    module_syms[sym_info.name] = sym_info
                    self._add_symbol(sym_info.name, sym_info)
                    
            elif isinstance(node, ast.Assign):
                # Register module-level constants
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.isupper():
                        sym_info = SymbolInfo(
                            name=target.id,
                            symbol_type=SymbolType.CONSTANT,
                            module=module_name,
                            file_path=file_path,
                            location=(node.lineno, node.col_offset)
                        )
                        module_syms[target.id] = sym_info
                        self._add_symbol(target.id, sym_info)
        
        self.module_symbols[module_name] = module_syms
    
    def _register_function(self, node: ast.FunctionDef, module: str, file_path: Path) -> Optional[SymbolInfo]:
        """Register a function definition."""
        # Extract parameters
        params = []
        pii_params = set()
        
        for arg in node.args.args:
            param_name = arg.arg
            type_ann = safe_unparse(arg.annotation) if arg.annotation else None
            
            # Check if parameter name suggests PII
            is_pii = self._is_pii_parameter_name(param_name)
            if is_pii:
                pii_params.add(param_name)
            
            params.append(Parameter(
                name=param_name,
                type_annotation=type_ann,
                is_pii_related=is_pii
            ))
        
        # Extract decorators
        decorators = [safe_unparse(dec) for dec in node.decorator_list]
        
        # Extract return type
        return_type = safe_unparse(node.returns) if node.returns else None
        
        # Check if function performs sensitive operations
        sensitive_ops = self._detect_sensitive_operations(node)
        
        signature = FunctionSignature(
            name=node.name,
            parameters=params,
            return_type=return_type,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            decorators=decorators,
            docstring=ast.get_docstring(node),
            pii_parameters=pii_params,
            sensitive_operations=sensitive_ops
        )
        
        # Mark as sensitive if it performs sensitive operations
        if sensitive_ops:
            self.sensitive_functions.add(f"{module}.{node.name}")
        
        return SymbolInfo(
            name=node.name,
            symbol_type=SymbolType.FUNCTION,
            module=module,
            file_path=file_path,
            location=(node.lineno, node.col_offset),
            function_signature=signature
        )
    
    def _register_class(self, node: ast.ClassDef, module: str, file_path: Path) -> Optional[SymbolInfo]:
        """Register a class definition."""
        # Extract base classes
        bases = [safe_unparse(base) for base in node.bases]
        
        # Extract decorators
        decorators = [safe_unparse(dec) for dec in node.decorator_list]
        
        # Extract methods and attributes
        methods = {}
        attributes = set()
        pii_attributes = set()
        
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Register method
                method_info = self._register_function(item, module, file_path)
                if method_info and method_info.function_signature:
                    method_info.symbol_type = SymbolType.METHOD
                    methods[item.name] = method_info.function_signature
            
            elif isinstance(item, ast.AnnAssign):
                # Class attribute with type annotation
                if isinstance(item.target, ast.Name):
                    attr_name = item.target.id
                    attributes.add(attr_name)
                    if self._is_pii_parameter_name(attr_name):
                        pii_attributes.add(attr_name)
        
        class_info = ClassInfo(
            name=node.name,
            base_classes=bases,
            attributes=attributes,
            methods=methods,
            decorators=decorators,
            docstring=ast.get_docstring(node),
            pii_attributes=pii_attributes
        )
        
        return SymbolInfo(
            name=node.name,
            symbol_type=SymbolType.CLASS,
            module=module,
            file_path=file_path,
            location=(node.lineno, node.col_offset),
            class_info=class_info
        )
    
    def _is_pii_parameter_name(self, name: str) -> bool:
        """Check if parameter/attribute name suggests PII data."""
        pii_indicators = {
            'email', 'password', 'passwd', 'pwd', 'token', 'api_key', 'secret',
            'ssn', 'social_security', 'credit_card', 'cc_number', 'card_number', 'cvv',
            'phone', 'mobile', 'cell', 'address', 'street', 'city', 'zip', 'postal',
            'user_id', 'username', 'name', 'firstname', 'lastname', 'fullname',
            'birth_date', 'dob', 'ip_address', 'location', 'geo', 'lat', 'lon',
            'auth', 'credential', 'session', 'jwt', 'cookie', 'iban', 'bank_account'
        }
        
        name_lower = name.lower()
        return any(indicator in name_lower for indicator in pii_indicators)
    
    def _detect_sensitive_operations(self, node: ast.FunctionDef) -> Set[str]:
        """Detect if function performs sensitive operations (DB, logging, network)."""
        operations = set()
        
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    # Check for logging calls
                    if child.func.attr in ('info', 'debug', 'warning', 'error', 'log'):
                        operations.add('logging')
                    
                    # Check for DB operations
                    if child.func.attr in ('execute', 'add', 'commit', 'query', 'insert', 'update', 'delete'):
                        operations.add('db_write')
                    
                    # Check for network operations
                    if child.func.attr in ('get', 'post', 'put', 'delete', 'request', 'urlopen'):
                        operations.add('network')
                
                elif isinstance(child.func, ast.Name):
                    # Check for print statements
                    if child.func.id == 'print':
                        operations.add('logging')
        
        return operations
    
    def _add_symbol(self, name: str, symbol_info: SymbolInfo):
        """Add symbol to global table."""
        if name not in self.symbols:
            self.symbols[name] = []
        self.symbols[name].append(symbol_info)
    
    def lookup(self, symbol_name: str, context: Optional[str] = None) -> Optional[SymbolInfo]:
        """
        Lookup a symbol, optionally in a specific module context.
        
        Args:
            symbol_name: Name of symbol to find
            context: Module name for context-aware lookup
            
        Returns:
            SymbolInfo if found, None otherwise
        """
        # Try context-specific lookup first
        if context and context in self.module_symbols:
            if symbol_name in self.module_symbols[context]:
                return self.module_symbols[context][symbol_name]
        
        # Try global lookup
        if symbol_name in self.symbols:
            # Return first match (could be improved with better resolution)
            return self.symbols[symbol_name][0]
        
        return None
    
    def get_function_signature(self, function_name: str, module: Optional[str] = None) -> Optional[FunctionSignature]:
        """Get function signature by name."""
        sym_info = self.lookup(function_name, context=module)
        if sym_info and sym_info.function_signature:
            return sym_info.function_signature
        return None
    
    def get_class_info(self, class_name: str, module: Optional[str] = None) -> Optional[ClassInfo]:
        """Get class information by name."""
        sym_info = self.lookup(class_name, context=module)
        if sym_info and sym_info.class_info:
            return sym_info.class_info
        return None
    
    def is_sensitive_function(self, function_name: str, module: str) -> bool:
        """Check if a function performs sensitive operations."""
        qualified_name = f"{module}.{function_name}"
        return qualified_name in self.sensitive_functions
    
    def get_module_exports(self, module: str) -> Set[str]:
        """Get all symbols exported by a module."""
        if module in self.module_symbols:
            return set(self.module_symbols[module].keys())
        return set()
    
    def find_functions_with_pii_params(self) -> List[Tuple[str, FunctionSignature]]:
        """Find all functions that accept PII parameters."""
        results = []
        for sym_list in self.symbols.values():
            for sym in sym_list:
                if sym.function_signature and sym.function_signature.pii_parameters:
                    qualified_name = f"{sym.module}.{sym.name}"
                    results.append((qualified_name, sym.function_signature))
        return results
    
    def find_sensitive_operations(self, operation_type: str) -> List[Tuple[str, FunctionSignature]]:
        """
        Find all functions performing a specific sensitive operation.
        
        Args:
            operation_type: 'logging', 'db_write', or 'network'
            
        Returns:
            List of (qualified_name, FunctionSignature) tuples
        """
        results = []
        for sym_list in self.symbols.values():
            for sym in sym_list:
                if sym.function_signature and operation_type in sym.function_signature.sensitive_operations:
                    qualified_name = f"{sym.module}.{sym.name}"
                    results.append((qualified_name, sym.function_signature))
        return results
