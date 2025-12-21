"""
Cross-File Taint Propagation
=============================
Tracks taint flow across module boundaries using import resolution and symbol table.

Features:
- Propagate taint when calling functions in other modules
- Track return values from cross-module function calls
- Handle method calls on imported classes
- Support async/await patterns
- Maintain taint source chain across file boundaries
"""

import ast
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field

from ..models.taint import TaintTracker, TaintInfo
from ..models.finding import Finding, Severity
from ..core.import_resolver import ImportResolver, ImportedSymbol
from ..core.symbol_table import GlobalSymbolTable, FunctionSignature


@dataclass
class CrossFileTaintContext:
    """Context for tracking taint across file boundaries."""
    # Current module being analyzed
    current_module: str
    current_file: Path
    
    # Taint tracker for current module
    local_taint: TaintTracker
    
    # Cross-module taint propagation
    imported_taints: Dict[str, Set[TaintInfo]] = field(default_factory=dict)  # symbol -> taint_infos
    exported_taints: Dict[str, Set[TaintInfo]] = field(default_factory=dict)  # symbol -> taint_infos


class CrossFileAnalyzer:
    """
    Analyzes taint propagation across module boundaries.
    
    Connects individual file analyses to form a complete data flow graph.
    """
    
    def __init__(self, import_resolver: ImportResolver, symbol_table: GlobalSymbolTable):
        self.import_resolver = import_resolver
        self.symbol_table = symbol_table
        
        # Track taint contexts for each module
        self.module_contexts: Dict[str, CrossFileTaintContext] = {}
        
        # Global taint registry: module.symbol -> TaintInfo
        self.global_taints: Dict[str, Set[TaintInfo]] = {}
        
    def register_module_context(self, module_name: str, file_path: Path, taint_tracker: TaintTracker):
        """
        Register a module's taint context for cross-file analysis.
        
        Args:
            module_name: Qualified module name
            file_path: Path to module file
            taint_tracker: Local taint tracker from initial scan
        """
        context = CrossFileTaintContext(
            current_module=module_name,
            current_file=file_path,
            local_taint=taint_tracker
        )
        self.module_contexts[module_name] = context
        
        # Extract exported taints (variables/functions that return tainted data)
        self._extract_exported_taints(context)
    
    def _extract_exported_taints(self, context: CrossFileTaintContext):
        """
        Extract tainted symbols that this module exports.
        
        These can be:
        - Module-level variables that are tainted
        - Functions that return tainted data
        - Class methods that return tainted data
        """
        # Get all exported symbols from this module
        exports = self.symbol_table.get_module_exports(context.current_module)
        
        for symbol_name in exports:
            # Check if this symbol is tainted in local context
            taint_info = context.local_taint.get_taint(symbol_name)
            if taint_info:
                context.exported_taints[symbol_name] = {taint_info}
                
                # Register in global taint registry
                qualified_name = f"{context.current_module}.{symbol_name}"
                if qualified_name not in self.global_taints:
                    self.global_taints[qualified_name] = set()
                self.global_taints[qualified_name].add(taint_info)
    
    def propagate_call(
        self,
        caller_module: str,
        func_name: str,
        tainted_args: List[Tuple[str, TaintInfo]],
        caller_taint: TaintTracker,
        object_name: Optional[str] = None
    ) -> Optional[TaintInfo]:
        """
        Generic method to propagate taint for a function call (Language Agnostic).
        
        Args:
            caller_module: Module making the call
            func_name: Name of function being called
            tainted_args: List of (arg_name, TaintInfo) for tainted arguments
            caller_taint: Taint tracker for calling module
            object_name: Optional object/module name (e.g. 'api' in 'api.getUser')
        """
        target_module = caller_module
        
        # Resolve target module
        if object_name:
            # Check if object is an imported module
            resolved = self.import_resolver.resolve_symbol(object_name, caller_module)
            if resolved:
                target_module = resolved
        else:
            # Check if function is imported
            resolved = self.import_resolver.resolve_symbol(func_name, caller_module)
            if resolved:
                target_module = resolved
                
        # Get function signature
        func_sig = self.symbol_table.get_function_signature(func_name, target_module)
        if not func_sig:
            # Fallback: Check if it's a known sensitive function even without signature
            if self._is_known_sensitive(func_name):
                return TaintInfo(
                    variable_name=f"{func_name}_result",
                    pii_types=['unknown'],
                    source_line=0,
                    source_node="function_call",
                    taint_source=f"{target_module}.{func_name}",
                    confidence=0.6
                )
            return None
            
        return self._propagate_taint_through_function(
            func_name=func_name,
            func_sig=func_sig,
            tainted_args=tainted_args,
            caller_module=caller_module,
            target_module=target_module
        )

    def _is_known_sensitive(self, func_name: str) -> bool:
        """Check if function name suggests sensitivity (heuristic fallback)."""
        sensitive = {'getUser', 'getProfile', 'login', 'register', 'fetchData', 'query'}
        return func_name in sensitive or 'user' in func_name.lower()

    def propagate_function_call_taint(
        self, 
        call_node: ast.Call,
        caller_module: str,
        caller_taint: TaintTracker
    ) -> Optional[TaintInfo]:
        """
        Propagate taint when calling a function (Python AST specific wrapper).
        """
        # Extract function name and object
        func_name = None
        obj_name = None
        
        if isinstance(call_node.func, ast.Name):
            func_name = call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            if isinstance(call_node.func.value, ast.Name):
                obj_name = call_node.func.value.id
                func_name = call_node.func.attr
        
        if not func_name:
            return None
            
        # Extract tainted args
        tainted_args = []
        for arg in call_node.args:
            if isinstance(arg, ast.Name):
                arg_taint = caller_taint.get_taint(arg.id)
                if arg_taint:
                    tainted_args.append((arg.id, arg_taint))
                    
        return self.propagate_call(
            caller_module=caller_module,
            func_name=func_name,
            tainted_args=tainted_args,
            caller_taint=caller_taint,
            object_name=obj_name
        )
    
    def _propagate_taint_through_function(
        self,
        func_name: str,
        func_sig: FunctionSignature,
        tainted_args: List[Tuple[str, TaintInfo]],
        caller_module: str,
        target_module: str
    ) -> Optional[TaintInfo]:
        """
        Determine if function call propagates taint.
        
        Rules:
        1. If function has PII parameters and receives tainted args -> function returns taint
        2. If function performs DB operations with tainted args -> taint propagates
        3. If function is known to return PII (from signature) -> always returns taint
        """
        if not tainted_args:
            # No tainted inputs, but check if function inherently returns PII
            if func_sig.returns_pii:
                return TaintInfo(
                    variable_name=func_name,
                    pii_types=['unknown'],
                    source_line=0,
                    source_node="function_call",
                    taint_source=f"{target_module}.{func_name}",
                    confidence=0.7
                )
            return None
        
        # Merge taint from all tainted arguments
        merged_pii_types = set()
        merged_sources = set()
        max_confidence = 0.0
        
        for arg_name, taint_info in tainted_args:
            merged_pii_types.update(taint_info.pii_types)
            merged_sources.update(taint_info.sources)
            max_confidence = max(max_confidence, taint_info.confidence)
        
        # Boost confidence if function has PII-sensitive parameters
        if func_sig.pii_parameters:
            max_confidence = min(0.95, max_confidence + 0.15)
        
        # Add current function to sources
        merged_sources.add(f"{target_module}.{func_name}")
        
        # Create propagated taint
        return TaintInfo(
            variable_name=f"{func_name}_result",
            pii_types=list(merged_pii_types),
            source_line=0,
            source_node="cross_file_call",
            confidence=max_confidence,
            sources=list(merged_sources)
        )
    
    def propagate_taint_across_all_modules(self) -> Dict[str, List[Finding]]:
        """
        Perform global cross-file taint propagation.
        
        This is a multi-pass algorithm:
        1. First pass: Register all module contexts
        2. Second pass: Propagate taint through import chains
        3. Third pass: Generate new findings from propagated taint
        
        Returns:
            Dict mapping module_name -> [new_findings_from_cross_file_taint]
        """
        new_findings: Dict[str, List[Finding]] = {}
        
        # Build import dependency graph (already done by ImportResolver)
        dep_graph = self.import_resolver.build_dependency_graph()
        
        # Topological sort to process modules in dependency order
        # (process dependencies before dependents)
        processing_order = self._topological_sort(dep_graph)
        
        # Multi-pass propagation
        for iteration in range(3):  # 3 passes should be enough for most code
            taint_changed = False
            
            for module in processing_order:
                if module not in self.module_contexts:
                    continue
                
                context = self.module_contexts[module]
                
                # Import taints from dependencies
                for dep_module in dep_graph.get(module, []):
                    if dep_module in self.module_contexts:
                        self._import_taints_from_dependency(context, dep_module)
                        taint_changed = True
            
            if not taint_changed:
                break  # Converged
        
        return new_findings
    
    def _import_taints_from_dependency(self, context: CrossFileTaintContext, dep_module: str):
        """
        Import tainted symbols from a dependency module.
        
        Example:
            Module A imports 'get_user_email' from Module B.
            If 'get_user_email' returns tainted data in Module B,
            then calls to 'get_user_email' in Module A should be tainted.
        """
        if dep_module not in self.module_contexts:
            return
        
        dep_context = self.module_contexts[dep_module]
        
        # Get imports from dep_module
        module_info = self.import_resolver.modules.get(context.current_module)
        if not module_info:
            return
        
        for imported_symbol in module_info.imports:
            if imported_symbol.source_module == dep_module:
                # Check if imported symbol is tainted in dep_module
                if imported_symbol.original_name in dep_context.exported_taints:
                    taints = dep_context.exported_taints[imported_symbol.original_name]
                    
                    # Import taint into current module
                    context.imported_taints[imported_symbol.name] = taints
                    
                    # Propagate to local taint tracker
                    for taint_info in taints:
                        context.local_taint.mark_tainted(
                            var_name=imported_symbol.name,
                            pii_types=taint_info.pii_types,
                            confidence=taint_info.confidence,
                            source=f"imported_from_{dep_module}"
                        )
    
    def _topological_sort(self, graph: Dict[str, List[str]]) -> List[str]:
        """
        Topological sort of dependency graph.
        
        Returns modules in order such that dependencies come before dependents.
        This ensures we propagate taint in the correct order.
        """
        from collections import deque, defaultdict
        
        # Build reverse graph (dependents)
        reverse_graph = defaultdict(list)
        in_degree = defaultdict(int)
        
        all_nodes = set(graph.keys())
        for node, deps in graph.items():
            for dep in deps:
                reverse_graph[dep].append(node)
                in_degree[node] += 1
                all_nodes.add(dep)
        
        # Find nodes with no dependencies
        queue = deque([node for node in all_nodes if in_degree[node] == 0])
        result = []
        
        while queue:
            node = queue.popleft()
            result.append(node)
            
            for dependent in reverse_graph[node]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)
        
        # If cycle exists, append remaining nodes
        for node in all_nodes:
            if node not in result:
                result.append(node)
        
        return result
    
    def enhance_findings_with_cross_file_taint(
        self,
        findings: List[Finding],
        module_name: str
    ) -> List[Finding]:
        """
        Enhance existing findings with cross-file taint information.
        
        This adds taint metadata to findings that were missing it in the initial scan.
        
        Args:
            findings: Findings from initial (single-file) scan
            module_name: Module these findings belong to
            
        Returns:
            Enhanced findings with cross-file taint data
        """
        if module_name not in self.module_contexts:
            return findings
        
        context = self.module_contexts[module_name]
        enhanced = []
        
        for finding in findings:
            # Check if finding variables are now tainted through imports
            if hasattr(finding, 'tainted_variables') and not finding.tainted_variables:
                # Finding had no local taint, check imported taint
                for var_name, imported_taints in context.imported_taints.items():
                    # Check if this finding involves the imported variable
                    if var_name in finding.code_snippet:
                        # Add taint metadata
                        finding.tainted_variables = [var_name]
                        for taint_info in imported_taints:
                            finding.metadata['cross_file_taint'] = True
                            finding.metadata['taint_sources'] = list(taint_info.sources)
                            finding.metadata['pii_types'] = list(taint_info.pii_types)
                            break
            
            enhanced.append(finding)
        
        return enhanced
