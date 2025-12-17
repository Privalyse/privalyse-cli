"""Python code analyzer with AST-based taint tracking"""

import ast
import re
from typing import List, Dict, Any, Optional, Set, Tuple
from pathlib import Path

from ..models.finding import Finding, Severity, ClassificationResult
from ..models.taint import TaintTracker
from ..utils.classification import classify_pii_enhanced
from ..utils.helpers import extract_ast_snippet, should_filter_log_finding, should_filter_db_finding
from ..config.framework_patterns import (
    get_db_result_methods,
    get_db_write_methods,
    is_pii_sensitive_model,
    PII_MODEL_KEYWORDS
)
from .base_analyzer import BaseAnalyzer, AnalyzedSymbol, AnalyzedImport

# Patterns for detecting hardcoded secrets
SECRET_PATTERNS = {
    'api_key': r'(api[_-]?key|apikey|api[_-]?token)',
    'password': r'(password|passwd|pwd)',
    'secret': r'(secret[_-]?key|client[_-]?secret|app[_-]?secret)',
    'token': r'(access[_-]?token|auth[_-]?token|bearer[_-]?token|refresh[_-]?token|id[_-]?token)',
    'aws': r'(aws[_-]?secret|aws[_-]?access|aws[_-]?key)',
    'private_key': r'(private[_-]?key|priv[_-]?key|rsa[_-]?key|dsa[_-]?key)',
    'database': r'(db[_-]?password|database[_-]?password|db[_-]?pass|connection[_-]?string|dsn)',
    'jwt': r'(jwt|json[_-]?web[_-]?token)',
}

# High-entropy string pattern (likely a secret)
HIGH_ENTROPY_PATTERN = r'^[A-Za-z0-9+/=_-]{32,}$'

def is_likely_secret(var_name: str, value: str) -> Tuple[Optional[str], float]:
    """
    Check if a variable assignment is likely a hardcoded secret.
    Returns (secret_type, confidence) if detected, (None, 0.0) otherwise.
    """
    var_lower = var_name.lower()
    
    # Check variable name patterns
    for secret_type, pattern in SECRET_PATTERNS.items():
        if re.search(pattern, var_lower, re.IGNORECASE):
            # Variable name suggests it's a secret
            # Check if value looks like a secret (not empty, not obvious placeholder)
            if value and len(value) > 8:
                if not value.lower() in ['your_api_key_here', 'changeme', 'secret', 'password', 'todo']:
                    # Check for high entropy to increase confidence
                    if re.match(HIGH_ENTROPY_PATTERN, value):
                        return secret_type, 1.0 # High confidence
                    return secret_type, 0.6 # Medium confidence (name matches, value is string)
    
    # Check for high-entropy strings (likely encoded secrets)
    if re.match(HIGH_ENTROPY_PATTERN, value) and len(value) >= 32:
        return 'token', 0.9 # High confidence based on entropy
    
    return None, 0.0


class PythonAnalyzer(BaseAnalyzer):
    """Analyzes Python code for privacy issues using AST parsing"""
    
    def __init__(self, cross_file_analyzer=None):
        self.cross_file_analyzer = cross_file_analyzer  # Cross-file taint support
        self.taint_tracker = None  # Will be set during analyze_file()
    
    def analyze_file(self, file_path: Path, code: str, **kwargs) -> Tuple[List[Finding], List[Dict[str, Any]]]:
        """
        Analyze a Python file for privacy issues
        
        Returns:
            tuple: (findings, data_flows)
        """
        findings = []
        flows = []
        
        # Extract kwargs if present (backward compatibility)
        consts = kwargs.get('consts', {})
        envmap = kwargs.get('envmap', {})
        
        try:
            tree = ast.parse(code, filename=str(file_path))
        except SyntaxError as e:
            import logging
            logging.getLogger(__name__).warning(f"Syntax error in {file_path}: {e}")
            return findings, flows
        
        # Initialize taint tracker for this file
        taint_tracker = TaintTracker()
        self.taint_tracker = taint_tracker  # Make accessible for cross-file analyzer
        self.current_file = file_path
        self.current_module = None  # Will be set by scanner
        
        # Create AST visitor with taint tracking
        visitor = self._create_visitor(
            file_path, code, consts, envmap, 
            findings, flows, taint_tracker
        )
        
        visitor.visit(tree)
        
        return findings, flows

    def extract_symbols(self, code: str) -> List[AnalyzedSymbol]:
        """
        Extract Python functions and classes for the Symbol Table using AST.
        """
        symbols = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    symbols.append(AnalyzedSymbol(
                        name=node.name,
                        type='function',
                        line=node.lineno,
                        is_exported=not node.name.startswith('_'),
                        signature=f"def {node.name}(...)"
                    ))
                elif isinstance(node, ast.AsyncFunctionDef):
                    symbols.append(AnalyzedSymbol(
                        name=node.name,
                        type='function',
                        line=node.lineno,
                        is_exported=not node.name.startswith('_'),
                        signature=f"async def {node.name}(...)"
                    ))
                elif isinstance(node, ast.ClassDef):
                    symbols.append(AnalyzedSymbol(
                        name=node.name,
                        type='class',
                        line=node.lineno,
                        is_exported=not node.name.startswith('_'),
                        signature=f"class {node.name}"
                    ))
        except SyntaxError:
            pass # Skip files with syntax errors
            
        return symbols

    def extract_imports(self, code: str) -> List[AnalyzedImport]:
        """
        Extract Python imports for the Dependency Graph using AST.
        """
        imports = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(AnalyzedImport(
                            source_module=alias.name,
                            imported_names=[], # Entire module imported
                            line=node.lineno
                        ))
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported_names = [alias.name for alias in node.names]
                        imports.append(AnalyzedImport(
                            source_module=node.module,
                            imported_names=imported_names,
                            line=node.lineno
                        ))
        except SyntaxError:
            pass
            
        return imports
    
    def _create_visitor(self, file_path: Path, code: str,
                       consts: Dict, envmap: Dict,
                       findings: List, flows: List,
                       taint_tracker: TaintTracker):
        """Create AST visitor with taint tracking capabilities"""
        
        # Phase 2.4: Capture outer scope for cross-file analyzer access
        outer_self = self
        
        class TaintAwareVisitor(ast.NodeVisitor):
            """AST visitor that tracks tainted variables"""
            
            def visit_Assign(self, node: ast.Assign):
                """Track variable assignments for taint propagation"""
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        target_name = target.id
                        
                        # ===== NEW: Request parameter tracking =====
                        # Detect: email = request.args.get('email')
                        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute):
                            # Check for request.args.get(), request.form.get(), request.json.get()
                            func_attr = node.value.func
                            if (hasattr(func_attr.value, 'attr') and 
                                func_attr.value.attr in ('args', 'form', 'json') and
                                func_attr.attr == 'get'):
                                # Extract field name from first argument
                                if node.value.args and isinstance(node.value.args[0], ast.Constant):
                                    field_name = node.value.args[0].value
                                    # Infer PII type from field name
                                    pii_types = taint_tracker.infer_pii_type(field_name)
                                    if pii_types:
                                        taint_tracker.mark_tainted(
                                            var_name=target_name,
                                            pii_types=pii_types,
                                            source_line=node.lineno,
                                            source_node='request.args.get',
                                            taint_source=f"request parameter '{field_name}'"
                                        )
                        
                        # ===== NEW: Hardcoded Secret Detection =====
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            secret_type, confidence = is_likely_secret(target_name, node.value.value)
                            if secret_type:
                                # Completely mask the secret value
                                snippet = f'{target_name} = "***"'
                                
                                findings.append(Finding(
                                    rule="HARDCODED_SECRET",
                                    file=str(file_path),
                                    line=node.lineno,
                                    snippet=snippet,
                                    severity=Severity.CRITICAL if confidence > 0.8 else Severity.HIGH,
                                    classification=ClassificationResult(
                                        pii_types=[secret_type, 'credentials'],
                                        sectors=['security', 'authentication'],
                                        severity='critical' if confidence > 0.8 else 'high',
                                        article='Art. 32',
                                        legal_basis_required=True,
                                        category='credentials',
                                        confidence=confidence,
                                        reasoning=f"Hardcoded {secret_type} violates Art. 32 security requirements"
                                    ),
                                    metadata={
                                        'description': f'Hardcoded {secret_type} detected in source code',
                                        'variable': target_name,
                                        'secret_type': secret_type
                                    }
                                ))
                                # Also mark as tainted for backward tracking
                                taint_tracker.mark_tainted(
                                    target_name, [secret_type, 'credentials'], node.lineno,
                                    "hardcoded_secret", f"{target_name}=***"
                                )
                        
                        # Check if assignment source contains PII
                        if isinstance(node.value, ast.Attribute):
                            attr_name = node.value.attr
                            
                            # Phase 3: Check if accessing DB query result
                            # e.g., user = result.scalar_one() or scan = result.first()
                            # Supports multiple ORMs: SQLAlchemy, Django, Peewee, etc.
                            db_result_methods = get_db_result_methods()
                            if attr_name in db_result_methods:
                                # Check if base is tainted (the query result)
                                if isinstance(node.value.value, ast.Name):
                                    base_var = node.value.value.id
                                    if taint_tracker.is_tainted(node.value.value):
                                        # Propagate taint from query result to extracted object
                                        taint_info = taint_tracker.get_taint_info(node.value.value)
                                        if taint_info:
                                            taint_tracker.mark_tainted(
                                                target_name, taint_info.pii_types, node.lineno,
                                                "db_result_extraction", f"{base_var}.{attr_name}()"
                                            )
                            
                            # Phase 3.4: Transitive taint propagation from base object
                            # If base object is tainted, propagate to attribute access
                            # e.g., email = user.email (if 'user' is tainted, 'email' inherits taint)
                            if isinstance(node.value.value, ast.Name):
                                base_var = node.value.value.id
                                if taint_tracker.is_tainted(node.value.value):
                                    taint_info = taint_tracker.get_taint_info(node.value.value)
                                    if taint_info:
                                        # Propagate base taint + infer additional from attribute name
                                        attr_pii_types = taint_tracker.infer_pii_type(attr_name)
                                        combined_pii = list(set(taint_info.pii_types + attr_pii_types))
                                        taint_tracker.mark_tainted(
                                            target_name, combined_pii, node.lineno,
                                            "attribute_propagation", f"{base_var}.{attr_name}"
                                        )
                            
                            # Fallback: PII inference from attribute name only - REMOVED to reduce false positives
                            # We only want to track data that comes from a known source or is already tainted.
                            # Simply having a variable named 'email' or 'name' is not enough if it doesn't come from a source.
                            elif not taint_tracker.is_tainted(ast.Name(id=target_name)):
                                pass
                        
                        elif isinstance(node.value, ast.Name):
                            taint_tracker.propagate_through_assignment(
                                target_name, node.value, node.lineno
                            )
                        
                        elif isinstance(node.value, ast.Subscript):
                            # STRICT MODE: Only propagate if container is tainted
                            is_container_tainted = False
                            if isinstance(node.value.value, ast.Name):
                                if taint_tracker.is_tainted(node.value.value):
                                    is_container_tainted = True
                            
                            if is_container_tainted and isinstance(node.value.slice, ast.Constant):
                                key = str(node.value.slice.value)
                                pii_types = taint_tracker.infer_pii_type(key)
                                if pii_types and pii_types != ['unknown']:
                                    taint_tracker.mark_tainted(
                                        target_name, pii_types, node.lineno,
                                        "subscript", f"dict['{key}']"
                                    )
                        
                        elif isinstance(node.value, ast.Call):
                            func_name = ""
                            call_node = node.value
                            
                            if isinstance(call_node.func, ast.Name):
                                func_name = call_node.func.id
                            elif isinstance(call_node.func, ast.Attribute):
                                func_name = call_node.func.attr
                                
                                # Phase 3.3: Check for DB result extraction (result.scalar_one(), etc.)
                                # Supports multiple ORMs via framework_patterns config
                                db_result_methods = get_db_result_methods()
                                if func_name in db_result_methods:
                                    # Check if base object is tainted (the query result)
                                    if isinstance(call_node.func.value, ast.Name):
                                        base_var = call_node.func.value.id
                                        if taint_tracker.is_tainted(call_node.func.value):
                                            # Propagate taint from query result to extracted object
                                            taint_info = taint_tracker.get_taint_info(call_node.func.value)
                                            if taint_info:
                                                taint_tracker.mark_tainted(
                                                    target_name, taint_info.pii_types, node.lineno,
                                                    "db_result_extraction", f"{base_var}.{func_name}()"
                                                )
                            
                            # Phase 3: DB Query detection - SELECT returns tainted data!
                            is_db_query = False
                            queried_models = []
                            
                            # Check for db.execute(select(...)) pattern
                            if func_name == 'execute':
                                # Check if first argument is select() call
                                if call_node.args and isinstance(call_node.args[0], ast.Call):
                                    inner_call = call_node.args[0]
                                    if isinstance(inner_call.func, ast.Name) and inner_call.func.id == 'select':
                                        is_db_query = True
                                        # Extract model from select(User) or select(Scan)
                                        for arg in inner_call.args:
                                            if isinstance(arg, ast.Name):
                                                queried_models.append(arg.id)
                            
                            # Check for db.query(User) pattern
                            elif func_name == 'query':
                                is_db_query = True
                                for arg in call_node.args:
                                    if isinstance(arg, ast.Name):
                                        queried_models.append(arg.id)
                            
                            # If DB query, mark result as tainted
                            if is_db_query and queried_models:
                                # Infer PII from model names (User, Account, etc.)
                                pii_models = ['user', 'account', 'profile', 'member', 'organization', 'customer', 'person']
                                contains_pii = any(model.lower() in pii_models for model in queried_models)
                                
                                if contains_pii:
                                    taint_tracker.mark_tainted(
                                        target_name, ['email', 'name'], node.lineno,
                                        "db_query", f"SELECT {','.join(queried_models)}"
                                    )
                            
                            # Original PII inference from function name
                            pii_types = taint_tracker.infer_pii_type(func_name, target_name)
                            if pii_types and pii_types != ['unknown']:
                                taint_tracker.mark_tainted(
                                    target_name, pii_types, node.lineno,
                                    "function_call", func_name
                                )
                        
                        # Phase 3: Handle await expressions (await db.execute(...))
                        elif isinstance(node.value, ast.Await):
                            if isinstance(node.value.value, ast.Call):
                                call_node = node.value.value
                                func_name = ""
                                
                                if isinstance(call_node.func, ast.Attribute):
                                    func_name = call_node.func.attr
                                elif isinstance(call_node.func, ast.Name):
                                    func_name = call_node.func.id
                                
                                # Check for await db.execute(select(...).where(...))
                                if func_name == 'execute' and call_node.args:
                                    # Use helper to recursively extract models from select()
                                    queried_models = self._extract_select_models(call_node.args[0])
                                    
                                    if queried_models:
                                        # Check if models contain PII using framework_patterns
                                        contains_pii = any(is_pii_sensitive_model(m) for m in queried_models)
                                        
                                        if contains_pii:
                                            taint_tracker.mark_tainted(
                                                target_name, ['email', 'name'], node.lineno,
                                                "db_query_await", f"SELECT {','.join(queried_models)}"
                                            )
                
                self.generic_visit(node)
            
            def visit_FunctionDef(self, node: ast.FunctionDef):
                """Track function parameters for taint analysis"""
                param_names = [arg.arg for arg in node.args.args]
                taint_tracker.function_params[node.name] = param_names
                
                # STRICT MODE: Do not infer taint from parameter names
                # We only track taint from known sources
                
                self.generic_visit(node)
            
            def visit_Call(self, node: ast.Call):
                """Analyze function calls for privacy issues"""
                # Phase 2.4: Check for cross-file taint propagation
                if outer_self.cross_file_analyzer and outer_self.current_module:
                    cross_taint = outer_self.cross_file_analyzer.propagate_function_call_taint(
                        node, outer_self.current_module, taint_tracker
                    )
                    if cross_taint:
                        # Merge cross-file taint into local taint tracker
                        result_var = f"_call_result_{node.lineno}"
                        taint_tracker.mark_tainted(
                            result_var,
                            list(cross_taint.pii_types),
                            node.lineno,
                            "cross_file_call",
                            f"Imported from {list(cross_taint.sources)}"
                        )
                        # Also taint any assignment target
                        parent = getattr(node, '_parent', None)
                        if parent and isinstance(parent, ast.Assign):
                            for target in parent.targets:
                                if isinstance(target, ast.Name):
                                    taint_tracker.mark_tainted(
                                        target.id,
                                        list(cross_taint.pii_types),
                                        node.lineno,
                                        "cross_file_assignment",
                                        f"From {list(cross_taint.sources)}"
                                    )
                
                # ===== NEW: Backward Taint Tracking for Keyword Arguments =====
                # Check if any keyword argument name suggests sensitive data
                for kw in node.keywords:
                    arg_name = kw.arg
                    if arg_name:
                        # Check if argument name is sensitive (password, token, secret, etc.)
                        sensitive_pii = taint_tracker.infer_pii_type(arg_name)
                        # STRICT MODE: Only flag hardcoded credentials (passwords, tokens), not general PII like names
                        if sensitive_pii and 'password' in sensitive_pii:
                            # Now trace back: is the value a hardcoded string or variable?
                            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                                # Hardcoded string passed as password/secret - CRITICAL
                                secret_value = kw.value.value
                                if len(secret_value) > 3:  # Skip empty/placeholder values
                                    snippet = extract_ast_snippet(code, node.lineno, node.lineno)
                                    findings.append(Finding(
                                        rule="HARDCODED_CREDENTIAL_IN_CALL",
                                        file=str(file_path),
                                        line=node.lineno,
                                        snippet=snippet,
                                        severity=Severity.CRITICAL,
                                        classification=ClassificationResult(
                                            pii_types=sensitive_pii,
                                            sectors=['security', 'authentication'],
                                            severity='critical',
                                            article='Art. 32',
                                            legal_basis_required=True,
                                            category='credentials',
                                            confidence=0.98,
                                            reasoning=f"Hardcoded {sensitive_pii[0]} passed to function call"
                                        ),
                                        metadata={'description': f'Hardcoded credential in function call', 'param': arg_name}
                                    ))
                            elif isinstance(kw.value, ast.Name):
                                # Variable passed - check if it's tainted and trace origin
                                var_name = kw.value.id
                                taint_info = taint_tracker.get_taint_info(kw.value)
                                if taint_info and taint_info.taint_source and 'hardcoded_secret' in taint_info.taint_source:
                                    # Variable comes from hardcoded secret - report it
                                    snippet = extract_ast_snippet(code, node.lineno, node.lineno)
                                    findings.append(Finding(
                                        rule="HARDCODED_SECRET_PROPAGATION",
                                        file=str(file_path),
                                        line=node.lineno,
                                        snippet=snippet,
                                        severity=Severity.CRITICAL,
                                        classification=ClassificationResult(
                                            pii_types=sensitive_pii + ['credentials'],
                                            sectors=['security', 'authentication'],
                                            severity='critical',
                                            article='Art. 32',
                                            legal_basis_required=True,
                                            category='credentials',
                                            confidence=0.95,
                                            reasoning=f"Hardcoded secret variable '{var_name}' used in '{arg_name}' parameter"
                                        ),
                                        metadata={'description': 'Hardcoded secret propagated through variable', 'var': var_name, 'param': arg_name}
                                    ))
                
                # Extract tainted variables from call arguments
                tainted_args = []
                tainted_pii_types = []
                
                def extract_tainted_from_node(n):
                    if isinstance(n, ast.Name):
                        if taint_tracker.is_tainted(n):
                            tainted_args.append(n.id)
                            taint_info = taint_tracker.get_taint_info(n)
                            if taint_info:
                                tainted_pii_types.extend(taint_info.pii_types)
                    
                    elif isinstance(n, ast.JoinedStr):
                        for value in n.values:
                            if isinstance(value, ast.FormattedValue):
                                extract_tainted_from_node(value.value)
                    
                    elif isinstance(n, ast.Attribute):
                        if taint_tracker.is_tainted_attribute(n):
                            base_name = ""
                            if isinstance(n.value, ast.Name):
                                base_name = n.value.id
                            var_repr = f"{base_name}.{n.attr}" if base_name else n.attr
                            if var_repr not in tainted_args:
                                tainted_args.append(var_repr)
                            pii_types = taint_tracker.infer_pii_type(n.attr)
                            if pii_types:
                                tainted_pii_types.extend(pii_types)
                    
                    elif isinstance(n, ast.Dict):
                        for key, value in zip(n.keys, n.values):
                            if value:
                                extract_tainted_from_node(value)
                    
                    elif isinstance(n, (ast.List, ast.Tuple)):
                        for elt in n.elts:
                            extract_tainted_from_node(elt)
                    
                    else:
                        for child in ast.iter_child_nodes(n):
                            extract_tainted_from_node(child)
                
                for arg in node.args:
                    extract_tainted_from_node(arg)
                
                for kw in node.keywords:
                    extract_tainted_from_node(kw.value)
                
                # Check for print() calls with PII
                if isinstance(node.func, ast.Name) and node.func.id == "print":
                    self._handle_print_call(node, tainted_args, tainted_pii_types)
                
                # Analyze specific call types
                if isinstance(node.func, ast.Attribute):
                    self._analyze_attribute_call(
                        node, tainted_args, tainted_pii_types
                    )
                
                self.generic_visit(node)
            
            def _analyze_attribute_call(self, node, tainted_args, tainted_pii_types):
                """Analyze attribute-based calls (logging, requests, db)"""
                base = getattr(node.func.value, "id", None) or getattr(node.func.value, "attr", None)
                attr = node.func.attr
                
                # Logging calls
                if base in ("logging", "logger") and attr in ("info", "warning", "error", "debug", "exception", "critical"):
                    self._handle_logging_call(node, tainted_args, tainted_pii_types)
                
                # Network calls
                elif base in ("requests", "httpx") and attr in ("get", "post", "put", "patch", "delete", "request"):
                    self._handle_network_call(node, tainted_args, tainted_pii_types)
                
                # Database calls (generic - supports multiple ORMs)
                elif attr in get_db_write_methods():
                    self._handle_db_call(node, tainted_args, tainted_pii_types)
            
            def _handle_logging_call(self, node, tainted_args, tainted_pii_types):
                """Handle logging.* calls"""
                # STRICT MODE: Only report if arguments are tainted from a known source
                if not tainted_args:
                    return

                snip = extract_ast_snippet(code, node)
                
                if should_filter_log_finding(snip, f"logging call in {file_path}"):
                    return
                
                # Extract variable names from the AST node for precise classification
                variable_names = self._extract_variable_names(node)
                
                classification = classify_pii_enhanced(
                    snip, f"logging call in {file_path}",
                    variable_names=variable_names
                )
                
                # Boost confidence for tainted flows
                classification["confidence"] = max(classification["confidence"], 0.8)
                classification["pii_types"] = list(set(
                    classification["pii_types"] + tainted_pii_types
                ))
                if not classification["reasoning"]:
                    classification["reasoning"] = ""
                classification["reasoning"] += f" [TAINT: Variables {','.join(tainted_args)} contain {','.join(set(tainted_pii_types))}]"
                
                if classification["pii_types"] and classification["confidence"] > 0.2:
                    rule_id = "LOG_PII"
                    severity = classification["severity"]
                    
                    # Check GDPR articles (can be multiple)
                    gdpr_articles = classification.get("gdpr_articles", [])
                    if not gdpr_articles and classification.get("article"):
                        gdpr_articles = [classification["article"]]
                    
                    if "Art. 9" in gdpr_articles:
                        rule_id = "LOG_PII_ARTICLE9"
                        severity = "critical"
                    elif classification["pii_types"] and classification["pii_types"][0] in ("email", "token"):
                        rule_id = f"LOG_PII_{classification['pii_types'][0].upper()}"
                    elif tainted_args:
                        severity = "high" if severity == "medium" else severity
                    
                    finding = Finding(
                        rule=rule_id,
                        severity=Severity(severity),
                        file=str(file_path),
                        line=node.lineno,
                        snippet=snip,
                        classification=ClassificationResult(**classification),
                        data_flow_type="logging",
                        tainted_variables=tainted_args if tainted_args else [],
                        taint_sources=[
                            taint_tracker.tainted_vars[v].taint_source
                            for v in tainted_args
                            if v in taint_tracker.tainted_vars
                        ] if tainted_args else []
                    )
                    findings.append(finding)
            
            def _handle_print_call(self, node, tainted_args, tainted_pii_types):
                """Handle print() calls with PII (common anti-pattern)"""
                # STRICT MODE: Only report if arguments are tainted from a known source
                if not tainted_args:
                    return

                snip = extract_ast_snippet(code, node)
                
                if should_filter_log_finding(snip, f"print in {file_path}"):
                    return
                
                # Extract variable names from the AST node
                variable_names = self._extract_variable_names(node)
                
                # Check for PII patterns in the snippet
                classification = classify_pii_enhanced(
                    snip, f"print call in {file_path}",
                    variable_names=variable_names
                )
                
                # Boost confidence for tainted flows
                classification["confidence"] = max(classification["confidence"], 0.85)
                classification["pii_types"] = list(set(
                    classification["pii_types"] + tainted_pii_types
                ))
                if not classification["reasoning"]:
                    classification["reasoning"] = ""
                classification["reasoning"] += f" [TAINT: Variables {','.join(tainted_args)} contain PII: {','.join(set(tainted_pii_types))}]"
                
                # Only report if we found PII (lower threshold than logging)
                if classification["pii_types"] and classification["confidence"] > 0.2:
                    rule_id = "PRINT_PII"
                    severity = classification["severity"]
                    
                    # Check GDPR articles
                    gdpr_articles = classification.get("gdpr_articles", [])
                    if not gdpr_articles and classification.get("article"):
                        gdpr_articles = [classification["article"]]
                    
                    if "Art. 9" in gdpr_articles:
                        rule_id = "PRINT_PII_ARTICLE9"
                        severity = "critical"
                    elif tainted_args:
                        severity = "high" if severity == "medium" else severity
                    
                    finding = Finding(
                        rule=rule_id,
                        severity=Severity(severity),
                        file=str(file_path),
                        line=node.lineno,
                        snippet=snip,
                        classification=ClassificationResult(**classification),
                        data_flow_type="logging",
                        tainted_variables=tainted_args if tainted_args else [],
                        taint_sources=[
                            taint_tracker.tainted_vars[v].taint_source
                            for v in tainted_args
                            if v in taint_tracker.tainted_vars
                        ] if tainted_args else []
                    )
                    findings.append(finding)
            
            def _extract_variable_names(self, node):
                """Extract all variable/attribute names from an AST node"""
                names = []
                for child in ast.walk(node):
                    if isinstance(child, ast.Name):
                        names.append(child.id)
                    elif isinstance(child, ast.Attribute):
                        names.append(child.attr)
                return names
            
            def _handle_network_call(self, node, tainted_args, tainted_pii_types):
                """Handle requests.* / httpx.* calls"""
                from urllib.parse import urlparse
                
                snip = extract_ast_snippet(code, node)
                
                # Extract URL from first argument
                url = None
                if node.args and isinstance(node.args[0], ast.Constant):
                    url = node.args[0].value
                
                secure = (url or "").startswith("https://") if url else False
                dom = urlparse(url or "").netloc.lower() if url else ""
                
                # Extract variable names for precise classification
                variable_names = self._extract_variable_names(node)
                
                classification = classify_pii_enhanced(
                    snip, f"network call to {dom}",
                    variable_names=variable_names
                )
                
                # Boost confidence for tainted flows
                if tainted_args:
                    classification["confidence"] = max(classification["confidence"], 0.9)
                    classification["pii_types"] = list(set(
                        classification["pii_types"] + tainted_pii_types
                    ))
                    if not classification["reasoning"]:
                        classification["reasoning"] = ""
                    classification["reasoning"] += f" [TAINT: Sending {','.join(set(tainted_pii_types))} via {','.join(tainted_args)}]"
                
                # Add to flows
                flow_entry = {
                    "type": "network",
                    "library": getattr(node.func.value, "id", "unknown"),
                    "url": url or "",
                    "domain": dom,
                    "secure": secure,
                    "file": str(file_path),
                    "line": node.lineno,
                    "snippet": snip[:400],
                    "classification": classification,
                    "data_flow_type": "transmission",
                    "tainted_variables": tainted_args if tainted_args else []
                }
                flows.append(flow_entry)
                
                # Create finding for insecure HTTP
                if url and url.startswith("http://"):
                    finding = Finding(
                        rule="HTTP_PLAIN",
                        severity=Severity.CRITICAL if classification["severity"] != "low" else Severity.HIGH,
                        file=str(file_path),
                        line=node.lineno,
                        snippet=snip,
                        classification=ClassificationResult(**classification),
                        data_flow_type="transmission",
                        url=url,
                        tainted_variables=tainted_args if tainted_args else [],
                        taint_sources=[
                            taint_tracker.tainted_vars[v].taint_source
                            for v in tainted_args
                            if v in taint_tracker.tainted_vars
                        ] if tainted_args else []
                    )
                    findings.append(finding)
            
            def _extract_select_models(self, node):
                """Recursively extract model names from select() calls in an AST node"""
                models = []
                
                # Direct select(...) call
                if isinstance(node, ast.Call):
                    func_id = None
                    if isinstance(node.func, ast.Name):
                        func_id = node.func.id
                    elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
                        # Handle select(...).where(...) pattern - recurse into base
                        models.extend(self._extract_select_models(node.func.value))
                    
                    if func_id == 'select':
                        # Extract models from args
                        for arg in node.args:
                            if isinstance(arg, ast.Name):
                                models.append(arg.id)
                
                return models
            
            def _handle_db_call(self, node, tainted_args, tainted_pii_types):
                """Handle database write calls"""
                snip = extract_ast_snippet(code, node)
                
                if should_filter_db_finding(snip):
                    return
                
                # Phase 3: Deep extraction of tainted args from ORM objects
                # Example: db.add(User(email=user_email, name=user_name))
                # We need to extract 'user_email' and 'user_name' from the User(...) call
                additional_tainted = []
                additional_pii_types = []
                
                for arg in node.args:
                    if isinstance(arg, ast.Call):  # ORM object creation like User(...)
                        for kw in arg.keywords:  # Extract keyword arguments
                            var_name = None
                            is_tainted = False
                            
                            # Handle ast.Name (simple variable)
                            if isinstance(kw.value, ast.Name):
                                var_name = kw.value.id
                                is_tainted = taint_tracker.is_tainted(kw.value)
                            
                            # Handle ast.Attribute (object.attribute like user_data.email)
                            elif isinstance(kw.value, ast.Attribute):
                                if isinstance(kw.value.value, ast.Name):
                                    base = kw.value.value.id
                                    attr = kw.value.attr
                                    var_name = f"{base}.{attr}"
                                    is_tainted = taint_tracker.is_tainted_attribute(kw.value)
                                    # STRICT MODE: Removed attribute name inference
                                    # We only track if the attribute is actually tainted
                            
                            if is_tainted and var_name:
                                if var_name not in tainted_args:
                                    additional_tainted.append(var_name)
                                taint_info = taint_tracker.get_taint_info(kw.value)
                                if taint_info:
                                    additional_pii_types.extend(taint_info.pii_types)
                                # Track DB column mapping
                                db_column = kw.arg  # e.g., 'email' in User(email=...)
                                taint_tracker.db_column_mapping[db_column] = {
                                    'source_var': var_name,
                                    'pii_types': taint_info.pii_types if taint_info else taint_tracker.infer_pii_type(kw.arg),
                                    'table': arg.func.id if isinstance(arg.func, ast.Name) else 'unknown'
                                }
                    
                    # Phase 3: Case 2 - db.add(user) where user was created earlier
                    elif isinstance(arg, ast.Name):
                        obj_name = arg.id
                        # Check if this variable is tainted
                        if taint_tracker.is_tainted(arg):
                            if obj_name not in tainted_args:
                                additional_tainted.append(obj_name)
                            taint_info = taint_tracker.get_taint_info(arg)
                            if taint_info:
                                additional_pii_types.extend(taint_info.pii_types)
                        # STRICT MODE: Removed variable name inference (ORM pattern)
                        # We only track if the variable is actually tainted
                
                # Merge with existing tainted args
                all_tainted = tainted_args + additional_tainted
                all_pii_types = tainted_pii_types + additional_pii_types
                
                # Extract variable names for precise classification
                variable_names = self._extract_variable_names(node)
                
                classification = classify_pii_enhanced(
                    snip, f"database operation in {file_path}",
                    variable_names=variable_names
                )
                
                # Boost confidence for tainted flows
                if all_tainted:
                    classification["confidence"] = max(classification["confidence"], 0.85)
                    classification["pii_types"] = list(set(
                        classification["pii_types"] + all_pii_types
                    ))
                    if not classification["reasoning"]:
                        classification["reasoning"] = ""
                    classification["reasoning"] += f" [TAINT: Storing {','.join(set(all_pii_types))} from {','.join(all_tainted)}]"
                
                # STRICT MODE: Only report if we have confirmed taint
                if all_tainted:
                    rule_id = "DB_WRITE"
                    severity = classification["severity"] if classification["confidence"] > 0.3 else "info"
                    
                    # Check GDPR articles (can be multiple)
                    gdpr_articles = classification.get("gdpr_articles", [])
                    if not gdpr_articles and classification.get("article"):
                        gdpr_articles = [classification["article"]]
                    
                    if "Art. 9" in gdpr_articles:
                        rule_id = "DB_WRITE_ARTICLE9"
                        severity = "critical"
                    elif all_tainted:
                        severity = "high" if severity in ("medium", "info") else severity
                    
                    finding = Finding(
                        rule=rule_id,
                        severity=Severity(severity),
                        file=str(file_path),
                        line=node.lineno,
                        snippet=snip,
                        classification=ClassificationResult(**classification),
                        data_flow_type="storage",
                        tainted_variables=all_tainted if all_tainted else [],
                        taint_sources=[
                            taint_tracker.tainted_vars[v].taint_source
                            for v in all_tainted
                            if v in taint_tracker.tainted_vars
                        ] if all_tainted else []
                    )
                    findings.append(finding)
        
        return TaintAwareVisitor()
