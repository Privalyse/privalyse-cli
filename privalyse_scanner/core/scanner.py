"""Main scanner orchestration class"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

from ..models.config import ScanConfig
from ..models.finding import Finding
from ..models.graph import SemanticDataFlowGraph, GraphNode, GraphEdge
from ..models.taint import DataFlowEdge
from ..analyzers.python_analyzer import PythonAnalyzer
from ..analyzers.javascript_analyzer import JavaScriptAnalyzer
from ..analyzers.cross_file_analyzer import CrossFileAnalyzer
from ..analyzers.injection_analyzer import InjectionAnalyzer
from ..analyzers.crypto_analyzer import CryptoAnalyzer
from ..analyzers.security_analyzer import SecurityAnalyzer
from ..analyzers.infrastructure_analyzer import InfrastructureAnalyzer
from .file_iterator import FileIterator
from .import_resolver import ImportResolver
from .symbol_table import GlobalSymbolTable, SymbolType
from ..utils.compliance_mapper import map_finding_to_compliance
from .score_recommendation import get_score_recommendation


logger = logging.getLogger(__name__)


class PrivalyseScanner:
    """
    Main scanner class that orchestrates privacy and GDPR compliance scanning
    """
    
    def __init__(self, config: Optional[ScanConfig] = None):
        """
        Initialize scanner with configuration
        
        Args:
            config: Scanner configuration (uses defaults if None)
        """
        self.config = config or ScanConfig()
        self.python_analyzer = PythonAnalyzer()
        self.javascript_analyzer = JavaScriptAnalyzer()
        # Advanced security analyzers
        # DISABLED: InjectionAnalyzer, CryptoAnalyzer, SecurityAnalyzer, InfrastructureAnalyzer
        # Reason: Focus strictly on PII and GDPR compliance, removing generic security noise.
        self.injection_analyzer = None # InjectionAnalyzer()
        self.crypto_analyzer = None # CryptoAnalyzer()
        self.security_analyzer = None # SecurityAnalyzer()
        self.infrastructure_analyzer = None # InfrastructureAnalyzer()
        
        # Import resolution for cross-file analysis
        self.import_resolver = ImportResolver(root_path=self.config.root_path)
        # Global symbol table for function/class tracking
        self.symbol_table = GlobalSymbolTable()
        # Cross-file taint propagation analyzer
        self.cross_file_analyzer = None  # Initialized after import/symbol analysis
        
        # Semantic Data Flow Graph
        self.graph = SemanticDataFlowGraph()
        
        # Load ignore list
        self.ignore_list = self._load_ignore_list()
    
    def _load_ignore_list(self) -> List[str]:
        """Load .privalyseignore patterns"""
        ignore_list = []
        ignore_file = self.config.root_path / '.privalyseignore' if self.config.root_path else Path('.privalyseignore')
        
        if ignore_file.exists():
            try:
                with open(ignore_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            ignore_list.append(line)
                logger.info(f"Loaded {len(ignore_list)} ignore patterns from .privalyseignore")
            except Exception as e:
                logger.warning(f"Failed to load .privalyseignore: {e}")
        
        return ignore_list

    def _should_ignore(self, finding: Finding) -> bool:
        """Check if finding should be ignored based on .privalyseignore"""
        import fnmatch
        
        # Check against ignore patterns
        # Patterns can be:
        # - rule_id (e.g. HARDCODED_SECRET)
        # - file path (e.g. tests/*)
        # - rule_id:file_path (e.g. HARDCODED_SECRET:tests/*)
        
        for pattern in self.ignore_list:
            if ':' in pattern:
                rule_pattern, file_pattern = pattern.split(':', 1)
                if (fnmatch.fnmatch(finding.rule, rule_pattern) and 
                    fnmatch.fnmatch(finding.file, file_pattern)):
                    return True
            else:
                # Check if pattern matches rule OR file
                if fnmatch.fnmatch(finding.rule, pattern) or fnmatch.fnmatch(finding.file, pattern):
                    return True
                if fnmatch.fnmatch(finding.file, pattern):
                    return True
                    
        return False

    def scan(self, root_path: Optional[Path] = None) -> Dict[str, Any]:
        """
        Scan a directory tree for privacy issues
        
        Args:
            root_path: Root directory to scan (uses config if None)
        
        Returns:
            Dictionary with findings, flows, and metadata
        """
        if root_path:
            self.config.root_path = Path(root_path)
        
        logger.info(f"Starting scan of {self.config.root_path}")
        
        # Find files to scan
        file_iterator = FileIterator(self.config)
        files = list(file_iterator.iter_files())
        
        logger.info(f"Found {len(files)} files to scan")
        
        # Collect findings and flows
        all_findings: List[Finding] = []
        all_flows: List[Dict[str, Any]] = []
        
        # Extract constants and env variables (simplified for now)
        consts = {}
        envmap = {}
        
        # Build import dependency graph FIRST (needed for cross-file analysis)
        logger.info("Building import dependency graph...")
        for file_path in files:
            analyzer = None
            if file_path.suffix in self.config.python_extensions:
                analyzer = self.python_analyzer
            elif file_path.suffix in {'.js', '.jsx', '.ts', '.tsx'}:
                analyzer = self.javascript_analyzer
            
            if analyzer:
                try:
                    module_info = self.import_resolver.analyze_module(file_path, analyzer)
                    # Register symbols from each module
                    self.symbol_table.register_module(file_path, module_info.package, analyzer)
                except Exception as e:
                    logger.warning(f"Error analyzing imports in {file_path}: {e}")
        
        dependency_graph = self.import_resolver.build_dependency_graph()
        logger.info(f"Analyzed {len(dependency_graph)} modules with imports")
        logger.info(f"Registered {len(self.symbol_table.symbols)} unique symbols")
        
        # Initialize cross-file analyzer
        self.cross_file_analyzer = CrossFileAnalyzer(self.import_resolver, self.symbol_table)
        logger.info("Initialized cross-file taint propagation")
        
        # Connect cross-file analyzer to python analyzer
        self.python_analyzer.cross_file_analyzer = self.cross_file_analyzer
        self.javascript_analyzer.cross_file_analyzer = self.cross_file_analyzer
        
        # Track module contexts for cross-file analysis
        module_taint_trackers = {}  # module_name -> TaintTracker
        module_findings = {}  # module_name -> List[Finding]
        
        logger.info(f"🔍 STARTING MAIN SCAN LOOP - {len(files)} files to process")
        
        # Scan each file
        for file_path in files:
            logger.debug(f"  Processing file: {file_path}")
            try:
                code = file_path.read_text(encoding='utf-8', errors='ignore')
                logger.debug(f"    Read {len(code)} bytes")
                logger.debug(f"    Suffix: '{file_path.suffix}' | Python exts: {self.config.python_extensions}")
                
                if file_path.suffix in self.config.python_extensions:
                    logger.debug(f"    Detected Python file: {file_path.name}")
                    # Set current module in analyzer for cross-file context
                    module_name = self.import_resolver._path_to_package_name(file_path)
                    self.python_analyzer.current_module = module_name
                    
                    logger.info(f"Analyzing Python file: {file_path.name}")
                    
                    findings, flows = self.python_analyzer.analyze_file(
                        file_path, code, consts=consts, envmap=envmap
                    )
                    
                    # ===== POPULATE GRAPH =====
                    self._populate_graph(file_path, flows)
                    
                    if self.config.verbose:
                        logger.info(f"  → {len(findings)} findings in {file_path.name}")
                    
                    logger.debug(f"  Python analyzer: {len(findings)} findings")
                    
                    # Run advanced security analyzers
                    # Pass taint tracker for data flow context
                    taint_tracker = getattr(self.python_analyzer, 'taint_tracker', None)
                    
                    if self.injection_analyzer:
                        logger.debug(f"  Running injection analyzer...")
                        injection_findings = self.injection_analyzer.analyze_file(file_path, code, taint_tracker)
                        logger.debug(f"  Injection: {len(injection_findings)} findings")
                        findings.extend(injection_findings)
                    
                    if self.crypto_analyzer:
                        logger.debug(f"  Running crypto analyzer...")
                        crypto_findings = self.crypto_analyzer.analyze_file(file_path, code)
                        logger.debug(f"  Crypto: {len(crypto_findings)} findings")
                        findings.extend(crypto_findings)
                    
                    if self.security_analyzer:
                        logger.debug(f"  Running security analyzer (cookies, headers)...")
                        security_findings = self.security_analyzer.analyze_file(file_path, code)
                        logger.debug(f"  Security: {len(security_findings)} findings")
                        findings.extend(security_findings)

                    logger.debug(f"  Total after security analyzers: {len(findings)} findings")
                    
                    # Register module context for cross-file analysis
                    if hasattr(self.python_analyzer, 'taint_tracker') and self.python_analyzer.taint_tracker:
                        self.cross_file_analyzer.register_module_context(
                            module_name, 
                            file_path, 
                            self.python_analyzer.taint_tracker
                        )
                        module_taint_trackers[module_name] = self.python_analyzer.taint_tracker
                    
                    # Store findings AFTER adding security findings
                    module_findings[module_name] = findings
                    all_findings.extend(findings)
                    all_flows.extend(flows)
                
                elif file_path.suffix in {'.js', '.jsx', '.ts', '.tsx'}:
                    # Analyze JavaScript/TypeScript files
                    logger.info(f"Analyzing JavaScript/TypeScript file: {file_path.name}")
                    
                    # Calculate module name for JS
                    module_name = self.import_resolver._path_to_package_name(file_path)
                    
                    findings, flows = self.javascript_analyzer.analyze_file(
                        file_path, code, consts, envmap, module_name=module_name
                    )
                    
                    # ===== POPULATE GRAPH =====
                    self._populate_graph(file_path, flows)
                    
                    if self.config.verbose:
                        logger.info(f"  → {len(findings)} findings in {file_path.name}")
                    
                    # Store JavaScript findings separately (they don't have module context for cross-file analysis)
                    # module_name is already set by import_resolver.register_module above
                    module_findings[module_name] = findings
                    
                    # Register module context for cross-file analysis (JS support)
                    if hasattr(self.javascript_analyzer, 'taint_tracker') and self.javascript_analyzer.taint_tracker:
                        self.cross_file_analyzer.register_module_context(
                            module_name, 
                            file_path, 
                            self.javascript_analyzer.taint_tracker
                        )
                        module_taint_trackers[module_name] = self.javascript_analyzer.taint_tracker
                    all_findings.extend(findings)
                    all_flows.extend(flows)

                elif file_path.name in self.config.docker_files or file_path.suffix in self.config.config_extensions:
                    # Analyze Infrastructure files
                    # DISABLED: Infrastructure analysis for PII-only focus
                    pass
                    # logger.info(f"Analyzing Infrastructure file: {file_path.name}")
                    # findings = self.infrastructure_analyzer.analyze_file(file_path, code)
                    
                    # if self.config.verbose:
                    #     logger.info(f"  → {len(findings)} findings in {file_path.name}")
                    
                    # # Store findings
                    # module_name = f"infra:{file_path.name}"
                    # module_findings[module_name] = findings
                    # all_findings.extend(findings)
                    # # No data flows for infra files usually
                
            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")
                continue
        
        # Link network flows (JS -> Python)
        self.graph.link_network_flows()
        
        # Populate structure graph (Functions, Classes)
        self._populate_structure_graph()
        
        logger.info(f"Initial scan completed: {len(all_findings)} findings")
        
        # Propagate taint across modules
        logger.info("Propagating taint across module boundaries...")
        self.cross_file_analyzer.propagate_taint_across_all_modules()
        
        # Re-analyze files with cross-file taint context (second pass)
        logger.info("Applying symbol table PII intelligence...")
        additional_tainted = 0
        
        # Use symbol table to identify functions that handle PII or perform sensitive operations
        pii_functions = self.symbol_table.find_functions_with_pii_params()
        pii_func_names = {name.split('.')[-1] for name, _ in pii_functions}
        
        # Also include all sensitive functions (logging, db, network)
        sensitive_func_names = {name.split('.')[-1] for name in self.symbol_table.sensitive_functions}
        
        all_sensitive_names = pii_func_names | sensitive_func_names
        logger.info(f"Found {len(pii_func_names)} PII functions + {len(sensitive_func_names)} sensitive operations = {len(all_sensitive_names)} total")
        
        for module_name, findings_list in module_findings.items():
            for finding in findings_list:
                if not finding.tainted_variables:
                    # Get snippet from finding
                    snippet = getattr(finding, 'snippet', '') or getattr(finding, 'code_snippet', '')
                    if snippet:
                        # Check if finding involves a sensitive function
                        for func_name in all_sensitive_names:
                            if func_name in snippet and len(func_name) > 3:  # Avoid false matches on short names
                                # This finding involves a sensitive function - mark as tainted
                                finding.tainted_variables = [func_name]
                                finding.metadata['cross_file_taint'] = True
                                finding.metadata['sensitive_function'] = func_name
                                finding.metadata['taint_source'] = 'symbol_table_analysis'
                                additional_tainted += 1
                                break
        
        logger.info(f"Added taint metadata to {additional_tainted} findings via symbol table")
        
        # Enhance findings with cross-file taint information
        enhanced_findings = []
        for module_name, findings in module_findings.items():
            enhanced = self.cross_file_analyzer.enhance_findings_with_cross_file_taint(
                findings, module_name
            )
            enhanced_findings.extend(enhanced)
        
        # Count findings with taint data (before and after enhancement)
        initial_tainted = sum(1 for f in all_findings if f.tainted_variables)
        enhanced_tainted = sum(1 for f in enhanced_findings if f.tainted_variables)
        
        logger.info(f"Taint enhancement: {initial_tainted} -> {enhanced_tainted} findings with taint data")
        logger.info(f"Scan completed: {len(enhanced_findings)} findings")
        
        # Use enhanced findings
        all_findings = enhanced_findings
        
        # Filter ignored findings
        all_findings = [f for f in all_findings if not self._should_ignore(f)]
        
        # Map findings to compliance data (GDPR articles, PII types, TOMs)
        findings_with_compliance = []
        for finding in all_findings:
            finding_dict = finding.to_dict()
            compliance_data = map_finding_to_compliance(finding_dict, finding.rule)
            finding_dict['compliance_mapping'] = compliance_data
            findings_with_compliance.append(finding_dict)
        
        # Build result
        return {
            "findings": findings_with_compliance,
            "flows": all_flows,
            "meta": {
                "files_scanned": len(files),
                "total_findings": len(all_findings),
                "root_path": str(self.config.root_path),
                "modules_analyzed": len(dependency_graph),
                "import_relationships": sum(len(deps) for deps in dependency_graph.values()),
                "symbols_registered": len(self.symbol_table.symbols),
                "sensitive_functions": len(self.symbol_table.sensitive_functions),
                "taint_coverage_initial": initial_tainted,
                "taint_coverage_enhanced": enhanced_tainted,
                "taint_coverage_improvement": f"{((enhanced_tainted - initial_tainted) / max(1, initial_tainted)) * 100:.1f}%",
            },
            "compliance": self._calculate_compliance(all_findings),
            "dependency_graph": dependency_graph,  # Include graph in results
            "semantic_graph": self.graph.to_dict(),
        }
    
    def _calculate_compliance(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Calculate GDPR compliance score with nuanced scoring algorithm
        
        Scoring Philosophy:
        - Base score: 100 points
        - Exponential decay prevents instant 0 score
        - GDPR Article 9 (special category data) has heavy penalty
        - Context-aware: hardcoded secrets worse than logging
        - Provides actionable feedback on what to fix first
        """
        if not findings:
            return {"score": 100.0, "status": "compliant", "critical_findings": 0, "high_findings": 0}
        
        # Enhanced severity weights with GDPR context
        base_weights = {
            "critical": 15,  # Reduced from 20 to allow more nuance
            "high": 8,       # Reduced from 10
            "medium": 3,     # Reduced from 5
            "low": 1,        # Reduced from 2
            "info": 0,
        }
        
        # Category multipliers for GDPR compliance
        category_multipliers = {
            "Art. 9": 2.0,   # Special category data (health, biometric, etc.)
            "Art. 8": 1.5,   # Children's data
            "Art. 32": 1.3,  # Security measures (passwords, encryption)
            "Art. 6": 1.0,   # Regular personal data
        }
        
        # Rule-specific adjustments
        rule_severity_boost = {
            "HARDCODED_SECRET": 1.5,          # Extremely dangerous
            "HARDCODED_CREDENTIAL_IN_CALL": 1.5,
            "PLAINTEXT_PASSWORD_STORAGE": 1.4,
            "HTTP_NOT_HTTPS": 1.2,
            "LOG_PII": 0.9,                   # Less critical than storage issues
            "THIRD_PARTY_SHARING": 1.3,       # Cross-border concerns
        }
        
        total_penalty = 0.0
        findings_by_category = {}
        
        for finding in findings:
            severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            base_penalty = base_weights.get(severity, 0)
            
            # Skip info findings in score calculation
            if base_penalty == 0:
                continue
            
            # Apply GDPR article multiplier
            article = finding.classification.article if finding.classification else None
            article_multiplier = 1.0
            if article:
                # Check for Article 9 or 32 etc.
                for gdpr_article, multiplier in category_multipliers.items():
                    if article.startswith(gdpr_article):
                        article_multiplier = multiplier
                        break
            
            # Apply rule-specific adjustments
            rule = finding.rule
            rule_multiplier = rule_severity_boost.get(rule, 1.0)
            
            # Calculate final penalty for this finding
            finding_penalty = base_penalty * article_multiplier * rule_multiplier
            total_penalty += finding_penalty
            
            # Track by category for reporting
            category = article or "General"
            if category not in findings_by_category:
                findings_by_category[category] = {"count": 0, "penalty": 0}
            findings_by_category[category]["count"] += 1
            findings_by_category[category]["penalty"] += finding_penalty
        
        # Exponential decay scoring (prevents instant 0)
        # Formula: 100 * e^(-penalty/scale)
        # Scale determines how fast score drops (higher = more forgiving)
        scale = 50  # Tuned so 50 penalty points ≈ 37/100 score
        score = 100 * (2.71828 ** (-total_penalty / scale))
        
        # Apply floor: minimum 5% for having some findings
        if findings and score < 5:
            score = 5.0
        
        # Round to 1 decimal
        score = round(score, 1)
        
        # Determine status with more granular thresholds
        if score >= 90:
            status = "compliant"
            risk_level = "low"
        elif score >= 75:
            status = "good"
            risk_level = "low"
        elif score >= 60:
            status = "needs_attention"
            risk_level = "medium"
        elif score >= 40:
            status = "critical"
            risk_level = "high"
        else:
            status = "severe"
            risk_level = "critical"
        
        # Count findings by severity (handle both string and enum)
        critical_count = 0
        high_count = 0
        medium_count = 0
        
        for f in findings:
            severity_str = str(f.severity).lower()
            if 'critical' in severity_str:
                critical_count += 1
            elif 'high' in severity_str:
                high_count += 1
            elif 'medium' in severity_str:
                medium_count += 1
        
        return {
            "score": score,
            "status": status,
            "risk_level": risk_level,
            "critical_findings": critical_count,
            "high_findings": high_count,
            "medium_findings": medium_count,
            "total_penalty": round(total_penalty, 2),
            "findings_by_category": findings_by_category,
            "recommendation": get_score_recommendation(score, critical_count, high_count)
        }

    def _populate_structure_graph(self):
        """Populate the graph with structural elements (functions, classes) from the symbol table."""
        logger.info("Populating graph with code structure...")
        
        # Add nodes for all symbols
        for symbol_name, symbol_list in self.symbol_table.symbols.items():
            for symbol in symbol_list:
                # Determine file ID (should match what _populate_graph uses)
                try:
                    file_id = str(symbol.file_path.relative_to(self.config.root_path)) if self.config.root_path else symbol.file_path.name
                except ValueError:
                    file_id = symbol.file_path.name
                
                # Create node ID
                node_id = f"{file_id}:{symbol.location[0]}:{symbol.name}"
                
                # Determine type and icon
                node_type = "function"
                if symbol.symbol_type == SymbolType.CLASS:
                    node_type = "class"
                elif symbol.symbol_type == SymbolType.VARIABLE:
                    node_type = "variable"
                
                # Add node
                self.graph.add_node(GraphNode(
                    id=node_id,
                    type=node_type,
                    label=symbol.name,
                    file_path=str(symbol.file_path),
                    line_number=symbol.location[0],
                    metadata={
                        "module": symbol.module,
                        "pii_related": bool(symbol.function_signature and symbol.function_signature.returns_pii)
                    }
                ))
                
                # Link to file node
                # Note: File node should already exist from _populate_graph, but if not, we might need to add it.
                # _populate_graph adds file node with ID = file_id
                
                # Check if file node exists, if not add it
                if file_id not in self.graph.nodes:
                    self.graph.add_node(GraphNode(
                        id=file_id,
                        type="file",
                        label=symbol.file_path.name,
                        file_path=str(symbol.file_path)
                    ))
                
                # Add containment edge (File -> Symbol)
                self.graph.add_edge(GraphEdge(
                    source_id=file_id,
                    target_id=node_id,
                    type="contains",
                    label="defines"
                ))

    def _populate_graph(self, file_path: Path, flows: List[DataFlowEdge]):
        """Populate the semantic graph with flows from a file."""
        try:
            file_id = str(file_path.relative_to(self.config.root_path)) if self.config.root_path else file_path.name
        except ValueError:
            file_id = file_path.name
            
        self.graph.add_node(GraphNode(
            id=file_id,
            type="file",
            label=file_path.name,
            file_path=str(file_path)
        ))
        
        for flow in flows:
            # Determine node types
            source_type = "variable"
            source_label = flow.source_var
            if flow.source_var.startswith("SOURCE:"):
                source_type = "source"
                source_label = flow.source_var.replace("SOURCE:", "")
            elif flow.source_var in ("logging", "print"):
                source_type = "sink"
                
            target_type = "variable"
            target_label = flow.target_var
            if flow.target_var in ("logging", "print") or "axios" in flow.target_var or "fetch" in flow.target_var:
                target_type = "sink"
            
            # Create nodes for source and target vars
            source_id = f"{file_id}:{flow.source_line}:{flow.source_var}"
            target_id = f"{file_id}:{flow.target_line}:{flow.target_var}"
            
            # Extract metadata from context
            node_metadata = {"context": flow.context}
            if flow.context:
                # Parse key-value pairs from context (e.g. "URL: /api/users, Route: /users")
                parts = [p.strip() for p in flow.context.split(',')]
                for part in parts:
                    if part.startswith("URL: "):
                        node_metadata['url'] = part.replace("URL: ", "").strip()
                    elif part.startswith("Route: "):
                        node_metadata['route'] = part.replace("Route: ", "").strip()
            
            self.graph.add_node(GraphNode(
                id=source_id, 
                type=source_type, 
                label=source_label, 
                file_path=str(file_path), 
                line_number=flow.source_line,
                metadata=node_metadata
            ))
            
            self.graph.add_node(GraphNode(
                id=target_id, 
                type=target_type, 
                label=target_label, 
                file_path=str(file_path), 
                line_number=flow.target_line,
                metadata=node_metadata
            ))
            
            self.graph.add_edge(GraphEdge(
                source_id=source_id,
                target_id=target_id,
                type="data_flow",
                label=flow.flow_type,
                metadata={"transformation": flow.transformation}
            ))
