"""Main scanner orchestration class"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
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
from .route_resolver import RouteResolver
from ..utils.compliance_mapper import map_finding_to_compliance
from .score_recommendation import get_score_recommendation
from .sink_resolver import SinkResolver


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
        
        # Sink Resolver for Data Sovereignty
        self.sink_resolver = SinkResolver()
        
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
        
        # 1. Discover files
        files = self._discover_files()
        
        # 2. Build dependency graph & Initialize symbols
        dependency_graph = self._build_dependency_graph(files)
        
        # 3. Initialize cross-file analyzer
        self._initialize_cross_file_analyzer()
        
        # 4. Analyze files (Single pass)
        all_findings, all_flows, module_findings = self._analyze_files(files)
        
        # 5. Resolve network routes (Frontend -> Backend)
        self._resolve_cross_file_routes()
        
        # 6. Populate structure graph
        self._populate_structure_graph()
        
        # 7. Propagate taint (Cross-module & Cross-network)
        enhanced_findings = self._propagate_taint(all_findings, module_findings)
        
        # 8. Post-process (Compliance mapping, filtering)
        result = self._post_process_results(enhanced_findings, all_flows, dependency_graph, files)
        
        return result

    def _discover_files(self) -> List[Path]:
        """Discover all files to be scanned."""
        file_iterator = FileIterator(self.config)
        files = list(file_iterator.iter_files())
        logger.info(f"Found {len(files)} files to scan")
        return files

    def _build_dependency_graph(self, files: List[Path]) -> Dict[str, Any]:
        """Build import dependency graph and register symbols."""
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
        return dependency_graph

    def _initialize_cross_file_analyzer(self):
        """Initialize the cross-file analyzer and connect it to language analyzers."""
        self.cross_file_analyzer = CrossFileAnalyzer(self.import_resolver, self.symbol_table)
        logger.info("Initialized cross-file taint propagation")
        
        # Connect cross-file analyzer to python analyzer
        self.python_analyzer.cross_file_analyzer = self.cross_file_analyzer
        self.javascript_analyzer.cross_file_analyzer = self.cross_file_analyzer

    def _analyze_files(self, files: List[Path]) -> Tuple[List[Finding], List[Dict[str, Any]], Dict[str, List[Finding]]]:
        """
        Analyze all files using appropriate analyzers.
        Returns: (all_findings, all_flows, module_findings)
        """
        all_findings: List[Finding] = []
        all_flows: List[Dict[str, Any]] = []
        module_findings: Dict[str, List[Finding]] = {}
        
        # Extract constants and env variables (simplified for now)
        consts = {}
        envmap = {}
        
        logger.info(f"🔍 STARTING MAIN SCAN LOOP - {len(files)} files to process")
        
        for file_path in files:
            logger.debug(f"  Processing file: {file_path}")
            try:
                code = file_path.read_text(encoding='utf-8', errors='ignore')
                
                findings = []
                flows = []
                module_name = ""
                
                if file_path.suffix in self.config.python_extensions:
                    module_name = self.import_resolver._path_to_package_name(file_path)
                    self.python_analyzer.current_module = module_name
                    
                    logger.info(f"Analyzing Python file: {file_path.name}")
                    findings, flows = self.python_analyzer.analyze_file(
                        file_path, code, consts=consts, envmap=envmap
                    )
                    
                    # Run advanced security analyzers
                    taint_tracker = getattr(self.python_analyzer, 'taint_tracker', None)
                    if self.injection_analyzer:
                        findings.extend(self.injection_analyzer.analyze_file(file_path, code, taint_tracker))
                    if self.crypto_analyzer:
                        findings.extend(self.crypto_analyzer.analyze_file(file_path, code))
                    if self.security_analyzer:
                        findings.extend(self.security_analyzer.analyze_file(file_path, code))
                    
                    # Register module context
                    if taint_tracker:
                        self.cross_file_analyzer.register_module_context(module_name, file_path, taint_tracker)

                elif file_path.suffix in {'.js', '.jsx', '.ts', '.tsx'}:
                    logger.info(f"Analyzing JavaScript/TypeScript file: {file_path.name}")
                    module_name = self.import_resolver._path_to_package_name(file_path)
                    
                    findings, flows = self.javascript_analyzer.analyze_file(
                        file_path, code, consts, envmap, module_name=module_name
                    )
                    
                    # Register module context
                    taint_tracker = getattr(self.javascript_analyzer, 'taint_tracker', None)
                    if taint_tracker:
                        self.cross_file_analyzer.register_module_context(module_name, file_path, taint_tracker)
                
                else:
                    continue

                # Common processing
                self._populate_graph(file_path, flows)
                
                if module_name:
                    module_findings[module_name] = findings
                
                all_findings.extend(findings)
                all_flows.extend(flows)
                
            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")
                continue
                
        return all_findings, all_flows, module_findings

    def _resolve_cross_file_routes(self):
        """Resolve network routes between frontend and backend."""
        resolver = RouteResolver(self.graph)
        links = resolver.resolve_routes()
        logger.info(f"Linked {links} cross-stack network flows")

    def _enrich_findings_with_sink_info(self, findings: List[Finding]) -> List[Finding]:
        """
        Enrich findings with Sink Intelligence (Data Sovereignty).
        Checks if findings contain URLs that match known sinks.
        """
        enriched_count = 0
        for finding in findings:
            # Check snippet for URLs
            # This is a simple heuristic. Ideally, we'd use the AST or Taint Sink info.
            snippet = finding.snippet
            if not snippet:
                continue
                
            # Simple regex to find URLs in snippet
            import re
            urls = re.findall(r'https?://[^\s"\']+', snippet)
            
            for url in urls:
                sink_info = self.sink_resolver.resolve(url)
                if sink_info:
                    # Add to metadata
                    if 'sink_intelligence' not in finding.metadata:
                        finding.metadata['sink_intelligence'] = []
                    
                    finding.metadata['sink_intelligence'].append({
                        "url": url,
                        "provider": sink_info.provider,
                        "country": sink_info.country,
                        "category": sink_info.category,
                        "gdpr_risk": sink_info.gdpr_risk,
                        "notes": sink_info.notes
                    })
                    
                    # Update finding description or classification if needed
                    if sink_info.gdpr_risk == 'high':
                        finding.severity = 'high' # Elevate risk
                        finding.classification.reasoning += f" [Data Sovereignty Risk: Data sent to {sink_info.provider} ({sink_info.country})]"
                    
                    # ===== POLICY ENFORCEMENT =====
                    policy = self.config.policy
                    
                    # 1. Check Blocked Countries
                    if not policy.is_country_allowed(sink_info.country):
                        finding.severity = 'critical'
                        finding.classification.severity = 'critical'
                        finding.classification.reasoning += f" [POLICY VIOLATION: Country {sink_info.country} is blocked]"
                        finding.rule = "POLICY_VIOLATION_COUNTRY"
                    
                    # 2. Check Blocked Providers
                    if not policy.is_provider_allowed(sink_info.provider):
                        finding.severity = 'critical'
                        finding.classification.severity = 'critical'
                        finding.classification.reasoning += f" [POLICY VIOLATION: Provider {sink_info.provider} is blocked]"
                        finding.rule = "POLICY_VIOLATION_PROVIDER"

                    enriched_count += 1
        
        if enriched_count > 0:
            logger.info(f"Enriched {enriched_count} findings with Sink Intelligence")
            
        return findings

    def _propagate_taint(self, all_findings: List[Finding], module_findings: Dict[str, List[Finding]]) -> List[Finding]:
        """Propagate taint across modules and network boundaries."""
        logger.info("Propagating taint across module boundaries...")
        self.cross_file_analyzer.propagate_taint_across_all_modules()
        
        # NEW: Propagate taint across network boundaries
        self._propagate_network_taint()
        
        logger.info("Applying symbol table PII intelligence...")
        additional_tainted = 0
        
        # Use symbol table to identify functions that handle PII
        pii_functions = self.symbol_table.find_functions_with_pii_params()
        pii_func_names = {name.split('.')[-1] for name, _ in pii_functions}
        sensitive_func_names = {name.split('.')[-1] for name in self.symbol_table.sensitive_functions}
        all_sensitive_names = pii_func_names | sensitive_func_names
        
        for findings_list in module_findings.values():
            for finding in findings_list:
                if not finding.tainted_variables:
                    snippet = getattr(finding, 'snippet', '') or getattr(finding, 'code_snippet', '')
                    if snippet:
                        for func_name in all_sensitive_names:
                            if func_name in snippet and len(func_name) > 3:
                                finding.tainted_variables = [func_name]
                                finding.metadata['cross_file_taint'] = True
                                finding.metadata['sensitive_function'] = func_name
                                finding.metadata['taint_source'] = 'symbol_table_analysis'
                                additional_tainted += 1
                                break
        
        logger.info(f"Added taint metadata to {additional_tainted} findings via symbol table")
        
        # Enhance findings
        enhanced_findings = []
        for module_name, findings in module_findings.items():
            enhanced = self.cross_file_analyzer.enhance_findings_with_cross_file_taint(
                findings, module_name
            )
            enhanced_findings.extend(enhanced)
            
        # NEW: Enrich with Sink Intelligence
        enhanced_findings = self._enrich_findings_with_sink_info(enhanced_findings)
            
        return enhanced_findings

    def _propagate_network_taint(self):
        """
        Propagate taint across network edges (Frontend -> Backend).
        Uses the graph edges created by RouteResolver.
        """
        logger.info("Propagating taint across network boundaries...")
        network_edges = [e for e in self.graph.edges if e.type == 'network_flow']
        
        count = 0
        for edge in network_edges:
            # Source: Frontend call (e.g. fetch)
            # Target: Backend route (e.g. api_handler)
            
            source_node = self.graph.nodes.get(edge.source_id)
            target_node = self.graph.nodes.get(edge.target_id)
            
            if not source_node or not target_node:
                continue
                
            # Check if source node involves tainted data
            # We need to find the module context for the source file
            source_file = Path(source_node.file_path)
            source_module = self.import_resolver._path_to_package_name(source_file)
            
            source_context = self.cross_file_analyzer.module_contexts.get(source_module)
            if not source_context:
                continue
                
            # Check if the variable used in the source node is tainted
            # The node label is often the variable name
            var_name = source_node.label
            taint_info = source_context.local_taint.get_taint(var_name)
            
            if taint_info:
                # Propagate to target
                target_file = Path(target_node.file_path)
                target_module = self.import_resolver._path_to_package_name(target_file)
                target_context = self.cross_file_analyzer.module_contexts.get(target_module)
                
                if target_context:
                    # Mark the target route handler's input as tainted
                    # Usually the target node label is the function name or 'request'
                    target_var = target_node.label
                    
                    logger.info(f"🔥 Network Taint Propagation: {source_module}.{var_name} -> {target_module}.{target_var}")
                    
                    # Create a new taint info for the target
                    from ..models.taint import TaintInfo
                    new_taint = TaintInfo(
                        source=f"Network:{source_module}.{var_name}",
                        source_type="network_propagation",
                        line_number=target_node.line_number
                    )
                    target_context.local_taint.add_taint(target_var, new_taint)
                    count += 1
        
        logger.info(f"Propagated taint across {count} network boundaries")

    def _post_process_results(self, findings: List[Finding], flows: List[Dict[str, Any]], 
                             dependency_graph: Dict[str, Any], files: List[Path]) -> Dict[str, Any]:
        """Format and filter results."""
        # Filter ignored findings
        filtered_findings = [f for f in findings if not self._should_ignore(f)]
        
        # Map to compliance
        findings_with_compliance = []
        for finding in filtered_findings:
            finding_dict = finding.to_dict()
            compliance_data = map_finding_to_compliance(finding_dict, finding.rule)
            finding_dict['compliance_mapping'] = compliance_data
            findings_with_compliance.append(finding_dict)
            
        # Calculate stats
        initial_tainted = sum(1 for f in findings if f.tainted_variables) # Approximation
        
        return {
            "findings": findings_with_compliance,
            "flows": flows,
            "meta": {
                "files_scanned": len(files),
                "total_findings": len(filtered_findings),
                "root_path": str(self.config.root_path),
                "modules_analyzed": len(dependency_graph),
                "import_relationships": sum(len(deps) for deps in dependency_graph.values()),
                "symbols_registered": len(self.symbol_table.symbols),
                "sensitive_functions": len(self.symbol_table.sensitive_functions),
            },
            "compliance": self._calculate_compliance(filtered_findings),
            "dependency_graph": dependency_graph,
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
        """
        Populate the semantic graph with flows from a file.
        Implements 'Serum' filtering: Only keeps flows related to AI Sinks or Critical Data Leaks.
        """
        try:
            file_id = file_path.relative_to(self.config.root_path).as_posix() if self.config.root_path else file_path.name
        except ValueError:
            file_id = file_path.name
            
        # Filter flows: Keep only if they are part of a chain leading to a Sink
        # or involve critical PII.
        # For now, we add all, but mark them.
        
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
            
            # Enhanced Sink Detection
            is_sink = False
            if "AI_SINK" in flow.target_var:
                target_type = "sink"
                is_sink = True
            elif flow.target_var in ("logging", "print") or "axios" in flow.target_var or "fetch" in flow.target_var:
                target_type = "sink"
                is_sink = True
            
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
            
            # Add nodes
            self.graph.add_node(GraphNode(
                id=source_id, 
                type=source_type, 
                label=source_label, 
                file_path=file_path.as_posix(), 
                line_number=flow.source_line,
                metadata=node_metadata
            ))
            
            self.graph.add_node(GraphNode(
                id=target_id, 
                type=target_type, 
                label=target_label, 
                file_path=file_path.as_posix(), 
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
