"""
HTML Report Exporter - Beautiful visual compliance reports
"""
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path


class HTMLExporter:
    """Export scan results as beautiful HTML reports with charts"""
    
    def __init__(self):
        self.severity_colors = {
            'critical': '#dc2626',  # Red
            'high': '#ea580c',      # Orange
            'medium': '#ca8a04',    # Yellow
            'low': '#16a34a',       # Green
            'info': '#0284c7'       # Blue
        }
        
        self.severity_labels = {
            'critical': '🔴 Critical',
            'high': '🟠 High',
            'medium': '🟡 Medium',
            'low': '🟢 Low',
            'info': 'ℹ️ Info'
        }
    
    def export(self, results: Dict[str, Any], output_path: str) -> None:
        """Export results to HTML file"""
        html = self._generate_html(results)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _generate_html(self, results: Dict[str, Any]) -> str:
        """Generate complete HTML document"""
        compliance = results.get('compliance', {})
        score = compliance.get('score', 0)
        status = compliance.get('status', 'unknown')
        findings = results.get('findings', [])
        meta = results.get('meta', {})
        
        # Group findings by severity
        grouped = self._group_by_severity(findings)
        
        # Generate sections
        header = self._generate_header()
        styles = self._generate_styles()
        score_section = self._generate_score_section(score, status, compliance, grouped)
        chart_section = self._generate_chart_section(grouped)
        
        # New: Global Architecture Graph (Cytoscape)
        global_graph_section = self._generate_global_graph_section(results)
        
        # New: Top Flows Section
        top_flows_section = self._generate_top_flows_section(findings)
        
        findings_section = self._generate_findings_section(findings, grouped)
        footer = self._generate_footer(meta)
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy Scan Report - Privalyse</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10.6.1/dist/mermaid.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
    <script src="https://unpkg.com/dagre@0.8.5/dist/dagre.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/cytoscape-dagre@2.5.0/cytoscape-dagre.min.js"></script>
    {styles}
</head>
<body>
    <div class="container">
        {header}
        {score_section}
        {global_graph_section}
        {chart_section}
        {top_flows_section}
        {findings_section}
        {footer}
    </div>
    {self._generate_chart_script(grouped)}
    <script>
        mermaid.initialize({{ 
            startOnLoad: true,
            theme: 'base',
            themeVariables: {{
                primaryColor: '#e0f2fe',
                primaryTextColor: '#0f172a',
                primaryBorderColor: '#0ea5e9',
                lineColor: '#64748b',
                secondaryColor: '#fef3c7',
                tertiaryColor: '#fee2e2'
            }}
        }});
    </script>
</body>
</html>"""
    
    def _generate_header(self) -> str:
        """Generate header section"""
        return """
        <header>
            <div class="logo">
                <span class="logo-icon">🔒</span>
                <h1>Privalyse</h1>
            </div>
            <p class="subtitle">Privacy & GDPR Compliance Report</p>
            <p class="timestamp">Generated: {}</p>
        </header>
        """.format(datetime.now().strftime("%B %d, %Y at %H:%M"))
    
    def _generate_styles(self) -> str:
        """Generate CSS styles"""
        return """
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }
        
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            margin-bottom: 10px;
        }
        
        .logo-icon {
            font-size: 48px;
        }
        
        h1 {
            font-size: 42px;
            font-weight: 700;
        }
        
        .subtitle {
            font-size: 18px;
            opacity: 0.9;
            margin-bottom: 8px;
        }
        
        .timestamp {
            font-size: 14px;
            opacity: 0.8;
        }
        
        .score-section {
            padding: 60px 40px;
            text-align: center;
            background: linear-gradient(to bottom, #f9fafb, white);
        }
        
        .score-display {
            font-size: 120px;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 20px;
        }
        
        .score-critical { color: #dc2626; }
        .score-warning { color: #ea580c; }
        .score-compliant { color: #16a34a; }
        
        .status-badge {
            display: inline-block;
            padding: 12px 24px;
            border-radius: 9999px;
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 30px;
        }
        
        .status-critical { 
            background: #fee2e2; 
            color: #dc2626; 
        }
        
        .status-warning { 
            background: #fed7aa; 
            color: #ea580c; 
        }
        
        .status-compliant { 
            background: #dcfce7; 
            color: #16a34a; 
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-top: 40px;
        }
        
        .stat-card {
            padding: 20px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        
        .stat-value {
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 8px;
        }
        
        .stat-label {
            font-size: 14px;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .chart-section {
            padding: 40px;
            background: white;
        }
        
        .chart-container {
            max-width: 400px;
            margin: 0 auto;
        }
        
        .findings-section {
            padding: 40px;
        }
        
        .section-title {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 3px solid #e5e7eb;
        }
        
        .severity-group {
            margin-bottom: 40px;
        }
        
        .severity-header {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 20px;
        }
        
        .finding-card {
            background: #f9fafb;
            border-left: 4px solid;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 16px;
        }
        
        .finding-card.critical { border-color: #dc2626; }
        .finding-card.high { border-color: #ea580c; }
        .finding-card.medium { border-color: #ca8a04; }
        .finding-card.low { border-color: #16a34a; }
        .finding-card.info { border-color: #0284c7; }
        
        .finding-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 12px;
            color: #111827;
        }
        
        .finding-meta {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin-bottom: 12px;
            font-size: 14px;
            color: #6b7280;
        }
        
        .finding-code {
            background: #1f2937;
            color: #f3f4f6;
            padding: 16px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 14px;
            margin: 12px 0;
        }
        
        .finding-gdpr {
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            padding: 12px;
            border-radius: 6px;
            margin: 12px 0;
            font-size: 14px;
        }
        
        .finding-gdpr strong {
            color: #1e40af;
        }
        
        footer {
            background: #f9fafb;
            padding: 30px 40px;
            text-align: center;
            color: #6b7280;
            font-size: 14px;
        }
        
        footer a {
            color: #667eea;
            text-decoration: none;
        }
        
        footer a:hover {
            text-decoration: underline;
        }
        
        .disclaimer {
            margin-top: 20px;
            padding: 15px;
            background: #fef3c7;
            border: 1px solid #fde047;
            border-radius: 6px;
            font-size: 13px;
        }
        
        .flows-grid {
            display: grid;
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .flow-visualization {
            background: #ffffff;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
            border: 1px solid #e5e7eb;
            overflow-x: auto;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            
            .container {
                box-shadow: none;
            }
            
            .finding-card {
                page-break-inside: avoid;
            }
        }
    </style>
        """
    
    def _generate_score_section(self, score: float, status: str, compliance: Dict, grouped: Dict) -> str:
        """Generate compliance score section"""
        # Determine score class and status badge
        if score >= 90:
            score_class = "score-compliant"
            status_class = "status-compliant"
            status_text = "✅ COMPLIANT"
        elif score >= 70:
            score_class = "score-warning"
            status_class = "status-warning"
            status_text = "⚠️ NEEDS WORK"
        else:
            score_class = "score-critical"
            status_class = "status-critical"
            status_text = "❌ CRITICAL"
        
        # Get finding counts from grouped findings (more accurate than compliance dict)
        critical = len(grouped.get('critical', []))
        high = len(grouped.get('high', []))
        medium = len(grouped.get('medium', []))
        low = len(grouped.get('low', []))
        
        return f"""
        <div class="score-section">
            <div class="score-display {score_class}">
                {score:.0f}<span style="font-size: 60px;">/100</span>
            </div>
            <div class="status-badge {status_class}">
                {status_text}
            </div>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" style="color: #dc2626;">{critical}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #ea580c;">{high}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #ca8a04;">{medium}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #16a34a;">{low}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
        </div>
        """
    
    def _generate_chart_section(self, grouped: Dict[str, List]) -> str:
        """Generate chart section"""
        return """
        <div class="chart-section">
            <h2 class="section-title">📊 Findings Distribution</h2>
            <div class="chart-container">
                <canvas id="findingsChart"></canvas>
            </div>
        </div>
        """
    
    def _prettify_rule(self, rule: str) -> str:
        """Make rule names more readable"""
        if not rule: return ""
        # Remove prefixes like JS_, PY_, DB_
        clean = rule
        for prefix in ['JS_', 'PY_', 'DB_', 'FORM_FIELD_', 'INFRA_']:
            if clean.startswith(prefix):
                clean = clean[len(prefix):]
        return clean.replace('_', ' ').title()

    def _generate_global_graph_section(self, results: Dict[str, Any]) -> str:
        """Generate the global data flow architecture graph using Cytoscape.js"""
        graph_data = results.get('semantic_graph', {})
        raw_nodes = graph_data.get('nodes', [])
        raw_edges = graph_data.get('edges', [])
        findings = results.get('findings', [])
        
        if not raw_nodes or not raw_edges:
            return ""
            
        # --- 1. Abstraction Layer: Simplify the Graph ---
        
        # Map every node ID to its "Owner" (File or Sink)
        node_owner_map = {} # node_id -> {id, type, label, category, is_critical}
        owner_nodes = {} # owner_id -> node_data
        
        # 1.0 Identify Sink Targets from Edges
        # Nodes that are targets of a 'sink' edge should be treated as Sinks, not just parts of a file.
        sink_target_ids = set()
        for edge in raw_edges:
            if edge.get('label') == 'sink':
                sink_target_ids.add(edge['target'])

        # Helper to categorize files/components
        def get_category(path, ntype, label):
            p = str(path).lower()
            l = str(label).lower()
            
            if ntype == 'sink':
                if any(x in l for x in ['api', 'http', 'request', 'fetch', 'axios', 'external', 'stripe', 'aws']): return 'external'
                return 'sink'
            
            # Input/Frontend
            if any(x in p for x in ['frontend', 'client', 'ui', 'web', 'view', 'template', 'html', 'form', 'page', 'screen']): return 'input'
            if any(x in p for x in ['cli', 'argparse', 'input', 'stdin']): return 'input'
            
            # External/Services
            if any(x in p for x in ['external', 'thirdparty', 'lib', 'requests', 'node_modules']): return 'external'
            
            # Processing/Backend (Default)
            # Includes: services, controllers, models, utils, etc.
            return 'processing'

        # 1.1 Identify Owners (Files and Sinks)
        for n in raw_nodes:
            nid = n['id']
            ntype = n.get('type', 'unknown')
            nlabel = n.get('label', '')
            fpath = n.get('file_path', '')
            
            owner_id = None
            cat = 'processing'
            
            # Check if this node is a Sink (either explicitly or via edge relationship)
            if ntype == 'sink' or nid in sink_target_ids:
                owner_id = f"sink_{nlabel}"
                cat = get_category(fpath, 'sink', nlabel)
                owner_nodes[owner_id] = {
                    "id": owner_id,
                    "label": nlabel,
                    "type": "sink",
                    "category": cat,
                    "is_critical": False
                }
            elif ntype == 'file':
                owner_id = f"file_{fpath}"
                cat = get_category(fpath, ntype, nlabel)
                owner_nodes[owner_id] = {
                    "id": owner_id,
                    "label": nlabel,
                    "type": "component",
                    "category": cat,
                    "full_path": fpath,
                    "is_critical": False
                }
            else:
                # Variables, Functions -> Belong to their File
                if fpath:
                    owner_id = f"file_{fpath}"
                    if owner_id not in owner_nodes:
                        cat = get_category(fpath, 'file', Path(fpath).name)
                        owner_nodes[owner_id] = {
                            "id": owner_id,
                            "label": Path(fpath).name,
                            "type": "component",
                            "category": cat,
                            "full_path": fpath,
                            "is_critical": False
                        }
            
            if owner_id:
                node_owner_map[nid] = owner_id

        # 1.2 Mark Critical Nodes based on Findings AND Infer Sinks
        # If a finding involves a file, mark that file as critical
        # Also, infer sinks from findings if they are missing in the graph
        
        aggregated_edges = {} # (src_owner, dst_owner) -> {count, labels, is_critical}

        for finding in findings:
            severity = finding.get('severity', 'low').lower()
            # Findings use 'file' key, but sometimes 'file_path' might be used in other contexts
            fpath = finding.get('file') or finding.get('file_path')
            rule = finding.get('rule', '')
            
            # Mark file as critical ONLY if it's a sink or has very high severity
            # We relax this: Files are structural, only Sinks should be red.
            # if severity in ['critical', 'high']:
            #     if fpath:
            #         owner_id = f"file_{fpath}"
            #         if owner_id in owner_nodes:
            #             owner_nodes[owner_id]['is_critical'] = True
            
            # Infer Sink from Finding
            inferred_sink_label = None
            inferred_sink_cat = 'sink'
            
            if 'PRINT_PII' in rule or 'LOG' in rule:
                inferred_sink_label = "Logs / Console"
            elif 'DB_' in rule or 'SQL_' in rule:
                inferred_sink_label = "Database"
            elif 'XSS' in rule:
                inferred_sink_label = "Web Browser"
                inferred_sink_cat = 'external'
            elif 'COMMAND_' in rule:
                inferred_sink_label = "OS Shell"
            elif 'NETWORK' in rule or 'API' in rule:
                inferred_sink_label = "External Network"
                inferred_sink_cat = 'external'
            elif 'HARDCODED_SECRET' in rule:
                # For secrets, the sink is the code itself, but let's visualize it as a "Leak"
                inferred_sink_label = "Source Code (Leak)"
            elif 'FORM_FIELD_' in rule:
                # Form fields are inputs, not sinks. Don't create a sink node for them.
                inferred_sink_label = None
            
            if inferred_sink_label and fpath:
                sink_id = f"sink_inferred_{inferred_sink_label.replace(' ', '_')}"
                file_id = f"file_{fpath}"
                
                # Create Sink Node if not exists
                if sink_id not in owner_nodes:
                    owner_nodes[sink_id] = {
                        "id": sink_id,
                        "label": inferred_sink_label,
                        "type": "sink",
                        "category": inferred_sink_cat,
                        "is_critical": True # Inferred sinks from findings are usually critical
                    }
                
                # Ensure File Node exists (might be missing if graph is incomplete)
                if file_id not in owner_nodes:
                     cat = get_category(fpath, 'file', Path(fpath).name)
                     owner_nodes[file_id] = {
                        "id": file_id,
                        "label": Path(fpath).name,
                        "type": "component",
                        "category": cat,
                        "full_path": fpath,
                        "is_critical": True
                    }
                
                # Create Edge
                key = (file_id, sink_id)
                if key not in aggregated_edges:
                    aggregated_edges[key] = {"count": 0, "labels": set(), "is_critical": True}
                aggregated_edges[key]["count"] += 1
                aggregated_edges[key]["labels"].add(self._prettify_rule(rule))

        # 1.3 Aggregate Edges (Existing Graph Edges)
        # aggregated_edges is already initialized above
        
        for edge in raw_edges:
            src = edge['source']
            dst = edge['target']
            
            owner_src = node_owner_map.get(src)
            owner_dst = node_owner_map.get(dst)
            
            if owner_src and owner_dst and owner_src != owner_dst:
                key = (owner_src, owner_dst)
                if key not in aggregated_edges:
                    aggregated_edges[key] = {"count": 0, "labels": set(), "is_critical": False}
                
                aggregated_edges[key]["count"] += 1
                if edge.get('label'):
                    aggregated_edges[key]["labels"].add(edge.get('label'))
                
                # Heuristic removed: Structural edges are not critical by default

        # 1.4 Heuristic: Connect Disconnected Layers (Implicit Flow)
        # If there are Input nodes and Processing nodes, but NO edges between them, add an implicit edge.
        input_nodes = [nid for nid, n in owner_nodes.items() if n['category'] == 'input']
        processing_nodes = [nid for nid, n in owner_nodes.items() if n['category'] == 'processing']
        
        has_input_processing_edge = False
        for (src, dst) in aggregated_edges.keys():
            src_cat = owner_nodes[src]['category']
            dst_cat = owner_nodes[dst]['category']
            if src_cat == 'input' and dst_cat == 'processing':
                has_input_processing_edge = True
                break
        
        if not has_input_processing_edge and input_nodes and processing_nodes:
            # Find best candidates (e.g. 'app' or 'server' for backend)
            target_node = processing_nodes[0]
            for nid in processing_nodes:
                if any(x in nid.lower() for x in ['app', 'server', 'main', 'api']):
                    target_node = nid
                    break
            
            # Connect all inputs to this target
            for src_node in input_nodes:
                key = (src_node, target_node)
                if key not in aggregated_edges:
                    aggregated_edges[key] = {
                        "count": 1, 
                        "labels": {"Implicit Flow"}, 
                        "is_critical": False,
                        "style": "dashed"
                    }

        # --- 2. Build Cytoscape Elements ---
        cy_elements = []
        
        # 2.1 Add Parent Nodes (Layers - Vertical Split)
        # Order matters for dagre usually, but we use compound nodes
        cy_elements.append({"data": {"id": "group_input", "label": "1. Input / Frontend", "category": "group"}})
        cy_elements.append({"data": {"id": "group_processing", "label": "2. Processing / Backend", "category": "group"}})
        cy_elements.append({"data": {"id": "group_sink", "label": "3. Data Sinks", "category": "group"}})
        cy_elements.append({"data": {"id": "group_external", "label": "4. External Services", "category": "group"}})
        
        # 2.2 Add Component Nodes
        for f in owner_nodes.values():
            parent = f"group_{f['category']}"
            classes = "critical" if f['is_critical'] else ""
            cy_elements.append({
                "data": {
                    "id": f['id'],
                    "label": f['label'],
                    "parent": parent,
                    "category": f['category'],
                    "type": f['type'],
                    "critical": f['is_critical']
                },
                "classes": classes
            })
            
        # 2.3 Add Edges
        for (src, dst), info in aggregated_edges.items():
            label = ""
            if len(info['labels']) > 0:
                label = ", ".join(list(info['labels'])[:2])
                if len(info['labels']) > 2: label += "..."
            
            classes = "critical" if info['is_critical'] else ""
            if info.get('style') == 'dashed':
                classes += " dashed"
            
            cy_elements.append({
                "data": {
                    "source": src,
                    "target": dst,
                    "weight": info['count'],
                    "label": label,
                    "critical": info['is_critical']
                },
                "classes": classes
            })

        import json
        elements_json = json.dumps(cy_elements)
        
        return f"""
        <div class="section-header">
            <h2>🗺️ System Privacy Map</h2>
            <p>Vertical data flow analysis: Input → Processing → Sinks. <span style="color: #ef4444; font-weight: bold;">● Red dots</span> indicate critical data paths.</p>
        </div>
        <div id="cy" style="width: 100%; height: 800px; border: 1px solid #e5e7eb; border-radius: 8px; background: #f8fafc;"></div>
        
        <script>
            document.addEventListener('DOMContentLoaded', function() {{
                var cy = cytoscape({{
                    container: document.getElementById('cy'),
                    elements: {elements_json},
                    style: [
                        {{
                            selector: 'node',
                            style: {{
                                'label': 'data(label)',
                                'text-valign': 'center',
                                'text-halign': 'center',
                                'font-size': '12px',
                                'font-weight': 'bold',
                                'color': '#1e293b',
                                'border-width': 2,
                                'border-color': '#94a3b8',
                                'background-color': '#fff'
                            }}
                        }},
                        {{
                            selector: 'node[category="group"]',
                            style: {{
                                'text-valign': 'top',
                                'text-halign': 'center',
                                'background-color': '#f8fafc',
                                'background-opacity': 0.5,
                                'border-width': 2,
                                'border-style': 'dashed',
                                'border-color': '#cbd5e1',
                                'font-size': '16px',
                                'font-weight': 'bold',
                                'color': '#475569',
                                'padding': 40
                            }}
                        }},
                        {{
                            selector: 'node[type="component"]',
                            style: {{
                                'shape': 'round-rectangle',
                                'width': 'label',
                                'height': 40,
                                'padding': 15
                            }}
                        }},
                        {{
                            selector: 'node[category="input"]',
                            style: {{ 'border-color': '#3b82f6', 'background-color': '#eff6ff' }}
                        }},
                        {{
                            selector: 'node[category="processing"]',
                            style: {{ 'border-color': '#a855f7', 'background-color': '#faf5ff' }}
                        }},
                        {{
                            selector: 'node[category="sink"]',
                            style: {{
                                'shape': 'database',
                                'background-color': '#fee2e2',
                                'border-color': '#ef4444',
                                'width': 60,
                                'height': 60
                            }}
                        }},
                        {{
                            selector: 'node[category="external"]',
                            style: {{
                                'shape': 'hexagon',
                                'background-color': '#fef3c7',
                                'border-color': '#f59e0b',
                                'width': 60,
                                'height': 60
                            }}
                        }},
                        {{
                            selector: 'node.critical',
                            style: {{
                                'border-width': 4,
                                'border-color': '#dc2626',
                                'background-color': '#fee2e2'
                            }}
                        }},
                        {{
                            selector: 'edge',
                            style: {{
                                'width': 2,
                                'line-color': '#cbd5e1',
                                'target-arrow-color': '#cbd5e1',
                                'target-arrow-shape': 'triangle',
                                'curve-style': 'taxi',
                                'taxi-direction': 'auto',
                                'taxi-turn': 20,
                                'taxi-turn-min-distance': 5,
                                'arrow-scale': 1.2
                            }}
                        }},
                        {{
                            selector: 'edge.critical',
                            style: {{
                                'width': 4,
                                'line-color': '#ef4444',
                                'target-arrow-color': '#ef4444',
                                'line-style': 'solid',
                                'z-index': 999
                            }}
                        }},
                        {{
                            selector: 'edge.dashed',
                            style: {{
                                'line-style': 'dashed',
                                'line-dash-pattern': [6, 3],
                                'opacity': 0.7
                            }}
                        }}
                    ],
                    layout: {{
                        name: 'dagre',
                        rankDir: 'LR',
                        nodeSep: 80,
                        rankSep: 250,
                        ranker: 'network-simplex',
                        padding: 50,
                        align: 'UL'
                    }}
                }});
                
                // Add red dots (badges) to critical nodes manually if needed, 
                // but border-width: 4 and red color is usually enough.
                // We can also use background images or specific shapes.
            }});
        </script>
        """
            


    def _generate_top_flows_section(self, findings: List[Dict]) -> str:
        """Generate section for top data flow stories"""
        # Filter for findings with flow paths
        flow_findings = [f for f in findings if f.get('flow_path') and len(f.get('flow_path')) > 1]
        
        # Sort by severity (Critical > High > Medium)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        flow_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'info'), 5))
        
        if not flow_findings:
            return ""
            
        html = """
        <div class="section-header">
            <h2>🌊 Top Data Flow Stories</h2>
            <p>Visualizing how sensitive data moves through your application.</p>
        </div>
        <div class="flows-grid">
        """
        
        for i, finding in enumerate(flow_findings[:5]):
            html += self._generate_flow_card(finding, i + 1)
            
        html += "</div>"
        return html

    def _generate_flow_card(self, finding: Dict, index: int) -> str:
        """Generate a card for a single flow story"""
        rule = finding.get('rule', 'Unknown')
        severity = finding.get('severity', 'info')
        file_path = finding.get('file', '')
        line = finding.get('line', 0)
        flow_path = finding.get('flow_path', [])
        
        # Clean up flow path
        cleaned_flow = []
        for step in flow_path:
            s = str(step).replace('"', "'")
            # Skip "Unknown Source" if it's the first step
            if s == "Unknown Source" and not cleaned_flow:
                continue
            cleaned_flow.append(s)
            
        if not cleaned_flow:
            cleaned_flow = ["Implicit Input", "Sink"]
        
        # Generate Mermaid Diagram
        mermaid_code = "graph LR\n"
        mermaid_code += "  classDef source fill:#e0f2fe,stroke:#0ea5e9,stroke-width:2px;\n"
        mermaid_code += "  classDef step fill:#f8fafc,stroke:#94a3b8,stroke-width:1px;\n"
        mermaid_code += "  classDef sink fill:#fee2e2,stroke:#ef4444,stroke-width:2px;\n"
        
        for i, label in enumerate(cleaned_flow):
            node_id = f"f{index}_s{i}"
            
            if i == 0:
                mermaid_code += f'  {node_id}(("{label}")):::source\n'
            elif i == len(cleaned_flow) - 1:
                mermaid_code += f'  {node_id}{{{"{label}"}}}:::sink\n'
            else:
                mermaid_code += f'  {node_id}["{label}"]:::step\n'
                
        for i in range(len(cleaned_flow) - 1):
            mermaid_code += f"  f{index}_s{i} --> f{index}_s{i+1}\n"
            
        return f"""
        <div class="finding-card" style="border-left: 5px solid {self.severity_colors.get(severity, '#ccc')}">
            <div class="finding-header">
                <div class="finding-title">
                    <span class="severity-badge severity-{severity}">{severity.upper()}</span>
                    {rule}
                </div>
                <div class="finding-location">{file_path}:{line}</div>
            </div>
            <div class="flow-visualization">
                <div class="mermaid">
                    {mermaid_code}
                </div>
            </div>
            <div class="finding-details">
                <p><strong>Data Flow:</strong> {len(flow_path)} steps detected from source to sink.</p>
            </div>
        </div>
        """

    def _generate_findings_section(self, findings: List[Dict], grouped: Dict) -> str:
        """Generate findings list section with aggregation"""
        html = '<div class="findings-section">\n'
        html += '    <h2 class="section-title">🔍 Detailed Findings</h2>\n'
        
        # Sort by severity
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        
        for severity in severity_order:
            items = grouped.get(severity, [])
            if not items:
                continue
            
            # Aggregate findings by (file, line, rule)
            aggregated = {}
            for f in items:
                key = (f.get('file'), f.get('line'), f.get('rule'))
                if key not in aggregated:
                    aggregated[key] = {
                        'base': f,
                        'pii_types': set(),
                        'count': 0
                    }
                aggregated[key]['count'] += 1
                # Extract PII type from classification or rule
                cls = f.get('classification', {})
                if cls and cls.get('pii_types'):
                    aggregated[key]['pii_types'].update(cls.get('pii_types'))
            
            html += f'    <div class="severity-group">\n'
            html += f'        <div class="severity-header">{self.severity_labels[severity]} ({len(aggregated)})</div>\n'
            
            for i, (key, data) in enumerate(aggregated.items(), 1):
                finding = data['base']
                pii_types = list(data['pii_types'])
                count = data['count']
                
                # Update finding with aggregated info for display
                if count > 1:
                    finding['aggregated_count'] = count
                    finding['aggregated_pii'] = pii_types
                
                html += self._generate_finding_card(finding, i, severity)
            
            html += '    </div>\n'
        
        html += '</div>\n'
        return html
    
    def _generate_finding_card(self, finding: Dict, index: int, severity: str) -> str:
        """Generate individual finding card"""
        rule = finding.get('rule', 'UNKNOWN')
        file_path = finding.get('file', 'N/A')
        line = finding.get('line', 'N/A')
        snippet = finding.get('snippet', '')
        classification = finding.get('classification', {})
        article = classification.get('article', 'N/A')
        reasoning = classification.get('reasoning', '')
        
        # Handle aggregated info
        count = finding.get('aggregated_count', 1)
        pii_list = finding.get('aggregated_pii', [])
        
        title_suffix = ""
        if count > 1:
            title_suffix = f" (x{count} occurrences)"
            if pii_list:
                reasoning += f"<br><strong>Aggregated PII Types:</strong> {', '.join(pii_list)}"
        
        return f"""
        <div class="finding-card {severity}">
            <div class="finding-title">
                {index}. {self._prettify_rule(rule)}{title_suffix}
            </div>
            <div class="finding-meta">
                <span>📍 <strong>File:</strong> {file_path}</span>
                <span>📏 <strong>Line:</strong> {line}</span>
            </div>
            {f'<div class="finding-code">{self._escape_html(snippet)}</div>' if snippet else ''}
            {f'<div class="finding-gdpr"><strong>GDPR:</strong> {article}</div>' if article != 'N/A' else ''}
            {f'<p style="margin-top: 12px; color: #4b5563;">{reasoning}</p>' if reasoning else ''}
        </div>
        """
    
    def _generate_chart_script(self, grouped: Dict) -> str:
        """Generate Chart.js script"""
        data = {
            'critical': len(grouped.get('critical', [])),
            'high': len(grouped.get('high', [])),
            'medium': len(grouped.get('medium', [])),
            'low': len(grouped.get('low', [])),
            'info': len(grouped.get('info', []))
        }
        
        return f"""
    <script>
        const ctx = document.getElementById('findingsChart');
        new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['🔴 Critical', '🟠 High', '🟡 Medium', '🟢 Low', 'ℹ️ Info'],
                datasets: [{{
                    data: [{data['critical']}, {data['high']}, {data['medium']}, {data['low']}, {data['info']}],
                    backgroundColor: [
                        '{self.severity_colors["critical"]}',
                        '{self.severity_colors["high"]}',
                        '{self.severity_colors["medium"]}',
                        '{self.severity_colors["low"]}',
                        '{self.severity_colors["info"]}'
                    ],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: true,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            padding: 20,
                            font: {{
                                size: 14
                            }}
                        }}
                    }},
                    tooltip: {{
                        callbacks: {{
                            label: function(context) {{
                                return context.label + ': ' + context.parsed + ' findings';
                            }}
                        }}
                    }}
                }}
            }}
        }});
    </script>
        """
    
    def _generate_footer(self, meta: Dict) -> str:
        """Generate footer section"""
        files_scanned = meta.get('files_scanned', 0)
        # Calculate scan duration from scanner metadata if available
        scan_time = meta.get('scan_duration', 0.0)
        
        return f"""
        <footer>
            <p><strong>Generated by Privalyse v0.1.0</strong></p>
            <p>Files scanned: {files_scanned} | Scan time: {scan_time:.2f}s</p>
            <p style="margin-top: 15px;">
                <a href="https://github.com/privalyse/privalyse-cli" target="_blank">GitHub</a> •
                <a href="https://github.com/privalyse/privalyse-cli/blob/main/DETECTION_RULES.md" target="_blank">Detection Rules</a>
            </p>
            <div class="disclaimer">
                ⚠️ <strong>Disclaimer:</strong> This is a technical report generated by automated code analysis. 
                It should not be considered as legal advice. Please consult with legal experts for compliance verification.
            </div>
        </footer>
        """
    
    def _group_by_severity(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by severity"""
        grouped = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in grouped:
                grouped[severity].append(finding)
        
        return grouped
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))
