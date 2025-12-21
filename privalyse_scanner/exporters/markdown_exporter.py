"""
Markdown Report Generator
Exports scan results to comprehensive, readable markdown reports
"""

from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path


class MarkdownExporter:
    """Generate professional markdown reports from scan results"""
    
    def __init__(self):
        self.severity_emoji = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵',
            'info': '⚪'
        }
    
    def export(self, scan_result: Dict[str, Any]) -> str:
        """
        Generate comprehensive markdown report
        
        Args:
            scan_result: Dictionary containing:
                - findings: List of finding dicts
                - metadata: Scan metadata (timestamp, file count, etc.)
                - flows: Optional data flow information
                - compliance_score: Optional compliance score
        
        Returns:
            Markdown formatted report string
        """
        sections = []
        
        # Header
        sections.append(self._generate_header(scan_result))
        
        # Executive Summary
        sections.append(self._generate_summary(scan_result))
        
        # AI Data Exposure (Top Priority!)
        sections.append(self._generate_ai_exposure_section(scan_result))
        
        # Top Data Flow Stories
        sections.append(self._generate_top_flows_section(scan_result))
        
        # Findings by Severity (Filtered)
        sections.append(self._generate_findings_by_severity(scan_result))
        
        # Visual Data Flow Graph (Mermaid)
        if scan_result.get('semantic_graph'):
            sections.append(self._generate_mermaid_graph(scan_result))
        
        # Statistics
        sections.append(self._generate_statistics(scan_result))
        
        # Footer
        sections.append(self._generate_footer())
        
        return '\n\n'.join(sections)
    
    def _generate_ai_exposure_section(self, scan_result: Dict[str, Any]) -> str:
        """Generate AI Data Exposure section - The Core Value Prop"""
        findings = scan_result.get('findings', [])
        ai_leaks = [f for f in findings if f.get('rule') == 'AI_PII_LEAK']
        
        if not ai_leaks:
            return """## 🤖 AI Data Exposure

**✅ No AI Data Leaks Detected.** 
Your application does not appear to be sending sensitive data to known AI providers (OpenAI, Anthropic, etc.) without sanitization.
"""
        
        section = [f"""## 🤖 AI Data Exposure - CRITICAL

Found **{len(ai_leaks)}** instances where data is being sent to AI models/APIs. 
These are your highest priority privacy risks.
"""]
        
        for i, finding in enumerate(ai_leaks, 1):
            section.append(self._format_finding_detailed(finding, i))
            
        return '\n'.join(section)

    def _generate_top_flows_section(self, scan_result: Dict[str, Any]) -> str:
        """Generate section for top data flow stories"""
        findings = scan_result.get('findings', [])
        
        # Filter for findings with flow paths, excluding AI leaks (already shown)
        flow_findings = [f for f in findings if f.get('flow_path') and len(f.get('flow_path')) > 1 and f.get('rule') != 'AI_PII_LEAK']
        
        # Sort by severity (Critical > High > Medium)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        flow_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'info'), 5))
        
        if not flow_findings:
            return ""
            
        section = ["""## 🌊 Other Critical Data Flows

These findings show the complete path of sensitive data from source to sink (Database, Logs, etc.).
"""]
        
        # Show top 5 flows
        for i, finding in enumerate(flow_findings[:5], 1):
            section.append(self._format_finding_detailed(finding, i))
            
        if len(flow_findings) > 5:
            section.append(f"\n*... and {len(flow_findings) - 5} more data flow stories.*")
            
        return '\n'.join(section)

    def _generate_header(self, scan_result: Dict[str, Any]) -> str:
        """Generate report header"""
        metadata = scan_result.get('meta', {})
        timestamp = metadata.get('scan_timestamp', datetime.now().isoformat())
        root_path = metadata.get('root_path', 'Unknown')
        
        return f"""# 🛡️ Privalyse: AI Privacy Guardian

**Generated:** {timestamp}  
**Target:** `{root_path}`  
**Focus:** AI Data Leakage & PII Protection"""
    
    def _generate_summary(self, scan_result: Dict[str, Any]) -> str:
        """Generate executive summary"""
        findings = scan_result.get('findings', [])
        
        # Count by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        ai_leak_count = 0
        
        for finding in findings:
            severity = finding.get('severity', 'info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            if finding.get('rule') == 'AI_PII_LEAK':
                ai_leak_count += 1
        
        # Status emoji
        if ai_leak_count > 0:
            status = '🚨 **AI DATA LEAK DETECTED**'
            status_color = 'red'
        elif severity_counts['critical'] > 0:
            status = '⚠️ **CRITICAL PRIVACY RISKS**'
            status_color = 'orange'
        else:
            status = '✅ **AI SAFE**'
            status_color = 'green'
        
        summary = f"""## 📊 Executive Summary

{status}

| Metric | Value |
|--------|-------|
| **AI Data Leaks** | {self.severity_emoji['critical'] if ai_leak_count > 0 else '✅'} {ai_leak_count} |
| **Total Findings** | {len(findings)} |
| **Critical** | {self.severity_emoji['critical']} {severity_counts['critical']} |
| **High** | {self.severity_emoji['high']} {severity_counts['high']} |
"""
        return summary
    
    def _generate_critical_section(self, scan_result: Dict[str, Any]) -> str:
        # Deprecated, replaced by _generate_ai_exposure_section
        return ""
    
    def _format_finding_detailed(self, finding: Dict[str, Any], number: int = None) -> str:
        """Format a single finding with full details"""
        rule = finding.get('rule', 'Unknown Rule')
        file_path = finding.get('file', 'Unknown file')
        line = finding.get('line', 0)
        snippet = finding.get('snippet', '')
        classification = finding.get('classification', {})
        
        pii_types = classification.get('pii_types', [])
        severity = finding.get('severity', 'info')
        category = classification.get('category', 'unknown')
        
        # Header
        if number:
            header = f"### {number}. {rule}"
        else:
            header = f"### {rule}"
        
        # Location
        location = f"**📍 Location:** `{file_path}:{line}`"
        
        # Issue description
        issue = f"**⚠️ Issue:** {category.replace('_', ' ').title()}"
        
        # PII types if available
        pii_section = ""
        if pii_types:
            pii_list = ', '.join(pii_types)
            pii_section = f"**🔍 PII Detected:** {pii_list}"
        
        # Data Flow Visualization (Mermaid)
        flow_section = ""
        flow_path = finding.get('flow_path', [])
        if flow_path and len(flow_path) > 1:
            flow_diagram = self._generate_finding_flow_diagram(finding)
            if flow_diagram:
                flow_section = f"**🌊 Data Flow:**\n\n{flow_diagram}"

        # Code snippet
        code_section = "**💻 Code:**"
        if snippet:
            # Detect language from file extension
            lang = self._detect_language(file_path)
            code_section += f"\n```{lang}\n{snippet}\n```"
        
        # Remediation
        fix = self._generate_fix_suggestion(finding)
        fix_section = f"**✅ How to Fix:**\n{fix}"
        
        # Risk explanation
        risk = self._generate_risk_explanation(finding)
        risk_section = f"**💡 Why This Matters:**\n{risk}"
        
        # Assemble
        parts = [header, location, issue]
        if pii_section:
            parts.append(pii_section)
        if flow_section:
            parts.append(flow_section)
        parts.extend([code_section, risk_section, fix_section])
        
        return '\n\n'.join(parts) + "\n\n---\n"

    def _generate_finding_flow_diagram(self, finding: Dict[str, Any]) -> str:
        """Generate a mini Mermaid diagram for a specific finding"""
        flow_path = finding.get('flow_path', [])
        if not flow_path:
            return ""
            
        lines = ["```mermaid", "graph TD"]
        
        # Styles
        lines.append("  classDef source fill:#e6fffa,stroke:#00b8d9,stroke-width:2px;")
        lines.append("  classDef step fill:#f4f5f7,stroke:#505f79,stroke-width:1px;")
        lines.append("  classDef sink fill:#ffebe6,stroke:#ff5630,stroke-width:2px;")
        
        # Nodes
        for i, step in enumerate(flow_path):
            label = str(step).replace('"', "'").replace('\n', ' ').replace('\r', '')
            
            # Skip "Unknown Source" if it's the first step
            if i == 0 and label == "Unknown Source":
                continue
                
            node_id = f"step_{i}"
            
            # Determine type
            if i == 0:
                css_class = "source"
                shape_open, shape_close = "((", "))"
            elif i == len(flow_path) - 1:
                css_class = "sink"
                shape_open, shape_close = "{{", "}}"
            else:
                css_class = "step"
                shape_open, shape_close = "[", "]"
                
            lines.append(f'  {node_id}{shape_open}"{label}"{shape_close}')
            lines.append(f'  class {node_id} {css_class}')
            
        # Edges
        # We need to track valid nodes to connect them correctly
        valid_indices = [i for i, step in enumerate(flow_path) if not (i == 0 and str(step) == "Unknown Source")]
        
        for i in range(len(valid_indices) - 1):
            curr_idx = valid_indices[i]
            next_idx = valid_indices[i+1]
            lines.append(f"  step_{curr_idx} --> step_{next_idx}")
            
        lines.append("```")
        return "\n".join(lines)
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext = Path(file_path).suffix.lower()
        lang_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'jsx',
            '.tsx': 'tsx',
            '.java': 'java',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.cs': 'csharp',
        }
        return lang_map.get(ext, 'text')
    
    def _generate_fix_suggestion(self, finding: Dict[str, Any]) -> str:
        """Generate actionable fix suggestion"""
        rule = finding.get('rule', '')
        classification = finding.get('classification', {})
        pii_types = classification.get('pii_types', [])
        
        # Rule-specific suggestions
        if 'LOG' in rule.upper() or 'LOGGING' in rule.upper():
            return """- **Remove PII from log messages**
  - Use user IDs instead of emails/names
  - Hash sensitive identifiers before logging
  - Implement log sanitization middleware

Example:
```python
# ❌ Before
logger.info(f"User {user.email} logged in")

# ✅ After
logger.info(f"User {user.id} logged in")
```"""
        
        elif 'HTTP' in rule.upper() and 'PLAIN' in rule.upper():
            return """- **Use HTTPS instead of HTTP**
  - Update all API endpoints to use HTTPS
  - Configure SSL/TLS certificates
  - Enforce HTTPS-only in production

Example:
```javascript
// ❌ Before
fetch("http://api.example.com/users")

// ✅ After
fetch("https://api.example.com/users")
```"""
        
        elif 'API_KEY' in rule.upper() or 'SECRET' in rule.upper():
            return """- **Move secrets to environment variables**
  - Use `.env` file (add to .gitignore)
  - Use secret management service (AWS Secrets Manager, etc.)
  - Never commit secrets to version control

Example:
```python
# ❌ Before
API_KEY = "sk-proj-abc123..."

# ✅ After
API_KEY = os.getenv("API_KEY")
```"""
        
        elif 'PASSWORD' in rule.upper():
            return """- **Hash passwords before storage**
  - Use bcrypt, argon2, or pbkdf2
  - Never store plaintext passwords
  - Use salted hashes

Example:
```python
# ❌ Before
user.password = password

# ✅ After
import bcrypt
user.password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```"""
        
        else:
            return f"""- Review this finding and implement appropriate security controls
- Ensure PII is properly encrypted, hashed, or removed
- Follow GDPR best practices for data handling"""
    
    def _generate_risk_explanation(self, finding: Dict[str, Any]) -> str:
        """Explain why this finding matters"""
        rule = finding.get('rule', '')
        classification = finding.get('classification', {})
        severity = finding.get('severity', 'info')
        
        if 'LOG' in rule.upper():
            return """Exposing PII in logs creates multiple risks:
- **GDPR Violation** (Art. 32) - Inadequate security measures
- **Data Breach Risk** - Logs often stored long-term and widely accessible
- **Potential Fine** - Up to €500,000 for serious violations
- **Reputation Damage** - Customer trust erosion"""
        
        elif 'HTTP' in rule.upper() and 'PLAIN' in rule.upper():
            return """Transmitting PII over unencrypted HTTP is dangerous:
- **Man-in-the-Middle Attacks** - Traffic can be intercepted
- **GDPR Violation** (Art. 32) - Encryption required for PII
- **Compliance Failure** - Most standards require HTTPS (PCI-DSS, etc.)
- **Easy Exploitation** - Attackers can read sensitive data in transit"""
        
        elif 'PASSWORD' in rule.upper() or 'SECRET' in rule.upper():
            return """Hardcoded secrets are a critical security vulnerability:
- **Immediate Access** - Anyone with code access has credentials
- **Version Control Exposure** - Secrets persist in Git history
- **Lateral Movement** - Compromised keys enable broader attacks
- **Compliance Violation** - Fails security audits"""
        
        else:
            return f"""This {severity} severity finding indicates a privacy/security concern that should be addressed to maintain GDPR compliance and protect user data."""
    
    def _generate_findings_by_severity(self, scan_result: Dict[str, Any]) -> str:
        """Generate findings organized by severity, filtering out generic security noise"""
        findings = scan_result.get('findings', [])
        
        # Filter out "BS" findings as requested
        ignored_rules = [
            'INFRA_EXPRESS_HELMET_MISSING',
            'INFRA_EXPRESS_FINGERPRINT',
            'HTTP_INSECURE_API', # Unless it's AI related, which is handled separately
            'TRACKING_GOOGLE_ANALYTICS', # Lower priority
            'TRACKING_FACEBOOK_PIXEL',
            'TRACKING_MIXPANEL',
            'TRACKING_HOTJAR',
            'TRACKING_SEGMENT'
        ]
        
        filtered_findings = [f for f in findings if f.get('rule') not in ignored_rules]
        
        section = ["## 📋 All Findings by Severity\n"]
        
        for severity in ['high', 'medium', 'low', 'info']:
            severity_findings = [f for f in filtered_findings if f.get('severity') == severity]
            
            if not severity_findings:
                continue
            
            section.append(f"### {self.severity_emoji[severity]} {severity.title()} Severity ({len(severity_findings)} findings)\n")
            
            # Show summary table for non-critical
            if len(severity_findings) > 3:
                section.append("| Rule | Location | PII Types |")
                section.append("|------|----------|-----------|")
                for finding in severity_findings[:10]:  # Max 10
                    rule = finding.get('rule', 'Unknown')
                    file_path = finding.get('file', 'Unknown')
                    line = finding.get('line', 0)
                    pii = ', '.join(finding.get('classification', {}).get('pii_types', []))
                    section.append(f"| {rule} | `{file_path}:{line}` | {pii or '-'} |")
                
                if len(severity_findings) > 10:
                    section.append(f"\n*... and {len(severity_findings) - 10} more {severity} findings*\n")
            else:
                # Show details for few findings
                for finding in severity_findings:
                    section.append(self._format_finding_brief(finding))
        
        return '\n'.join(section)
    
    def _format_finding_brief(self, finding: Dict[str, Any]) -> str:
        """Format finding in brief mode"""
        rule = finding.get('rule', 'Unknown')
        file_path = finding.get('file', 'Unknown')
        line = finding.get('line', 0)
        pii = ', '.join(finding.get('classification', {}).get('pii_types', []))
        
        return f"- **{rule}** at `{file_path}:{line}`" + (f" (PII: {pii})" if pii else "")
    
    def _generate_dataflow_section(self, scan_result: Dict[str, Any]) -> str:
        """Generate data flow analysis section"""
        flows = scan_result.get('flows', [])
        
        if not flows:
            return ""
        
        section = ["""## 🔗 Data Flow Analysis

Critical data paths detected in your application:
"""]
        
        # Convert DataFlowEdge objects to dicts if necessary
        processed_flows = []
        for f in flows:
            if hasattr(f, 'to_dict'):
                processed_flows.append(f.to_dict())
            elif hasattr(f, '__dict__'):
                processed_flows.append(f.__dict__)
            else:
                processed_flows.append(f)
        
        # Group flows by risk (simplified logic as risk_level might not be present in raw edges)
        # For now, just list flows that involve sinks
        sink_flows = [f for f in processed_flows if f.get('flow_type') == 'sink']
        
        if sink_flows:
            section.append("### Detected Sinks\n")
            for flow in sink_flows[:10]:
                source = flow.get('source_var', 'Unknown')
                target = flow.get('target_var', 'Unknown')
                line = flow.get('target_line', '?')
                
                section.append(f"- **{source}** → **{target}** (Line {line})")
        
        return '\n'.join(section)

    def _generate_mermaid_graph(self, scan_result: Dict[str, Any]) -> str:
        """Generate horizontal layered architecture graph with risk-based coloring"""
        graph_data = scan_result.get('semantic_graph', {})
        nodes = graph_data.get('nodes', [])
        edges = graph_data.get('edges', [])
        findings = scan_result.get('findings', [])
        
        if not nodes or not edges:
            return ""
        
        # Build severity map for sinks (finding severity -> sink coloring)
        sink_severity_map = {}  # sink_node_id -> highest_severity
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        
        for finding in findings:
            sink_node = finding.get('sink_node')
            if sink_node:
                current = sink_severity_map.get(sink_node)
                new_severity = finding.get('severity', 'info')
                
                if not current or severity_order.get(new_severity, 0) > severity_order.get(current, 0):
                    sink_severity_map[sink_node] = new_severity
        
        lines = ["## 🗺️ Data Flow Architecture", "", 
                 "> **Note:** This diagram uses [Mermaid](https://mermaid.js.org/). View in GitHub, VS Code Preview (Ctrl+Shift+V), or install the [Markdown Preview Mermaid Support](https://marketplace.visualstudio.com/items?itemName=bierner.markdown-mermaid) extension.",
                 "", "```mermaid", "flowchart LR"]
        
        # Advanced Styles - Risk-based coloring
        lines.append("  %% Styles")
        lines.append("  classDef frontend fill:#dbeafe,stroke:#3b82f6,stroke-width:2px,color:#1e3a8a")
        lines.append("  classDef backend fill:#e9d5ff,stroke:#9333ea,stroke-width:2px,color:#581c87")
        lines.append("  classDef storage fill:#fef3c7,stroke:#f59e0b,stroke-width:2px,color:#78350f")
        lines.append("  classDef piiVar fill:#fed7aa,stroke:#ea580c,stroke-width:2px,color:#7c2d12")
        lines.append("  classDef sinkCritical fill:#fecaca,stroke:#dc2626,stroke-width:4px,color:#7f1d1d")
        lines.append("  classDef sinkHigh fill:#fed7aa,stroke:#ea580c,stroke-width:3px,color:#7c2d12")
        lines.append("  classDef sinkMedium fill:#fef3c7,stroke:#f59e0b,stroke-width:2px,color:#78350f")
        lines.append("  classDef sinkLow fill:#d1fae5,stroke:#10b981,stroke-width:2px,color:#065f46")
        lines.append("")
        
        # Categorize nodes into horizontal layers
        pii_keywords = ['email', 'password', 'ssn', 'phone', 'credit', 'name', 'address', 'dob', 'birth']
        
        layer_frontend = []  # 📱 User Input (Forms, Client)
        layer_backend = []   # ⚙️ Processing (Functions, Transforms)
        layer_storage = []   # 💾 PII Variables (Backend data)
        layer_sinks = {}     # 🚨 Sinks (Database, Logs, APIs) - deduplicated
        
        def make_id(node):
            # Sanitize ID to be a valid Mermaid identifier
            # Replace all non-alphanumeric characters with underscores
            import re
            clean_id = re.sub(r'[^a-zA-Z0-9_]', '_', node['id'])
            # Ensure it doesn't start with a number
            if clean_id and clean_id[0].isdigit():
                clean_id = '_' + clean_id
            return clean_id
        
        for node in nodes:
            ntype = node.get('type', 'variable')
            label = node.get('label', '')
            fpath = node.get('file_path', '')
            
            if ntype == 'file':
                continue
            
            # Detection
            is_frontend = 'frontend' in fpath.lower() or 'client' in fpath.lower() or 'component' in fpath.lower()
            is_backend = 'backend' in fpath.lower() or 'server' in fpath.lower() or 'service' in fpath.lower()
            is_pii = any(kw in label.lower() for kw in pii_keywords)
            is_function = ntype == 'function'
            is_sink = ntype == 'sink' or label in ['console.log', 'User.create', 'res.json', 'res.send']
            
            # Layer Assignment
            if is_sink:
                if label not in layer_sinks:
                    layer_sinks[label] = node
            elif is_function:
                if is_frontend:
                    layer_frontend.append(node)
                else:
                    layer_backend.append(node)
            elif is_pii:
                if is_frontend:
                    layer_frontend.append(node)
                else:
                    layer_storage.append(node)
            else:
                if is_backend:
                    layer_backend.append(node)
                else:
                    layer_storage.append(node)
        
        # Generate Layers (Left to Right)
        
        # Helper to sanitize labels
        def sanitize_label(label):
            # Escape quotes and brackets, remove newlines
            return label.replace('"', "'").replace('[', '(').replace(']', ')').replace('\n', ' ').replace('\r', '')

        # Layer 1: Frontend (Input Collection)
        if layer_frontend:
            lines.append('  subgraph L1["📱 FRONTEND<br/>User Input & Forms"]')
            lines.append('    direction TB')
            for node in layer_frontend:
                nid = make_id(node)
                label = sanitize_label(node.get('label', ''))
                ntype = node.get('type', '')
                if ntype == 'function':
                    lines.append(f'    {nid}["{label}"]:::frontend')
                else:
                    lines.append(f'    {nid}("{label}"):::frontend')
            lines.append('  end')
            lines.append('')
        
        # Layer 2: Backend Processing
        if layer_backend:
            lines.append('  subgraph L2["⚙️ BACKEND<br/>Processing & Logic"]')
            lines.append('    direction TB')
            for node in layer_backend:
                nid = make_id(node)
                label = sanitize_label(node.get('label', ''))
                lines.append(f'    {nid}["{label}"]:::backend')
            lines.append('  end')
            lines.append('')
        
        # Layer 3: Storage/PII Variables
        if layer_storage:
            lines.append('  subgraph L3["💾 DATA STORAGE<br/>PII Variables"]')
            lines.append('    direction TB')
            for node in layer_storage:
                nid = make_id(node)
                label = sanitize_label(node.get('label', ''))
                is_pii = any(kw in label.lower() for kw in pii_keywords)
                if is_pii:
                    lines.append(f'    {nid}("{label}"):::piiVar')
                else:
                    lines.append(f'    {nid}["{label}"]:::storage')
            lines.append('  end')
            lines.append('')
        
        # Layer 4: Sinks (Risk-based coloring)
        if layer_sinks:
            lines.append('  subgraph L4["🚨 SINKS<br/>Data Destinations"]')
            lines.append('    direction TB')
            for label, node in layer_sinks.items():
                nid = make_id(node)
                safe_label = sanitize_label(label)
                
                # Determine severity-based style
                severity = sink_severity_map.get(node['id'], 'low')
                sink_class = f'sink{severity.capitalize()}'
                
                # Add severity indicator
                severity_icon = self.severity_emoji.get(severity, '⚪')
                lines.append(f'    {nid}["{severity_icon} {safe_label}"]:::{sink_class}')
            lines.append('  end')
            lines.append('')
        
        # Data Flows with sink deduplication
        sink_label_to_id = {label: make_id(node) for label, node in layer_sinks.items()}
        
        # Build node ID lookup
        node_lookup = {n['id']: n for n in nodes}
        
        lines.append("  %% Data Flows")
        for edge in edges:
            src_id = edge['source']
            dst_id = edge['target']
            edge_label = edge.get('label', '')
            
            # Skip structural edges (file definitions), show only data flows
            if edge_label in ['defines', 'contains']:
                continue
            
            # Skip if source or destination doesn't exist
            src_node = node_lookup.get(src_id)
            dst_node = node_lookup.get(dst_id)
            if not src_node or not dst_node:
                continue
            
            # Skip file nodes
            if src_node.get('type') == 'file' or dst_node.get('type') == 'file':
                continue
            
            # Map to deduplicated sinks
            dst_label = dst_node.get('label', '')
            if dst_label in sink_label_to_id:
                dst_id_mapped = sink_label_to_id[dst_label]
            else:
                dst_id_mapped = make_id(dst_node)
            
            src_id_mapped = make_id(src_node)
            
            if edge_label == 'HTTP Request':
                lines.append(f'  {src_id_mapped} -.->|HTTP| {dst_id_mapped}')
            elif edge_label and edge_label != 'sink':
                edge_label = edge_label.replace('"', "'")
                lines.append(f'  {src_id_mapped} -->|{edge_label}| {dst_id_mapped}')
            else:
                lines.append(f'  {src_id_mapped} --> {dst_id_mapped}')
        
        lines.append("```")
        lines.append("")
        lines.append("### 🔍 Graph Legend")
        lines.append("- **📱 Frontend**: User input collection (forms, components)")
        lines.append("- **⚙️ Backend**: Processing functions and business logic")
        lines.append("- **💾 Storage**: PII variables and data structures")
        lines.append("- **🚨 Sinks**: Final data destinations, colored by risk:")
        lines.append("  - 🔴 **Critical**: Immediate security threat")
        lines.append("  - 🟠 **High**: Major privacy concern")
        lines.append("  - 🟡 **Medium**: Should be reviewed")
        lines.append("  - 🟢 **Low**: Acceptable with precautions")
        lines.append("")
        
        return "\n".join(lines)
    
    def _generate_compliance_section(self, scan_result: Dict[str, Any]) -> str:
        """Generate GDPR compliance section"""
        findings = scan_result.get('findings', [])
        
        # Count GDPR violations
        art6_violations = 0
        art9_violations = 0
        art32_violations = 0
        
        for finding in findings:
            classification = finding.get('classification', {})
            article = classification.get('article', '') or ''
            
            if '6' in str(article):
                art6_violations += 1
            if '9' in str(article):
                art9_violations += 1
            if '32' in str(article):
                art32_violations += 1
        
        section = ["""## ⚖️ GDPR Compliance

| Article | Violations | Description |
|---------|------------|-------------|
| **Art. 6** | """ + str(art6_violations) + """ | Lawfulness of processing |
| **Art. 9** | """ + str(art9_violations) + """ | Special categories of data |
| **Art. 32** | """ + str(art32_violations) + """ | Security of processing |
"""]
        
        if art6_violations + art9_violations + art32_violations > 0:
            section.append("""
**⚠️ Compliance Risk:** Your application has GDPR compliance issues that should be addressed.""")
        else:
            section.append("""
**✅ Compliance Status:** No obvious GDPR violations detected.""")
        
        return '\n'.join(section)
    
    def _generate_statistics(self, scan_result: Dict[str, Any]) -> str:
        """Generate scan statistics"""
        metadata = scan_result.get('metadata', {})
        findings = scan_result.get('findings', [])
        
        files_scanned = metadata.get('files_scanned', 0)
        scan_duration = metadata.get('scan_duration_seconds', 0)
        lines_analyzed = metadata.get('lines_analyzed', 0)
        
        # Unique PII types
        pii_types_set = set()
        for finding in findings:
            pii_types = finding.get('classification', {}).get('pii_types', [])
            pii_types_set.update(pii_types)
        
        return f"""## 📈 Scan Statistics

- **Files Scanned:** {files_scanned}
- **Findings:** {len(findings)}
- **Unique PII Types:** {len(pii_types_set)}
- **Scan Duration:** {scan_duration:.2f}s
- **Analysis Rate:** {lines_analyzed / scan_duration if scan_duration > 0 else 0:.0f} lines/sec"""
    
    def _generate_footer(self) -> str:
        """Generate report footer"""
        return """---

## 💡 Next Steps

1. **Fix Critical Issues** - Address all critical findings immediately
2. **Review High/Medium** - Plan fixes for high and medium severity items
3. **Update Documentation** - Document security decisions
4. **Re-scan** - Run Privalyse again after fixes to verify

## 🔗 Resources

- [Privalyse Documentation](https://docs.privalyse.com)
- [GDPR Compliance Guide](https://gdpr.eu/)
- [OWASP Security Guidelines](https://owasp.org/)

---

**Generated by [Privalyse](https://privalyse.com)** - Privacy scanner for modern code  
*Report any issues or false positives: [GitHub Issues](https://github.com/privalyse/privalyse/issues)*
"""


def export_to_markdown(scan_result: Dict[str, Any], output_path: str = None) -> str:
    """
    Convenience function to export scan results to markdown
    
    Args:
        scan_result: Scan result dictionary
        output_path: Optional output file path. If None, returns string
    
    Returns:
        Markdown report string
    """
    exporter = MarkdownExporter()
    markdown = exporter.export(scan_result)
    
    if output_path:
        Path(output_path).write_text(markdown, encoding='utf-8')
    
    return markdown
