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
        
        # Critical Issues (Top Priority!)
        sections.append(self._generate_critical_section(scan_result))
        
        # Findings by Severity
        sections.append(self._generate_findings_by_severity(scan_result))
        
        # Data Flow Analysis (if available)
        if scan_result.get('flows'):
            sections.append(self._generate_dataflow_section(scan_result))
            
        # Visual Data Flow Graph (Mermaid)
        if scan_result.get('semantic_graph'):
            sections.append(self._generate_mermaid_graph(scan_result))
        
        # GDPR Compliance
        sections.append(self._generate_compliance_section(scan_result))
        
        # Statistics
        sections.append(self._generate_statistics(scan_result))
        
        # Footer
        sections.append(self._generate_footer())
        
        return '\n\n'.join(sections)
    
    def _generate_header(self, scan_result: Dict[str, Any]) -> str:
        """Generate report header"""
        metadata = scan_result.get('meta', {})
        timestamp = metadata.get('scan_timestamp', datetime.now().isoformat())
        root_path = metadata.get('root_path', 'Unknown')
        
        return f"""# 🔒 Privalyse Security Scan Report

**Generated:** {timestamp}  
**Folder:** `{root_path}`  
**Scanner Version:** v0.1"""
    
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
        
        for finding in findings:
            severity = finding.get('severity', 'info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        compliance_score = scan_result.get('compliance_score', 0)
        
        # Status emoji
        if severity_counts['critical'] > 0:
            status = '🚨 **ACTION REQUIRED**'
            status_color = 'red'
        elif severity_counts['high'] > 0:
            status = '⚠️ **NEEDS ATTENTION**'
            status_color = 'orange'
        elif severity_counts['medium'] > 0:
            status = '📋 **REVIEW RECOMMENDED**'
            status_color = 'yellow'
        else:
            status = '✅ **LOOKING GOOD**'
            status_color = 'green'
        
        summary = f"""## 📊 Executive Summary

{status}

| Metric | Value |
|--------|-------|
| **Total Findings** | {len(findings)} |
| **Critical** | {self.severity_emoji['critical']} {severity_counts['critical']} |
| **High** | {self.severity_emoji['high']} {severity_counts['high']} |
| **Medium** | {self.severity_emoji['medium']} {severity_counts['medium']} |
| **Low** | {self.severity_emoji['low']} {severity_counts['low']} |
| **Info** | {self.severity_emoji['info']} {severity_counts['info']} |"""
        
        if compliance_score > 0:
            summary += f"\n| **Compliance Score** | {compliance_score}/100 |"
        
        return summary
    
    def _generate_critical_section(self, scan_result: Dict[str, Any]) -> str:
        """Generate critical issues section - most important!"""
        findings = scan_result.get('findings', [])
        critical = [f for f in findings if f.get('severity') == 'critical']
        
        if not critical:
            return """## 🎉 Critical Issues

**No critical issues found!** Great job!"""
        
        section = [f"""## 🚨 CRITICAL ISSUES - FIX IMMEDIATELY

Found **{len(critical)}** critical privacy/security issues that need immediate attention:
"""]
        
        # Show top 5 critical (don't overwhelm)
        for i, finding in enumerate(critical[:5], 1):
            section.append(self._format_finding_detailed(finding, i))
        
        if len(critical) > 5:
            section.append(f"\n*... and {len(critical) - 5} more critical issues. See full findings below.*\n")
        
        return '\n'.join(section)
    
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
        parts.extend([code_section, risk_section, fix_section])
        
        return '\n\n'.join(parts) + "\n\n---\n"
    
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
        """Generate findings organized by severity"""
        findings = scan_result.get('findings', [])
        
        section = ["## 📋 All Findings by Severity\n"]
        
        for severity in ['high', 'medium', 'low', 'info']:
            severity_findings = [f for f in findings if f.get('severity') == severity]
            
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
        """Generate Mermaid.js graph visualization"""
        graph_data = scan_result.get('semantic_graph', {})
        nodes = graph_data.get('nodes', [])
        edges = graph_data.get('edges', [])
        
        if not nodes or not edges:
            return ""
            
        lines = ["## 🗺️ Visual Data Flow Graph", "", "```mermaid", "graph LR"]
        
        # Add nodes with styling
        lines.append("  %% Styles")
        lines.append("  classDef source fill:#ffcccc,stroke:#ff0000,stroke-width:2px;")
        lines.append("  classDef sink fill:#ccccff,stroke:#0000ff,stroke-width:2px;")
        lines.append("  classDef variable fill:#eeeeee,stroke:#333333;")
        lines.append("  classDef file fill:#ffffff,stroke:#999999,stroke-dasharray: 5 5;")
        
        # Map original IDs to clean IDs to avoid syntax errors
        id_map = {n['id']: f"node_{i}" for i, n in enumerate(nodes)}
        
        # Add Nodes
        for node in nodes:
            clean_node_id = id_map.get(node['id'])
            if not clean_node_id: continue
            
            label = node['label'].replace('"', "'")
            node_type = node['type']
            
            # Shape based on type
            shape_open = "["
            shape_close = "]"
            if node_type == 'file':
                shape_open = "(("
                shape_close = "))"
            elif node_type == 'sink':
                shape_open = "{{"
                shape_close = "}}"
            elif node_type == 'source':
                shape_open = "(("
                shape_close = "))"
            
            # Apply class
            css_class = "variable"
            if node_type in ['source', 'sink', 'file']:
                css_class = node_type
            
            lines.append(f'  {clean_node_id}{shape_open}"{label}"{shape_close}::: {css_class}')
            
        # Add Edges
        for edge in edges:
            src = id_map.get(edge['source'])
            dst = id_map.get(edge['target'])
            
            if src and dst:
                label = edge.get('label', '')
                arrow = "-->"
                
                if edge['type'] == 'network_flow':
                    arrow = "-.->|HTTP|"
                elif label:
                    # Sanitize label
                    label = label.replace('"', "'")
                    arrow = f"-->|{label}|"
                
                lines.append(f"  {src} {arrow} {dst}")
                
        lines.append("```")
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
