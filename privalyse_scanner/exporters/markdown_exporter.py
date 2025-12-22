"""
Markdown Report Generator
Exports scan results to comprehensive, readable markdown reports
"""

from typing import Dict, Any, List, Union
from datetime import datetime
from pathlib import Path
from privalyse_scanner.exporters.report_generator import ReportGenerator
from privalyse_scanner.models.finding import Finding

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
    
    def export(self, findings: List[Union[Finding, Dict[str, Any]]], metadata: Dict[str, Any]) -> str:
        """
        Generate comprehensive markdown report
        
        Args:
            findings: List of Finding objects or dicts
            metadata: Scan metadata
        
        Returns:
            Markdown formatted report string
        """
        # Use ReportGenerator to process data
        generator = ReportGenerator(findings, metadata)
        data = generator.get_data()
        
        sections = []
        
        # Header
        sections.append(self._generate_header(metadata))
        
        # Executive Summary
        sections.append(self._generate_summary(data['summary']))
        
        # Compliance Report
        sections.append(self._generate_compliance_section(data['compliance']))
        
        # Top Riskiest Files
        sections.append(self._generate_riskiest_files(data['files']))
        
        # Detailed Findings (Top Critical/High)
        sections.append(self._generate_detailed_findings(findings))
        
        # Visual Data Flow Graph (Mermaid) - reusing existing logic if graph data exists in metadata
        if metadata.get('semantic_graph'):
            # We need to reconstruct a pseudo scan_result for the graph generator
            # This is a bit of a hack to reuse the complex graph logic without rewriting it entirely right now
            scan_result = {
                'semantic_graph': metadata.get('semantic_graph'),
                'findings': [f if isinstance(f, dict) else f.to_dict() for f in findings]
            }
            sections.append(self._generate_mermaid_graph(scan_result))
        
        # Footer
        sections.append(self._generate_footer())
        
        return '\n\n'.join(sections)

    def _generate_header(self, metadata: Dict[str, Any]) -> str:
        """Generate report header"""
        timestamp = metadata.get('scan_timestamp', datetime.now().isoformat())
        root_path = metadata.get('root_path', 'Unknown')
        
        return f"""# 🛡️ Privalyse Scan Report

**Generated:** {timestamp}  
**Target:** `{root_path}`  
**Focus:** GDPR Compliance & Data Privacy"""
    
    def _generate_summary(self, summary: Dict[str, int]) -> str:
        """Generate executive summary"""
        total = summary['total']
        critical = summary['critical']
        high = summary['high']
        
        if critical > 0:
            status = '🚨 **CRITICAL RISKS DETECTED**'
        elif high > 0:
            status = '⚠️ **HIGH RISKS DETECTED**'
        else:
            status = '✅ **NO CRITICAL ISSUES**'
        
        return f"""## 📊 Executive Summary

{status}

| Severity | Count |
|----------|-------|
| **Total Findings** | **{total}** |
| {self.severity_emoji['critical']} Critical | {critical} |
| {self.severity_emoji['high']} High | {high} |
| {self.severity_emoji['medium']} Medium | {summary['medium']} |
| {self.severity_emoji['low']} Low | {summary['low']} |
"""

    def _generate_compliance_section(self, compliance_data: Dict[str, Any]) -> str:
        """Generate GDPR compliance section"""
        if not compliance_data:
            return "## ⚖️ GDPR Compliance\n\nNo specific GDPR violations detected."
            
        section = ["## ⚖️ GDPR Compliance Report\n"]
        section.append("| Article | Description | Violations |")
        section.append("|---------|-------------|------------|")
        
        for article, data in compliance_data.items():
            count = data['count']
            desc = data['description']
            section.append(f"| **{article}** | {desc} | {count} |")
            
        section.append("\n> **Note:** This mapping is automated and does not constitute legal advice.")
        return '\n'.join(section)

    def _generate_riskiest_files(self, files_data: Dict[str, Any]) -> str:
        """Generate section for top riskiest files"""
        if not files_data:
            return ""
            
        section = ["## 📂 Top Riskiest Files\n"]
        section.append("Files with the highest concentration of privacy issues:\n")
        section.append("| File | Risk Score | Findings | Critical |")
        section.append("|------|------------|----------|----------|")
        
        # Show top 5
        for file_path, data in list(files_data.items())[:5]:
            score = data['score']
            count = data['findings_count']
            crit = data['critical_count']
            section.append(f"| `{file_path}` | {score} | {count} | {crit} |")
            
        return '\n'.join(section)

    def _generate_detailed_findings(self, findings: List[Union[Finding, Dict[str, Any]]]) -> str:
        """Generate detailed findings section"""
        # Helper to get severity
        def get_severity(f):
            if isinstance(f, dict):
                return f.get('severity', 'info')
            return f.severity.value if hasattr(f.severity, 'value') else f.severity

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            findings, 
            key=lambda x: severity_order.get(get_severity(x), 5)
        )
        
        # Take top 10 critical/high
        top_findings = [f for f in sorted_findings if get_severity(f) in ['critical', 'high']][:10]
        
        if not top_findings:
            return "## 🔍 Detailed Findings\n\nNo critical or high severity findings to detail."
            
        section = ["## 🔍 Top Critical & High Findings\n"]
        
        for i, finding in enumerate(top_findings, 1):
            f_dict = finding if isinstance(finding, dict) else finding.to_dict()
            section.append(self._format_finding_detailed(f_dict, i))
            
        remaining = len(findings) - len(top_findings)
        if remaining > 0:
            section.append(f"\n*... and {remaining} more findings. See JSON report for full details.*")
            
        return '\n'.join(section)

    def _format_finding_detailed(self, finding: Dict[str, Any], number: int) -> str:
        """Format a single finding with full details"""
        rule = finding.get('rule', 'Unknown Rule')
        file_path = finding.get('file', 'Unknown file')
        line = finding.get('line', 0)
        snippet = finding.get('snippet', '')
        classification = finding.get('classification', {})
        severity = finding.get('severity', 'info')
        
        # Header
        header = f"### {number}. {rule} ({self.severity_emoji.get(severity, '')} {severity.title()})"
        
        # Location
        location = f"**📍 Location:** `{file_path}:{line}`"
        
        # PII types if available
        pii_section = ""
        pii_types = classification.get('pii_types', [])
        if pii_types:
            pii_list = ', '.join(pii_types)
            pii_section = f"**🔍 PII Detected:** {pii_list}"
        
        # Code snippet
        code_section = ""
        if snippet:
            lang = self._detect_language(file_path)
            code_section = f"**💻 Code:**\n```{lang}\n{snippet}\n```"
        
        # Remediation
        fix = self._generate_fix_suggestion(finding)
        fix_section = f"**✅ How to Fix:**\n{fix}"
        
        # Flow Story
        flow_section = ""
        flow_path = finding.get('flow_path', [])
        if flow_path:
            flow_section = "**🌊 Data Flow Story:**\n"
            flow_section += "```mermaid\nflowchart TD\n"
            for i, step in enumerate(flow_path):
                step_clean = str(step).replace('"', "'").replace('(', '').replace(')', '')
                if i == 0:
                    flow_section += f"    step{i}([\"🟢 {step_clean}\"])\n"
                elif i == len(flow_path) - 1:
                    flow_section += f"    step{i}([\"🔴 {step_clean}\"])\n"
                else:
                    flow_section += f"    step{i}[\"🔄 {step_clean}\"]\n"
                
                if i > 0:
                    flow_section += f"    step{i-1} --> step{i}\n"
            flow_section += "```"
        
        parts = [header, location]
        if pii_section:
            parts.append(pii_section)
        if flow_section:
            parts.append(flow_section)
        if code_section:
            parts.append(code_section)
        parts.append(fix_section)
        
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
        
        if 'LOG' in rule.upper():
            return "- Remove PII from log messages\n- Use user IDs instead of emails/names"
        elif 'HTTP' in rule.upper() and 'PLAIN' in rule.upper():
            return "- Use HTTPS instead of HTTP\n- Update all API endpoints to use HTTPS"
        elif 'API_KEY' in rule.upper() or 'SECRET' in rule.upper():
            return "- Move secrets to environment variables\n- Use `.env` file"
        elif 'PASSWORD' in rule.upper():
            return "- Hash passwords before storage\n- Never store plaintext passwords"
        else:
            return "- Review this finding and implement appropriate security controls"

    def _generate_mermaid_graph(self, scan_result: Dict[str, Any]) -> str:
        """Generate horizontal layered architecture graph with risk-based coloring"""
        graph_data = scan_result.get('semantic_graph', {})
        nodes = graph_data.get('nodes', [])
        edges = graph_data.get('edges', [])
        
        if not nodes or not edges:
            return ""
            
        lines = ["## 🗺️ Data Flow Architecture", "", 
                 "> **Note:** This diagram uses [Mermaid](https://mermaid.js.org/).",
                 "", "```mermaid", "flowchart LR"]
        
        # Basic styles
        lines.append("  classDef sinkCritical fill:#fecaca,stroke:#dc2626,stroke-width:4px")
        lines.append("  classDef default fill:#f9f9f9,stroke:#333,stroke-width:1px")
        
        # Limit graph size for readability
        if len(edges) > 50:
             lines.append("  %% Graph too large to render inline")
             lines.append("```")
             return "\n".join(lines)

        for edge in edges:
             src = edge['source'].replace('-', '_').replace('.', '_').replace('/', '_')
             dst = edge['target'].replace('-', '_').replace('.', '_').replace('/', '_')
             lines.append(f"  {src} --> {dst}")
             
        lines.append("```")
        return "\n".join(lines)

    def _generate_footer(self) -> str:
        """Generate report footer"""
        return """---
**Generated by [Privalyse](https://privalyse.com)**"""
