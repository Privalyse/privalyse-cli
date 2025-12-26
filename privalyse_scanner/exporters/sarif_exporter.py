import json
from typing import Dict, Any, List, Union
from privalyse_scanner.models.finding import Finding
from privalyse_scanner import __version__

class SARIFExporter:
    """
    Export scan results to SARIF format (Static Analysis Results Interchange Format).
    """

    def export(self, findings: List[Union[Finding, Dict[str, Any]]], metadata: Dict[str, Any]) -> str:
        """
        Generate SARIF report.
        
        Args:
            findings: List of Finding objects
            metadata: Scan metadata
            
        Returns:
            SARIF JSON string
        """
        rules = {}
        results = []
        
        for finding in findings:
            # Handle both object and dict (legacy)
            if isinstance(finding, dict):
                rule_id = finding.get('rule', 'UNKNOWN')
                severity = finding.get('severity', 'warning')
                file_path = finding.get('file', '')
                line = finding.get('line', 1)
                message = finding.get('classification', {}).get('reasoning', 'Privacy issue detected')
                snippet = finding.get('snippet', '')
            else:
                rule_id = finding.rule
                severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
                file_path = finding.file
                line = finding.line
                message = finding.classification.reasoning
                snippet = finding.snippet

            # Map severity to SARIF level
            level = self._map_severity(severity)
            
            # Register rule if not exists
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {
                        "text": f"Privacy violation: {rule_id}"
                    },
                    "fullDescription": {
                        "text": message
                    },
                    "properties": {
                        "security-severity": self._map_security_severity(severity)
                    }
                }

            # Create result
            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": message
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path
                            },
                            "region": {
                                "startLine": int(line) if line else 1,
                                "snippet": {
                                    "text": snippet
                                }
                            }
                        }
                    }
                ]
            }
            results.append(result)

        sarif_output = {
            "version": "2.1.0",
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Privalyse",
                            "version": __version__,
                            "rules": list(rules.values())
                        }
                    },
                    "results": results
                }
            ]
        }
        
        return json.dumps(sarif_output, indent=2)

    def _map_severity(self, severity: str) -> str:
        """Map Privalyse severity to SARIF level"""
        severity = severity.lower()
        if severity in ['critical', 'high']:
            return 'error'
        elif severity in ['medium']:
            return 'warning'
        else:
            return 'note'

    def _map_security_severity(self, severity: str) -> str:
        """Map Privalyse severity to GitHub Security Severity (0.0-10.0)"""
        severity = severity.lower()
        mapping = {
            'critical': "9.0",
            'high': "7.0",
            'medium': "5.0",
            'low': "3.0",
            'info': "1.0"
        }
        return mapping.get(severity, "1.0")
