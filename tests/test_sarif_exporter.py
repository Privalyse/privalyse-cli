import unittest
import json
import os
from privalyse_scanner.exporters.sarif_exporter import SARIFExporter
from privalyse_scanner.models.finding import Finding, Severity, ClassificationResult

class TestSARIFExporter(unittest.TestCase):
    def setUp(self):
        self.exporter = SARIFExporter()
        self.classification = ClassificationResult(
            pii_types=['email'],
            sectors=['marketing'],
            severity='high',
            article='Art. 6',
            legal_basis_required=True,
            category='PII',
            confidence=0.9,
            reasoning='Email found in log',
            gdpr_articles=['Art. 6']
        )
        self.finding = Finding(
            rule='LOG_LEAK',
            severity=Severity.HIGH,
            file='src/app.py',
            line=10,
            snippet='logger.info(email)',
            classification=self.classification
        )
        self.findings = [self.finding]
        self.metadata = {'scan_time': 1.5}

    def test_sarif_structure(self):
        output = self.exporter.export(self.findings, self.metadata)
        data = json.loads(output)
        
        # Check root structure
        self.assertEqual(data['version'], '2.1.0')
        self.assertEqual(data['runs'][0]['tool']['driver']['name'], 'Privalyse')
        
        # Check rules
        rules = data['runs'][0]['tool']['driver']['rules']
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]['id'], 'LOG_LEAK')
        self.assertEqual(rules[0]['properties']['security-severity'], '7.0')  # High = 7.0
        
        # Check results
        results = data['runs'][0]['results']
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['ruleId'], 'LOG_LEAK')
        self.assertEqual(results[0]['level'], 'error')  # High = error
        self.assertEqual(results[0]['locations'][0]['physicalLocation']['artifactLocation']['uri'], 'src/app.py')

    def test_severity_mapping(self):
        # Test Critical
        self.assertEqual(self.exporter._map_severity('critical'), 'error')
        self.assertEqual(self.exporter._map_security_severity('critical'), '9.0')
        
        # Test Medium
        self.assertEqual(self.exporter._map_severity('medium'), 'warning')
        self.assertEqual(self.exporter._map_security_severity('medium'), '5.0')
        
        # Test Low
        self.assertEqual(self.exporter._map_severity('low'), 'note')
        self.assertEqual(self.exporter._map_security_severity('low'), '3.0')
