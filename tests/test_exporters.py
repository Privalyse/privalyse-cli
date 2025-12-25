import unittest
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
from privalyse_scanner.exporters.json_exporter import JSONExporter
from privalyse_scanner.exporters.markdown_exporter import MarkdownExporter
from privalyse_scanner.exporters.html_exporter import HTMLExporter
from privalyse_scanner.models.finding import Finding

class TestExporters(unittest.TestCase):

    def setUp(self):
        self.findings = [
            {
                'rule': 'TEST_RULE',
                'file': 'test.py',
                'line': 10,
                'severity': 'high',
                'description': 'Test finding',
                'snippet': 'secret = "123"',
                'confidence': 'high',
                'classification': {'pii_types': []}
            }
        ]
        self.metadata = {
            'timestamp': '2023-01-01T00:00:00',
            'files_scanned': 10,
            'duration': 1.5
        }
        self.scan_result = {
            'findings': self.findings,
            'metadata': self.metadata,
            'compliance': {'score': 85, 'status': 'compliant'},
            'flows': []
        }

    def test_json_exporter(self):
        exporter = JSONExporter()
        json_output = exporter.export(self.findings, self.metadata)
        
        data = json.loads(json_output)
        self.assertIn('summary', data)
        self.assertIn('findings', data)
        self.assertEqual(len(data['findings']), 1)
        self.assertEqual(data['findings'][0]['rule'], 'TEST_RULE')

    def test_markdown_exporter(self):
        exporter = MarkdownExporter()
        md_output = exporter.export(self.findings, self.metadata)
        
        self.assertIn('# 🛡️ Privalyse Scan Report', md_output)
        self.assertIn('TEST_RULE', md_output)
        self.assertIn('test.py', md_output)

    def test_html_exporter(self):
        exporter = HTMLExporter()
        output_path = 'test_report.html'
        
        try:
            exporter.export(self.scan_result, output_path)
            
            self.assertTrue(os.path.exists(output_path))
            with open(output_path, 'r') as f:
                content = f.read()
                self.assertIn('<!DOCTYPE html>', content)
                self.assertIn('Test Rule', content)
        finally:
            if os.path.exists(output_path):
                os.remove(output_path)

if __name__ == '__main__':
    unittest.main()
