import unittest
import sys
import os
from pathlib import Path
import tempfile
import shutil
import json

# Add parent directory to path to import privalyse_scanner
sys.path.insert(0, str(Path(__file__).parent.parent))

from privalyse_scanner.core.scanner import PrivalyseScanner
from privalyse_scanner.models.config import ScanConfig

class TestScannerSmoke(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.test_file = Path(self.test_dir) / "test_app.py"
        with open(self.test_file, "w") as f:
            f.write("""
from flask import request

def process_user_data():
    email = request.args.get('email')
    password = request.args.get('password')
    print(f"User email: {email}")  # PII in logs
    db.execute(f"INSERT INTO users VALUES ('{password}')")  # SQL Injection + Password
            """)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_scanner_runs(self):
        config = ScanConfig(
            root_path=Path(self.test_dir)
        )
        scanner = PrivalyseScanner(config)
        results = scanner.scan()
        
        self.assertGreater(len(results['findings']), 0, "Scanner should find issues")
        
        # Check for specific findings
        found_email = any("email" in str(f['classification']['pii_types']) for f in results['findings'])
        self.assertTrue(found_email, "Should detect email PII")

if __name__ == '__main__':
    unittest.main()
