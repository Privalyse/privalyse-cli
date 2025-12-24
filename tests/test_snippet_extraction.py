import unittest
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from privalyse_scanner.analyzers.python_analyzer import PythonAnalyzer

class TestSnippetExtraction(unittest.TestCase):
    """
    Regression tests for snippet extraction.
    Ensures that findings contain the correct source code context.
    """
    
    def setUp(self):
        self.analyzer = PythonAnalyzer()
        self.file_path = Path("test_snippet.py")

    def test_ai_pii_leak_snippet(self):
        """Test that AI_PII_LEAK findings contain the correct code snippet."""
        # We need to simulate a tainted flow for the analyzer to pick it up
        code = """
import openai
def process_request(request):
    # Source: request.json (tainted)
    data = request.json
    email = data.get("email")
    
    # Sink: OpenAI (AI_PII_LEAK)
    openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": email}]
    )
"""
        findings, _ = self.analyzer.analyze_file(self.file_path, code)
        
        ai_leak = next((f for f in findings if f.rule == "AI_PII_LEAK"), None)
        self.assertIsNotNone(ai_leak, "Should detect AI_PII_LEAK")
        
        # Verify snippet is not empty and contains relevant code
        self.assertTrue(ai_leak.snippet, "Snippet should not be empty")
        self.assertIn("openai.ChatCompletion.create", ai_leak.snippet)
        self.assertIn("model=\"gpt-4\"", ai_leak.snippet)

    def test_hardcoded_secret_snippet(self):
        """Test that HARDCODED_SECRET findings contain the correct code snippet."""
        code = """
def connect():
    api_key = "sk_live_DUMMY_TEST_KEY_DO_NOT_USE_12345"
    return api_key
"""
        findings, _ = self.analyzer.analyze_file(self.file_path, code)
        
        secret_finding = next((f for f in findings if f.rule == "HARDCODED_SECRET"), None)
        self.assertIsNotNone(secret_finding, "Should detect HARDCODED_SECRET")
        
        self.assertTrue(secret_finding.snippet, "Snippet should not be empty")
        # Secrets are redacted in snippets
        self.assertIn("api_key =", secret_finding.snippet)
        self.assertIn("***", secret_finding.snippet)

    def test_print_sensitive_data_snippet(self):
        """Test that PRINT_SENSITIVE_DATA findings contain the correct code snippet."""
        code = """
def debug_user(request):
    data = request.json
    password = data.get("password")
    print(f"User password is: {password}")
"""
        findings, _ = self.analyzer.analyze_file(self.file_path, code)
        
        print_finding = next((f for f in findings if f.rule == "PRINT_SENSITIVE_DATA"), None)
        self.assertIsNotNone(print_finding, "Should detect PRINT_SENSITIVE_DATA")
        
        self.assertTrue(print_finding.snippet, "Snippet should not be empty")
        self.assertIn("print(", print_finding.snippet)
        self.assertIn("password", print_finding.snippet)

if __name__ == '__main__':
    unittest.main()
