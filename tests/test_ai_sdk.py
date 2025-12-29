import unittest
import ast
from pathlib import Path
from privalyse_scanner.analyzers.python_analyzer import PythonAnalyzer, is_masked_text, PRIVALYSE_MASK_PATTERN
from privalyse_scanner.models.finding import Finding

class TestAISDKDetection(unittest.TestCase):
    def setUp(self):
        self.analyzer = PythonAnalyzer()

    def test_openai_leak(self):
        code = """
import openai

def chat(user_email):
    # user_email is PII
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"User {user_email} asked..."}]
    )
"""
        # We need to simulate taint tracking context
        # Since analyze_file does everything, we can use it directly but we need to ensure
        # user_email is treated as tainted.
        # In a real scan, this comes from sources. Here we can mock it or use a known source pattern.
        
        # Let's use a known source pattern to trigger taint
        code_with_source = """
from flask import request
import openai

@app.route('/chat')
def chat():
    user_email = request.json['email'] # Source
    # Sink
    openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_email}]
    )
"""
        findings, _ = self.analyzer.analyze_file(Path("test.py"), code_with_source)
        
        ai_leaks = [f for f in findings if f.rule == "AI_PII_LEAK"]
        self.assertTrue(len(ai_leaks) > 0)
        self.assertEqual(ai_leaks[0].classification.reasoning, "Unsanitized PII (email) sent to AI Sink (openai)")

    def test_langchain_leak(self):
        code = """
from flask import request
from langchain.llms import OpenAI

def process():
    secret = request.json['api_key'] # Source: password/token
    llm = OpenAI()
    llm.predict(f"The key is {secret}")
"""
        findings, _ = self.analyzer.analyze_file(Path("test.py"), code)
        ai_leaks = [f for f in findings if f.rule == "AI_PII_LEAK"]
        self.assertTrue(len(ai_leaks) > 0)
        self.assertIn("langchain", ai_leaks[0].classification.reasoning.lower())

    def test_sanitized_ai_call(self):
        code = """
from flask import request
import openai
from utils import anonymize

def chat():
    email = request.json['email']
    safe_email = anonymize(email) # Sanitizer
    
    openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": safe_email}]
    )
"""
        findings, _ = self.analyzer.analyze_file(Path("test.py"), code)
        ai_leaks = [f for f in findings if f.rule == "AI_PII_LEAK"]
        self.assertEqual(len(ai_leaks), 0, "Should not report leak if sanitized")


class TestPrivalyseMaskIntegration(unittest.TestCase):
    """Tests for privalyse-mask library integration"""
    
    def setUp(self):
        self.analyzer = PythonAnalyzer()
    
    def test_masked_text_pattern_detection(self):
        """Test that privalyse-mask placeholder patterns are detected"""
        # Valid masked text patterns from privalyse-mask
        self.assertTrue(is_masked_text("{Name_x92}"))
        self.assertTrue(is_masked_text("{Email_abc123}"))
        self.assertTrue(is_masked_text("{German_IBAN}"))
        self.assertTrue(is_masked_text("{Phone_xyz}"))
        self.assertTrue(is_masked_text("Hello {Name_x92}, your email is {Email_abc}"))
        
        # Non-masked text should return False
        self.assertFalse(is_masked_text("peter@example.com"))
        self.assertFalse(is_masked_text("Regular text without masking"))
        self.assertFalse(is_masked_text("{incomplete"))
        self.assertFalse(is_masked_text(""))
    
    def test_privalyse_mask_sanitizer_recognition(self):
        """Test that privalyse-mask function calls are recognized as sanitizers"""
        code = """
from flask import request
from privalyse_mask import PrivalyseMasker
import openai

masker = PrivalyseMasker()

def chat():
    user_email = request.json['email']
    masked_text, mapping = masker.mask(user_email)  # Sanitizer!
    
    # This should NOT be flagged - masked data is safe
    openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": masked_text}]
    )
"""
        findings, _ = self.analyzer.analyze_file(Path("test.py"), code)
        ai_leaks = [f for f in findings if f.rule == "AI_PII_LEAK"]
        self.assertEqual(len(ai_leaks), 0, "Should not flag masked data as PII leak")
    
    def test_privalyse_mask_struct_sanitizer(self):
        """Test that mask_struct is recognized as sanitizer"""
        code = """
from flask import request
from privalyse_mask import PrivalyseMasker
import openai

masker = PrivalyseMasker()

def chat():
    user_data = request.json  # Contains PII
    safe_data, mapping = masker.mask_struct(user_data)  # Sanitizer!
    
    openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": str(safe_data)}]
    )
"""
        findings, _ = self.analyzer.analyze_file(Path("test.py"), code)
        ai_leaks = [f for f in findings if f.rule == "AI_PII_LEAK"]
        self.assertEqual(len(ai_leaks), 0, "mask_struct should be recognized as sanitizer")

    def test_unsanitized_privalyse_mask_import_still_flags(self):
        """Test that importing privalyse-mask doesn't auto-sanitize everything"""
        code = """
from flask import request
from privalyse_mask import PrivalyseMasker
import openai

masker = PrivalyseMasker()

def chat():
    user_email = request.json['email']
    # Note: NOT masking before sending!
    
    openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_email}]  # BAD!
    )
"""
        findings, _ = self.analyzer.analyze_file(Path("test.py"), code)
        ai_leaks = [f for f in findings if f.rule == "AI_PII_LEAK"]
        self.assertTrue(len(ai_leaks) > 0, "Should flag direct PII even with privalyse-mask imported")


class TestAdditionalAISinks(unittest.TestCase):
    """Tests for additional AI provider detection"""
    
    def setUp(self):
        self.analyzer = PythonAnalyzer()
    
    def test_anthropic_leak(self):
        """Test Claude/Anthropic detection"""
        code = """
from flask import request
import anthropic

def chat():
    user_email = request.json['email']
    client = anthropic.Anthropic()
    client.messages.create(
        model="claude-3",
        messages=[{"role": "user", "content": user_email}]
    )
"""
        findings, _ = self.analyzer.analyze_file(Path("test.py"), code)
        ai_leaks = [f for f in findings if f.rule == "AI_PII_LEAK"]
        self.assertTrue(len(ai_leaks) > 0, "Should detect Anthropic AI leak")

    def test_google_gemini_leak(self):
        """Test Google Gemini detection"""
        code = """
from flask import request
import google.generativeai as genai

def chat():
    user_email = request.json['email']
    model = genai.GenerativeModel('gemini-pro')
    model.generate_content(user_email)
"""
        findings, _ = self.analyzer.analyze_file(Path("test.py"), code)
        ai_leaks = [f for f in findings if f.rule == "AI_PII_LEAK"]
        self.assertTrue(len(ai_leaks) > 0, "Should detect Google Gemini AI leak")


if __name__ == '__main__':
    unittest.main()
