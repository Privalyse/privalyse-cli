import unittest
import ast
from privalyse_scanner.models.taint import TaintTracker, TaintInfo

class TestSanitization(unittest.TestCase):
    def setUp(self):
        self.tracker = TaintTracker()

    def test_sanitizer_detection(self):
        self.assertTrue(self.tracker.is_sanitizer("hash"))
        self.assertTrue(self.tracker.is_sanitizer("hashlib.sha256"))
        self.assertTrue(self.tracker.is_sanitizer("anonymize_user"))
        self.assertFalse(self.tracker.is_sanitizer("print"))
        self.assertFalse(self.tracker.is_sanitizer("requests.post"))

    def test_propagation_through_sanitizer(self):
        # Code: hashed = hash(password)
        # password is tainted
        
        # 1. Taint password
        self.tracker.mark_tainted("password", ["password"], 1, "source")
        
        # 2. Simulate assignment: hashed = hash(password)
        # AST construction
        call_node = ast.Call(
            func=ast.Name(id="hash", ctx=ast.Load()),
            args=[ast.Name(id="password", ctx=ast.Load())],
            keywords=[]
        )
        
        self.tracker.propagate_through_assignment("hashed", call_node, 2)
        
        # 3. Verify hashed is tainted but sanitized
        info = self.tracker.get_taint("hashed")
        self.assertIsNotNone(info)
        self.assertTrue(info.is_sanitized)
        self.assertEqual(info.pii_types, ["password"])

    def test_propagation_through_non_sanitizer(self):
        # Code: leaked = print(password)
        
        self.tracker.mark_tainted("password", ["password"], 1, "source")
        
        call_node = ast.Call(
            func=ast.Name(id="print", ctx=ast.Load()),
            args=[ast.Name(id="password", ctx=ast.Load())],
            keywords=[]
        )
        
        self.tracker.propagate_through_assignment("leaked", call_node, 2)
        
        info = self.tracker.get_taint("leaked")
        self.assertIsNotNone(info)
        self.assertFalse(info.is_sanitized)

    def test_propagation_of_already_sanitized(self):
        # Code: 
        # h = hash(p)
        # x = h
        
        self.tracker.mark_tainted("p", ["password"], 1, "source")
        
        # h = hash(p)
        call_node = ast.Call(
            func=ast.Name(id="hash", ctx=ast.Load()),
            args=[ast.Name(id="p", ctx=ast.Load())],
            keywords=[]
        )
        self.tracker.propagate_through_assignment("h", call_node, 2)
        
        h_info = self.tracker.get_taint("h")
        self.assertTrue(h_info.is_sanitized)
        
        # x = h
        self.tracker.propagate_through_assignment("x", ast.Name(id="h", ctx=ast.Load()), 3)
        
        x_info = self.tracker.get_taint("x")
        self.assertIsNotNone(x_info)
        self.assertTrue(x_info.is_sanitized)

if __name__ == '__main__':
    unittest.main()
