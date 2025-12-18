import unittest
from pathlib import Path
from privalyse_scanner.core.scanner import PrivalyseScanner
from privalyse_scanner.models.config import ScanConfig

class TestFlowGraph(unittest.TestCase):
    def test_flow_graph_generation(self):
        # Setup
        demo_path = Path("examples/flow-story-demo")
        config = ScanConfig(root_path=demo_path)
        scanner = PrivalyseScanner(config)
        
        # Scan
        results = scanner.scan()
        graph = results['semantic_graph']
        
        # Verify Nodes
        nodes = {n['id']: n for n in graph['nodes']}
        # We expect nodes for 'email', 'log_message', and potentially 'data' in process_user_data
        
        # Find email node
        email_nodes = [n for n in nodes.values() if n['label'] == 'email']
        self.assertTrue(len(email_nodes) > 0, "Should find 'email' variable node")
        
        # Find log_message node
        log_nodes = [n for n in nodes.values() if n['label'] == 'log_message']
        self.assertTrue(len(log_nodes) > 0, "Should find 'log_message' variable node")
        
        # Verify Edges
        edges = graph['edges']
        # We expect flow from email -> log_message (via process_user_data or direct assignment if simplified)
        
        # Check for at least one data flow edge
        data_flow_edges = [e for e in edges if e['type'] == 'data_flow']
        self.assertTrue(len(data_flow_edges) > 0, "Should have data flow edges")
        
        # Check if we captured the flow type
        flow_types = [e['label'] for e in data_flow_edges]
        print(f"Captured flow types: {flow_types}")
        
        # Check for findings
        findings = results['findings']
        self.assertTrue(len(findings) > 0, "Should find the leak")
        
        # Check if finding has graph info (if we implemented that part yet - we added fields to Finding model)
        # Note: We haven't yet linked the graph back to the Finding object in the scanner logic, 
        # but the Finding model supports it.
        
if __name__ == '__main__':
    unittest.main()
