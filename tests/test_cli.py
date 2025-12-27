import unittest
from unittest.mock import patch, MagicMock
import sys
import json
import logging
from pathlib import Path
from privalyse_scanner.cli import setup_logging, PrivalyseJSONEncoder, main

class TestCLI(unittest.TestCase):

    def test_setup_logging(self):
        with patch('logging.basicConfig') as mock_basic_config:
            setup_logging(debug=True)
            mock_basic_config.assert_called_with(
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%H:%M:%S',
                level=logging.DEBUG
            )

            setup_logging(quiet=True)
            mock_basic_config.assert_called_with(
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%H:%M:%S',
                level=logging.ERROR
            )

            setup_logging()
            mock_basic_config.assert_called_with(
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%H:%M:%S',
                level=logging.INFO
            )

    def test_json_encoder(self):
        encoder = PrivalyseJSONEncoder()
        
        # Test set
        self.assertEqual(encoder.default({1, 2, 3}), [1, 2, 3])
        
        # Test Path
        # Normalize path separators for cross-platform compatibility
        encoded_path = encoder.default(Path('/tmp/test'))
        self.assertEqual(str(Path(encoded_path)), str(Path('/tmp/test')))
        
        # Test object with to_dict
        class MockObj:
            def to_dict(self):
                return {'a': 1}
        self.assertEqual(encoder.default(MockObj()), {'a': 1})
        
        # Test default behavior (should raise TypeError for unknown types)
        with self.assertRaises(TypeError):
            encoder.default(object())

    @patch('privalyse_scanner.cli.PrivalyseScanner')
    @patch('privalyse_scanner.cli.ConfigLoader')
    @patch('argparse.ArgumentParser.parse_args')
    def test_main_execution(self, mock_args, mock_config_loader, mock_scanner_cls):
        # Setup mocks
        mock_args.return_value = MagicMock(
            root=Path('.'),
            out='report.md',
            exclude=None,
            max_workers=4,
            max_files=None,
            format='md',
            debug=False,
            quiet=False,
            init=False
        )
        
        mock_scanner = mock_scanner_cls.return_value
        mock_scanner.scan.return_value = {
            'findings': [],
            'meta': {'total_findings': 0},
            'compliance': {'score': 100, 'status': 'compliant', 'critical_findings': 0, 'high_findings': 0}
        }

        # Run main
        with patch('builtins.print'): # Suppress print output
            main()

        # Verify scanner was initialized and run
        mock_scanner_cls.assert_called()
        mock_scanner.scan.assert_called()

    @patch('sys.argv', ['privalyse', '--root', '/tmp', '--out', 'out.json', '--format', 'json'])
    @patch('privalyse_scanner.cli.PrivalyseScanner')
    @patch('privalyse_scanner.cli.ConfigLoader')
    def test_main_args(self, mock_config_loader, mock_scanner_cls):
        mock_scanner = mock_scanner_cls.return_value
        mock_scanner.scan.return_value = {
            'findings': [], 
            'meta': {'total_findings': 0},
            'compliance': {'score': 80, 'status': 'compliant', 'critical_findings': 0, 'high_findings': 0}
        }
        
        with patch('builtins.print'):
            main()
            
        # Verify args were passed correctly (implicitly via the mock calls if we inspected them deeply, 
        # but here just ensuring it runs without error with these args)
        mock_scanner_cls.assert_called()

if __name__ == '__main__':
    unittest.main()
