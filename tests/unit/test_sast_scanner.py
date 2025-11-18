import unittest
from unittest.mock import patch
from src.redteam.scanners.sast_scanner import SastScanner

class TestSastScanner(unittest.TestCase):
    def setUp(self):
        self.config = {
            'static_analysis_path': '/path/to/code',
        }

    @patch('src.redteam.scanners.sast_scanner.AIVulnerabilityDiscovery')
    def test_init(self, mock_sast_engine):
        """Tests that the scanner can be initialized correctly."""
        scanner = SastScanner(self.config)
        mock_sast_engine.assert_called_once()
        self.assertEqual(scanner.config['static_analysis_path'], '/path/to/code')

if __name__ == '__main__':
    unittest.main()
