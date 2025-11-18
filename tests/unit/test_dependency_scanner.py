import unittest
from unittest.mock import patch, mock_open
from src.redteam.scanners.dependency_scanner import DependencyScanner

class TestDependencyScanner(unittest.TestCase):
    """
    Tests for the DependencyScanner.
    """

    @patch('requests.get')
    def test_scan_dependency_confusion(self, mock_get):
        """
        Tests that the scanner correctly identifies a dependency confusion vulnerability.
        """
        # Mock the response from PyPI
        mock_response = unittest.mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'info': {
                'version': '1.0.0'
            }
        }
        mock_get.return_value = mock_response

        # Create a dummy requirements.txt
        requirements_content = "vulnerable-package==0.1.0"
        m = mock_open(read_data=requirements_content)
        with patch('builtins.open', m):
            scanner = DependencyScanner(config={'dependency_file': 'requirements.txt'})
            findings = scanner._scan_implementation()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, 'Dependency Confusion')
        self.assertIn('vulnerable-package', findings[0].description)

if __name__ == '__main__':
    unittest.main()
