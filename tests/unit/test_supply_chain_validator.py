import unittest
from unittest.mock import patch, MagicMock
from src.redteam.scanners.supply_chain_validator import SupplyChainValidator
from src.redteam.core.finding import Finding, Severity
import json

class TestSupplyChainValidator(unittest.TestCase):
    def setUp(self):
        self.config = {
            "static_analysis_path": "/path/to/project",
            "sbom_path": "/path/to/project/sbom.json",
        }
        self.scanner = SupplyChainValidator(self.config)

    @patch("os.path.exists")
    @patch("builtins.open")
    @patch("requests.post")
    def test_scan_dependencies_for_malware(
        self, mock_requests_post, mock_open, mock_os_path_exists
    ):
        mock_os_path_exists.return_value = True
        mock_open.return_value = unittest.mock.mock_open(read_data="requests==2.25.1").return_value
        mock_requests_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"vulns": [{"summary": "Malicious package"}]},
        )

        with patch.object(self.scanner, "_extract_dependencies", return_value=[{"name": "requests", "version": "2.25.1", "ecosystem": "PyPI"}]):
            findings = self.scanner._scan_dependencies_for_malware()

        # Should have one finding for malware
        self.assertEqual(len(findings), 1)
        self.assertIsInstance(findings[0], Finding)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertIn("Malicious Dependency Detected", findings[0].title)

if __name__ == "__main__":
    unittest.main()
