import unittest
from unittest.mock import patch, MagicMock
from src.redteam.scanners.llm_autonomous_hunter import LLMAutonomousHunter
from src.redteam.core.finding import Finding, Severity
import json

class TestLLMAutonomousHunter(unittest.TestCase):
    def setUp(self):
        self.config = {
            "static_analysis_path": "/path/to/source_code",
        }

    @patch("os.walk")
    @patch("src.redteam.scanners.llm_autonomous_hunter.LLMAutonomousHunter._get_anthropic_client")
    @patch("json.loads")
    def test_scan_implementation_with_vulnerability(
        self, mock_json_loads, mock_get_anthropic_client, mock_os_walk
    ):
        scanner = LLMAutonomousHunter(self.config)
        mock_os_walk.return_value = [("/path/to/source_code", [], ["test.py"])]

        mock_anthropic_instance = MagicMock()
        mock_get_anthropic_client.return_value = mock_anthropic_instance
        mock_json_loads.return_value = [{"vulnerability_type": "SQL Injection", "line_number": 10, "attack_vector": "...", "confidence": 0.9}]

        # Mock hypothesis generation
        mock_anthropic_instance.messages.create.side_effect = [
            MagicMock(content=[MagicMock()]),
            MagicMock(content=[MagicMock(text="Deep analysis content... remediation ...")]),
            MagicMock(content=[MagicMock(text="requests.post(...)")]),
        ]

        # Patch the file reading
        with patch("builtins.open", unittest.mock.mock_open(read_data="test code")):
            findings = scanner._scan_implementation()

        self.assertEqual(len(findings), 1)
        self.assertIsInstance(findings[0], Finding)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("LLM-Discovered: SQL Injection", findings[0].title)

if __name__ == "__main__":
    unittest.main()
