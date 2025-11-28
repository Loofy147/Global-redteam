import unittest
from unittest.mock import patch, MagicMock
from src.redteam.scanners.formal_verifier import FormalVerifier
from src.redteam.core.finding import Finding, Severity

class TestFormalVerifier(unittest.TestCase):
    def setUp(self):
        self.config = {
            "static_analysis_path": "/path/to/c_code",
            "verification_engine": "frama-c",
        }
        self.scanner = FormalVerifier(self.config)

    @patch("os.walk")
    @patch("subprocess.run")
    def test_scan_implementation_with_vulnerability(
        self, mock_subprocess_run, mock_os_walk
    ):
        mock_os_walk.return_value = [("/path/to/c_code", [], ["test.c"])]
        mock_subprocess_run.return_value = MagicMock(
            stdout="ALARM", stderr="", returncode=0
        )

        findings = self.scanner._scan_implementation()

        self.assertEqual(len(findings), len(self.scanner.properties_to_verify))
        self.assertIsInstance(findings[0], Finding)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    @patch("os.walk")
    @patch("subprocess.run")
    def test_scan_implementation_no_vulnerability(
        self, mock_subprocess_run, mock_os_walk
    ):
        mock_os_walk.return_value = [("/path/to/c_code", [], ["test.c"])]
        mock_subprocess_run.return_value = MagicMock(
            stdout="VALID", stderr="", returncode=0
        )

        findings = self.scanner._scan_implementation()

        self.assertEqual(len(findings), 0)

if __name__ == "__main__":
    unittest.main()
