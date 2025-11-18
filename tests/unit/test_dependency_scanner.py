import unittest
from unittest.mock import patch
from src.redteam.scanners.dependency_scanner import DependencyScanner
import os

class TestDependencyScanner(unittest.TestCase):
    """
    Tests for the DependencyScanner.
    """

    @patch('requests.get')
    def test_scan_multi_ecosystem_dependency_confusion(self, mock_get):
        """
        Tests that the scanner correctly identifies dependency confusion vulnerabilities
        in both Python and Node.js projects.
        """
        def mock_requests_get(url, **kwargs):
            mock_response = unittest.mock.Mock()
            if "pypi.org" in url:
                if "requests" in url or "flask" in url:
                    mock_response.status_code = 200
                    mock_response.json.return_value = {'info': {'version': '1.0.0'}}
                else:
                    mock_response.status_code = 404
            elif "registry.npmjs.org" in url:
                if "express" in url or "jest" in url:
                    mock_response.status_code = 200
                else:
                    mock_response.status_code = 404
            return mock_response

        mock_get.side_effect = mock_requests_get

        # Create dummy dependency files for the scanner to find
        os.makedirs("./test_scan_dir/vulnerable_app", exist_ok=True)
        with open("./test_scan_dir/vulnerable_app/requirements.txt", "w") as f:
            f.write("requests==2.28.1\nflask==2.1.2")
        with open("./test_scan_dir/vulnerable_app/package.json", "w") as f:
            f.write("""
{
  "dependencies": {
    "express": "4.17.1",
    "internal-package": "1.0.0"
  },
  "devDependencies": {
    "jest": "27.0.6"
  }
}
            """)

        scanner = DependencyScanner(config={'static_analysis_path': './test_scan_dir'})
        findings = scanner.scan()

        self.assertEqual(len(findings), 4)

        pypi_findings = [f for f in findings if f.affected_component.endswith("requirements.txt")]
        npm_findings = [f for f in findings if f.affected_component.endswith("package.json")]

        self.assertEqual(len(pypi_findings), 2)
        pypi_packages = {f.evidence.split(",")[0].split(": ")[1] for f in pypi_findings}
        self.assertIn("requests", pypi_packages)
        self.assertIn("flask", pypi_packages)

        self.assertEqual(len(npm_findings), 2)
        npm_packages = {f.evidence.split(",")[0].split(": ")[1] for f in npm_findings}
        self.assertIn("express", npm_packages)
        self.assertIn("jest", npm_packages)

        # Clean up dummy files
        os.remove("./test_scan_dir/vulnerable_app/requirements.txt")
        os.remove("./test_scan_dir/vulnerable_app/package.json")
        os.rmdir("./test_scan_dir/vulnerable_app")
        os.rmdir("./test_scan_dir")

if __name__ == '__main__':
    unittest.main()
