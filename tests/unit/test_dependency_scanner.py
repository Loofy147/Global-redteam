import pytest
from src.redteam.scanners.dependency_scanner import DependencyScanner
from src.redteam.core.finding import Severity
from unittest.mock import patch, MagicMock
import json
import os
from urllib.parse import urlparse


@patch('requests.post')
def test_scan_multi_ecosystem_dependency_confusion(mock_post):
    """
    Tests that the scanner correctly identifies dependency confusion vulnerabilities
    in both Python and Node.js projects.
    """
    def mock_requests_post(url, **kwargs):
        mock_response = MagicMock()
        data = json.loads(kwargs.get("data", "{}"))
        package_name = data.get("package", {}).get("name")

        if "osv.dev" in url:
            mock_response.status_code = 200
            if package_name in ["requests", "flask", "express", "jest", "internal-package"]:
                 mock_response.json.return_value = {"vulns": [{"summary": "mock vulnerability"}]}
            else:
                mock_response.json.return_value = {}

        return mock_response

    mock_post.side_effect = mock_requests_post

    # Create dummy dependency files for the scanner to find
    os.makedirs("./test_scan_dir/vulnerable_app", exist_ok=True)
    with open("./test_scan_dir/vulnerable_app/requirements.txt", "w") as f:
        f.write("requests==2.28.1\nflask==2.1.2\ninternal-package==1.0.0")
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

    scanner = DependencyScanner(config={'path': './test_scan_dir'})
    findings = scanner.scan()

    assert len(findings) == 5

    pypi_findings = [f for f in findings if f.file_path.endswith("requirements.txt")]
    npm_findings = [f for f in findings if f.file_path.endswith("package.json")]

    assert len(pypi_findings) == 3
    pypi_packages = {f.title.split(": ")[1].split("==")[0] for f in pypi_findings}
    assert "requests" in pypi_packages
    assert "flask" in pypi_packages
    assert "internal-package" in pypi_packages

    assert len(npm_findings) == 2
    npm_packages = {f.title.split(": ")[1].split("@")[0] for f in npm_findings}
    assert "express" in npm_packages
    assert "internal-package" in npm_packages

    # Clean up dummy files
    os.remove("./test_scan_dir/vulnerable_app/requirements.txt")
    os.remove("./test_scan_dir/vulnerable_app/package.json")
    os.rmdir("./test_scan_dir/vulnerable_app")
    os.rmdir("./test_scan_dir")

