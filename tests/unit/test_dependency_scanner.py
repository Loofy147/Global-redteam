import pytest
from src.redteam.scanners.dependency_scanner import DependencyScanner
from src.redteam.core.finding import Severity
from unittest.mock import patch, MagicMock
import json
import os


@pytest.fixture
def requirements_file():
    requirements_content = """
requests==2.32.5
numpy==1.20.3
"""
    file_path = "test_requirements.txt"
    with open(file_path, "w") as f:
        f.write(requirements_content)
    yield file_path
    os.remove(file_path)


@patch('requests.post')
def test_dependency_scanner(mock_requests_post, requirements_file):
    def mock_post_side_effect(url, data):
        payload = json.loads(data)
        if payload["package"]["name"] == "requests":
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "vulns": [
                    {
                        "id": "OSV-2021-1234",
                        "summary": "Request vulnerability",
                        "database_specific": {"severity": "HIGH"}
                    }
                ]
            }
            return response
        else:
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {}
            return response

    mock_requests_post.side_effect = mock_post_side_effect

    scanner = DependencyScanner(config={"path": os.path.dirname(requirements_file)})
    findings = scanner.scan()

    assert len(findings) == 1
    assert findings[0].title == "Vulnerable Dependency: requests==2.32.5"
    assert findings[0].severity == Severity.HIGH
