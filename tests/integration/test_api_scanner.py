import pytest
import os
import jwt
import json
from unittest.mock import patch, MagicMock
from src.redteam.scanners.api_scanner import APIScanner
from src.redteam.core.finding import Finding, Severity
from vulnerable_app.app import app as vulnerable_app


@pytest.fixture
def swagger_file():
    swagger_file = "test_swagger.json"
    with open(swagger_file, "w") as f:
        f.write(
            """
            {
                "paths": {
                    "/api/invoices/{invoice_id}": {
                        "get": {
                            "security": [{"bearerAuth": []}]
                        }
                    }
                }
            }
            """
        )
    yield swagger_file
    os.remove(swagger_file)


@patch('requests.get')
def test_idor_scanner_detects_vulnerability(mock_requests_get, swagger_file):
    """
    Test that the IDORScanner can successfully detect the
    vulnerability in the vulnerable_app.
    """
    app = vulnerable_app.test_client()
    secret_key = "your-secret-key"
    primary_user_token = jwt.encode(
        {"user_id": 1}, secret_key, algorithm="HS256"
    )
    secondary_user_token = jwt.encode(
        {"user_id": 2}, secret_key, algorithm="HS256"
    )

    def mock_request_side_effect(url, headers):
        response = app.get(url, headers=headers)
        mock_response = MagicMock()
        mock_response.status_code = response.status_code
        try:
            mock_response.json.return_value = json.loads(response.data)
        except json.JSONDecodeError:
            mock_response.json.return_value = {}
        mock_response.headers = response.headers
        return mock_response

    mock_requests_get.side_effect = mock_request_side_effect

    config = {
        "api_url": "http://localhost:5000",
        "swagger_file": swagger_file,
        "primary_user_token": primary_user_token,
        "secondary_user_token": secondary_user_token,
        "secondary_user_resource_ids": [2],
    }

    scanner = APIScanner(config)
    findings = scanner.scan()

    idor_findings = [f for f in findings if f.title == "Insecure Direct Object Reference (IDOR)"]
    assert len(idor_findings) == 1
    assert idor_findings[0].severity == Severity.HIGH
    assert idor_findings[0].description == "User 1 can access resource belonging to user 2 at GET /api/invoices/{invoice_id}"
