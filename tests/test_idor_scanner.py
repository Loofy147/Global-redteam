"""
Tests for the advanced IDOR Scanner
"""

import unittest
import os
import jwt
import json
from unittest.mock import patch
from src.redteam.scanners.idor_scanner import IDORScanner
from vulnerable_app.app import app as vulnerable_app


class TestIDORScanner(unittest.TestCase):
    """Test suite for the IDORScanner."""

    def setUp(self):
        """Set up the test environment."""
        self.app = vulnerable_app.test_client()
        self.secret_key = "your-secret-key"

        # Generate tokens for two different users
        self.primary_user_token = jwt.encode(
            {"user_id": 1}, self.secret_key, algorithm="HS256"
        )
        self.secondary_user_token = jwt.encode(
            {"user_id": 2}, self.secret_key, algorithm="HS256"
        )

        # Create a dummy swagger file for the test
        self.swagger_file = "test_swagger.json"
        with open(self.swagger_file, "w") as f:
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

    def tearDown(self):
        """Clean up the test environment."""
        os.remove(self.swagger_file)

    @patch('src.redteam.scanners.idor_scanner.make_api_request')
    def test_idor_scanner_detects_vulnerability(self, mock_make_api_request):
        """
        Test that the IDORScanner can successfully detect the
        vulnerability in the vulnerable_app.
        """
        def mock_request_side_effect(base_url, endpoint, token=None, **kwargs):
            headers = {"Authorization": f"Bearer {token}"}
            response = self.app.open(
                endpoint.path,
                method=endpoint.method,
                headers=headers,
                json=endpoint.body
            )
            response_body = {}
            try:
                response_body = json.loads(response.data)
            except json.JSONDecodeError:
                response_body = {"raw": response.data.decode()}

            return {
                "status_code": response.status_code,
                "body": response_body,
                "headers": dict(response.headers),
            }

        mock_make_api_request.side_effect = mock_request_side_effect

        config = {
            "api_url": "http://localhost:5000",
            "swagger_file": self.swagger_file,
            "primary_user_token": self.primary_user_token,
            "secondary_user_token": self.secondary_user_token,
            "secondary_user_resource_ids": [2],
        }

        scanner = IDORScanner(config)
        findings = scanner.scan()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vulnerability"], "Insecure Direct Object Reference (IDOR)")
        self.assertEqual(findings[0]["severity"], "High")
        self.assertEqual(findings[0]["endpoint"], "GET /api/invoices/{invoice_id}")


if __name__ == "__main__":
    unittest.main()
