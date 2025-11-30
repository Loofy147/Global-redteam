from src.redteam.scanners.base import BaseScanner
from typing import List, Dict, Any
from src.redteam.core.finding import Finding, Severity
from src.redteam.utils.rate_limiter import RateLimiter
import requests
import json


class APIScanner(BaseScanner):
    def get_required_config_fields(self) -> List[str]:
        return ["api_url", "swagger_file", "primary_user_token", "secondary_user_token", "secondary_user_resource_ids"]

    def __init__(self, config: dict):
        super().__init__(config)
        self.rate_limiter = RateLimiter(
            max_requests=self.config.get('rate_limit', 10),
            time_window=1  # per second
        )
        self.common_endpoints = ["/admin", "/backup", "/config"]

    def _make_request(self, url: str, token: str) -> requests.Response:
        self.rate_limiter.acquire()
        headers = {"Authorization": f"Bearer {token}"}
        return requests.get(url, headers=headers)

    def _parse_swagger(self, swagger_file: str) -> List[Dict[str, Any]]:
        with open(swagger_file, 'r') as f:
            swagger_data = json.load(f)

        endpoints = []
        for path, methods in swagger_data.get('paths', {}).items():
            for method, details in methods.items():
                if 'security' in details:
                    endpoints.append({'path': path, 'method': method.upper()})
        return endpoints

    def _check_security_headers(self, headers: dict) -> List[Finding]:
        findings = []
        expected_headers = {
            "Strict-Transport-Security": None,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": None,
        }
        for header, value in expected_headers.items():
            if header not in headers:
                findings.append(Finding(
                    title="Missing Security Header",
                    description=f"Missing security header: {header}",
                    severity=Severity.MEDIUM,
                    evidence=f"Header '{header}' not found in response.",
                ))
            elif value and headers[header] != value:
                findings.append(Finding(
                    title="Misconfigured Security Header",
                    description=f"Misconfigured security header: {header}",
                    severity=Severity.MEDIUM,
                    evidence=f"Header '{header}' has value '{headers[header]}' but expected '{value}'.",
                ))
        return findings

    def _scan_implementation(self) -> List[Finding]:
        findings = []
        endpoints = self._parse_swagger(self.config['swagger_file'])

        # IDOR check
        for endpoint in endpoints:
            for resource_id in self.config['secondary_user_resource_ids']:
                path = endpoint['path'].replace('{invoice_id}', str(resource_id))
                url = f"{self.config['api_url']}{path}"

                response = self._make_request(url, self.config['primary_user_token'])

                if response.status_code == 200:
                    findings.append(Finding(
                        title="Insecure Direct Object Reference (IDOR)",
                        description=f"User 1 can access resource belonging to user 2 at {endpoint['method']} {endpoint['path']}",
                        severity=Severity.HIGH,
                        file_path=self.config['swagger_file'],
                        evidence=f"Status code: {response.status_code}"
                    ))

        # Security headers check
        response = self._make_request(self.config['api_url'], self.config['primary_user_token'])
        findings.extend(self._check_security_headers(response.headers))

        # Guessable endpoints check
        for endpoint in self.common_endpoints:
            url = f"{self.config['api_url']}{endpoint}"
            response = self._make_request(url, self.config['primary_user_token'])
            if response.status_code == 200:
                findings.append(Finding(
                    title="Guessable Endpoint Found",
                    description=f"Found guessable endpoint: {endpoint}",
                    severity=Severity.MEDIUM,
                    evidence=f"Endpoint '{endpoint}' is accessible.",
                ))

        return findings
