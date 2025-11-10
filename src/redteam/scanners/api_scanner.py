"""
Advanced API Security Testing Framework
Tests for OWASP API Security Top 10 and beyond
"""

import json
import time
import hashlib
import jwt
import requests
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import itertools
from ..utils.rate_limiter import RateLimiter


class APIVulnerabilityType(Enum):
    """API-specific vulnerability categories"""

    BROKEN_OBJECT_LEVEL_AUTH = "bola"  # IDOR
    BROKEN_USER_AUTH = "broken_auth"
    EXCESSIVE_DATA_EXPOSURE = "data_exposure"
    LACK_OF_RESOURCES = "rate_limiting"
    BROKEN_FUNCTION_LEVEL_AUTH = "broken_function_auth"
    MASS_ASSIGNMENT = "mass_assignment"
    SECURITY_MISCONFIGURATION = "misconfiguration"
    INJECTION = "injection"
    IMPROPER_ASSETS_MANAGEMENT = "assets_management"
    INSUFFICIENT_LOGGING = "logging"


@dataclass
class APIEndpoint:
    """Represents an API endpoint to test"""

    path: str
    method: str
    requires_auth: bool = True
    params: Optional[Dict[str, Any]] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[Dict] = None


@dataclass
class APITestResult:
    """Result of an API security test"""

    endpoint: APIEndpoint
    vulnerability_type: APIVulnerabilityType
    severity: str  # critical, high, medium, low
    passed: bool
    details: str
    evidence: Any = None
    remediation: str = ""


from .base import BaseScanner

class APISecurityTester(BaseScanner):
    """Comprehensive API security testing framework"""

    def __init__(self, config: dict):
        super().__init__(config)
        self.base_url = config.get("api_url", "").rstrip("/")
        self.auth_token = config.get("auth_token")
        self.results: List[APITestResult] = []
        self.request_history: List[Dict] = []
        self.session = requests.Session()
        self.rate_limiter = RateLimiter(max_requests=config.get("rate_limit", 10), time_window=1)

    def _make_request(
        self,
        endpoint: APIEndpoint,
        override_headers: Optional[Dict] = None,
        override_body: Optional[Dict] = None,
    ) -> Dict:
        """Perform an HTTP request"""
        self.rate_limiter.acquire()
        headers = endpoint.headers.copy()
        if override_headers:
            headers.update(override_headers)

        if endpoint.requires_auth and self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        body = override_body if override_body is not None else endpoint.body
        url = f"{self.base_url}{endpoint.path}"

        request_details = {
            "url": url,
            "method": endpoint.method,
            "headers": headers,
            "json": body,
            "timestamp": time.time(),
        }
        self.request_history.append(request_details)

        try:
            response = self.session.request(
                method=endpoint.method, url=url, headers=headers, json=body, timeout=5
            )

            response_body = {}
            try:
                response_body = response.json()
            except json.JSONDecodeError:
                response_body = {"raw": response.text}

            return {
                "status_code": response.status_code,
                "body": response_body,
                "headers": dict(response.headers),
            }
        except requests.exceptions.RequestException as e:
            return {"status_code": 500, "body": {"error": str(e)}, "headers": {}}

    def test_bola_idor(
        self, endpoint: APIEndpoint, user_id_param: str
    ) -> APITestResult:
        """
        Test for Broken Object Level Authorization (BOLA/IDOR)
        OWASP API1:2023
        """
        vulnerabilities_found = []

        # Test 1: Sequential ID enumeration
        if user_id_param in endpoint.path:
            test_ids = [1, 2, 3, 100, 999, 1000]
            for test_id in test_ids:
                modified_path = endpoint.path.replace(
                    f"{{{user_id_param}}}", str(test_id)
                )
                test_endpoint = APIEndpoint(
                    path=modified_path,
                    method=endpoint.method,
                    requires_auth=endpoint.requires_auth,
                )

                response = self._make_request(test_endpoint)

                # Check if we can access other users' data
                if response["status_code"] == 200:
                    vulnerabilities_found.append(f"Accessed user ID {test_id}")

        # Test 2: UUID prediction/guessing
        test_uuids = [
            "00000000-0000-0000-0000-000000000001",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "12345678-1234-1234-1234-123456789012",
        ]

        for test_uuid in test_uuids:
            if "{id}" in endpoint.path:
                modified_path = endpoint.path.replace("{id}", test_uuid)
                test_endpoint = APIEndpoint(
                    path=modified_path,
                    method=endpoint.method,
                    requires_auth=endpoint.requires_auth,
                )

                response = self._make_request(test_endpoint)
                if response["status_code"] == 200:
                    vulnerabilities_found.append(f"Accessed UUID {test_uuid}")

        passed = len(vulnerabilities_found) == 0

        return APITestResult(
            endpoint=endpoint,
            vulnerability_type=APIVulnerabilityType.BROKEN_OBJECT_LEVEL_AUTH,
            severity="critical" if not passed else "none",
            passed=passed,
            details=f"BOLA/IDOR test: {len(vulnerabilities_found)} unauthorized accesses",
            evidence=vulnerabilities_found,
            remediation="Implement proper authorization checks. Verify user owns resource.",
        )

    def test_authentication_bypass(self, endpoint: APIEndpoint) -> APITestResult:
        """
        Test for authentication bypass vulnerabilities
        OWASP API2:2023
        """
        bypass_attempts = []

        # Test 1: No token
        test_endpoint = APIEndpoint(
            path=endpoint.path, method=endpoint.method, requires_auth=False
        )
        response = self._make_request(test_endpoint)
        if response["status_code"] != 401:
            bypass_attempts.append("No authentication required")

        # Test 2: Empty token
        response = self._make_request(endpoint, override_headers={"Authorization": ""})
        if response["status_code"] != 401:
            bypass_attempts.append("Empty token accepted")

        # Test 3: Invalid token format
        invalid_tokens = [
            "Bearer invalid",
            "Bearer null",
            "Bearer undefined",
            "Basic admin:admin",
            "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",  # None algorithm
        ]

        for invalid_token in invalid_tokens:
            response = self._make_request(
                endpoint, override_headers={"Authorization": invalid_token}
            )
            if response["status_code"] != 401:
                bypass_attempts.append(f"Invalid token accepted: {invalid_token}")

        # Test 4: JWT algorithm confusion
        if self.auth_token and self.auth_token.startswith("eyJ"):
            try:
                # Decode without verification
                decoded = jwt.decode(
                    self.auth_token, algorithms=["HS256"], options={"verify_signature": False}
                )

                # Try to create token with alg=none
                none_token = jwt.encode(decoded, None, algorithm=None)
                response = self._make_request(
                    endpoint, override_headers={"Authorization": f"Bearer {none_token}"}
                )
                if response["status_code"] != 401:
                    bypass_attempts.append("JWT alg=none accepted")

            except Exception:
                pass

        passed = len(bypass_attempts) == 0

        return APITestResult(
            endpoint=endpoint,
            vulnerability_type=APIVulnerabilityType.BROKEN_USER_AUTH,
            severity="critical" if not passed else "none",
            passed=passed,
            details=f"Authentication bypass: {len(bypass_attempts)} bypasses found",
            evidence=bypass_attempts,
            remediation="Implement strong authentication. Validate tokens properly. Use secure JWT algorithms.",
        )

    def test_excessive_data_exposure(self, endpoint: APIEndpoint) -> APITestResult:
        """
        Test for excessive data exposure
        OWASP API3:2023
        """
        sensitive_fields = [
            "password",
            "ssn",
            "credit_card",
            "api_key",
            "secret",
            "token",
            "private_key",
            "salt",
            "hash",
            "internal_id",
        ]

        response = self._make_request(endpoint)
        exposed_fields = []

        if response["status_code"] == 200 and response["body"]:
            response_str = json.dumps(response["body"]).lower()

            for sensitive_field in sensitive_fields:
                if sensitive_field in response_str:
                    exposed_fields.append(sensitive_field)

        passed = len(exposed_fields) == 0

        return APITestResult(
            endpoint=endpoint,
            vulnerability_type=APIVulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
            severity="high" if not passed else "none",
            passed=passed,
            details=f"Data exposure: {len(exposed_fields)} sensitive fields exposed",
            evidence=exposed_fields,
            remediation="Implement response filtering. Only return necessary data. Use DTOs.",
        )

    def test_rate_limiting(
        self, endpoint: APIEndpoint, requests_count: int = 100
    ) -> APITestResult:
        """
        Test for lack of rate limiting
        OWASP API4:2023
        """
        start_time = time.time()
        successful_requests = 0

        for _ in range(requests_count):
            response = self._make_request(endpoint)
            if response["status_code"] not in [429, 503]:
                successful_requests += 1

        elapsed = time.time() - start_time
        requests_per_second = successful_requests / elapsed if elapsed > 0 else 0

        # If we can make >10 req/s without being blocked, likely no rate limiting
        passed = requests_per_second < 10 or successful_requests < requests_count * 0.8

        return APITestResult(
            endpoint=endpoint,
            vulnerability_type=APIVulnerabilityType.LACK_OF_RESOURCES,
            severity="medium" if not passed else "none",
            passed=passed,
            details=f"Rate limiting: {successful_requests}/{requests_count} requests succeeded at {requests_per_second:.1f} req/s",
            evidence={"successful": successful_requests, "rps": requests_per_second},
            remediation="Implement rate limiting. Use token bucket or sliding window.",
        )

    def test_function_level_authorization(
        self, endpoint: APIEndpoint, admin_only: bool = True
    ) -> APITestResult:
        """
        Test for broken function level authorization
        OWASP API5:2023
        """
        unauthorized_accesses = []

        # Test with regular user token (simulate by removing admin claims)
        if admin_only:
            # Test common admin endpoints with non-admin token
            admin_paths = [
                "/admin",
                "/api/admin",
                "/users/all",
                "/api/users/delete",
                "/settings",
                "/config",
                "/debug",
                "/internal",
            ]

            for admin_path in admin_paths:
                test_endpoint = APIEndpoint(
                    path=admin_path, method="GET", requires_auth=True
                )

                response = self._make_request(test_endpoint)
                if response["status_code"] == 200:
                    unauthorized_accesses.append(admin_path)

        # Test HTTP method tampering
        if endpoint.method == "GET":
            for method in ["POST", "PUT", "DELETE", "PATCH"]:
                test_endpoint = APIEndpoint(
                    path=endpoint.path,
                    method=method,
                    requires_auth=endpoint.requires_auth,
                )

                response = self._make_request(test_endpoint)
                if response["status_code"] not in [405, 403]:
                    unauthorized_accesses.append(f"{method} {endpoint.path}")

        passed = len(unauthorized_accesses) == 0

        return APITestResult(
            endpoint=endpoint,
            vulnerability_type=APIVulnerabilityType.BROKEN_FUNCTION_LEVEL_AUTH,
            severity="critical" if not passed else "none",
            passed=passed,
            details=f"Function auth: {len(unauthorized_accesses)} unauthorized function accesses",
            evidence=unauthorized_accesses,
            remediation="Implement role-based access control. Verify permissions on every request.",
        )

    def test_mass_assignment(self, endpoint: APIEndpoint) -> APITestResult:
        """
        Test for mass assignment vulnerabilities
        OWASP API6:2023
        """
        if endpoint.method not in ["POST", "PUT", "PATCH"]:
            return APITestResult(
                endpoint=endpoint,
                vulnerability_type=APIVulnerabilityType.MASS_ASSIGNMENT,
                severity="none",
                passed=True,
                details="Not applicable for this method",
                remediation="",
            )

        vulnerable_fields = []

        # Test injecting privileged fields
        privileged_fields = {
            "is_admin": True,
            "role": "admin",
            "permissions": ["*"],
            "verified": True,
            "balance": 999999,
            "credit": 999999,
        }

        if endpoint.body:
            test_body = endpoint.body.copy()
            test_body.update(privileged_fields)

            response = self._make_request(endpoint, override_body=test_body)

            # Check if privileged fields were accepted
            if response["status_code"] == 200:
                response_body = response.get("body", {})
                for field in privileged_fields:
                    if field in json.dumps(response_body):
                        vulnerable_fields.append(field)

        passed = len(vulnerable_fields) == 0

        return APITestResult(
            endpoint=endpoint,
            vulnerability_type=APIVulnerabilityType.MASS_ASSIGNMENT,
            severity="high" if not passed else "none",
            passed=passed,
            details=f"Mass assignment: {len(vulnerable_fields)} privileged fields accepted",
            evidence=vulnerable_fields,
            remediation="Use allow-lists for input fields. Explicitly define writable fields.",
        )

    def test_injection_attacks(self, endpoint: APIEndpoint) -> APITestResult:
        """
        Test for injection vulnerabilities
        OWASP API8:2023
        """
        injection_payloads = {
            "sql": [
                "' OR '1'='1",
                "'; DROP TABLE users--",
                "1' UNION SELECT * FROM users--",
            ],
            "nosql": ["{'$gt': ''}", "{'$ne': null}", "[$ne]=null"],
            "command": ["; ls -la", "| cat /etc/passwd", "&& whoami"],
            "ldap": ["*", "admin*", "*)(uid=*))(|(uid=*"],
            "xpath": ["' or '1'='1", "' or 1=1 or ''='"],
        }

        vulnerabilities = []

        for injection_type, payloads in injection_payloads.items():
            for payload in payloads:
                # Test in query parameters, if applicable
                if endpoint.params is not None:
                    for param_name in endpoint.params:
                        test_endpoint = APIEndpoint(
                            path=f"{endpoint.path}?{param_name}={payload}",
                            method=endpoint.method,
                            requires_auth=endpoint.requires_auth,
                        )
                        try:
                            response = self._make_request(test_endpoint)
                            response_str = json.dumps(response).lower()
                            indicators = ["error", "exception", "syntax", "root:", "admin"]
                            if any(ind in response_str for ind in indicators):
                                vulnerabilities.append(f"{injection_type}: {payload} in param {param_name}")
                        except Exception as e:
                            vulnerabilities.append(f"{injection_type}: {payload} in param {param_name} (caused exception)")

                # Test in body
                if endpoint.body:
                    test_body = {"input": payload}
                    try:
                        response = self._make_request(endpoint, override_body=test_body)
                        response_str = json.dumps(response).lower()
                        if any(ind in response_str for ind in indicators):
                            vulnerabilities.append(
                                f"{injection_type} in body: {payload}"
                            )
                    except Exception:
                        pass

        passed = len(vulnerabilities) == 0

        return APITestResult(
            endpoint=endpoint,
            vulnerability_type=APIVulnerabilityType.INJECTION,
            severity="critical" if not passed else "none",
            passed=passed,
            details=f"Injection: {len(vulnerabilities)} potential injection points",
            evidence=vulnerabilities,
            remediation="Use parameterized queries. Validate and sanitize all inputs. Use ORMs.",
        )

    def test_comprehensive(self, endpoints: List[APIEndpoint]) -> List[APITestResult]:
        """Run comprehensive security tests on all endpoints"""
        print("[*] Starting comprehensive API security testing")
        print(f"[*] Testing {len(endpoints)} endpoints")
        print("=" * 80)

        for endpoint in endpoints:
            print(f"\n[*] Testing {endpoint.method} {endpoint.path}")

            # Run all tests
            tests = [
                self.test_bola_idor(endpoint, "id"),
                self.test_authentication_bypass(endpoint),
                self.test_excessive_data_exposure(endpoint),
                self.test_rate_limiting(endpoint, requests_count=50),
                self.test_function_level_authorization(endpoint),
                self.test_mass_assignment(endpoint),
                self.test_injection_attacks(endpoint),
            ]

            self.results.extend(tests)

            # Report results
            for test in tests:
                status = "✓ PASS" if test.passed else "✗ FAIL"
                severity = f"[{test.severity.upper()}]" if not test.passed else ""
                print(
                    f"  {status} {severity} {test.vulnerability_type.value}: {test.details}"
                )

        print("\n" + "=" * 80)
        print(self.generate_report())

        return self.results

    def discover_endpoints_from_swagger(self, swagger_file: str) -> List[APIEndpoint]:
        """Parses a Swagger/OpenAPI file to discover endpoints."""
        endpoints = []
        try:
            with open(swagger_file, "r") as f:
                swagger_data = json.load(f)

            for path, path_item in swagger_data.get("paths", {}).items():
                for method, operation in path_item.items():
                    # A basic check for auth, can be improved
                    requires_auth = "security" in operation or "Authorization" in str(
                        operation
                    )

                    endpoint = APIEndpoint(
                        path=path, method=method.upper(), requires_auth=requires_auth
                    )
                    endpoints.append(endpoint)
            print(f"[*] Discovered {len(endpoints)} endpoints from {swagger_file}")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[!] Error parsing Swagger file: {e}")
        return endpoints

    def scan(self) -> List[APITestResult]:
        """Run a comprehensive API scan."""
        endpoints = self.discover_endpoints_from_swagger(self.config.get("swagger_file"))
        return self.test_comprehensive(endpoints)

    def generate_report(self) -> str:
        """Generate comprehensive security report"""
        report = []
        report.append("\nAPI SECURITY TEST REPORT")
        report.append("=" * 80)

        # Statistics
        total = len(self.results)
        failed = sum(1 for r in self.results if not r.passed)
        passed = total - failed

        report.append(f"\nTotal Tests: {total}")
        report.append(f"Passed: {passed}")
        report.append(f"Failed: {failed}")

        # Group by severity
        by_severity = {"critical": [], "high": [], "medium": [], "low": []}
        for result in self.results:
            if not result.passed and result.severity in by_severity:
                by_severity[result.severity].append(result)

        for severity in ["critical", "high", "medium", "low"]:
            findings = by_severity[severity]
            if findings:
                report.append(
                    f"\n{severity.upper()} SEVERITY ({len(findings)} findings):"
                )
                report.append("-" * 80)

                for finding in findings:
                    report.append(f"\n  {finding.vulnerability_type.value.upper()}")
                    report.append(
                        f"  Endpoint: {finding.endpoint.method} {finding.endpoint.path}"
                    )
                    report.append(f"  Details: {finding.details}")
                    if finding.evidence:
                        report.append(f"  Evidence: {finding.evidence}")
                    report.append(f"  Remediation: {finding.remediation}")

        report.append("\n" + "=" * 80)
        return "\n".join(report)


from ..utils.config import Settings

# Example usage
if __name__ == "__main__":
    settings = Settings()
    # Define API endpoints to test
    endpoints = [
        APIEndpoint(path="/api/users/{id}", method="GET", requires_auth=True),
        APIEndpoint(
            path="/api/users",
            method="POST",
            requires_auth=True,
            body={"username": "test", "email": "test@example.com"},
        ),
        APIEndpoint(path="/api/admin/users", method="GET", requires_auth=True),
        APIEndpoint(path="/api/search", method="GET", requires_auth=False),
    ]

    # Initialize tester
    tester = APISecurityTester(
        base_url="https://api.example.com",
        auth_token=settings.example_auth_token,
    )

    # Run comprehensive tests
    results = tester.test_comprehensive(endpoints)
