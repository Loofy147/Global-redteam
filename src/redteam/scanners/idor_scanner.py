"""
Advanced IDOR (Insecure Direct Object Reference) Scanner
"""

import re
from typing import Dict, List, Any, Optional

from .base import BaseScanner
from ..utils.api_utils import (
    discover_endpoints_from_swagger,
    make_api_request,
    APIEndpoint,
)


class IDORScanner(BaseScanner):
    """
    A scanner dedicated to finding Insecure Direct Object Reference vulnerabilities.
    It uses two sets of credentials to verify if one user can access another's resources.
    """

    def __init__(self, config: dict):
        super().__init__(config)
        self.base_url = self.config.get("api_url", "").rstrip("/")
        self.primary_user_token = self.config.get("primary_user_token")
        self.secondary_user_token = self.config.get("secondary_user_token")
        self.secondary_user_resource_ids = self.config.get("secondary_user_resource_ids", [])

    def get_required_config_fields(self) -> List[str]:
        """Return required configuration fields for the scanner."""
        return [
            "api_url",
            "swagger_file",
            "primary_user_token",
            "secondary_user_token",
            "secondary_user_resource_ids",
        ]

    def _scan_implementation(self) -> List[Dict]:
        """
        The main implementation of the IDOR scan.
        """
        findings = []
        endpoints = discover_endpoints_from_swagger(self.config.get("swagger_file"))
        potential_endpoints = self._identify_potential_idor_endpoints(endpoints)

        for endpoint in potential_endpoints:
            finding = self._test_endpoint_for_idor(endpoint)
            if finding:
                findings.append(finding)

        return findings

    def _identify_potential_idor_endpoints(
        self, endpoints: List[APIEndpoint]
    ) -> List[APIEndpoint]:
        """
        Identifies endpoints that are likely to be vulnerable to IDOR.
        """
        potential_endpoints = []
        # A regex to find common ID patterns in URL paths
        id_regex = re.compile(r"\{([a-zA-Z0-9_]*id[a-zA-Z0-9_]*)\}", re.IGNORECASE)

        for endpoint in endpoints:
            if endpoint.method.upper() in ["GET", "PUT", "DELETE", "PATCH"]:
                if id_regex.search(endpoint.path):
                    potential_endpoints.append(endpoint)

        return potential_endpoints

    def _test_endpoint_for_idor(self, endpoint: APIEndpoint) -> Optional[Dict]:
        """
        Tests a single endpoint for IDOR vulnerabilities.
        """
        id_regex = re.compile(r"\{([a-zA-Z0-9_]*id[a-zA-Z0-9_]*)\}", re.IGNORECASE)
        match = id_regex.search(endpoint.path)

        if not match:
            return None

        for resource_id in self.secondary_user_resource_ids:
            modified_path = endpoint.path.replace(match.group(0), str(resource_id))

            test_endpoint = APIEndpoint(
                path=modified_path,
                method=endpoint.method,
                requires_auth=endpoint.requires_auth,
            )

            # Make a request with the primary user's token to the secondary user's resource
            response = make_api_request(
                self.base_url, test_endpoint, token=self.primary_user_token
            )

            # If we get a 2xx response, it's a potential IDOR
            if 200 <= response["status_code"] < 300:
                return {
                    "vulnerability": "Insecure Direct Object Reference (IDOR)",
                    "severity": "High",
                    "endpoint": f"{endpoint.method} {endpoint.path}",
                    "details": f"User with token '{self.primary_user_token[:10]}...' was able to access a resource belonging to another user at '{modified_path}'.",
                    "evidence": {
                        "status_code": response["status_code"],
                        "response_body": response["body"],
                    },
                }

        return None
