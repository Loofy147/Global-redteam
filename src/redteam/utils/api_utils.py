"""
API Utilities for the Red Team Framework
"""

import json
from typing import Dict, List, Any, Optional
import requests
from dataclasses import dataclass, field


@dataclass
class APIEndpoint:
    """Represents an API endpoint to test"""

    path: str
    method: str
    requires_auth: bool = True
    params: Optional[Dict[str, Any]] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[Dict] = None


def discover_endpoints_from_swagger(swagger_file: str) -> List[APIEndpoint]:
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


def make_api_request(
    base_url: str,
    endpoint: APIEndpoint,
    token: Optional[str] = None,
    override_headers: Optional[Dict] = None,
    override_body: Optional[Dict] = None,
) -> Dict:
    """Perform an HTTP request"""
    headers = endpoint.headers.copy()
    if override_headers:
        headers.update(override_headers)

    if endpoint.requires_auth and token:
        headers["Authorization"] = f"Bearer {token}"

    body = override_body if override_body is not None else endpoint.body
    url = f"{base_url}{endpoint.path}"

    try:
        response = requests.request(
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
