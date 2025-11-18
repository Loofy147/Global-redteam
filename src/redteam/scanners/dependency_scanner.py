import requests
import json
import os
from src.redteam.scanners.base import BaseScanner
from ..core.finding import Finding, Severity, SecurityTestCategory
from typing import List, Dict, Tuple

class DependencyScanner(BaseScanner):
    """
    Scans for dependency confusion vulnerabilities across multiple ecosystems.
    """

    def get_required_config_fields(self) -> List[str]:
        return ["static_analysis_path"]  # Scan a directory for dependency files

    def _scan_implementation(self) -> List[Finding]:
        """
        Scans the target directory for dependency files and checks for confusion.
        """
        target_path = self.config.get("static_analysis_path")
        findings = []

        if not os.path.isdir(target_path):
            return findings

        for root, _, files in os.walk(target_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file == 'requirements.txt':
                    findings.extend(self._check_python_dependencies(file_path))
                elif file == 'package.json':
                    findings.extend(self._check_npm_dependencies(file_path))

        return findings

    def _check_python_dependencies(self, file_path: str) -> List[Finding]:
        """Checks a requirements.txt file against the PyPI registry."""
        findings = []
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    package_name = line.split('==')[0].strip()
                    if self._check_registry("pypi", package_name):
                        findings.append(self._create_finding(file_path, package_name, "PyPI"))
        except FileNotFoundError:
            pass  # Fail silently if file is not found
        return findings

    def _check_npm_dependencies(self, file_path: str) -> List[Finding]:
        """Checks a package.json file against the npm registry."""
        findings = []
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                dependencies = data.get('dependencies', {})
                dev_dependencies = data.get('devDependencies', {})
                all_dependencies = {**dependencies, **dev_dependencies}

                for package_name in all_dependencies.keys():
                    if self._check_registry("npm", package_name):
                        findings.append(self._create_finding(file_path, package_name, "npm"))
        except (FileNotFoundError, json.JSONDecodeError):
            pass  # Fail silently
        return findings

    def _check_registry(self, registry: str, package_name: str) -> bool:
        """Checks if a package exists in a given public registry."""
        urls = {
            "pypi": f"https://pypi.org/pypi/{package_name}/json",
            "npm": f"https://registry.npmjs.org/{package_name}",
        }
        url = urls.get(registry)
        if not url:
            return False

        try:
            response = requests.get(url, timeout=10)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def _create_finding(self, file_path: str, package_name: str, registry_name: str) -> Finding:
        """Creates a Finding object for a dependency confusion vulnerability."""
        return Finding(
            id=f"dep-{package_name}",
            category=SecurityTestCategory.SUPPLY_CHAIN,
            severity=Severity.HIGH,
            title="Potential Dependency Confusion",
            description=f"Package '{package_name}' exists on the public {registry_name} registry. If this is an internal package, this could lead to a dependency confusion attack.",
            affected_component=file_path,
            evidence=f"Package: {package_name}, Public Registry: {registry_name}",
            remediation="Ensure that your private package names do not conflict with public package names. Consider using a private registry and scoped packages.",
        )
