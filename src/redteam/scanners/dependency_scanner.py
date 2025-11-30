from src.redteam.scanners.base import BaseScanner
from typing import List
from src.redteam.core.finding import Finding, Severity
import requests
import json
import os


class DependencyScanner(BaseScanner):
    def get_required_config_fields(self) -> List[str]:
        return ["path"]

    def _scan_implementation(self) -> List[Finding]:
        findings = []

        # Scan requirements.txt
        requirements_file = os.path.join(self.config["path"], "requirements.txt")
        if os.path.exists(requirements_file):
            findings.extend(self._scan_requirements(requirements_file))

        # Scan package.json
        package_json_file = os.path.join(self.config["path"], "package.json")
        if os.path.exists(package_json_file):
            findings.extend(self._scan_package_json(package_json_file))

        return findings

    def _scan_requirements(self, file_path: str) -> List[Finding]:
        findings = []
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                package, version = self._parse_requirement(line)
                if package and version:
                    vulnerabilities = self._check_osv(package, version, "PyPI")
                    for vuln in vulnerabilities:
                        findings.append(Finding(
                            title=f"Vulnerable Dependency: {package}=={version}",
                            description=vuln["summary"],
                            severity=self._get_severity(vuln),
                            file_path=file_path,
                            evidence=str(vuln),
                            remediation=f"Upgrade {package} to a non-vulnerable version."
                        ))
        return findings

    def _scan_package_json(self, file_path: str) -> List[Finding]:
        findings = []
        with open(file_path, 'r') as f:
            data = json.load(f)
            dependencies = data.get('dependencies', {})
            for package, version in dependencies.items():
                vulnerabilities = self._check_osv(package, version, "npm")
                for vuln in vulnerabilities:
                    findings.append(Finding(
                        title=f"Vulnerable Dependency: {package}@{version}",
                        description=vuln["summary"],
                        severity=self._get_severity(vuln),
                        file_path=file_path,
                        evidence=str(vuln),
                        remediation=f"Upgrade {package} to a non-vulnerable version."
                    ))
        return findings

    def _parse_requirement(self, line: str):
        parts = line.split("==")
        if len(parts) == 2:
            return parts[0], parts[1]
        return None, None

    def _check_osv(self, package: str, version: str, ecosystem: str) -> List[dict]:
        url = "https://api.osv.dev/v1/query"
        query = {
            "version": version,
            "package": {
                "name": package,
                "ecosystem": ecosystem
            }
        }
        response = requests.post(url, data=json.dumps(query))
        if response.status_code == 200:
            data = response.json()
            return data.get("vulns", [])
        return []

    def _get_severity(self, vuln: dict) -> Severity:
        severity = vuln.get("database_specific", {}).get("severity", "UNKNOWN")
        if severity == "CRITICAL":
            return Severity.CRITICAL
        elif severity == "HIGH":
            return Severity.HIGH
        elif severity == "MODERATE":
            return Severity.MEDIUM
        else:
            return Severity.LOW
