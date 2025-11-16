import requests
from src.redteam.scanners.base import BaseScanner
from ..core.finding import Finding, Severity, SecurityTestCategory

class DependencyScanner(BaseScanner):
    """
    Scans for dependency confusion vulnerabilities.
    """
    def __init__(self, config: dict):
        super().__init__(config)

    def scan(self, target):
        """
        Scans the target's requirements.txt for dependency confusion.
        """
        findings = []
        print(f"SCANNING {target}")
        try:
            with open(target, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    package_name = line.split('==')[0]
                    pypi_url = f"https://pypi.org/pypi/{package_name}/json"
                    response = requests.get(pypi_url)
                    if response.status_code == 200:
                        pypi_data = response.json()
                        latest_version = pypi_data['info']['version']
                        findings.append(Finding(
                            id=f"dep-{package_name}",
                            category=SecurityTestCategory.SUPPLY_CHAIN,
                            severity=Severity.CRITICAL,
                            title="Dependency Confusion",
                            description=f"Package '{package_name}' exists on PyPI with version {latest_version}. This could lead to a dependency confusion attack.",
                            affected_component=target,
                            evidence=f"Package: {package_name}, Public Version: {latest_version}",
                            remediation="Ensure that your private package names do not conflict with public package names.",
                        ))
        except FileNotFoundError:
            findings.append({
                "type": "File Not Found",
                "description": f"The file '{target}' was not found.",
                "file_path": target
            })
        return findings
