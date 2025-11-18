from .base import BaseScanner
from ..core.finding import Finding, Severity, SecurityTestCategory
from ai_vulnerability_discovery import AIVulnerabilityDiscovery
import os
import hashlib
from typing import List

class SastScanner(BaseScanner):
    """Static analysis scanner."""

    def __init__(self, config: dict):
        super().__init__(config)
        self.sast_engine = AIVulnerabilityDiscovery()

    def get_required_config_fields(self) -> List[str]:
        return ["static_analysis_path"]

    def _scan_implementation(self) -> list[Finding]:
        """Run the SAST scanner and return a list of findings."""
        target_path = self.config.get("static_analysis_path")
        findings = []

        if not os.path.isdir(target_path):
            return findings

        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith((".py", ".js")):
                    file_path = os.path.join(root, file)
                    language = "javascript" if file.endswith(".js") else "python"
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            code = f.read()
                    except (FileNotFoundError, IOError):
                        continue

                    results = self.sast_engine.discover_vulnerabilities(
                        code, file_path, language=language
                    )
                    for vuln in results.get("static_analysis", []):
                        finding = self._convert_code_vuln_to_finding(vuln)
                        findings.append(finding)
        return findings

    def _convert_code_vuln_to_finding(self, vuln: dict) -> Finding:
        """Converts a CodeVulnerability object to a Finding object."""
        pattern = vuln["pattern"]
        code_snippet = vuln.get('code_snippet', '')
        unique_str = f"{vuln['file_path']}:{vuln['line_number']}:{pattern.value}:{code_snippet}"
        finding_id = f"sast-{hashlib.sha256(unique_str.encode()).hexdigest()[:16]}"

        return Finding(
            id=finding_id,
            category=SecurityTestCategory.STATIC_ANALYSIS,
            severity=Severity(vuln["severity"]),
            title=f"{pattern.value.replace('_', ' ').title()} in {os.path.basename(vuln['file_path'])}",
            description=vuln["explanation"],
            affected_component=f"{vuln['file_path']}:{vuln['line_number']}",
            evidence=code_snippet,
            remediation=vuln['remediation'],
        )
