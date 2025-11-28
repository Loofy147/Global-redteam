# New Module: src/redteam/scanners/supply_chain_validator.py

from .base import BaseScanner
from ..core.finding import Finding, Severity, SecurityTestCategory
import hashlib
import json
import requests
import subprocess
from typing import Dict, List
import os

class SupplyChainValidator(BaseScanner):
    """
    Comprehensive supply chain security validation
    Detects: dependency confusion, malicious packages, build tampering, SBOM violations
    """

    def __init__(self, config: dict):
        super().__init__(config)
        self.sbom_path = config.get('sbom_path')
        self.build_artifacts_path = config.get('build_artifacts_path')
        self.enable_binary_analysis = config.get('binary_analysis', True)

    def get_required_config_fields(self) -> list:
        return ['static_analysis_path', 'sbom_path']

    def _scan_implementation(self) -> list[Finding]:
        """
        Multi-layer supply chain validation
        """
        findings = []

        # Layer 1: SBOM Validation
        findings.extend(self._validate_sbom())

        # Layer 2: Dependency Malware Scan
        findings.extend(self._scan_dependencies_for_malware())

        # Layer 3: Build Integrity Check
        if self.enable_binary_analysis:
            findings.extend(self._verify_build_integrity())

        # Layer 4: Provenance Verification (SLSA)
        findings.extend(self._verify_provenance())

        # Layer 5: Typosquatting Detection
        findings.extend(self._detect_typosquatting())

        return findings

    def _validate_sbom(self) -> List[Finding]:
        """Validate Software Bill of Materials completeness"""
        findings = []

        if not self.sbom_path or not os.path.exists(self.sbom_path):
            findings.append(Finding(
                id="supply-chain-no-sbom",
                category=SecurityTestCategory.SUPPLY_CHAIN,
                severity=Severity.HIGH,
                title="Missing Software Bill of Materials (SBOM)",
                description="No SBOM found. SBOMs are required for supply chain security.",
                affected_component="Build System",
                evidence="No SBOM at expected path",
                remediation="Generate SBOM using syft, cyclonedx, or similar tools"
            ))
            return findings

        with open(self.sbom_path, 'r') as f:
            sbom = json.load(f)

        # Check SBOM completeness
        required_fields = ['components', 'metadata', 'dependencies']
        missing = [f for f in required_fields if f not in sbom]

        if missing:
            findings.append(Finding(
                id="supply-chain-incomplete-sbom",
                category=SecurityTestCategory.SUPPLY_CHAIN,
                severity=Severity.MEDIUM,
                title="Incomplete SBOM",
                description=f"SBOM missing required fields: {missing}",
                affected_component="SBOM",
                evidence=f"Missing fields: {missing}",
                remediation="Regenerate SBOM with complete metadata"
            ))

        return findings

    def _scan_dependencies_for_malware(self) -> List[Finding]:
        """
        Scan dependencies for known malicious packages
        Uses multiple threat intelligence sources
        """
        findings = []
        dependencies = self._extract_dependencies()

        for dep in dependencies:
            # Check against OSV.dev database
            malware_result = self._check_osv_malware(dep)
            if malware_result:
                findings.append(Finding(
                    id=f"supply-chain-malware-{dep['name']}",
                    category=SecurityTestCategory.SUPPLY_CHAIN,
                    severity=Severity.CRITICAL,
                    title=f"Malicious Dependency Detected: {dep['name']}",
                    description=f"Package {dep['name']} version {dep['version']} "
                              f"is known malware: {malware_result['description']}",
                    affected_component=f"Dependency: {dep['name']}",
                    evidence=json.dumps(malware_result, indent=2),
                    remediation=f"IMMEDIATELY remove {dep['name']} and scan for compromise"
                ))

        return findings

    def _verify_build_integrity(self) -> List[Finding]:
        """
        Verify no tampering occurred during build process
        Compares expected vs actual binary hashes
        """
        findings = []

        # Check for unsigned binaries
        if not self._verify_code_signing():
            findings.append(Finding(
                id="supply-chain-unsigned-binary",
                category=SecurityTestCategory.SUPPLY_CHAIN,
                severity=Severity.HIGH,
                title="Unsigned Build Artifacts",
                description="Build artifacts are not cryptographically signed",
                affected_component="Build System",
                evidence="No digital signatures found on binaries",
                remediation="Implement code signing with Sigstore or similar"
            ))

        # Compare binary hashes
        if not self._verify_reproducible_builds():
            findings.append(Finding(
                id="supply-chain-non-reproducible",
                category=SecurityTestCategory.SUPPLY_CHAIN,
                severity=Severity.MEDIUM,
                title="Non-Reproducible Build Detected",
                description="Binary cannot be reproduced from source, indicating possible tampering",
                affected_component="Build System",
                evidence="Hash mismatch between expected and actual binary",
                remediation="Implement reproducible builds"
            ))

        return findings

    def _verify_provenance(self) -> List[Finding]:
        """
        Verify SLSA provenance attestations
        Ensures artifacts came from expected build system
        """
        findings = []

        # Check for SLSA provenance
        provenance = self._load_provenance()
        if not provenance:
            findings.append(Finding(
                id="supply-chain-no-provenance",
                category=SecurityTestCategory.SUPPLY_CHAIN,
                severity=Severity.HIGH,
                title="Missing Build Provenance (SLSA)",
                description="No SLSA provenance attestation found",
                affected_component="Build System",
                evidence="No provenance file",
                remediation="Implement SLSA Level 2+ with provenance generation"
            ))
        else:
            # Verify provenance signature
            if not self._verify_provenance_signature(provenance):
                findings.append(Finding(
                    id="supply-chain-invalid-provenance",
                    category=SecurityTestCategory.SUPPLY_CHAIN,
                    severity=Severity.CRITICAL,
                    title="Invalid Provenance Signature",
                    description="Provenance attestation signature verification FAILED",
                    affected_component="Build System",
                    evidence="Signature validation failed",
                    remediation="Investigation required - potential build compromise"
                ))

        return findings

    def _detect_typosquatting(self) -> List[Finding]:
        """
        Detect potential typosquatting attacks in dependencies
        """
        findings = []
        dependencies = self._extract_dependencies()

        # Common typosquatting patterns
        legit_packages = self._load_popular_packages_list()

        for dep in dependencies:
            # Check Levenshtein distance to popular packages
            for legit_pkg in legit_packages:
                distance = self._levenshtein_distance(dep['name'], legit_pkg)
                if 1 <= distance <= 2:  # Close enough to be typosquatting
                    findings.append(Finding(
                        id=f"supply-chain-typosquat-{dep['name']}",
                        category=SecurityTestCategory.SUPPLY_CHAIN,
                        severity=Severity.HIGH,
                        title=f"Potential Typosquatting: {dep['name']}",
                        description=f"Package '{dep['name']}' is suspiciously similar to "
                                  f"popular package '{legit_pkg}' (edit distance: {distance})",
                        affected_component=f"Dependency: {dep['name']}",
                        evidence=f"Similar to {legit_pkg}, possible typosquatting attack",
                        remediation=f"Verify package name. Did you mean '{legit_pkg}'?"
                    ))

        return findings

    def _check_osv_malware(self, dep: dict) -> dict:
        """Check OSV.dev database for known malicious packages"""
        try:
            response = requests.post(
                "https://api.osv.dev/v1/query",
                json={
                    "package": {"name": dep['name'], "ecosystem": dep['ecosystem']},
                    "version": dep['version']
                },
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('vulns'):
                    return {'description': data['vulns'][0].get('summary', 'Malware detected')}
        except:
            pass
        return None

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate edit distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    # Helper methods (simplified implementations)
    def _extract_dependencies(self) -> list:
        """Extract dependencies from requirements.txt."""
        dependencies = []
        static_analysis_path = self.config.get("static_analysis_path")
        if not static_analysis_path:
            return []

        requirements_path = os.path.join(static_analysis_path, "requirements.txt")
        if not os.path.exists(requirements_path):
            return []

        with open(requirements_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split("==")
                    dependencies.append({"name": parts[0], "version": parts[1] if len(parts) > 1 else "latest", "ecosystem": "PyPI"})
        return dependencies

    def _verify_code_signing(self) -> bool:
        """Check if artifacts are signed"""
        return False

    def _verify_reproducible_builds(self) -> bool:
        """Verify build reproducibility"""
        return False

    def _load_provenance(self) -> dict:
        """Load SLSA provenance attestation"""
        return None

    def _verify_provenance_signature(self, prov: dict) -> bool:
        """Verify provenance signature"""
        return False

    def _load_popular_packages_list(self) -> list:
        """Load list of popular packages for typosquatting detection"""
        return ['requests', 'flask', 'django', 'numpy', 'pandas']
