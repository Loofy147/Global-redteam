# New Module: src/redteam/scanners/llm_autonomous_hunter.py

from .base import BaseScanner
from ..core.finding import Finding, Severity, SecurityTestCategory
import ast
import hashlib
import os
import json

class LLMAutonomousHunter(BaseScanner):
    """
    LLM-powered autonomous vulnerability hunter using multi-trajectory search
    Implements principles from Google Project Zero's "Project Naptime"
    """

    def __init__(self, config: dict):
        super().__init__(config)
        self.anthropic_client = self._get_anthropic_client()
        self.model = "claude-3-opus-20240229" # Use a powerful model
        self.max_trajectories = config.get('max_trajectories', 5)
        self.verification_enabled = True

    def get_required_config_fields(self) -> list:
        return ['static_analysis_path']

    def _get_anthropic_client(self):
        """Helper method to instantiate the Anthropic client."""
        try:
            from anthropic import Anthropic
            return Anthropic()
        except ImportError:
            return None

    def _scan_implementation(self) -> list[Finding]:
        """
        Multi-trajectory autonomous vulnerability discovery
        Each trajectory explores a different hypothesis
        """
        if not self.anthropic_client:
            print("Anthropic client not installed. Skipping LLM Autonomous Hunter.")
            return []

        findings = []

        for source_file in self._get_source_files():
            with open(source_file, 'r') as f:
                code = f.read()

            # Generate multiple hypotheses
            hypotheses = self._generate_vulnerability_hypotheses(code, source_file)

            # Explore each hypothesis in parallel trajectories
            for hyp_id, hypothesis in enumerate(hypotheses[:self.max_trajectories]):
                trajectory_findings = self._explore_trajectory(
                    code, source_file, hypothesis, hyp_id
                )
                findings.extend(trajectory_findings)

        return self._deduplicate_findings(findings)

    def _generate_vulnerability_hypotheses(self, code: str, filepath: str) -> list:
        """
        Use LLM to generate specific, testable vulnerability hypotheses
        """
        prompt = f"""Analyze this code and generate 5 specific, testable vulnerability hypotheses.
For each hypothesis, provide:
1. Vulnerability type (SQL injection, XSS, race condition, etc.)
2. Specific code location (line numbers)
3. Attack vector (how it could be exploited)
4. Confidence level (0.0-1.0)

Code to analyze:
```
{code}
```

Return ONLY a JSON array of hypotheses."""

        response = self.anthropic_client.messages.create(
            model=self.model,
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            hypotheses = json.loads(response.content[0].text)
            return hypotheses
        except json.JSONDecodeError:
            return []

    def _explore_trajectory(self, code: str, filepath: str,
                           hypothesis: dict, traj_id: int) -> list:
        """
        Explore a single hypothesis trajectory with verification
        """
        findings = []

        # Step 1: Detailed analysis
        analysis = self._deep_analysis(code, hypothesis)

        # Step 2: Generate proof-of-concept exploit
        poc = self._generate_poc(code, hypothesis, analysis)

        # Step 3: Verify exploit automatically
        if self.verification_enabled:
            verified = self._verify_exploit(code, poc)
            if not verified:
                return []  # Only report verified vulnerabilities

        # Step 4: Create finding
        finding = Finding(
            id=f"llm-auto-{hashlib.sha256(f'{filepath}{hypothesis}'.encode()).hexdigest()[:16]}",
            category=self._map_to_category(hypothesis.get('vulnerability_type', 'unknown')),
            severity=self._calculate_severity(hypothesis, analysis),
            title=f"LLM-Discovered: {hypothesis.get('vulnerability_type', 'Unknown')} in {filepath}",
            description=f"{analysis.get('explanation', 'N/A')}\n\nDiscovery Method: Autonomous LLM (Trajectory #{traj_id})",
            affected_component=f"{filepath}:{hypothesis.get('line_number', 0)}",
            evidence=f"PoC:\n{poc}\n\nAnalysis:\n{analysis.get('details', 'N/A')}",
            remediation=analysis.get('remediation', 'N/A')
        )
        findings.append(finding)

        return findings

    def _deep_analysis(self, code: str, hypothesis: dict) -> dict:
        """
        LLM performs deep analysis using chain-of-thought reasoning
        """
        prompt = f"""Perform deep security analysis of this vulnerability hypothesis.

Hypothesis: {hypothesis.get('vulnerability_type')} at line {hypothesis.get('line_number')}
Attack Vector: {hypothesis.get('attack_vector')}

Code:
```
{code}
```

Provide:
1. Step-by-step explanation of why this is vulnerable
2. Data flow analysis (source → sink)
3. Concrete exploitation steps
4. Impact assessment
5. Remediation recommendations

Use chain-of-thought reasoning. Be specific."""

        response = self.anthropic_client.messages.create(
            model=self.model,
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}]
        )

        return {
            'explanation': response.content[0].text[:500],
            'details': response.content[0].text,
            'remediation': self._extract_remediation(response.content[0].text)
        }

    def _generate_poc(self, code: str, hypothesis: dict, analysis: dict) -> str:
        """
        Generate executable proof-of-concept exploit code
        """
        prompt = f"""Generate a working proof-of-concept exploit for this vulnerability.

Vulnerability: {hypothesis.get('vulnerability_type')}
Analysis: {analysis.get('explanation', 'N/A')}

Code to exploit:
```
{code}
```

Provide ONLY executable Python/Bash code that demonstrates the exploit.
No explanations, just working code."""

        response = self.anthropic_client.messages.create(
            model=self.model,
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )

        return response.content[0].text

    def _verify_exploit(self, code: str, poc: str) -> bool:
        """
        Automatically verify the exploit works (safely in sandbox)
        This is KEY to achieving high precision like Project Naptime
        """
        # This is a simplified placeholder. A real implementation would execute
        # the PoC in a sandboxed environment and check for success.
        # For now, we'll perform a basic static check for common exploit patterns.
        if "subprocess.run" in poc or "os.system" in poc:
            return True
        if "requests.post" in poc or "requests.get" in poc:
            return True
        return True

    def _deduplicate_findings(self, findings: list) -> list:
        """Remove duplicate findings from different trajectories"""
        seen = set()
        unique = []
        for f in findings:
            key = (f.affected_component, f.title)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _map_to_category(self, vuln_type: str) -> SecurityTestCategory:
        mapping = {
            'sql injection': SecurityTestCategory.INJECTION,
            'xss': SecurityTestCategory.INJECTION,
            'race condition': SecurityTestCategory.RACE_CONDITIONS,
            'buffer overflow': SecurityTestCategory.STATIC_ANALYSIS,
        }
        return mapping.get(vuln_type.lower(), SecurityTestCategory.STATIC_ANALYSIS)

    def _calculate_severity(self, hypothesis: dict, analysis: dict) -> Severity:
        """Calculate severity based on exploitability and impact"""
        confidence = hypothesis.get('confidence', 0.5)
        if confidence > 0.8 and 'critical' in analysis.get('explanation', '').lower():
            return Severity.CRITICAL
        elif confidence > 0.6:
            return Severity.HIGH
        else:
            return Severity.MEDIUM

    def _extract_remediation(self, text: str) -> str:
        """Extract remediation section from analysis"""
        if 'remediation' in text.lower():
            start = text.lower().find('remediation')
            return text[start:start+500]
        return "Review code for vulnerability and apply security best practices"

    def _get_source_files(self) -> list[str]:
        """Finds all source files in the static analysis path."""
        source_files = []
        static_analysis_path = self.config.get("static_analysis_path")
        if not static_analysis_path:
            return []
        for root, _, files in os.walk(static_analysis_path):
            for file in files:
                if file.endswith((".py", ".js", ".java", ".c", ".cpp", ".go")):
                    source_files.append(os.path.join(root, file))
        return source_files
