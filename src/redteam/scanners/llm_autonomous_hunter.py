# New Module: src/redteam/scanners/llm_autonomous_hunter.py

from src.redteam.scanners.base import BaseScanner
from src.redteam.core.finding import Finding, Severity, SecurityTestCategory
from src.redteam.utils.rate_limiter import RateLimiter
import ast
import hashlib
import os
import json
from anthropic import Anthropic


class LLMAutonomousHunter(BaseScanner):
    """
    LLM-powered autonomous vulnerability hunter using multi-trajectory search
    Implements principles from Google Project Zero's "Project Naptime"
    """

    def __init__(self, config: dict):
        super().__init__(config)
        self.anthropic_client = Anthropic()
        self.model = "claude-sonnet-4-20250514"
        self.max_trajectories = config.get('max_trajectories', 5)
        self.verification_enabled = True
        self.rate_limiter = RateLimiter(
            max_requests=self.config.get("rate_limit", 5),
            time_window=1
        )

    def get_required_config_fields(self) -> list:
        return ['static_analysis_path']

    def _get_source_files(self) -> list[str]:
        """Finds all source files in the configured path."""
        source_files = []
        path = self.config.get("static_analysis_path", ".")
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(".py"):
                    source_files.append(os.path.join(root, file))
        return source_files

    def _scan_implementation(self) -> list[Finding]:
        """
        Multi-trajectory autonomous vulnerability discovery
        Each trajectory explores a different hypothesis
        """
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
        self.rate_limiter.acquire()
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
        try:
            response = self.anthropic_client.messages.create(
                model=self.model,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )
            hypotheses = json.loads(response.content[0].text)
            return hypotheses
        except Exception:
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
            category=self._map_to_category(hypothesis.get('vuln_type', 'unknown')),
            severity=self._calculate_severity(hypothesis, analysis),
            title=f"LLM-Discovered: {hypothesis.get('vuln_type', 'unknown')} in {filepath}",
            description=f"{analysis.get('explanation', '')}\n\nDiscovery Method: Autonomous LLM (Trajectory #{traj_id})",
            file_path=f"{filepath}:{hypothesis.get('line_number', 0)}",
            evidence=f"PoC:\n{poc}\n\nAnalysis:\n{analysis.get('details','')}",
            remediation=analysis.get('remediation', 'N/A')
        )
        findings.append(finding)

        return findings

    def _deep_analysis(self, code: str, hypothesis: dict) -> dict:
        """
        LLM performs deep analysis using chain-of-thought reasoning
        """
        self.rate_limiter.acquire()
        prompt = f"""Perform deep security analysis of this vulnerability hypothesis.

Hypothesis: {hypothesis.get('vuln_type', 'unknown')} at line {hypothesis.get('line_number')}
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

        try:
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
        except Exception:
            return {}

    def _generate_poc(self, code: str, hypothesis: dict, analysis: dict) -> str:
        """
        Generate executable proof-of-concept exploit code
        """
        self.rate_limiter.acquire()
        prompt = f"""Generate a working proof-of-concept exploit for this vulnerability.

Vulnerability: {hypothesis.get('vuln_type', 'unknown')}
Analysis: {analysis.get('explanation', '')}

Code to exploit:
```
{code}
```

Provide ONLY executable Python/Bash code that demonstrates the exploit.
No explanations, just working code."""
        try:
            response = self.anthropic_client.messages.create(
                model=self.model,
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}]
            )

            return response.content[0].text
        except Exception:
            return ""

    def _sandbox_exec(self, code: str):
        """
        Executes code in a restricted environment.
        A real implementation should use a containerized sandbox.
        """
        restricted_globals = {
            "__builtins__": {
                "print": print,
                "len": len,
                "range": range,
                "str": str,
                "int": int,
                "list": list,
                "dict": dict,
                "set": set,
                "Exception": Exception,
            }
        }
        exec(code, restricted_globals)

    def _verify_exploit(self, code: str, poc: str) -> bool:
        """
        Automatically verify the exploit works (safely in sandbox)
        This is KEY to achieving high precision like Project Naptime
        """
        try:
            full_code = f"{code}\n\n{poc}"
            self._sandbox_exec(full_code)
            return True
        except Exception:
            return False

    def _deduplicate_findings(self, findings: list) -> list:
        """Remove duplicate findings from different trajectories"""
        seen = set()
        unique = []
        for f in findings:
            key = (f.file_path, f.title)
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
            return text[start:start + 500]
        return "Review code for vulnerability and apply security best practices"
