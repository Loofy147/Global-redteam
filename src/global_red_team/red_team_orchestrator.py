"""
Complete Red Team Orchestration Framework
Integrates all testing methodologies into a unified platform
"""

import json
import time
import hashlib
import argparse
from . import database as db
from .red_team_api_tester import APISecurityTester, APIEndpoint
from .red_team_fuzzer import CoverageGuidedFuzzer
from .red_team_property_testing import PropertyTester
from .red_team_race_detector import RaceConditionDetector
from .reporting import ReportGenerator
from .models import Finding, Severity, SecurityTestCategory, TestSuite
from .config import Settings
import os
from .threat_intelligence import ThreatIntelligence
from ai_vulnerability_discovery import AIVulnerabilityDiscovery, CodeVulnerability, VulnerabilityPattern
from typing import Dict, List, Callable, Optional
from datetime import datetime
from .logger import logger


class RedTeamOrchestrator:
    """
    Master orchestrator for comprehensive red team operations
    Coordinates all testing frameworks and generates unified reports
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.target_system = settings.target_system
        self.findings: List[Finding] = []
        self.test_suites: List[TestSuite] = []
        self.execution_log: List[Dict] = []
        self.threat_intelligence = ThreatIntelligence(
            "src/global_red_team/known_exploited_vulnerabilities.json"
        )

        self.stats = {
            "total_tests": 0,
            "tests_passed": 0,
            "tests_failed": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
            "start_time": datetime.now(),
            "end_time": datetime.now(),
        }

    def register_test_suite(
        self,
        name: str,
        category: SecurityTestCategory,
        tests: List[Callable],
        description: str = "",
    ):
        """Register a test suite"""
        suite = TestSuite(
            name=name, category=category, tests=tests, description=description
        )
        self.test_suites.append(suite)
        logger.info(f"Registered test suite: {suite.name} ({len(suite.tests)} tests)")

    def add_finding_from_result(self, result, category):
        """Add a finding from a test result object"""
        if not result.passed:
            unique_str = f"{result.vulnerability_type.value}:{result.endpoint.path}:{result.evidence}"
            finding_id = f"api-{hashlib.sha256(unique_str.encode()).hexdigest()[:16]}"
            finding = Finding(
                id=finding_id,
                category=category,
                severity=Severity(result.severity),
                title=f"Vulnerability: {result.vulnerability_type.value}",
                description=result.details,
                affected_component=f"{result.endpoint.method} {result.endpoint.path}",
                evidence=result.evidence,
                remediation=result.remediation,
            )
            self.add_finding(finding)

    def run_api_tests(self):
        """Run the API security test suite"""
        api_tester = APISecurityTester(
            base_url=self.settings.api_url, auth_token=self.settings.auth_token
        )

        if self.settings.swagger_file:
            endpoints = api_tester.discover_endpoints_from_swagger(
                self.settings.swagger_file
            )
        else:
            endpoints = [
                APIEndpoint(path="/api/users/2", method="GET"),
                APIEndpoint(path="/api/admin/users", method="GET"),
            ]

        results = api_tester.test_comprehensive(endpoints)
        for result in results:
            self.add_finding_from_result(result, SecurityTestCategory.API_SECURITY)
        return not any(not r.passed for r in results)

    def run_fuzz_tests(self):
        """Run the fuzz testing suite"""
        fuzz_settings = self.settings.fuzzing
        target_function_name = fuzz_settings.target_function

        # Simple mapping of target function names to actual functions
        # In a real-world scenario, this might involve dynamic imports
        def vulnerable_parser(data: bytes):
            if b"CRASH" in data:
                raise ValueError("Fuzzer found a crash!")

        target_functions = {"vulnerable_parser": vulnerable_parser}

        if target_function_name not in target_functions:
            logger.warning(
                f"Fuzzing target function '{target_function_name}' not found. Skipping."
            )
            return True

        fuzzer = CoverageGuidedFuzzer(
            target_function=target_functions[target_function_name],
            max_iterations=fuzz_settings.max_iterations,
            timeout=fuzz_settings.timeout,
        )

        for seed in fuzz_settings.seeds:
            fuzzer.add_seed(seed.encode())

        fuzzer.run()

        if fuzzer.crashes:
            for crash in fuzzer.crashes:
                finding_id = f"fuzz-{hashlib.sha256(crash.input_data).hexdigest()[:16]}"
                finding = Finding(
                    id=finding_id,
                    category=SecurityTestCategory.FUZZING,
                    severity=Severity.HIGH,
                    title="Fuzzer discovered a crash",
                    description=str(crash.exception),
                    affected_component=target_function_name,
                    evidence=crash.input_data.hex(),
                    remediation="Investigate crash and fix the underlying bug.",
                )
                self.add_finding(finding)
            return False
        return True

    def run_property_tests(self):
        """Run the property-based testing suite"""
        property_tester = PropertyTester(iterations=10)

        def vulnerable_sql_query(user_input: str):
            if "'" in user_input:
                return "SQL error"
            return "OK"

        property_tester.test_injection_resistance(vulnerable_sql_query)
        if property_tester.failures:
            for failure in property_tester.failures:
                unique_str = f"{failure.vulnerability_type.value}:{failure.input_value}"
                finding_id = f"prop-{hashlib.sha256(unique_str.encode()).hexdigest()[:16]}"
                finding = Finding(
                    id=finding_id,
                    category=SecurityTestCategory.PROPERTY_BASED,
                    severity=Severity.HIGH,
                    title=f"Property test failed: {failure.vulnerability_type.value}",
                    description=f"Input: {failure.input_value}, Output: {failure.output_value}",
                    affected_component="vulnerable_sql_query",
                    evidence=failure.input_value,
                    remediation="Fix the code to satisfy the tested property.",
                )
                self.add_finding(finding)
            return False
        return True

    def _convert_code_vuln_to_finding(self, vuln: Dict) -> Finding:
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

    def run_sast_scan(self):
        """Runs the AI-powered static analysis scan on the target codebase."""
        sast_engine = AIVulnerabilityDiscovery()
        target_path = self.settings.static_analysis_path

        if not os.path.isdir(target_path):
            logger.warning(f"Invalid static analysis path: {target_path}")
            return False

        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            code = f.read()
                    except (FileNotFoundError, IOError) as e:
                        logger.error(f"Error reading file {file_path}: {e}")
                        continue

                    results = sast_engine.discover_vulnerabilities(code, file_path)
                    for vuln in results.get("static_analysis", []):
                        finding = self._convert_code_vuln_to_finding(vuln)
                        self.add_finding(finding)

        return True

    def run_race_condition_tests(self):
        """Run the race condition detection suite on the withdrawal endpoint"""
        race_detector = RaceConditionDetector(threads=10, iterations=5)
        url = f"{self.settings.api_url}/api/payments/withdraw"
        headers = {"Authorization": f"Bearer {self.settings.auth_token}"}
        # Attempt to withdraw 100 from an account with a balance of 1000 ten times concurrently
        json_payload = {"amount": 100}

        result = race_detector.test_api_endpoint(
            url, "POST", headers=headers, json=json_payload
        )

        if result.is_vulnerable:
            finding = Finding(
                id="RACE-API-WITHDRAW",
                category=SecurityTestCategory.RACE_CONDITIONS,
                severity=Severity(result.severity),
                title="Race Condition in Withdrawal API (Double Spend)",
                description=f"Concurrent requests to the withdrawal API resulted in multiple outcomes, "
                f"indicating a race condition. This could allow for 'double spending'. "
                f"Details: {result.details}",
                affected_component="POST /api/payments/withdraw",
                evidence=f"{result.unique_outcomes} unique outcomes observed.",
                remediation="Implement a pessimistic lock (e.g., a mutex or database-level lock) "
                "around the balance check and withdrawal operation.",
            )
            self.add_finding(finding)
            return False
        return True

    def add_finding(self, finding: Finding):
        """Add a security finding"""
        if finding.cve_id:
            threat_info = self.threat_intelligence.get_threat_info(finding.cve_id)
            if threat_info:
                finding.severity = Severity.CRITICAL
                finding.threat_intel = threat_info

        self.findings.append(finding)
        db.save_finding(finding)

        # Update statistics
        if finding.severity == Severity.CRITICAL:
            self.stats["critical_findings"] += 1
        elif finding.severity == Severity.HIGH:
            self.stats["high_findings"] += 1
        elif finding.severity == Severity.MEDIUM:
            self.stats["medium_findings"] += 1
        elif finding.severity == Severity.LOW:
            self.stats["low_findings"] += 1

        logger.warning(f"Finding: [{finding.severity.value.upper()}] {finding.title}")

    def execute_all_tests(self):
        """Execute all registered test suites"""
        logger.info("=" * 80)
        logger.info(f"RED TEAM ASSESSMENT: {self.target_system}")
        logger.info("=" * 80)
        logger.info(f"Start Time: {datetime.now()}")
        logger.info(f"Test Suites: {len(self.test_suites)}")
        logger.info("=" * 80)

        self.stats["start_time"] = datetime.now()

        for suite in self.test_suites:
            if not suite.enabled:
                continue

            logger.info(f"\n[*] Executing Test Suite: {suite.name}")
            logger.info(f"    Category: {suite.category.value}")
            logger.info(f"    Tests: {len(suite.tests)}")
            logger.info("-" * 80)

            for i, test_func in enumerate(suite.tests, 1):
                try:
                    logger.info(f"  [{i}/{len(suite.tests)}] Running {test_func.__name__}...")

                    start = time.time()
                    result = test_func()
                    elapsed = time.time() - start

                    self.stats["total_tests"] += 1

                    # Log execution
                    log_entry = {
                        "suite": suite.name,
                        "test": test_func.__name__,
                        "result": "pass" if result else "fail",
                        "elapsed": elapsed,
                        "timestamp": datetime.now().isoformat(),
                    }
                    self.execution_log.append(log_entry)

                    if result:
                        self.stats["tests_passed"] += 1
                        logger.info(f"      ✓ PASS ({elapsed:.2f}s)")
                    else:
                        self.stats["tests_failed"] += 1
                        logger.warning(f"      ✗ FAIL ({elapsed:.2f}s)")

                except Exception as e:
                    self.stats["total_tests"] += 1
                    self.stats["tests_failed"] += 1
                    logger.error(f"      ✗ ERROR: {e}")

                    # Log error
                    log_entry = {
                        "suite": suite.name,
                        "test": test_func.__name__,
                        "result": "error",
                        "error": str(e),
                        "timestamp": datetime.now().isoformat(),
                    }
                    self.execution_log.append(log_entry)

        self.stats["end_time"] = datetime.now()

        db.close_old_findings(self.stats["start_time"])

        logger.info("\n" + "=" * 80)
        logger.info("Assessment Complete")
        logger.info("=" * 80)
        self._print_summary()

    def _print_summary(self):
        """Print execution summary"""
        duration = (self.stats["end_time"] - self.stats["start_time"]).total_seconds()

        logger.info(f"\nExecution Time: {duration:.2f}s")
        logger.info(f"Total Tests: {self.stats['total_tests']}")
        logger.info(f"  Passed: {self.stats['tests_passed']}")
        logger.info(f"  Failed: {self.stats['tests_failed']}")

        summary = db.get_findings_summary()
        new_findings = (
            summary.get("critical_new", 0)
            + summary.get("high_new", 0)
            + summary.get("medium_new", 0)
            + summary.get("low_new", 0)
        )
        regressions = (
            summary.get("critical_regression", 0)
            + summary.get("high_regression", 0)
            + summary.get("medium_regression", 0)
            + summary.get("low_regression", 0)
        )

        logger.info(f"\nFindings: {len(self.findings)}")
        logger.info(f"  New: {new_findings}")
        logger.info(f"  Regressions: {regressions}")
        logger.info(f"  Critical: {self.stats['critical_findings']}")
        logger.info(f"  High: {self.stats['high_findings']}")
        logger.info(f"  Medium: {self.stats['medium_findings']}")
        logger.info(f"  Low: {self.stats['low_findings']}")


if __name__ == "__main__":
    settings = Settings()

    parser = argparse.ArgumentParser(description="Red Team Orchestrator")
    parser.add_argument(
        "--target",
        type=str,
        default=settings.target_system,
        help="Target system for assessment",
    )
    parser.add_argument(
        "--api-url",
        type=str,
        default=settings.api_url,
        help="Base URL for API testing",
    )
    parser.add_argument(
        "--auth-token",
        type=str,
        default=settings.auth_token,
        help="Auth token for API testing",
    )
    parser.add_argument(
        "--suites",
        nargs="+",
        default=None,
        help="Test suites to run (api, fuzz, property, race, all)",
    )
    parser.add_argument(
        "--dashboard", action="store_true", help="Display the security dashboard"
    )
    parser.add_argument(
        "--swagger",
        type=str,
        default=settings.swagger_file,
        help="Path to Swagger/OpenAPI file for API discovery",
    )

    args = parser.parse_args()

    # Update settings from command line arguments
    settings.target_system = args.target
    settings.api_url = args.api_url
    settings.auth_token = args.auth_token
    settings.swagger_file = args.swagger

    orchestrator = RedTeamOrchestrator(settings)

    suites = {
        "api": (
            SecurityTestCategory.API_SECURITY,
            [orchestrator.run_api_tests],
            "Comprehensive API security testing.",
        ),
        "fuzz": (
            SecurityTestCategory.FUZZING,
            [orchestrator.run_fuzz_tests],
            "Coverage-guided fuzzing of vulnerable functions.",
        ),
        "property": (
            SecurityTestCategory.PROPERTY_BASED,
            [orchestrator.run_property_tests],
            "Adversarial property-based testing.",
        ),
        "race": (
            SecurityTestCategory.RACE_CONDITIONS,
            [orchestrator.run_race_condition_tests],
            "Detecting concurrency vulnerabilities.",
        ),
        "sast": (
            SecurityTestCategory.STATIC_ANALYSIS,
            [orchestrator.run_sast_scan],
            "AI-powered static analysis of the codebase.",
        ),
    }

    if args.dashboard:
        # Note: The dashboard functionality might need to be moved to the reporting module as well
        # For now, we'll leave it here.
        summary = db.get_findings_summary()
        open_findings = db.get_open_findings()

        logger.info("=" * 80)
        logger.info("SECURITY DASHBOARD")
        logger.info("=" * 80)

        logger.info("\n--- Open Findings by Severity ---")
        criticals = summary.get("critical_open", 0) + summary.get("critical_new", 0)
        highs = summary.get("high_open", 0) + summary.get("high_new", 0)
        mediums = summary.get("medium_open", 0) + summary.get("medium_new", 0)
        lows = summary.get("low_open", 0) + summary.get("low_new", 0)
        regressions = sum(v for k, v in summary.items() if "regression" in k)

        logger.info(f"  Critical: {criticals}")
        logger.info(f"  High:     {highs}")
        logger.info(f"  Medium:   {mediums}")
        logger.info(f"  Low:      {lows}")
        logger.info(f"  Regressions: {regressions}")
        logger.info("-" * 30)
        logger.info(f"  Total:    {criticals + highs + mediums + lows}")

        logger.info("\n--- Recent Open Findings ---")
        if not open_findings:
            logger.info("  No open findings. Great job!")
        else:
            for finding in open_findings[:10]:  # Display top 10
                status = (
                    "REGRESSION"
                    if finding["is_regression"]
                    else finding["status"].upper()
                )
                logger.info(
                    f"  - [{finding['severity'].upper()}] [{status}] {finding['title']} (Last Seen: {finding['last_seen']})"
                )

        logger.info("\n" + "=" * 80)

    elif args.suites:
        suites_to_run = args.suites
        if "all" in suites_to_run:
            suites_to_run = suites.keys()

        for suite_name in suites_to_run:
            if suite_name in suites:
                category, tests, description = suites[suite_name]
                orchestrator.register_test_suite(
                    suite_name, category, tests, description
                )

        orchestrator.execute_all_tests()

        report_generator = ReportGenerator(
            orchestrator.target_system,
            orchestrator.findings,
            orchestrator.stats,
            orchestrator.test_suites,
        )

        logger.info("\n" + report_generator.generate_executive_summary())
        logger.info("\n" + report_generator.generate_technical_report())

        report_generator.export_json("red_team_findings.json")
        report_generator.export_csv("red_team_findings.csv")
        report_generator.export_html("red_team_report.html")
    else:
        parser.print_help()
