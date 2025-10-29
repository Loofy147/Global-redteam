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
from .models import Finding, Severity, TestCategory, TestSuite
from .config import Settings
from .threat_intelligence import ThreatIntelligence
from typing import Dict, List, Callable, Optional
from datetime import datetime


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
        category: TestCategory,
        tests: List[Callable],
        description: str = "",
    ):
        """Register a test suite"""
        suite = TestSuite(
            name=name, category=category, tests=tests, description=description
        )
        self.test_suites.append(suite)
        print(f"[+] Registered test suite: {suite.name} ({len(suite.tests)} tests)")

    def add_finding_from_result(self, result, category):
        """Add a finding from a test result object"""
        if not result.passed:
            finding = Finding(
                id=f"{result.vulnerability_type.value}-{hashlib.sha1(str(result.evidence).encode()).hexdigest()[:10]}",
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
            self.add_finding_from_result(result, TestCategory.API_SECURITY)
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
            print(
                f"[!] Fuzzing target function '{target_function_name}' not found. Skipping."
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
                finding = Finding(
                    id=f"FUZZ-{hashlib.sha1(crash.input_data).hexdigest()}",
                    category=TestCategory.FUZZING,
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
                finding = Finding(
                    id=f"PROP-{failure.vulnerability_type.value}",
                    category=TestCategory.PROPERTY_BASED,
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
                category=TestCategory.RACE_CONDITIONS,
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

        print(f"[!] Finding: [{finding.severity.value.upper()}] {finding.title}")

    def execute_all_tests(self):
        """Execute all registered test suites"""
        print("=" * 80)
        print(f"RED TEAM ASSESSMENT: {self.target_system}")
        print("=" * 80)
        print(f"Start Time: {datetime.now()}")
        print(f"Test Suites: {len(self.test_suites)}")
        print("=" * 80)

        self.stats["start_time"] = datetime.now()

        for suite in self.test_suites:
            if not suite.enabled:
                continue

            print(f"\n[*] Executing Test Suite: {suite.name}")
            print(f"    Category: {suite.category.value}")
            print(f"    Tests: {len(suite.tests)}")
            print("-" * 80)

            for i, test_func in enumerate(suite.tests, 1):
                try:
                    print(f"  [{i}/{len(suite.tests)}] Running {test_func.__name__}...")

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
                        print(f"      ✓ PASS ({elapsed:.2f}s)")
                    else:
                        self.stats["tests_failed"] += 1
                        print(f"      ✗ FAIL ({elapsed:.2f}s)")

                except Exception as e:
                    self.stats["total_tests"] += 1
                    self.stats["tests_failed"] += 1
                    print(f"      ✗ ERROR: {e}")

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

        print("\n" + "=" * 80)
        print("Assessment Complete")
        print("=" * 80)
        self._print_summary()

    def _print_summary(self):
        """Print execution summary"""
        duration = (self.stats["end_time"] - self.stats["start_time"]).total_seconds()

        print(f"\nExecution Time: {duration:.2f}s")
        print(f"Total Tests: {self.stats['total_tests']}")
        print(f"  Passed: {self.stats['tests_passed']}")
        print(f"  Failed: {self.stats['tests_failed']}")

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

        print(f"\nFindings: {len(self.findings)}")
        print(f"  New: {new_findings}")
        print(f"  Regressions: {regressions}")
        print(f"  Critical: {self.stats['critical_findings']}")
        print(f"  High: {self.stats['high_findings']}")
        print(f"  Medium: {self.stats['medium_findings']}")
        print(f"  Low: {self.stats['low_findings']}")


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
            TestCategory.API_SECURITY,
            [orchestrator.run_api_tests],
            "Comprehensive API security testing.",
        ),
        "fuzz": (
            TestCategory.FUZZING,
            [orchestrator.run_fuzz_tests],
            "Coverage-guided fuzzing of vulnerable functions.",
        ),
        "property": (
            TestCategory.PROPERTY_BASED,
            [orchestrator.run_property_tests],
            "Adversarial property-based testing.",
        ),
        "race": (
            TestCategory.RACE_CONDITIONS,
            [orchestrator.run_race_condition_tests],
            "Detecting concurrency vulnerabilities.",
        ),
    }

    if args.dashboard:
        # Note: The dashboard functionality might need to be moved to the reporting module as well
        # For now, we'll leave it here.
        summary = db.get_findings_summary()
        open_findings = db.get_open_findings()

        print("=" * 80)
        print("SECURITY DASHBOARD")
        print("=" * 80)

        print("\n--- Open Findings by Severity ---")
        criticals = summary.get("critical_open", 0) + summary.get("critical_new", 0)
        highs = summary.get("high_open", 0) + summary.get("high_new", 0)
        mediums = summary.get("medium_open", 0) + summary.get("medium_new", 0)
        lows = summary.get("low_open", 0) + summary.get("low_new", 0)
        regressions = sum(v for k, v in summary.items() if "regression" in k)

        print(f"  Critical: {criticals}")
        print(f"  High:     {highs}")
        print(f"  Medium:   {mediums}")
        print(f"  Low:      {lows}")
        print(f"  Regressions: {regressions}")
        print("-" * 30)
        print(f"  Total:    {criticals + highs + mediums + lows}")

        print("\n--- Recent Open Findings ---")
        if not open_findings:
            print("  No open findings. Great job!")
        else:
            for finding in open_findings[:10]:  # Display top 10
                status = (
                    "REGRESSION"
                    if finding["is_regression"]
                    else finding["status"].upper()
                )
                print(
                    f"  - [{finding['severity'].upper()}] [{status}] {finding['title']} (Last Seen: {finding['last_seen']})"
                )

        print("\n" + "=" * 80)

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

        print("\n" + report_generator.generate_executive_summary())
        print("\n" + report_generator.generate_technical_report())

        report_generator.export_json("red_team_findings.json")
        report_generator.export_csv("red_team_findings.csv")
        report_generator.export_html("red_team_report.html")
    else:
        parser.print_help()
