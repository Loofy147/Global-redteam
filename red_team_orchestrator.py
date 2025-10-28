"""
Complete Red Team Orchestration Framework
Integrates all testing methodologies into a unified platform
"""

import json
import time
import hashlib
import argparse
from red_team_api_tester import APISecurityTester, APIEndpoint
from red_team_fuzzer import CoverageGuidedFuzzer
from red_team_property_testing import PropertyTester
from red_team_race_detector import RaceConditionDetector
from typing import Dict, List, Any, Callable, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class TestCategory(Enum):
    """Categories of security tests"""
    PROPERTY_BASED = "property_based"
    FUZZING = "fuzzing"
    API_SECURITY = "api_security"
    RACE_CONDITIONS = "race_conditions"
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHY = "cryptography"
    BUSINESS_LOGIC = "business_logic"
    INFRASTRUCTURE = "infrastructure"


class Severity(Enum):
    """Severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a security finding"""
    id: str
    category: TestCategory
    severity: Severity
    title: str
    description: str
    affected_component: str
    evidence: Any
    remediation: str
    cvss_score: float = 0.0
    cwe_id: Optional[str] = None
    references: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class TestSuite:
    """A collection of related tests"""
    name: str
    category: TestCategory
    tests: List[Callable]
    description: str = ""
    enabled: bool = True


class RedTeamOrchestrator:
    """
    Master orchestrator for comprehensive red team operations
    Coordinates all testing frameworks and generates unified reports
    """
    
    def __init__(self, target_system: str, config: Optional[Dict] = None):
        self.target_system = target_system
        self.config = config or {}
        self.findings: List[Finding] = []
        self.test_suites: List[TestSuite] = []
        self.execution_log: List[Dict] = []
        
        self.stats = {
            'total_tests': 0,
            'tests_passed': 0,
            'tests_failed': 0,
            'critical_findings': 0,
            'high_findings': 0,
            'medium_findings': 0,
            'low_findings': 0,
            'start_time': None,
            'end_time': None
        }
    
    def register_test_suite(self, test_suite: TestSuite):
        """Register a test suite"""
        self.test_suites.append(test_suite)
        print(f"[+] Registered test suite: {test_suite.name} ({len(test_suite.tests)} tests)")
    
    def add_finding(self, finding: Finding):
        """Add a security finding"""
        self.findings.append(finding)
        
        # Update statistics
        if finding.severity == Severity.CRITICAL:
            self.stats['critical_findings'] += 1
        elif finding.severity == Severity.HIGH:
            self.stats['high_findings'] += 1
        elif finding.severity == Severity.MEDIUM:
            self.stats['medium_findings'] += 1
        elif finding.severity == Severity.LOW:
            self.stats['low_findings'] += 1
        
        print(f"[!] Finding: [{finding.severity.value.upper()}] {finding.title}")
    
    def execute_all_tests(self):
        """Execute all registered test suites"""
        print("=" * 80)
        print(f"RED TEAM ASSESSMENT: {self.target_system}")
        print("=" * 80)
        print(f"Start Time: {datetime.now()}")
        print(f"Test Suites: {len(self.test_suites)}")
        print("=" * 80)
        
        self.stats['start_time'] = datetime.now()
        
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
                    
                    self.stats['total_tests'] += 1
                    
                    # Log execution
                    log_entry = {
                        'suite': suite.name,
                        'test': test_func.__name__,
                        'result': 'pass' if result else 'fail',
                        'elapsed': elapsed,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.execution_log.append(log_entry)
                    
                    if result:
                        self.stats['tests_passed'] += 1
                        print(f"      ✓ PASS ({elapsed:.2f}s)")
                    else:
                        self.stats['tests_failed'] += 1
                        print(f"      ✗ FAIL ({elapsed:.2f}s)")
                
                except Exception as e:
                    self.stats['total_tests'] += 1
                    self.stats['tests_failed'] += 1
                    print(f"      ✗ ERROR: {e}")
                    
                    # Log error
                    log_entry = {
                        'suite': suite.name,
                        'test': test_func.__name__,
                        'result': 'error',
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    }
                    self.execution_log.append(log_entry)
        
        self.stats['end_time'] = datetime.now()
        
        print("\n" + "=" * 80)
        print("Assessment Complete")
        print("=" * 80)
        self._print_summary()
    
    def _print_summary(self):
        """Print execution summary"""
        duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        
        print(f"\nExecution Time: {duration:.2f}s")
        print(f"Total Tests: {self.stats['total_tests']}")
        print(f"  Passed: {self.stats['tests_passed']}")
        print(f"  Failed: {self.stats['tests_failed']}")
        
        print(f"\nFindings: {len(self.findings)}")
        print(f"  Critical: {self.stats['critical_findings']}")
        print(f"  High: {self.stats['high_findings']}")
        print(f"  Medium: {self.stats['medium_findings']}")
        print(f"  Low: {self.stats['low_findings']}")
    
    def calculate_risk_score(self) -> float:
        """
        Calculate overall risk score (0-100)
        Higher score = higher risk
        """
        weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 5.0,
            Severity.MEDIUM: 2.0,
            Severity.LOW: 0.5
        }
        
        total_score = 0
        for finding in self.findings:
            total_score += weights.get(finding.severity, 0)
        
        # Normalize to 0-100 scale
        max_score = len(self.findings) * weights[Severity.CRITICAL]
        risk_score = min(100, (total_score / max_score * 100) if max_score > 0 else 0)
        
        return risk_score
    
    def generate_executive_summary(self) -> str:
        """Generate executive-level summary"""
        risk_score = self.calculate_risk_score()
        
        risk_level = "LOW"
        if risk_score >= 75:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        
        summary = []
        summary.append("=" * 80)
        summary.append("EXECUTIVE SUMMARY")
        summary.append("=" * 80)
        summary.append(f"\nTarget System: {self.target_system}")
        summary.append(f"Assessment Date: {self.stats['start_time'].strftime('%Y-%m-%d')}")
        summary.append(f"\nOVERALL RISK SCORE: {risk_score:.1f}/100 [{risk_level}]")
        
        summary.append(f"\nKEY FINDINGS:")
        summary.append(f"  • Critical Vulnerabilities: {self.stats['critical_findings']}")
        summary.append(f"  • High Vulnerabilities: {self.stats['high_findings']}")
        summary.append(f"  • Medium Vulnerabilities: {self.stats['medium_findings']}")
        summary.append(f"  • Low Vulnerabilities: {self.stats['low_findings']}")
        
        summary.append(f"\nTOP CONCERNS:")
        critical_findings = [f for f in self.findings if f.severity == Severity.CRITICAL]
        for i, finding in enumerate(critical_findings[:3], 1):
            summary.append(f"  {i}. {finding.title}")
            summary.append(f"     Impact: {finding.description}")
        
        summary.append(f"\nRECOMMENDATIONS:")
        if self.stats['critical_findings'] > 0:
            summary.append("  • IMMEDIATE ACTION REQUIRED: Address all critical vulnerabilities within 24-48 hours")
        if self.stats['high_findings'] > 0:
            summary.append("  • Address high-severity vulnerabilities within 1 week")
        if self.stats['medium_findings'] > 0:
            summary.append("  • Plan remediation for medium-severity issues within 30 days")
        
        summary.append(f"\nCOMPLIANCE IMPACT:")
        summary.append("  • PCI-DSS: " + ("NON-COMPLIANT" if critical_findings else "REVIEW REQUIRED"))
        summary.append("  • GDPR: " + ("HIGH RISK" if self.stats['critical_findings'] > 0 else "MODERATE RISK"))
        summary.append("  • SOC 2: " + ("FINDINGS REQUIRE REMEDIATION" if len(self.findings) > 0 else "ON TRACK"))
        
        summary.append("\n" + "=" * 80)
        return "\n".join(summary)
    
    def generate_technical_report(self) -> str:
        """Generate detailed technical report"""
        report = []
        report.append("=" * 80)
        report.append("TECHNICAL SECURITY ASSESSMENT REPORT")
        report.append("=" * 80)
        
        report.append(f"\n1. ASSESSMENT OVERVIEW")
        report.append(f"   Target: {self.target_system}")
        report.append(f"   Start: {self.stats['start_time']}")
        report.append(f"   End: {self.stats['end_time']}")
        report.append(f"   Duration: {(self.stats['end_time'] - self.stats['start_time']).total_seconds():.2f}s")
        report.append(f"   Total Tests: {self.stats['total_tests']}")
        
        report.append(f"\n2. METHODOLOGY")
        for suite in self.test_suites:
            report.append(f"   • {suite.name} ({suite.category.value})")
            report.append(f"     {suite.description}")
        
        report.append(f"\n3. DETAILED FINDINGS")
        
        # Group findings by severity
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            findings = [f for f in self.findings if f.severity == severity]
            
            if findings:
                report.append(f"\n   {severity.value.upper()} SEVERITY ({len(findings)} findings)")
                report.append("   " + "-" * 76)
                
                for i, finding in enumerate(findings, 1):
                    report.append(f"\n   Finding #{i}: {finding.title}")
                    report.append(f"   ID: {finding.id}")
                    report.append(f"   Category: {finding.category.value}")
                    report.append(f"   Component: {finding.affected_component}")
                    if finding.cvss_score > 0:
                        report.append(f"   CVSS Score: {finding.cvss_score}")
                    if finding.cwe_id:
                        report.append(f"   CWE: {finding.cwe_id}")
                    
                    report.append(f"\n   Description:")
                    report.append(f"   {finding.description}")
                    
                    report.append(f"\n   Evidence:")
                    report.append(f"   {finding.evidence}")
                    
                    report.append(f"\n   Remediation:")
                    report.append(f"   {finding.remediation}")
                    
                    if finding.references:
                        report.append(f"\n   References:")
                        for ref in finding.references:
                            report.append(f"   • {ref}")
                    
                    report.append("")
        
        report.append(f"\n4. ATTACK SURFACE ANALYSIS")
        categories = {}
        for finding in self.findings:
            cat = finding.category.value
            categories[cat] = categories.get(cat, 0) + 1
        
        for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            report.append(f"   • {category}: {count} findings")
        
        report.append(f"\n5. RISK ASSESSMENT")
        risk_score = self.calculate_risk_score()
        report.append(f"   Overall Risk Score: {risk_score:.1f}/100")
        report.append(f"   Critical Findings: {self.stats['critical_findings']}")
        report.append(f"   High Findings: {self.stats['high_findings']}")
        report.append(f"   Total Findings: {len(self.findings)}")
        
        report.append(f"\n6. REMEDIATION ROADMAP")
        report.append("   Phase 1 (Immediate - 0-7 days):")
        report.append("   • Fix all CRITICAL vulnerabilities")
        report.append("   • Implement emergency controls for HIGH vulnerabilities")
        
        report.append("\n   Phase 2 (Short-term - 7-30 days):")
        report.append("   • Fix all HIGH vulnerabilities")
        report.append("   • Begin addressing MEDIUM vulnerabilities")
        
        report.append("\n   Phase 3 (Medium-term - 30-90 days):")
        report.append("   • Complete MEDIUM vulnerability remediation")
        report.append("   • Address LOW vulnerabilities")
        report.append("   • Implement preventive controls")
        
        report.append("\n   Phase 4 (Long-term - 90+ days):")
        report.append("   • Security architecture improvements")
        report.append("   • Continuous monitoring enhancement")
        report.append("   • Security training and culture")
        
        report.append("\n" + "=" * 80)
        return "\n".join(report)
    
    def export_json(self, filepath: str):
        """Export findings as JSON"""
        data = {
            'target_system': self.target_system,
            'assessment_date': self.stats['start_time'].isoformat(),
            'risk_score': self.calculate_risk_score(),
            'statistics': {
                'total_tests': self.stats['total_tests'],
                'tests_passed': self.stats['tests_passed'],
                'tests_failed': self.stats['tests_failed'],
                'critical_findings': self.stats['critical_findings'],
                'high_findings': self.stats['high_findings'],
                'medium_findings': self.stats['medium_findings'],
                'low_findings': self.stats['low_findings']
            },
            'findings': [
                {
                    'id': f.id,
                    'category': f.category.value,
                    'severity': f.severity.value,
                    'title': f.title,
                    'description': f.description,
                    'affected_component': f.affected_component,
                    'evidence': str(f.evidence),
                    'remediation': f.remediation,
                    'cvss_score': f.cvss_score,
                    'cwe_id': f.cwe_id,
                    'references': f.references,
                    'discovered_at': f.discovered_at.isoformat()
                }
                for f in self.findings
            ]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[+] Report exported to {filepath}")
    
    def export_csv(self, filepath: str):
        """Export findings as CSV"""
        import csv
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'ID', 'Severity', 'Category', 'Title', 'Component',
                'CVSS', 'CWE', 'Description', 'Remediation'
            ])
            
            for finding in self.findings:
                writer.writerow([
                    finding.id,
                    finding.severity.value,
                    finding.category.value,
                    finding.title,
                    finding.affected_component,
                    finding.cvss_score,
                    finding.cwe_id or '',
                    finding.description,
                    finding.remediation
                ])
        
        print(f"[+] CSV exported to {filepath}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Red Team Orchestrator")
    parser.add_argument("--target", type=str, default="Production API v2.0", help="Target system for assessment")
    parser.add_argument("--api-url", type=str, default="https://api.example.com", help="Base URL for API testing")
    parser.add_argument("--auth-token", type=str, default="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.test", help="Auth token for API testing")
    parser.add_argument("--suites", nargs='+', default=['all'], help="Test suites to run (api, fuzz, property, race, all)")
    
    args = parser.parse_args()

    orchestrator = RedTeamOrchestrator(
        target_system=args.target,
        config={
            'max_threads': 100,
            'timeout': 5.0,
            'verbose': True,
            'api_url': args.api_url,
            'auth_token': args.auth_token
        }
    )

    def run_api_tests():
        """Run the API security test suite"""
        api_tester = APISecurityTester(base_url=orchestrator.config['api_url'], auth_token=orchestrator.config['auth_token'])
        endpoints = [
            APIEndpoint(path="/api/users/{id}", method="GET"),
            APIEndpoint(path="/api/users", method="POST", body={'username': 'test', 'email': 'test@example.com'}),
            APIEndpoint(path="/api/admin/users", method="GET"),
            APIEndpoint(path="/api/search", method="GET", requires_auth=False)
        ]
        results = api_tester.test_comprehensive(endpoints)
        for result in results:
            if not result.passed:
                finding = Finding(
                    id=f"API-{result.vulnerability_type.value}",
                    category=TestCategory.API_SECURITY,
                    severity=Severity(result.severity),
                    title=f"API Vulnerability: {result.vulnerability_type.value}",
                    description=result.details,
                    affected_component=f"{result.endpoint.method} {result.endpoint.path}",
                    evidence=result.evidence,
                    remediation=result.remediation
                )
                orchestrator.add_finding(finding)
        return not any(not r.passed for r in results)

    def run_fuzz_tests():
        """Run the fuzz testing suite"""
        def vulnerable_parser(data: bytes):
            if b"CRASH" in data:
                raise ValueError("Fuzzer found a crash!")
        fuzzer = CoverageGuidedFuzzer(target_function=vulnerable_parser, max_iterations=1000)
        fuzzer.add_seed(b"some initial data")
        fuzzer.run()
        if fuzzer.crashes:
            for crash in fuzzer.crashes:
                finding = Finding(
                    id=f"FUZZ-{hashlib.sha1(crash.input_data).hexdigest()}",
                    category=TestCategory.FUZZING,
                    severity=Severity.HIGH,
                    title="Fuzzer discovered a crash",
                    description=str(crash.exception),
                    affected_component="vulnerable_parser",
                    evidence=crash.input_data.hex(),
                    remediation="Investigate crash and fix the underlying bug."
                )
                orchestrator.add_finding(finding)
            return False
        return True

    def run_property_tests():
        """Run the property-based testing suite"""
        property_tester = PropertyTester(iterations=100)
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
                    remediation="Fix the code to satisfy the tested property."
                )
                orchestrator.add_finding(finding)
            return False
        return True

    def run_race_condition_tests():
        """Run the race condition detection suite"""
        race_detector = RaceConditionDetector(threads=50)
        class Counter:
            def __init__(self):
                self.value = 0
            def increment(self):
                current = self.value
                time.sleep(0.0001)
                self.value = current + 1
        counter = Counter()
        result = race_detector.test_concurrent_execution(counter.increment)
        if result.is_vulnerable:
            finding = Finding(
                id="RACE-CONCURRENT-EXEC",
                category=TestCategory.RACE_CONDITIONS,
                severity=Severity(result.severity),
                title="Race condition detected in concurrent execution",
                description=result.details,
                affected_component="Counter.increment",
                evidence=f"{result.unique_outcomes} unique outcomes",
                remediation="Use locks or other synchronization primitives."
            )
            orchestrator.add_finding(finding)
            return False
        return True

    suites = {
        'api': TestSuite(name="API Security", category=TestCategory.API_SECURITY, tests=[run_api_tests], description="Comprehensive API security testing."),
        'fuzz': TestSuite(name="Fuzz Testing", category=TestCategory.FUZZING, tests=[run_fuzz_tests], description="Coverage-guided fuzzing of vulnerable functions."),
        'property': TestSuite(name="Property-Based Testing", category=TestCategory.PROPERTY_BASED, tests=[run_property_tests], description="Adversarial property-based testing."),
        'race': TestSuite(name="Race Condition Detection", category=TestCategory.RACE_CONDITIONS, tests=[run_race_condition_tests], description="Detecting concurrency vulnerabilities.")
    }

    suites_to_run = args.suites
    if 'all' in suites_to_run:
        suites_to_run = suites.keys()

    for suite_name in suites_to_run:
        if suite_name in suites:
            orchestrator.register_test_suite(suites[suite_name])
    
    orchestrator.execute_all_tests()
    
    print("\n" + orchestrator.generate_executive_summary())
    print("\n" + orchestrator.generate_technical_report())
    
    orchestrator.export_json("red_team_findings.json")
    orchestrator.export_csv("red_team_findings.csv")
