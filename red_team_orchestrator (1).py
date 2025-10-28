"""
Complete Red Team Orchestration Framework
Integrates all testing methodologies into a unified platform
"""

import json
import time
import hashlib
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


# Example comprehensive red team assessment
if __name__ == "__main__":
    
    # Initialize orchestrator
    orchestrator = RedTeamOrchestrator(
        target_system="Production API v2.0",
        config={
            'max_threads': 100,
            'timeout': 5.0,
            'verbose': True
        }
    )
    
    # Define test functions for different categories
    def test_sql_injection():
        """Test for SQL injection vulnerabilities"""
        # Simulated test
        vulnerable = True  # In real scenario, this would test actual endpoints
        
        if vulnerable:
            finding = Finding(
                id="VULN-001",
                category=TestCategory.INJECTION,
                severity=Severity.CRITICAL,
                title="SQL Injection in User Login",
                description="The login endpoint is vulnerable to SQL injection via the username parameter",
                affected_component="/api/auth/login",
                evidence="Payload: ' OR '1'='1' -- resulted in successful authentication bypass",
                remediation="Use parameterized queries. Implement input validation. Use ORM framework.",
                cvss_score=9.8,
                cwe_id="CWE-89",
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cwe.mitre.org/data/definitions/89.html"
                ]
            )
            orchestrator.add_finding(finding)
            return False
        return True
    
    def test_authentication_bypass():
        """Test for authentication bypass"""
        vulnerable = True
        
        if vulnerable:
            finding = Finding(
                id="VULN-002",
                category=TestCategory.AUTHENTICATION,
                severity=Severity.CRITICAL,
                title="JWT Algorithm Confusion Attack",
                description="API accepts JWT tokens with 'alg=none', allowing authentication bypass",
                affected_component="/api/*",
                evidence="Modified JWT with alg=none was accepted and granted full access",
                remediation="Explicitly validate JWT algorithm. Only accept RS256 or HS256. Reject 'none' algorithm.",
                cvss_score=9.1,
                cwe_id="CWE-287",
                references=[
                    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
                ]
            )
            orchestrator.add_finding(finding)
            return False
        return True
    
    def test_idor():
        """Test for IDOR/BOLA"""
        vulnerable = True
        
        if vulnerable:
            finding = Finding(
                id="VULN-003",
                category=TestCategory.AUTHORIZATION,
                severity=Severity.CRITICAL,
                title="Insecure Direct Object Reference (IDOR)",
                description="Users can access other users' data by modifying the user_id parameter",
                affected_component="/api/users/{user_id}",
                evidence="User A (id=123) successfully accessed User B's data (id=124) without authorization",
                remediation="Implement proper authorization checks. Verify user owns requested resource. Use UUIDs instead of sequential IDs.",
                cvss_score=8.2,
                cwe_id="CWE-639",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                ]
            )
            orchestrator.add_finding(finding)
            return False
        return True
    
    def test_rate_limiting():
        """Test for lack of rate limiting"""
        vulnerable = True
        
        if vulnerable:
            finding = Finding(
                id="VULN-004",
                category=TestCategory.API_SECURITY,
                severity=Severity.HIGH,
                title="No Rate Limiting on Critical Endpoints",
                description="API endpoints accept unlimited requests, enabling brute force and DoS attacks",
                affected_component="/api/auth/login, /api/password/reset",
                evidence="Successfully made 10,000 requests in 30 seconds without throttling",
                remediation="Implement rate limiting using token bucket or sliding window algorithm. Set appropriate limits per endpoint.",
                cvss_score=7.5,
                cwe_id="CWE-770",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"
                ]
            )
            orchestrator.add_finding(finding)
            return False
        return True
    
    def test_race_condition():
        """Test for race conditions"""
        vulnerable = True
        
        if vulnerable:
            finding = Finding(
                id="VULN-005",
                category=TestCategory.RACE_CONDITIONS,
                severity=Severity.HIGH,
                title="Race Condition in Payment Processing",
                description="Concurrent requests can lead to double-spending vulnerability",
                affected_component="/api/payments/withdraw",
                evidence="Successfully withdrew $1000 from account with $500 balance using concurrent requests",
                remediation="Implement database transactions with proper isolation level. Use optimistic locking or row-level locking.",
                cvss_score=7.8,
                cwe_id="CWE-362",
                references=[
                    "https://cwe.mitre.org/data/definitions/362.html"
                ]
            )
            orchestrator.add_finding(finding)
            return False
        return True
    
    def test_sensitive_data_exposure():
        """Test for sensitive data exposure"""
        vulnerable = True
        
        if vulnerable:
            finding = Finding(
                id="VULN-006",
                category=TestCategory.API_SECURITY,
                severity=Severity.HIGH,
                title="Sensitive Data Exposure in API Responses",
                description="API responses include sensitive fields like passwords, tokens, and internal IDs",
                affected_component="/api/users",
                evidence="Response includes: password_hash, api_key, internal_user_id, ssn_last4",
                remediation="Filter response data. Only include necessary fields. Use DTOs (Data Transfer Objects).",
                cvss_score=7.2,
                cwe_id="CWE-200",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"
                ]
            )
            orchestrator.add_finding(finding)
            return False
        return True
    
    def test_mass_assignment():
        """Test for mass assignment"""
        vulnerable = True
        
        if vulnerable:
            finding = Finding(
                id="VULN-007",
                category=TestCategory.API_SECURITY,
                severity=Severity.MEDIUM,
                title="Mass Assignment Vulnerability",
                description="Users can set arbitrary fields including privileged ones (is_admin, role)",
                affected_component="/api/users/update",
                evidence="Successfully set 'is_admin': true and 'role': 'admin' via API request body",
                remediation="Use allow-lists for updatable fields. Implement separate endpoints for privileged operations.",
                cvss_score=6.5,
                cwe_id="CWE-915",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"
                ]
            )
            orchestrator.add_finding(finding)
            return False
        return True
    
    def test_csrf():
        """Test for CSRF protection"""
        vulnerable = True
        
        if vulnerable:
            finding = Finding(
                id="VULN-008",
                category=TestCategory.API_SECURITY,
                severity=Severity.MEDIUM,
                title="Missing CSRF Protection",
                description="State-changing operations lack CSRF tokens, enabling cross-site attacks",
                affected_component="/api/users/delete, /api/settings/update",
                evidence="Successfully executed DELETE /api/users/123 from attacker-controlled domain",
                remediation="Implement CSRF tokens. Use SameSite cookie attribute. Validate Origin/Referer headers.",
                cvss_score=6.1,
                cwe_id="CWE-352",
                references=[
                    "https://owasp.org/www-community/attacks/csrf"
                ]
            )
            orchestrator.add_finding(finding)
            return False
        return True
    
    def test_security_headers():
        """Test for security headers"""
        vulnerable = True
        
        if vulnerable:
            finding = Finding(
                id="VULN-009",
                category=TestCategory.INFRASTRUCTURE,
                severity=Severity.LOW,
                title="Missing Security Headers",
                description="Application lacks important security headers (CSP, HSTS, X-Frame-Options)",
                affected_component="All endpoints",
                evidence="Missing: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options",
                remediation="Implement all recommended security headers. Use helmet.js or equivalent.",
                cvss_score=4.3,
                cwe_id="CWE-16",
                references=[
                    "https://owasp.org/www-project-secure-headers/"
                ]
            )
            orchestrator.add_finding(finding)
            return False
        return True
    
    def test_error_handling():
        """Test error handling and information disclosure"""
        vulnerable = True
        
        if vulnerable:
            finding = Finding(
                id="VULN-010",
                category=TestCategory.INFRASTRUCTURE,
                severity=Severity.LOW,
                title="Verbose Error Messages",
                description="Error messages expose internal system details including stack traces and file paths",
                affected_component="All endpoints",
                evidence="Error response includes: full stack trace, database connection string, file system paths",
                remediation="Implement generic error messages for users. Log detailed errors server-side only.",
                cvss_score=3.7,
                cwe_id="CWE-209",
                references=[
                    "https://cwe.mitre.org/data/definitions/209.html"
                ]
            )
            orchestrator.add_finding(finding)
            return False
        return True
    
    # Register test suites
    injection_suite = TestSuite(
        name="Injection Attack Testing",
        category=TestCategory.INJECTION,
        tests=[test_sql_injection],
        description="Tests for SQL, NoSQL, Command, and other injection vulnerabilities"
    )
    orchestrator.register_test_suite(injection_suite)
    
    auth_suite = TestSuite(
        name="Authentication & Authorization Testing",
        category=TestCategory.AUTHENTICATION,
        tests=[test_authentication_bypass, test_idor],
        description="Tests for authentication bypass and authorization flaws"
    )
    orchestrator.register_test_suite(auth_suite)
    
    api_suite = TestSuite(
        name="API Security Testing",
        category=TestCategory.API_SECURITY,
        tests=[
            test_rate_limiting,
            test_sensitive_data_exposure,
            test_mass_assignment,
            test_csrf
        ],
        description="Comprehensive API security testing (OWASP API Top 10)"
    )
    orchestrator.register_test_suite(api_suite)
    
    race_suite = TestSuite(
        name="Concurrency Testing",
        category=TestCategory.RACE_CONDITIONS,
        tests=[test_race_condition],
        description="Tests for race conditions and TOCTOU vulnerabilities"
    )
    orchestrator.register_test_suite(race_suite)
    
    infra_suite = TestSuite(
        name="Infrastructure Security Testing",
        category=TestCategory.INFRASTRUCTURE,
        tests=[test_security_headers, test_error_handling],
        description="Tests for infrastructure and configuration issues"
    )
    orchestrator.register_test_suite(infra_suite)
    
    # Execute all tests
    orchestrator.execute_all_tests()
    
    # Generate reports
    print("\n" + orchestrator.generate_executive_summary())
    print("\n" + orchestrator.generate_technical_report())
    
    # Export results
    orchestrator.export_json("red_team_findings.json")
    orchestrator.export_csv("red_team_findings.csv")
    
    print("\n[*] Red Team Assessment Complete")
    print(f"[*] Risk Score: {orchestrator.calculate_risk_score():.1f}/100")
    print(f"[*] Total Findings: {len(orchestrator.findings)}")
    print(f"[*] Critical: {orchestrator.stats['critical_findings']}")
