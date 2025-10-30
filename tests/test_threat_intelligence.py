import pytest
from src.global_red_team.red_team_orchestrator import RedTeamOrchestrator
from src.global_red_team.models import Finding, SecurityTestCategory, Severity
from src.global_red_team.config import Settings
from src.global_red_team.reporting import ReportGenerator


@pytest.fixture
def settings():
    """Returns a default settings object for testing."""
    return Settings()


def test_threat_intelligence_enrichment(settings):
    """
    Tests that a finding with a known CVE is enriched with threat intelligence.
    """
    orchestrator = RedTeamOrchestrator(settings)
    finding = Finding(
        id="test-finding",
        category=SecurityTestCategory.API_SECURITY,
        severity=Severity.HIGH,
        title="Test Finding with Known CVE",
        description="This is a test finding with a known CVE.",
        affected_component="Test Component",
        evidence="Test Evidence",
        remediation="Test Remediation",
        cve_id="CVE-2021-44228",  # Log4Shell
    )

    orchestrator.add_finding(finding)

    assert len(orchestrator.findings) == 1
    enriched_finding = orchestrator.findings[0]

    assert enriched_finding.severity == Severity.CRITICAL
    assert enriched_finding.threat_intel is not None
    assert "Log4j" in enriched_finding.threat_intel["name"]

    report_generator = ReportGenerator(
        orchestrator.target_system, orchestrator.findings, orchestrator.stats, orchestrator.test_suites
    )
    executive_summary = report_generator.generate_executive_summary()
    technical_report = report_generator.generate_technical_report()

    assert "ACTIVELY EXPLOITED VULNERABILITIES DETECTED" in executive_summary
    assert "THREAT INTELLIGENCE: ACTIVELY EXPLOITED" in technical_report
