import pytest
from src.global_red_team.red_team_orchestrator import RedTeamOrchestrator
from src.global_red_team.models import Finding, SecurityTestCategory, Severity
from src.global_red_team.config import Settings
from src.global_red_team.reporting import ReportGenerator
from src.global_red_team.database import SecureDatabase

@pytest.fixture
def settings():
    """Returns a default settings object for testing."""
    return Settings(auth_token="a_valid_token_that_is_long_enough")  # nosec

@pytest.fixture
def orchestrator(settings):
    """
    Provides a RedTeamOrchestrator instance with an in-memory database.
    """
    orchestrator = RedTeamOrchestrator(settings)
    orchestrator.db = SecureDatabase(db_path=":memory:")
    return orchestrator


def test_threat_intelligence_enrichment(orchestrator):
    """
    Tests that a finding with a known CVE is enriched with threat intelligence.
    """
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
    assert "Log4j" in enriched_finding.threat_intel["summary"]

    report_generator = ReportGenerator(
        orchestrator.target_system, orchestrator.findings, orchestrator.stats, orchestrator.test_suites, orchestrator.db
    )
    executive_summary = report_generator.generate_executive_summary()
    technical_report = report_generator.generate_technical_report()

    assert "ACTIVELY EXPLOITED VULNERABILITIES DETECTED" in executive_summary
    assert "THREAT INTELLIGENCE: ACTIVELY EXPLOITED" in technical_report