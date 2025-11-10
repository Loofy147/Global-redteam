import pytest
from src.redteam.core.orchestrator import RedTeamOrchestrator
from src.redteam.core.finding import Finding, SecurityTestCategory, Severity, TestSuite
from src.redteam.utils.config import Settings


@pytest.fixture
def settings():
    """Returns a default settings object for testing."""
    return Settings(auth_token="a_valid_token_that_is_long_enough")  # nosec


def test_register_test_suite(settings):
    """Tests that a test suite can be registered correctly."""
    orchestrator = RedTeamOrchestrator(settings)
    assert len(orchestrator.test_suites) == 0

    def dummy_test():
        return True

    orchestrator.register_test_suite(
        name="Dummy Suite",
        category=SecurityTestCategory.API_SECURITY,
        tests=[dummy_test],
        description="A dummy test suite.",
    )

    assert len(orchestrator.test_suites) == 1
    assert orchestrator.test_suites[0].name == "Dummy Suite"


def test_add_finding(settings):
    """Tests that a finding can be added correctly."""
    orchestrator = RedTeamOrchestrator(settings)
    assert len(orchestrator.findings) == 0

    finding = Finding(
        id="test-finding",
        category=SecurityTestCategory.API_SECURITY,
        severity=Severity.HIGH,
        title="Test Finding",
        description="This is a test finding.",
        affected_component="Test Component",
        evidence="Test Evidence",
        remediation="Test Remediation",
    )
    orchestrator.add_finding(finding)

    assert len(orchestrator.findings) == 1
    assert orchestrator.stats["high_findings"] == 1
