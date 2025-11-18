import unittest
from unittest.mock import MagicMock, patch
import pytest
from src.redteam.core.orchestrator import RedTeamOrchestrator
from src.redteam.core.finding import Finding, SecurityTestCategory, Severity, TestSuite
from src.redteam.utils.config import Settings
from src.redteam.scanners.base import BaseScanner

@pytest.fixture
def settings():
    """Returns a default settings object for testing."""
    return Settings(auth_token="a_valid_token_that_is_long_enough")  # nosec


def test_init(settings):
    """Tests that the orchestrator is initialized correctly."""
    with patch('src.redteam.core.orchestrator.SecureDatabase') as mock_db:
        orchestrator = RedTeamOrchestrator(settings)
        assert orchestrator.settings == settings
        assert orchestrator.target_system == settings.target_system
        mock_db.assert_called_once()


def test_register_test_suite(settings):
    """Tests that a test suite can be registered correctly."""
    with patch('src.redteam.core.orchestrator.SecureDatabase'):
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
    with patch('src.redteam.core.orchestrator.SecureDatabase'):
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

def test_add_finding_from_result(settings):
    """Tests that a finding can be added from a result object."""
    with patch('src.redteam.core.orchestrator.SecureDatabase'):
        orchestrator = RedTeamOrchestrator(settings)
        assert len(orchestrator.findings) == 0

        result = MagicMock()
        result.passed = False
        result.vulnerability_type.value = "SQL_INJECTION"
        result.endpoint.path = "/api/test"
        result.endpoint.method = "GET"
        result.evidence = "SQL query"
        result.severity = "critical"
        result.details = "A detailed description"
        result.remediation = "Sanitize your inputs"

        orchestrator.add_finding_from_result(result, SecurityTestCategory.API_SECURITY)

        assert len(orchestrator.findings) == 1
        assert orchestrator.stats["critical_findings"] == 1

def test_run_scan(settings):
    """Tests that a scanner can be run correctly."""
    with patch('src.redteam.core.orchestrator.SecureDatabase'):
        orchestrator = RedTeamOrchestrator(settings)

        class MockScanner(BaseScanner):
            def get_required_config_fields(self):
                return []
            def _scan_implementation(self):
                return [Finding(
                    id="test-finding",
                    category=SecurityTestCategory.API_SECURITY,
                    severity=Severity.HIGH,
                    title="Test Finding",
                    description="This is a test finding.",
                    affected_component="Test Component",
                    evidence="Test Evidence",
                    remediation="Test Remediation",
                )]

        scanner = MockScanner(config={})
        orchestrator.run_scan(scanner)

        assert len(orchestrator.findings) == 1
        assert orchestrator.stats["high_findings"] == 1

@patch('src.redteam.core.orchestrator.DependencyScanner')
def test_run_dependency_scan(mock_scanner, settings):
    """Tests that the dependency scanner can be run correctly."""
    with patch('src.redteam.core.orchestrator.SecureDatabase'):
        orchestrator = RedTeamOrchestrator(settings)
        orchestrator.run_dependency_scan()
        mock_scanner.assert_called_once_with(settings.model_dump())
        mock_scanner.return_value.scan.assert_called_once()

@patch('src.redteam.core.orchestrator.SastScanner')
def test_run_sast_scan(mock_scanner, settings):
    """Tests that the SAST scanner can be run correctly."""
    with patch('src.redteam.core.orchestrator.SecureDatabase'):
        orchestrator = RedTeamOrchestrator(settings)
        orchestrator.run_sast_scan()
        mock_scanner.assert_called_once_with(settings.model_dump())
        mock_scanner.return_value.scan.assert_called_once()

def test_run_api_tests(settings):
    """Tests that the placeholder API tests can be run."""
    with patch('src.redteam.core.orchestrator.SecureDatabase'):
        orchestrator = RedTeamOrchestrator(settings)
        assert orchestrator.run_api_tests()

def test_run_fuzz_tests(settings):
    """Tests that the placeholder fuzz tests can be run."""
    with patch('src.redteam.core.orchestrator.SecureDatabase'):
        orchestrator = RedTeamOrchestrator(settings)
        assert orchestrator.run_fuzz_tests()

def test_run_property_tests(settings):
    """Tests that the placeholder property tests can be run."""
    with patch('src.redteam.core.orchestrator.SecureDatabase'):
        orchestrator = RedTeamOrchestrator(settings)
        assert orchestrator.run_property_tests()

def test_run_race_condition_tests(settings):
    """Tests that the placeholder race condition tests can be run."""
    with patch('src.redteam.core.orchestrator.SecureDatabase'):
        orchestrator = RedTeamOrchestrator(settings)
        assert orchestrator.run_race_condition_tests()

def test_execute_all_tests(settings):
    """Tests that all test suites can be executed."""
    with patch('src.redteam.core.orchestrator.SecureDatabase'):
        orchestrator = RedTeamOrchestrator(settings)

        def dummy_test():
            pass
        mock_test = MagicMock(spec=dummy_test, __name__='dummy_test', return_value=True)

        orchestrator.register_test_suite(
            name="Dummy Suite",
            category=SecurityTestCategory.API_SECURITY,
            tests=[mock_test],
            description="A dummy test suite.",
        )

        orchestrator.execute_all_tests()

        mock_test.assert_called_once()
        assert orchestrator.stats['total_tests'] == 1
        assert orchestrator.stats['tests_passed'] == 1
