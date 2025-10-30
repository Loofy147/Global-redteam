import pytest
from src.global_red_team.red_team_orchestrator import RedTeamOrchestrator
from src.global_red_team.config import Settings
from src.global_red_team.models import SecurityTestCategory


def test_sast_integration():
    """
    Tests that the SAST suite can be run through the orchestrator.
    """
    settings = Settings(target_system="./vulnerable_app")
    orchestrator = RedTeamOrchestrator(settings)

    orchestrator.register_test_suite(
        name="SAST",
        category=SecurityTestCategory.STATIC_ANALYSIS,
        tests=[orchestrator.run_sast_scan],
        description="AI-powered static analysis of the codebase.",
    )

    orchestrator.execute_all_tests()

    assert len(orchestrator.findings) > 0

    hardcoded_secret_vuln = [
        f for f in orchestrator.findings if "Hardcoded Secrets" in f.title
    ]
    assert len(hardcoded_secret_vuln) > 0
