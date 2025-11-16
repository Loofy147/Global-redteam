import pytest
from src.redteam.core.orchestrator import RedTeamOrchestrator
from src.redteam.utils.config import Settings
from src.redteam.scanners.sast_scanner import SastScanner
from src.redteam.core.finding import SecurityTestCategory


def test_sast_integration():
    """
    Tests that the SAST suite can be run through the orchestrator.
    """
    settings = Settings(target_system="./vulnerable_app", auth_token="a_valid_token_that_is_long_enough")  # nosec
    orchestrator = RedTeamOrchestrator(settings)

    sast_scanner = SastScanner(settings.model_dump())
    orchestrator.run_scan(sast_scanner)

    hardcoded_secret_vuln = [
        f for f in orchestrator.findings if "Hardcoded Secrets" in f.title
    ]
    assert len(hardcoded_secret_vuln) > 0
