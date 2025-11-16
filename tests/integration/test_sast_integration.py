import pytest
import subprocess
import sys
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


def test_strict_mode_fails_build_with_dependency_vuln():
    """
    Tests that the orchestrator exits with a non-zero status code when in --strict mode
    and a critical vulnerability is found.
    """
    with open("requirements.txt", "w") as f:
        f.write("requests==2.25.1")

    command = [
        sys.executable,
        "-m",
        "src.redteam.core.orchestrator",
        "--suites",
        "dependency",
        "--target",
        "requirements.txt",
        "--strict",
        "--auth-token",
        "a_valid_token_that_is_long_enough",  # nosec
    ]
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )
    assert process.returncode != 0
