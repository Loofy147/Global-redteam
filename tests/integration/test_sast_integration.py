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


def test_sast_javascript_scan():
    """
    Tests that the SAST scanner can find vulnerabilities in JavaScript files.
    """
    settings = Settings(target_system="./vulnerable_app", auth_token="a_valid_token_that_is_long_enough")  # nosec
    sast_scanner = SastScanner(settings.model_dump())
    findings = sast_scanner.scan()

    dom_xss_vulns = [
        f for f in findings if "Dom Based Xss" in f.title
    ]
    assert len(dom_xss_vulns) > 0
