import pytest
import subprocess
import time
import os
import signal
from red_team_orchestrator import RedTeamOrchestrator, TestCategory, Severity
from red_team_api_tester import APISecurityTester, APIEndpoint
from red_team_fuzzer import CoverageGuidedFuzzer
from red_team_property_testing import PropertyTester
from red_team_race_detector import RaceConditionDetector

@pytest.fixture(scope="module")
def vulnerable_app():
    """Starts the vulnerable Flask app as a background process"""
    db_file = "findings.db"
    if os.path.exists(db_file):
        os.remove(db_file)
    init_db_process = subprocess.Popen(["python3", "database.py"])
    init_db_process.wait()
    app_process = subprocess.Popen(["python3", "vulnerable_app/app.py"])
    time.sleep(2)  # Give the app time to start
    yield "http://localhost:5000"
    os.kill(app_process.pid, signal.SIGTERM)

def test_integration(vulnerable_app):
    """
    Runs the orchestrator against the vulnerable app and asserts that vulnerabilities are found.
    """
    orchestrator = RedTeamOrchestrator(
        target_system="Vulnerable Flask App",
        config={
            'api_url': vulnerable_app,
            'auth_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.rA-b_t_Bw_j_B-j_b-r_A-B_w'
        }
    )

    def run_api_tests():
        api_tester = APISecurityTester(base_url=orchestrator.config['api_url'], auth_token=orchestrator.config['auth_token'])
        endpoints = [
            APIEndpoint(path="/api/users/2", method="GET"),
            APIEndpoint(path="/api/admin/users", method="GET"),
        ]
        results = api_tester.test_comprehensive(endpoints)
        for result in results:
            if not result.passed:
                orchestrator.add_finding_from_result(result, TestCategory.API_SECURITY)
        return not any(not r.passed for r in results)

    orchestrator.register_test_suite(
        "API Security",
        TestCategory.API_SECURITY,
        [run_api_tests],
        "Integration test for API security"
    )

    orchestrator.execute_all_tests()

    assert orchestrator.stats['critical_findings'] > 0
    assert orchestrator.stats['medium_findings'] > 0
