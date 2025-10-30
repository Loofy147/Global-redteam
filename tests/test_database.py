import pytest
import sqlite3
from datetime import datetime, timedelta
from src.global_red_team import database
from src.global_red_team.models import Finding, SecurityTestCategory, Severity


@pytest.fixture
def setup_database(monkeypatch):
    """
    Sets up a shared in-memory database for a test and monkeypatches
    get_db_connection to always return the same connection object.
    """
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row

    def get_mock_db_connection():
        return conn

    monkeypatch.setattr(database, "get_db_connection", get_mock_db_connection)

    database.init_db()
    yield conn
    conn.close()


def test_init_db(setup_database):
    """Tests that the database is initialized correctly."""
    cursor = setup_database.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
    assert cursor.fetchone() is not None, "The 'findings' table should exist after init_db()"


def test_save_and_get_finding(setup_database):
    """Tests that a finding can be saved and retrieved from the database."""
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
    database.save_finding(finding)

    finding_hash = database.generate_finding_hash(finding)
    retrieved_finding = database.get_finding_by_hash(finding_hash)

    assert retrieved_finding is not None
    assert retrieved_finding["title"] == "Test Finding"


def test_close_old_findings(setup_database):
    """Tests that old findings are correctly closed."""
    finding = Finding(
        id="test-finding-to-close",
        category=SecurityTestCategory.API_SECURITY,
        severity=Severity.LOW,
        title="Old Finding",
        description="This is an old test finding.",
        affected_component="Old Component",
        evidence="Old Evidence",
        remediation="Old Remediation",
    )
    database.save_finding(finding)

    # Ensure the finding is "old" by setting the run time in the future
    run_start_time = datetime.now() + timedelta(seconds=1)
    database.close_old_findings(run_start_time)

    finding_hash = database.generate_finding_hash(finding)
    retrieved_finding = database.get_finding_by_hash(finding_hash)

    assert retrieved_finding is not None
    assert retrieved_finding["status"] == "closed"
