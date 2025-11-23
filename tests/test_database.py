import pytest
from datetime import datetime, timedelta
from src.global_red_team import database
from src.global_red_team.models import Finding, SecurityTestCategory, Severity
from src.global_red_team.config import Settings
import psycopg2


@pytest.fixture
def db_conn():
    """
    Provides a connection to the test database, creating and tearing down
    the 'findings' table for each test function.
    """
    settings = Settings()
    conn = psycopg2.connect(settings.database_url)
    database.init_db()
    yield conn

    # Teardown: drop the table to ensure test isolation
    with conn.cursor() as cursor:
        cursor.execute("DROP TABLE findings;")
    conn.commit()
    conn.close()


def test_init_db(db_conn):
    """Tests that the database is initialized correctly."""
    with db_conn.cursor() as cursor:
        cursor.execute(
            """
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'findings'
            );
        """
        )
        assert cursor.fetchone()[0], "The 'findings' table should exist after init_db()"


def test_save_and_get_finding(db_conn):
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


def test_close_old_findings(db_conn):
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
