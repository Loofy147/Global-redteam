import pytest
from datetime import datetime, timedelta
from src.global_red_team.database import SecureDatabase
from src.global_red_team.models import Finding, SecurityTestCategory, Severity, generate_finding_hash

@pytest.fixture
def db():
    """Provides an in-memory SecureDatabase instance for testing."""
    return SecureDatabase(db_path=":memory:")

def test_init_db(db):
    """Tests that the database is initialized correctly."""
    with db.pool.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
        assert cursor.fetchone() is not None, "The 'findings' table should exist after init_db()"

def test_save_and_get_finding(db):
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
    finding_hash = generate_finding_hash(finding)
    db.save_finding(
        finding_id=finding.id,
        finding_hash=finding_hash,
        category=finding.category.value,
        severity=finding.severity.value,
        title=finding.title,
        description=finding.description,
        affected_component=finding.affected_component,
        evidence=str(finding.evidence),
        remediation=finding.remediation,
    )

    retrieved_finding = db.get_finding_by_hash(finding_hash)

    assert retrieved_finding is not None
    assert retrieved_finding["title"] == "Test Finding"

def test_close_old_findings(db):
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
    finding_hash = generate_finding_hash(finding)
    db.save_finding(
        finding_id=finding.id,
        finding_hash=finding_hash,
        category=finding.category.value,
        severity=finding.severity.value,
        title=finding.title,
        description=finding.description,
        affected_component=finding.affected_component,
        evidence=str(finding.evidence),
        remediation=finding.remediation,
    )

    # Ensure the finding is "old" by setting the run time in the future
    run_start_time = datetime.now() + timedelta(seconds=1)
    db.close_old_findings(run_start_time)

    retrieved_finding = db.get_finding_by_hash(finding_hash)

    assert retrieved_finding is not None
    assert retrieved_finding["status"] == "closed"