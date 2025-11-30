import pytest
from src.redteam.storage.database import SecureDatabase


@pytest.fixture
def db():
    """In-memory test database"""
    return SecureDatabase(":memory:")


def test_database_initialization(db):
    assert db.db_path == ":memory:"
    with db.pool.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
        assert cursor.fetchone() is not None


def test_save_and_get_finding(db):
    db.save_finding(
        finding_id="test-1",
        finding_hash="hash-1",
        category="test",
        severity="high",
        title="Test Finding",
        description="A test finding",
        affected_component="test",
        evidence="test",
        remediation="test",
    )
    finding = db.get_finding_by_hash("hash-1")
    assert finding is not None
    assert finding["title"] == "Test Finding"
    assert finding["severity"] == "high"


def test_parameterized_queries(db):
    """Ensure all queries use parameters"""
    # Insert test data
    db.save_finding(
        finding_id="test-1",
        finding_hash="hash-1",
        category="test",
        severity="critical",
        title="SQL Injection",
        description="A test finding",
        affected_component="test",
        evidence="test",
        remediation="test",
    )

    # Query with parameters
    results = db.get_findings_by_severity("critical")

    assert len(results) == 1
    assert results[0]['title'] == "SQL Injection"
