import pytest
from redsight_mvp.api.main import create_app
from redsight_mvp.api.database import db, Finding
from datetime import datetime

@pytest.fixture
def app():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_get_finding(client):
    """Tests that a single finding can be retrieved by its ID."""
    finding = Finding(
        canonical_id="test-finding",
        title="Test Finding",
        description="This is a test finding.",
        severity="High",
        confidence=0.9,
        status="Open",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    db.session.add(finding)
    db.session.commit()

    retrieved_finding = Finding.query.filter_by(canonical_id="test-finding").first()
    assert retrieved_finding is not None

    response = client.get(f"/findings/{retrieved_finding.id}")
    assert response.status_code == 200
    assert response.json["title"] == "Test Finding"
