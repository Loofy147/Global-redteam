import os
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID
import uuid

db = SQLAlchemy()


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    canonical_id = db.Column(db.String, unique=True, nullable=False)
    title = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    severity = db.Column(db.String, nullable=False)
    cvss = db.Column(db.Numeric)
    cwe = db.Column(db.Integer)
    asset_id = db.Column(db.String)
    first_seen = db.Column(db.DateTime, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=False)
    canonical_fingerprint = db.Column(db.String)
    confidence = db.Column(db.Integer)
    occurrences = db.Column(db.Integer, default=1)
    status = db.Column(db.String, default="open")
    evidence = db.relationship(
        "Evidence", backref="finding", lazy=True, cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": str(self.id),
            "canonical_id": self.canonical_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss": float(self.cvss) if self.cvss else None,
            "cwe": self.cwe,
            "asset_id": self.asset_id,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "confidence": self.confidence,
            "status": self.status,
            "evidence": [e.to_dict() for e in self.evidence],
        }


class Evidence(db.Model):
    __tablename__ = "evidence"

    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(
        UUID(as_uuid=True), db.ForeignKey("findings.id"), nullable=False
    )
    type = db.Column(db.String)
    artifact_url = db.Column(db.String)
    content = db.Column(db.String)

    def to_dict(self):
        return {
            "type": self.type,
            "artifact_url": self.artifact_url,
            "content": self.content,
        }


def init_app(app):
    if "SQLALCHEMY_DATABASE_URI" not in app.config:
        app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)
    db.init_app(app)
