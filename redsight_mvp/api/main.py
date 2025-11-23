from flask import Flask, request, jsonify
from .database import db, init_app, Finding, Evidence
from .algorithms import generate_canonical_finding, compute_confidence
from .celery_app import init_celery
import uuid


def create_app(config_overrides=None):
    app = Flask(__name__)
    if config_overrides:
        app.config.update(config_overrides)
    init_app(app)
    init_celery(app)
    register_routes(app)
    return app


def register_routes(app):
    @app.route("/ingest", methods=["POST"])
    def ingest_finding():
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        process_finding.delay(data)
        return jsonify({"status": "accepted"}), 202

    @app.route("/findings", methods=["GET"])
    def get_findings():
        findings = Finding.query.all()
        return jsonify([f.to_dict() for f in findings])

    @app.route("/findings/<uuid:id>", methods=["GET"])
    def get_finding(id):
        finding = Finding.query.get(id)
        if finding is None:
            return jsonify({"error": "Finding not found"}), 404
        return jsonify(finding.to_dict())

    # Command to create DB tables
    @app.cli.command("initdb")
    def initdb_command():
        """Creates the database tables."""
        db.create_all()
        print("Initialized the database.")


from celery import Celery

# This file is now primarily for defining routes and commands.
# The app instance is created in app_factory.py
celery = Celery(__name__)


@celery.task
def process_finding(data):
    # Process the finding
    finding_model = generate_canonical_finding(data)

    # Calculate confidence score
    evidence_types = [ev.get("type") for ev in data.get("evidence", [])]
    # For MVP, repro_result is not yet implemented
    scanner_score = data.get(
        "scanner_confidence", 0.5
    )  # Default to 0.5 if not provided

    finding_model.confidence = compute_confidence(
        scanner_score=scanner_score,
        evidence_types=evidence_types,
        repro_result="pending",
        occurrences=finding_model.occurrences,
    )

    # Add to the session and commit
    db.session.add(finding_model)
    db.session.commit()
