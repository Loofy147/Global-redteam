from flask import Flask, request, jsonify
from .database import db, init_app, Finding
from .algorithms import generate_canonical_finding, compute_confidence

app = Flask(__name__)
init_app(app)

@app.route('/ingest', methods=['POST'])
def ingest_finding():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    # Process the finding
    finding_model = generate_canonical_finding(data)

    # Calculate confidence score
    evidence_types = [ev.get('type') for ev in data.get('evidence', [])]
    # For MVP, repro_result is not yet implemented
    scanner_score = data.get('scanner_confidence', 0.5) # Default to 0.5 if not provided

    finding_model.confidence = compute_confidence(
        scanner_score=scanner_score,
        evidence_types=evidence_types,
        repro_result="pending",
        occurrences=finding_model.occurrences
    )

    # Add to the session and commit
    db.session.add(finding_model)
    db.session.commit()

    return jsonify({"status": "created", "id": str(finding_model.id)}), 201

@app.route('/findings', methods=['GET'])
def get_findings():
    findings = Finding.query.all()
    return jsonify([f.to_dict() for f in findings])

# Command to create DB tables
@app.cli.command("initdb")
def initdb_command():
    """Creates the database tables."""
    with app.app_context():
        db.create_all()
    print("Initialized the database.")
