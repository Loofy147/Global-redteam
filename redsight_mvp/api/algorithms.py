import hashlib
from datetime import datetime
from .database import db, Finding, Evidence


def normalize_text(text):
    return text.lower().strip()


def generate_canonical_fingerprint(finding_data):
    """
    Computes a unique fingerprint for a finding.
    """
    title = normalize_text(finding_data.get("finding_title", ""))
    asset_id = finding_data.get("asset", {}).get("asset_id", "")
    cwe = finding_data.get("cwe", "")

    # In a real implementation, we would add more normalization logic here
    # (e.g., for file paths, stack traces, etc.)

    fingerprint_str = f"{title}|{asset_id}|{cwe}"
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()


def generate_canonical_finding(raw_finding):
    """
    Takes a raw finding payload, de-duplicates it, and returns a Finding DB model.
    """
    fingerprint = generate_canonical_fingerprint(raw_finding)
    existing_finding = Finding.query.filter_by(
        canonical_fingerprint=fingerprint
    ).first()

    now = datetime.utcnow()

    if existing_finding:
        existing_finding.last_seen = now
        existing_finding.occurrences = (existing_finding.occurrences or 0) + 1

        # Merge evidence (simple append for now)
        if raw_finding.get("evidence"):
            for ev in raw_finding["evidence"]:
                new_evidence = Evidence(
                    type=ev.get("type"),
                    content=ev.get("content"),
                    artifact_url=ev.get("artifact_url"),
                )
                existing_finding.evidence.append(new_evidence)
        return existing_finding
    else:
        asset = raw_finding.get("asset", {})
        new_finding = Finding(
            canonical_id=raw_finding.get("canonical_id"),
            title=raw_finding.get("finding_title"),
            description=raw_finding.get("description"),
            severity=raw_finding.get("severity"),
            cvss=raw_finding.get("cvss"),
            cwe=raw_finding.get("cwe"),
            asset_id=asset.get("asset_id"),
            first_seen=now,
            last_seen=now,
            canonical_fingerprint=fingerprint,
            occurrences=1,
            status="open",
        )

        if raw_finding.get("evidence"):
            for ev in raw_finding["evidence"]:
                new_evidence = Evidence(
                    type=ev.get("type"),
                    content=ev.get("content"),
                    artifact_url=ev.get("artifact_url"),
                )
                new_finding.evidence.append(new_evidence)

        return new_finding


def compute_confidence(scanner_score, evidence_types, repro_result, occurrences):
    """
    Calculates a confidence score from 0 to 100.
    """
    scanner_score = scanner_score or 0.0
    evidence_types = evidence_types or []

    # 1. Scanner Confidence Weight (0-40 points)
    scanner_weight = scanner_score * 40

    # 2. Evidence Presence Weight (0-30 points)
    evidence_weight = 0
    if "request" in evidence_types and "response" in evidence_types:
        evidence_weight += 20
    if "stacktrace" in evidence_types:
        evidence_weight += 10

    # 3. Reproducibility Weight (0-20 points)
    repro_weight = 0
    if repro_result == "verified":
        repro_weight = 20

    # 4. Occurrence Weight (0-10 points)
    occurrence_weight = min(occurrences, 5) / 5.0 * 10

    total_score = scanner_weight + evidence_weight + repro_weight + occurrence_weight
    return min(100, round(total_score))
