import pytest
from ..algorithms import generate_canonical_fingerprint, compute_confidence

def test_generate_canonical_fingerprint():
    finding_data = {
        "finding_title": "SQL Injection in getUser()",
        "asset": {"asset_id": "svc-user-api"},
        "cwe": 89
    }
    fingerprint = generate_canonical_fingerprint(finding_data)
    assert fingerprint is not None
    assert len(fingerprint) == 64

def test_compute_confidence():
    score = compute_confidence(0.8, ["request", "response"], "pending", 3)
    assert score == 58
