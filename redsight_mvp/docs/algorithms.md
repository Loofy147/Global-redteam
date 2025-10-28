# Core Algorithms: Deduplication & Scoring

**Document Version:** 1.0
**Date:** 2025-10-28

## 1. Deduplication & Canonical Fingerprinting

### Objective
The primary goal is to uniquely identify each security finding, even if it is reported by different scanners with slightly different descriptions. This prevents ticket duplication and allows for historical tracking.

### Algorithm (Pseudocode)
```
function generate_canonical_finding(raw_finding):
    // Step 1: Normalize key fields to ensure consistency
    normalized_title = normalize_text(raw_finding.title)
    normalized_path = normalize_path(raw_finding.asset.path)
    normalized_stacktrace = remove_timestamps_and_hashes(raw_finding.evidence.stacktrace)

    // Step 2: Compute the unique fingerprint
    fingerprint_str = (
        normalized_title +
        normalized_path +
        raw_finding.line_number +
        raw_finding.cwe +
        raw_finding.asset.asset_id
    )
    canonical_fingerprint = sha256(fingerprint_str)

    // Step 3: Check for existing finding
    existing_finding = lookup_in_db(canonical_fingerprint)

    if existing_finding:
        // Merge new evidence and update timestamps
        merge_evidence(existing_finding, raw_finding.evidence)
        update_last_seen(existing_finding, now())
        increment_occurrence_count(existing_finding)
        return existing_finding
    else:
        // Create a new canonical finding
        new_finding = create_new_finding_from(raw_finding)
        new_finding.canonical_fingerprint = canonical_fingerprint
        new_finding.occurrence_count = 1
        save_to_db(new_finding)
        return new_finding
```

### Advanced Clustering (Post-MVP)
For more advanced deduplication, a clustering algorithm can be used. If two findings have a small edit distance (< threshold) on their titles, share the same CWE, and affect the same asset, they can be flagged as potential duplicates and manually or automatically clustered under a single canonical ID.

---

## 2. Confidence Scoring

### Objective
To provide a reliable, quantifiable metric (0-100) of how likely a finding is to be a true positive and actionable. This score helps prioritize triage efforts.

### Weighted Calculation Model
The confidence score is calculated by combining four weighted factors.

| Factor | Weight | Description |
|---|---|---|
| **Scanner Confidence** | 40% | The confidence score provided by the source scanner, if available. |
| **Evidence Presence** | 30% | Points are awarded for the presence of high-quality evidence types. |
| **Reproducibility** | 20% | The result of an automated re-test or "proof-of-fix" job. |
| **Occurrence Count** | 10% | The number of times the finding has been seen, capped to prevent over-weighting. |

### Algorithm (Executable Pseudocode)
```python
def compute_confidence(scanner_score, evidence_types, repro_result, occurrences):
    """
    Calculates a confidence score from 0 to 100.

    :param scanner_score: The scanner's confidence (float, 0.0 to 1.0).
    :param evidence_types: A list of evidence types present (e.g., ["request", "response"]).
    :param repro_result: The result of an automated re-test ("verified", "unverified", "pending").
    :param occurrences: The number of times this finding has been seen.
    """

    # 1. Scanner Confidence Weight (0-40 points)
    scanner_weight = scanner_score * 40

    # 2. Evidence Presence Weight (0-30 points)
    evidence_weight = 0
    if "request" in evidence_types and "response" in evidence_types:
        evidence_weight += 20
    if "stacktrace" in evidence_types:
        evidence_weight += 10
    # Add more rules for other types like 'poC' or 'screenshot'

    # 3. Reproducibility Weight (0-20 points)
    repro_weight = 0
    if repro_result == "verified":
        repro_weight = 20

    # 4. Occurrence Weight (0-10 points)
    # The score increases with occurrences but is capped at 5 to avoid over-inflation.
    occurrence_weight = min(occurrences, 5) / 5.0 * 10

    # Calculate and cap the total score
    total_score = scanner_weight + evidence_weight + repro_weight + occurrence_weight
    return min(100, round(total_score))

```

### Example Calculation
- **Scanner Score:** 0.8 (from SAST tool)
- **Evidence:** `["request", "response"]`
- **Reproducibility:** Not yet tested (`"pending"`)
- **Occurrences:** 3

```
score = (0.8 * 40) + 20 + 0 + (min(3, 5) / 5.0 * 10)
      = 32 + 20 + 0 + (3 / 5.0 * 10)
      = 32 + 20 + 0 + 6
      = 58
```
The final confidence score is **58**.
