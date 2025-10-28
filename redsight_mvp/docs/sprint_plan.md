# MVP Build Plan (10-Week Sprints)

**Document Version:** 1.0
**Date:** 2025-10-28

## 1. Proposed Team Composition

- **1x Product Manager / Product Owner (Part-Time):** Responsible for the roadmap, backlog, and stakeholder communication.
- **1x Tech Lead:** Responsible for the overall architecture and technical decisions.
- **2x Backend Engineers:** Responsible for the API, database, and playbook engine.
- **1x Frontend Engineer:** Responsible for the web UI.
- **1x QA / DevOps Engineer (50% Allocation):** Responsible for testing, CI/CD, and infrastructure.
- **1x Security SME (Consulting):** Provides domain expertise on vulnerabilities and remediation.

## 2. Sprint Plan

This plan is based on 2-week sprints and is designed to deliver a functional Proof-of-Value (PoV) within 6-10 weeks.

### Sprint 0 (1 Week) - Discovery & Setup
- **Goal:** Finalize requirements and set up the development environment.
- **Deliverables:**
    - Collect sample outputs from at least two target scanners (e.g., one SAST, one DAST).
    - Finalize the `normalizer.schema.json`.
    - Define and agree upon the PoV acceptance criteria (see `pov_checklist.md`).
    - Set up the Git repository, CI/CD pipeline, and local development environments.

### Sprint 1 (2 Weeks) - Ingest, Normalize, & Store
- **Goal:** Build the core data ingestion and storage pipeline.
- **Deliverables:**
    - A functional `/ingest` API endpoint.
    - The deduplication and fingerprinting algorithm is implemented.
    - Ingested findings are correctly stored in the Postgres database.
    - A raw, unstyled list of findings is visible in the UI.

### Sprint 2 (2 Weeks) - Scoring & Evidence
- **Goal:** Implement the confidence scoring engine and evidence handling.
- **Deliverables:**
    - The confidence scoring algorithm is implemented and scores are calculated for all new findings.
    - The deduplication logic is refined based on real-world samples.
    - Evidence artifacts are correctly associated with findings and stored securely.
    - **Demo:** Show a live finding being ingested, scored, and de-duplicated correctly.

### Sprint 3 (2 Weeks) - Playbook Engine & Basic UI
- **Goal:** Build the skeleton of the playbook engine and the basic UI for viewing findings.
- **Deliverables:**
    - A YAML-based playbook runner that can execute a simple, linear playbook.
    - A basic trigger rule (e.g., `on_finding_severity: CRITICAL`).
    - A UI that displays a list of findings with their severity, confidence score, and asset.
    - **Demo:** A CRITICAL finding is ingested, which automatically triggers a playbook that logs a "ticket stub" to the console.

### Sprint 4 (2 Weeks) - Jira Integration
- **Goal:** Integrate with the Jira API to automatically create tickets.
- **Deliverables:**
    - A secure integration with the Jira REST API.
    - The `create_jira_issue` playbook action is fully implemented.
    - The field mapping logic is configurable.
    - **Demo:** A new finding automatically creates a correctly formatted ticket in a test Jira project.

### Sprint 5 (2 Weeks) - Proof-of-Fix & Reporting
- **Goal:** Implement the proof-of-fix loop and basic reporting.
- **Deliverables:**
    - The `re_test_finding` playbook action can trigger the CI workflow.
    - The platform can receive a callback from the CI workflow to update the finding status.
    - The playbook can automatically close the Jira ticket upon successful re-test.
    - The executive one-pager report can be generated with basic data.
    - **Demo:** Show the full, end-to-end "closed loop" for a single finding.
