# Proof-of-Value (PoV) Checklist & Acceptance Criteria

**Document Version:** 1.0
**Date:** 2025-10-28

## 1. Objective

The goal of this Proof-of-Value (PoV) is to demonstrate the core capabilities of the RedSight platform and validate its business value in a real-world, albeit limited, environment.

## 2. Scope

- **Scanners:** The PoV will focus on ingesting findings from **one SAST scanner** and **one DAST scanner**.
- **Dataset:** A sample dataset of at least 100 findings will be used, including known duplicates.
- **Playbook:** One playbook (`pb_001_sqli_remediation`) will be tested.
- **Integration:** One Jira project and one GitHub repository will be used for the integration tests.

## 3. Acceptance Criteria

The PoV will be considered successful if all of the following criteria are met:

| # | Criteria | Target | Result |
|---|---|---|---|
| 1 | **Data Ingestion:** The platform successfully ingests and normalizes the sample finding data from the two chosen scanners. | **PASS / FAIL** | |
| 2 | **Evidence Integrity:** At least 90% of the ingested findings include one or more evidence artifacts. | **≥ 90%** | |
| 3 | **Deduplication Efficiency:** The deduplication algorithm reduces the number of unique findings in the sample dataset by at least 40%. | **≥ 40%** | |
| 4 | **Automated Ticketing:** At least 3 sample findings are used to automatically create tickets in the test Jira project, with all fields mapped correctly. | **PASS / FAIL** | |
| 5 | **Proof-of-Fix Loop:** At least one finding is successfully closed through the full, end-to-end remediation loop: <br> 1. Ticket is created. <br> 2. A (manual) PR is created. <br> 3. The CI re-test job is triggered. <br> 4. The CI job reports a `PASS` result back to the platform. <br> 5. The platform automatically closes the finding and the Jira ticket. | **PASS / FAIL** | |
| 6 | **Reporting:** The Executive One-Pager report can be successfully generated and includes an estimated monthly savings calculation based on the sample data. | **PASS / FAIL** | |

## 4. Stakeholders

- **Project Sponsor:** [Name]
- **Technical Lead:** [Name]
- **Business Owner:** [Name]
