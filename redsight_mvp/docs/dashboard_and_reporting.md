# Dashboard, Metrics, and Reporting

**Document Version:** 1.0
**Date:** 2025-10-28

## 1. MVP Dashboard Metrics

The MVP dashboard will focus on providing a clear, at-a-glance view of the current security posture and the platform's operational efficiency.

### Key Metrics:
- **Total Open Findings (by Severity):** A bar or pie chart showing the breakdown of all `open` findings by `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` severity.
- **Mean Time to Remediate (MTTR):** The average time from when a finding is first ingested to when it is marked as `closed` (proof-of-fix validated).
- **Mean Time to Triage (MTTT):** The average time from when a finding is ingested to when a ticket is created in Jira.
- **Findings with Evidence:** The percentage of all ingested findings that contain at least one required evidence artifact (target: ≥95%).
- **False Positive Rate:** The percentage of findings manually marked as a false positive by the security team.
- **Top 10 Riskiest Assets:** A list of the top 10 assets, ranked by a calculated "Business Impact Risk" score (e.g., `estimated_monthly_revenue * severity_factor`).

## 2. Executive One-Pager Report Template

This report is designed to be generated on-demand and provides a high-level summary for leadership.

### Template Fields:
- **Overall Risk Trend:** A simple chart showing the trend of open `CRITICAL` and `HIGH` severity findings over the last 90 days.
- **Top 3 Critical Risks:** A brief description of the top 3 open findings that pose the most significant risk to the business.
- **Estimated Monthly Savings:** A calculation based on the ROI model, showing the estimated financial savings from remediated vulnerabilities.
- **Pilot/PoV Results:** A summary of the key success metrics from the latest Proof-of-Value engagement (e.g., "Reduced duplicate findings by 45%").
- **Key Wins This Month:** A list of significant achievements, such as critical vulnerabilities fixed or high-risk applications onboarded.
