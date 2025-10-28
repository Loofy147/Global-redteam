# Jira Integration: Payload & Mapping

**Document Version:** 1.0
**Date:** 2025-10-28

## 1. Overview

This document describes the process for automatically creating Jira tickets from findings within the RedSight platform.

## 2. Example Jira API Payload

Below is a sample JSON payload that the RedSight playbook engine will send to the Jira REST API to create a new issue.

```json
{
  "fields": {
    "project": {"key": "SEC"},
    "summary": "[CRITICAL] SQLi in svc-user-api - getUser()",
    "description": "Auto-created by RedSight. Evidence: s3://... \nRemediation: Use parameterized queries. See attached snippet.",
    "issuetype": {"name": "Bug"},
    "priority": {"name": "Highest"},
    "customfield_business_impact": "Revenue at risk: 500000 USD/month",
    "labels": ["redsight","auto-created"],
    "components": [{"name":"Payments"}],
    "customfield_evidence_links": ["s3://..."]
  }
}
```

## 3. Field Mapping Rules

The following rules define how data from a `Normalized Finding` is mapped to the corresponding fields in the Jira issue.

| RedSight Field | Jira Field | Transformation Logic |
|---|---|---|
| `severity` | `priority` | A direct mapping based on severity level. <br> `CRITICAL` -> `Highest` <br> `HIGH` -> `High` <br> `MEDIUM` -> `Medium` <br> `LOW` -> `Low` |
| `finding_title`, `asset.asset_id` | `summary` | Concatenate to create a descriptive title: `"[<severity>] <title> in <asset_id>"` |
| `description`, `evidence[0].artifact_url`, `remediation_hints[0]` | `description` | A formatted string combining the finding description, a link to the primary evidence, and the top remediation hint. |
| `asset.estimated_monthly_revenue` | `customfield_business_impact` | Directly map the estimated revenue to a custom Jira field to quantify business risk. |
| `confidence_score` | `customfield_confidence` | Directly map the calculated confidence score. |
| `evidence[*].artifact_url` | `customfield_evidence_links` | Aggregate all evidence URLs into a custom field for easy access. |
| `asset.business_owner` | `components` | Map the asset's business owner to a Jira component for correct team assignment. |
| `attack_surface_tags` | `labels` | Append any relevant tags as labels, in addition to standard labels like `"redsight"` and `"auto-created"`. |
