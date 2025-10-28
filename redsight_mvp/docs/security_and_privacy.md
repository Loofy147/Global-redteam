# Security, Privacy, and Legal Considerations

**Document Version:** 1.0
**Date:** 2025-10-28

## 1. Overview

This document outlines the key security, privacy, and legal considerations for the RedSight platform, particularly concerning the handling of sensitive data within evidence artifacts.

## 2. Data Security & Privacy

### 2.1. Storage of Sensitive Evidence
- **Risk:** Evidence artifacts (e.g., HTTP requests, responses, stack traces) may contain sensitive data, such as Personally Identifiable Information (PII), API keys, or proprietary source code.
- **Recommendations:**
    - **Encryption at Rest:** All evidence stored in object storage (e.g., S3) must be encrypted using strong, industry-standard encryption (e.g., S3-SSE with customer-managed keys). The Postgres database volumes should also be encrypted.
    - **Encryption in Transit:** All communication between RedSight components and with external systems (e.g., Jira) must use TLS 1.2 or higher.
    - **Data Masking:** Where possible, implement a pre-ingestion masking service to automatically identify and redact common PII patterns (e.g., credit card numbers, Social Security numbers) from evidence.
    - **Secure Storage:** Consider using a dedicated, isolated secret management service (e.g., HashiCorp Vault) for storing particularly sensitive artifacts.

### 2.2. Access Control
- **Risk:** Unauthorized users could access sensitive findings and evidence.
- **Recommendations:**
    - **Role-Based Access Control (RBAC):** Implement a robust RBAC model to ensure that users can only view findings and data related to the assets they own or have been granted access to.
    - **Audit Logging:** Maintain a comprehensive and immutable audit log of all user actions, particularly any access to evidence artifacts. This log should be readily available to administrators.

### 2.3. Data Retention
- **Risk:** Storing sensitive evidence indefinitely increases the risk of a data breach.
- **Recommendations:**
    - **Configurable Retention Policies:** Implement a default data retention policy for evidence artifacts (e.g., 90 days). This policy should be configurable on a per-customer or per-project basis to meet specific contractual or regulatory requirements.
    - **Secure Deletion:** Ensure that a robust process is in place for the secure and permanent deletion of evidence when the retention period expires.

## 3. Legal & Compliance

### 3.1. GDPR & CCPA
- **Consideration:** If the platform is used to scan applications that process the data of EU or California residents, the evidence artifacts may contain data subject to these regulations.
- **Recommendations:**
    - **Data Processing Agreement (DPA):** Have a clear DPA in place that outlines RedSight's role as a "data processor."
    - **Data Subject Rights:** Be prepared to handle Data Subject Access Requests (DSARs) if PII is stored in the platform.

### 3.2. PCI-DSS
- **Consideration:** If scanning applications that are in scope for PCI-DSS, the platform could be exposed to cardholder data.
- **Recommendations:**
    - **Scoping:** To the greatest extent possible, ensure that the RedSight platform itself remains out of scope for PCI-DSS by not storing, processing, or transmitting cardholder data.
    - **Data Masking:** Aggressively mask any potential cardholder data in evidence before it is stored.
