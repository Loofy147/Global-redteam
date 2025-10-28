# Proposal: Internal Red Team SaaS Platform (Project "Cerberus")

**Document Version:** 1.0
**Date:** 2025-10-28
**Author:** Jules, Global Red Team

## 1. The Opportunity

**Problem:** Our development teams currently lack a simple, automated way to run security tests on their applications. Security assessments are infrequent, manual, and create a bottleneck in the development lifecycle. As a result, vulnerabilities are often discovered late, increasing remediation costs and project delays.

**Solution:** We propose building an internal, self-service SaaS platform, codenamed **Project Cerberus**, based on the Global Red Team Framework. This platform will provide our developers with a "paved road" for security, enabling them to run automated security scans on their applications with the push of a button.

## 2. Business Value

- **Reduce Risk & Cost:** By "shifting left," we can find and fix vulnerabilities early, reducing the risk of a breach and lowering the average cost of remediation by over 90%.
- **Increase Development Velocity:** Automating security removes the manual testing bottleneck, allowing teams to deploy faster and more frequently.
- **Improve Security Culture:** Providing developers with direct, actionable security feedback fosters a stronger sense of ownership and improves the overall security posture of the organization.
- **Centralize & Track Risk:** The platform's dashboard will provide a single, unified view of the security posture of all applications, allowing us to track risk and compliance over time.

## 3. Minimum Viable Product (MVP) Scope

The goal of the MVP is to deliver a functional, end-to-end user journey that provides immediate value.

### Key MVP Features:
1.  **Web UI:** A simple, clean web interface for users to register their applications and manage scans.
2.  **Project Creation:** Users can create a "Project" by providing a Git repository URL and a staging API endpoint.
3.  **On-Demand Scanning:** A "Scan Now" button that triggers the Red Team Framework to run the `api` test suite against the project's staging URL.
4.  **Results Dashboard:** A basic dashboard that displays a summary of the latest scan results, including a list of findings, severities, and remediation advice.
5.  **User Authentication:** Integration with our corporate single sign-on (SSO) provider.

### Out of Scope for MVP:
- CI/CD integration.
- Fuzzing, property, and race condition test suites.
- Advanced user/team management and RBAC.
- Automated JIRA ticketing.

## 4. High-Level Architecture

```mermaid
graph TD
    subgraph "User Interface"
        WebApp[React WebApp]
    end

    subgraph "Backend Services"
        APIService[API Gateway / Flask]
        ScanManager[Scan Manager (Celery)]
        ScanWorker[Scan Worker (Celery)]
    end

    subgraph "Data Stores"
        DB[(PostgreSQL)]
    end

    WebApp -- "REST API" --> APIService
    APIService -- "Create Scan Job" --> ScanManager
    ScanManager -- "Distributes Task" --> ScanWorker
    ScanWorker -- "Runs Orchestrator" --> RedTeamFramework(Red Team Framework)
    RedTeamFramework -- "Saves Results" --> DB
    APIService -- "Reads Results" --> DB
```

## 5. Success Criteria & Metrics

- **Adoption:** At least 5 development teams are actively using the platform within the first quarter.
- **Scan Frequency:** At least 50 scans are run per month.
- **User Satisfaction:** A positive feedback survey (Net Promoter Score > 20) from early adopters.
- **Vulnerability Discovery:** The platform successfully identifies at least one `CRITICAL` or `HIGH` severity vulnerability in a pre-production application.

## 6. Hypothetical Pricing Model (Internal Cross-Charging)

To ensure the sustainability of the platform, we propose a simple, internal cross-charging model.

| Tier | Price/Month | Scans/Month | Key Feature |
|---|---|---|---|
| **Free** | $0 | 10 | On-demand API scans |
| **Standard**| $500 | 100 | + CI/CD integration |
| **Pro** | $1,500| Unlimited | + Fuzzing & advanced suites |

## 7. Next Steps

- **Q4 2025:** Secure stakeholder buy-in and assemble a dedicated team (1 Product Manager, 2 Engineers).
- **Q1 2026:** Develop and launch the MVP.
- **Q2 2026:** Onboard the first 5 development teams and gather feedback.
