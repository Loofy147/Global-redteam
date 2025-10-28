# RedSight MVP: Closed-Loop Remediation Platform

**Project Status:** MVP Specification

## 1. Overview

This repository contains the complete specification and architectural blueprint for the Minimum Viable Product (MVP) of **RedSight**, a closed-loop security remediation platform. RedSight is designed to ingest findings from various security scanners, normalize and de-duplicate them, and then automate the entire remediation lifecycle, from ticket creation to proof-of-fix.

This MVP is designed to be a fully deployable, self-contained solution, providing immediate value by streamlining the vulnerability management process.

## 2. Core Components

This repository is organized into the following key directories:

- **`/api`**: Contains the OpenAPI specification for the RedSight API.
- **`/ci`**: Contains a sample GitHub Actions workflow for the "proof-of-fix" re-testing process.
- **`/database`**: Contains the proposed Postgres database schema.
- **`/docs`**: Contains all supporting documentation, including the core algorithms, integration guides, and business case.
- **`/playbooks`**: Contains sample YAML playbooks that define the automated remediation workflows.
- **`/remediation_snippets`**: Contains code examples for fixing common vulnerabilities.
- **`/schemas`**: Contains the JSON schema for the canonical finding format.
- **`/tests`**: Contains an example of a failing test case used to verify a remediation.
- **`docker-compose.yml`**: A file to enable the quick, local deployment of all MVP components.

## 3. Key Documents

For a detailed understanding of the RedSight MVP, please refer to the following documents in the `/docs` directory:

- **`algorithms.md`**: A detailed explanation of the deduplication, fingerprinting, and confidence scoring logic.
- **`dashboard_and_reporting.md`**: A description of the key metrics and reports for the MVP.
- **`jira_integration.md`**: A guide to the Jira integration, including the API payload and field mapping.
- **`pov_checklist.md`**: The acceptance criteria for a successful Proof-of-Value pilot.
- **`roi_calculator.md`**: A model for calculating the Return on Investment of the platform.
- **`security_and_privacy.md`**: An overview of the key security and legal considerations.
- **`sprint_plan.md`**: A proposed 10-week sprint plan for building the MVP.

## 4. Getting Started (Local Deployment)

To deploy the RedSight MVP locally for testing and demonstration purposes, please follow these steps:

1.  **Prerequisites:**
    - Docker
    - Docker Compose

2.  **Build and Run:**
    ```bash
    docker-compose up --build
    ```

This command will build the container images for the web server and the worker, and start the Postgres, Redis, and application containers.

## 5. Vision Beyond MVP

The vision for RedSight extends far beyond this MVP. Future enhancements will include:
- A rich playbook marketplace.
- Developer-first integrations (IDE plugins, GitHub checks).
- Advanced, value-based analytics and ROI tracking.
- A fully-featured, multi-tenant SaaS offering.
