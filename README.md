# Global Red Team Framework

This repository contains a comprehensive, multi-dimensional adversarial excellence methodology that transcends traditional testing to become a philosophical engineering discipline.

## Overview

The framework is a suite of advanced security testing tools designed to be orchestrated for comprehensive red team operations. It includes modules for:

*   **API Security Testing:** Tests for OWASP API Security Top 10 and beyond.
*   **Fuzz Testing:** A coverage-guided fuzzer inspired by AFL.
*   **Property-Based Testing:** Generates adversarial test cases to discover edge cases.
*   **Race Condition Detection:** Finds TOCTOU and concurrent execution vulnerabilities.

## Getting Started

### Prerequisites

*   Python 3.6+
*   pip

### Installation

1.  Clone the repository:
    ```bash
    git clone <repository-url>
    cd global-redteam
    ```

2.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

### Configuration

1.  Create a `config.json` file from the example template:
    ```bash
    cp config.json.example config.json
    ```

2.  Edit `config.json` to match your target environment.

    *   `api_url`: The base URL of the target API.
    *   `auth_token`: An authentication token for accessing protected endpoints.
    *   `swagger_file`: Path to a Swagger/OpenAPI file for API endpoint discovery.
    *   `fuzzing`: Configuration for the fuzz testing suite.
        *   `enabled`: Enable or disable the fuzzing suite.
        *   `target_function`: The name of the function to fuzz.
        *   `max_iterations`: The number of fuzzing iterations to run.
        *   `timeout`: The timeout in seconds for each fuzzing run.
        *   `seeds`: A list of initial seed inputs for the fuzzer.
        *   `mutation_strategies`: A list of mutation strategies to use.

### Usage

The `red_team_orchestrator.py` script is the main entry point for running the test suites.

**Run all test suites:**

```bash
python3 red_team_orchestrator.py --suites all
```

**Run specific test suites:**

```bash
python3 red_team_orchestrator.py --suites api fuzz
```

**Available test suites:**

*   `api`: API Security Testing
*   `fuzz`: Fuzz Testing
*   `property`: Property-Based Testing
*   `race`: Race Condition Detection

**Override configuration with command-line arguments:**

```bash
python3 red_team_orchestrator.py --api-url https://my-api.com --auth-token my-secret-token
```

**Display the Security Dashboard:**

To view a summary of the current security posture, use the `--dashboard` flag.

```bash
python3 red_team_orchestrator.py --dashboard
```

## Running the Vulnerable App (for testing)

A vulnerable Flask application is included for testing the framework.

1.  Install the app's dependencies:
    ```bash
    pip install -r vulnerable_app/requirements.txt
    ```

2.  Run the app:
    ```bash
    python3 vulnerable_app/app.py
    ```

The app will be available at `http://localhost:5000`.

## Testing the Framework

The framework includes a suite of unit and integration tests.

1.  Install the testing dependencies:
    ```bash
    pip install -r requirements.txt
    ```

2.  Run the tests:
    ```bash
    pytest
    ```

## Reports

The orchestrator generates the following reports:

*   **Console Output:** Executive and technical summaries are printed to the console. The technical summary now includes historical context, identifying findings as `New`, `Ongoing`, or `Regression`.
*   `red_team_findings.json`: A detailed JSON report of all findings.
*   `red_team_findings.csv`: A CSV export of all findings.
*   `findings.db`: An SQLite database that stores historical findings to track regressions and trends over time.

## Strategic Deliverables

This repository also includes a `deliverables/` directory containing a suite of professional, actionable documents based on the framework's capabilities. These templates are designed to help security teams communicate risk and drive remediation.

*   **Executive Summary:** A 1-page summary for management.
*   **Security Roadmap:** A prioritized, actionable remediation plan.
*   **PenTest Report Template:** A formal report template with sample findings.
*   **Threat Model:** A detailed STRIDE threat model for the included vulnerable app.
*   **IR Playbook:** A ready-to-use incident response playbook for web application compromises.
*   **Red Team Checklist:** A practical checklist for conducting Red Team engagements.
*   **CI/CD Automation Architecture:** A reference architecture for automating security testing.
*   **Internal Tool MVP Proposal:** A proposal for building an internal SaaS security platform.
