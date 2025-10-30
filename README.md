# Global Red Team Framework

The Global Red Team Framework is a comprehensive, multi-dimensional security testing platform designed to automate and orchestrate a wide range of adversarial assessments. It integrates several advanced testing modules into a unified, extensible framework, providing a holistic view of an organization's security posture.

## Features

*   **Multi-Faceted Testing:** Combines several testing methodologies in one platform:
    *   **API Security:** Tests for common API vulnerabilities, including the OWASP Top 10.
    *   **Fuzz Testing:** Employs coverage-guided fuzzing to discover crashes and unexpected behavior.
    *   **Property-Based Testing:** Generates adversarial inputs to find edge cases and logical flaws.
    *   **Race Condition Detection:** Identifies concurrency issues that can lead to vulnerabilities like double-spending.
    *   **AI-Powered Static Analysis (SAST):** Uses Abstract Syntax Tree (AST) analysis to find vulnerabilities like SQL injection and XSS directly in the source code.
*   **Unified Orchestration:** A central orchestrator runs all test suites, aggregates findings, and provides a consolidated report.
*   **Historical Analysis:** Persists findings in a database to track new vulnerabilities, regressions, and security posture trends over time.
*   **Containerized & Production-Ready:** The entire application and its test environment are containerized with Docker, making it easy to set up, run, and deploy.
*   **Modern Configuration:** Uses Pydantic and `.env` files for type-safe, flexible, and environment-aware configuration.

## Project Structure

The project has been refactored into a standard Python package structure to improve maintainability and scalability:

```
├── src/
│   └── global_red_team/        # Main Python package
│       ├── __init__.py
│       ├── red_team_orchestrator.py # The main orchestrator script
│       ├── config.py           # Pydantic configuration models
│       ├── database.py         # Database interaction logic
│       ├── models.py           # Core data models (Finding, etc.)
│       ├── reporting.py        # Report generation logic
│       └── ...                 # Other testing modules
├── tests/                      # Pytest unit and integration tests
├── vulnerable_app/             # A vulnerable Flask app for testing
├── .env.example                # Example environment variables
├── Dockerfile                  # Dockerfile for the main application
├── docker-compose.yml          # Docker Compose to orchestrate all services
└── README.md
```

## Getting Started

### Prerequisites

*   Docker and Docker Compose

### Installation & Setup

The entire application, including the vulnerable test app, is designed to be run with Docker Compose.

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd global-red-team
    ```

2.  **Configure your environment:**
    Create a `.env` file from the example template. This file will be used to configure the application.
    ```bash
    cp .env.example .env
    ```
    *You can review and modify the `.env` file to change the application's configuration, such as the target API URL or auth tokens.*

3.  **Build and run the containers:**
    ```bash
    docker compose build
    docker compose up
    ```
    This command will build the Docker images for the orchestrator and the vulnerable app and start both services. The orchestrator will immediately run the default test suites as configured in your `.env` file.

## Usage

You can run the orchestrator with different test suites or commands by executing a command inside the running Docker container.

**Run a specific test suite (e.g., `sast`):**
```bash
docker compose exec orchestrator python3 -m src.global_red_team.red_team_orchestrator --suites sast
```

**Run all test suites:**
```bash
docker compose exec orchestrator python3 -m src.global_red_team.red_team_orchestrator --suites all
```

**Available test suites:**
*   `api`: API Security Testing
*   `fuzz`: Fuzz Testing
*   `property`: Property-Based Testing
*   `race`: Race Condition Detection
*   `sast`: AI-Powered Static Analysis

**Display the Security Dashboard:**
To view a summary of the current security posture from the findings database, use the `--dashboard` flag.
```bash
docker compose exec orchestrator python3 -m src.global_red_team.red_team_orchestrator --dashboard
```

## Testing the Framework

The framework includes a comprehensive suite of unit and integration tests.

**Run all tests with Pytest:**
```bash
docker compose exec orchestrator python3 -m pytest
```

## Reports

The orchestrator generates the following reports in the project's root directory:

*   **Console Output:** Executive and technical summaries are printed to the console, identifying findings as `New`, `Ongoing`, or `Regression`.
*   `red_team_findings.json`: A detailed JSON report of all findings.
*   `red_team_findings.csv`: A CSV export of all findings.
*   `findings.db`: An SQLite database that stores historical findings to track regressions and trends over time.
