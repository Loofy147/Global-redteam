import psycopg2
import psycopg2.extras
import hashlib
from datetime import datetime
from typing import Dict, Any, List
from .models import Finding
from .logger import logger
from .config import Settings

settings = Settings()


def get_db_connection():
    """
    Establishes a connection to the PostgreSQL database.
    """
    conn = psycopg2.connect(settings.database_url)
    return conn


def init_db() -> None:
    """Initializes the database and creates the findings table if it doesn't exist."""
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id SERIAL PRIMARY KEY,
                    finding_hash TEXT NOT NULL UNIQUE,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    affected_component TEXT NOT NULL,
                    evidence TEXT,
                    remediation TEXT,
                    status TEXT NOT NULL DEFAULT 'new',
                    first_seen TIMESTAMP NOT NULL,
                    last_seen TIMESTAMP NOT NULL,
                    is_regression BOOLEAN NOT NULL DEFAULT FALSE
                )
            """
            )
        conn.commit()
    logger.info("Database initialized.")


def generate_finding_hash(finding: Finding) -> str:
    """
    Generates a unique hash for a finding to prevent duplicates.
    """
    unique_string = f"{finding.category.value}|{finding.severity.value}|{finding.title}|{finding.affected_component}"
    return hashlib.sha256(unique_string.encode()).hexdigest()


def save_finding(finding: Finding) -> None:
    """Saves a new finding to the database or updates an existing one."""
    finding_hash = generate_finding_hash(finding)
    now = datetime.now()

    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT status FROM findings WHERE finding_hash = %s", (finding_hash,))
            existing_finding = cursor.fetchone()

            if existing_finding:
                is_regression = existing_finding[0] == "closed"
                status = "open"
                cursor.execute(
                    """
                    UPDATE findings
                    SET last_seen = %s, status = %s, is_regression = %s
                    WHERE finding_hash = %s
                """,
                    (now, status, is_regression, finding_hash),
                )
                logger.info(f"Updated existing finding: {finding.title}")
            else:
                cursor.execute(
                    """
                    INSERT INTO findings (finding_hash, category, severity, title, description, affected_component, evidence, remediation, first_seen, last_seen, status, is_regression)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'new', FALSE)
                """,
                    (
                        finding_hash,
                        finding.category.value,
                        finding.severity.value,
                        finding.title,
                        finding.description,
                        finding.affected_component,
                        str(finding.evidence),
                        finding.remediation,
                        now,
                        now,
                    ),
                )
                logger.info(f"Saved new finding: {finding.title}")
        conn.commit()


def close_old_findings(run_start_time: datetime) -> None:
    """
    Marks findings as 'closed' if they were not seen in the current run.
    """
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE findings
                SET status = 'closed', is_regression = FALSE
                WHERE last_seen < %s AND status != 'closed'
            """,
                (run_start_time,),
            )
            logger.info(f"Closed {cursor.rowcount} old findings.")
        conn.commit()


def get_findings_summary() -> Dict[str, Any]:
    """Retrieves a summary of findings from the database."""
    summary = {}
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            cursor.execute(
                """
                SELECT severity, status, is_regression, COUNT(*) as count
                FROM findings
                GROUP BY severity, status, is_regression
            """
            )
            summary_rows = cursor.fetchall()
            for row in summary_rows:
                key = f"{row['severity']}_{row['status']}"
                if row["is_regression"]:
                    key = f"{row['severity']}_regression"
                summary[key] = row["count"]
    return summary


def get_open_findings() -> List[Dict[str, Any]]:
    """
    Retrieves all open or new findings from the database.
    """
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM findings WHERE status IN ('new', 'open') ORDER BY severity, last_seen DESC"
            )
            return [dict(row) for row in cursor.fetchall()]


def get_finding_by_hash(finding_hash: str) -> Dict[str, Any]:
    """
    Retrieves a single finding by its hash.
    """
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            cursor.execute("SELECT * FROM findings WHERE finding_hash = %s", (finding_hash,))
            row = cursor.fetchone()
            return dict(row) if row else None


if __name__ == "__main__":
    init_db()
