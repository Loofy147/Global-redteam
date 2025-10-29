import sqlite3
import hashlib
from datetime import datetime
from typing import Dict, Any, List
from .models import Finding

DB_FILE = "findings.db"


def get_db_connection() -> sqlite3.Connection:
    """
    Establishes a connection to the SQLite database.

    Returns:
        sqlite3.Connection: A connection object to the database.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initializes the database and creates the findings table if it doesn't exist."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                is_regression BOOLEAN NOT NULL DEFAULT 0
            )
        """
        )
        conn.commit()
    print("[*] Database initialized.")


def generate_finding_hash(finding: Finding) -> str:
    """
    Generates a unique hash for a finding to prevent duplicates.

    Args:
        finding (Finding): The finding to hash.

    Returns:
        str: The SHA256 hash of the finding.
    """
    unique_string = f"{finding.category.value}|{finding.severity.value}|{finding.title}|{finding.affected_component}"
    return hashlib.sha256(unique_string.encode()).hexdigest()


def save_finding(finding: Finding) -> None:
    """Saves a new finding to the database or updates an existing one."""
    finding_hash = generate_finding_hash(finding)
    now = datetime.now()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE finding_hash = ?", (finding_hash,))
        existing_finding = cursor.fetchone()

        if existing_finding:
            is_regression = existing_finding["status"] == "closed"
            status = "open"
            cursor.execute(
                """
                UPDATE findings
                SET last_seen = ?, status = ?, is_regression = ?
                WHERE finding_hash = ?
            """,
                (now, status, is_regression, finding_hash),
            )
            print(f"[!] Updated existing finding: {finding.title}")
        else:
            # It's a new finding
            cursor.execute(
                """
                INSERT INTO findings (finding_hash, category, severity, title, description, affected_component, evidence, remediation, first_seen, last_seen, status, is_regression)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', 0)
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
            print(f"[!] Saved new finding: {finding.title}")
        conn.commit()


def close_old_findings(run_start_time: datetime) -> None:
    """
    Marks findings as 'closed' if they were not seen in the current run.

    Args:
        run_start_time (datetime): The start time of the current run.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE findings
            SET status = 'closed', is_regression = 0
            WHERE last_seen < ? AND status != 'closed'
        """,
            (run_start_time,),
        )
        conn.commit()
        print(f"[+] Closed {cursor.rowcount} old findings.")


def get_findings_summary() -> Dict[str, Any]:
    """Retrieves a summary of findings from the database."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT severity, status, is_regression, COUNT(*) as count
            FROM findings
            GROUP BY severity, status, is_regression
        """
        )
        summary_rows = cursor.fetchall()
        summary = {}
        for row in summary_rows:
            key = f"{row['severity']}_{row['status']}"
            if row["is_regression"]:
                key = f"{row['severity']}_regression"
            summary[key] = row["count"]
        return summary


def get_open_findings() -> List[Dict[str, Any]]:
    """
    Retrieves all open or new findings from the database.

    Returns:
        List[Dict[str, Any]]: A list of open or new findings.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM findings WHERE status IN ('new', 'open') ORDER BY severity, last_seen DESC"
        )
        return cursor.fetchall()


def get_finding_by_hash(finding_hash: str) -> Dict[str, Any]:
    """
    Retrieves a single finding by its hash.

    Args:
        finding_hash (str): The hash of the finding to retrieve.

    Returns:
        Dict[str, Any]: The finding, or None if not found.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE finding_hash = ?", (finding_hash,))
        return cursor.fetchone()


if __name__ == "__main__":
    # Initialize the database when the script is run directly
    init_db()
