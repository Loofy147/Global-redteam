import sqlite3
import hashlib
from datetime import datetime

DB_FILE = "findings.db"

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database and creates the findings table if it doesn't exist."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
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
                last_seen TIMESTAMP NOT NULL
            )
        """)
        conn.commit()
    print("[*] Database initialized.")

def generate_finding_hash(finding):
    """Generates a unique hash for a finding to prevent duplicates."""
    unique_string = f"{finding.category.value}|{finding.severity.value}|{finding.title}|{finding.affected_component}"
    return hashlib.sha256(unique_string.encode()).hexdigest()

def save_finding(finding):
    """Saves a new finding to the database or updates an existing one."""
    finding_hash = generate_finding_hash(finding)
    now = datetime.now()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE finding_hash = ?", (finding_hash,))
        existing_finding = cursor.fetchone()

        if existing_finding:
            # It's a regression or still present
            status = 'open' if existing_finding['status'] != 'new' else 'new'
            cursor.execute("""
                UPDATE findings
                SET last_seen = ?, status = ?
                WHERE finding_hash = ?
            """, (now, status, finding_hash))
            print(f"[!] Updated existing finding: {finding.title}")
        else:
            # It's a new finding
            cursor.execute("""
                INSERT INTO findings (finding_hash, category, severity, title, description, affected_component, evidence, remediation, first_seen, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new')
            """, (
                finding_hash,
                finding.category.value,
                finding.severity.value,
                finding.title,
                finding.description,
                finding.affected_component,
                str(finding.evidence),
                finding.remediation,
                now,
                now
            ))
            print(f"[!] Saved new finding: {finding.title}")
        conn.commit()

def get_findings_summary():
    """Retrieves a summary of findings from the database."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT severity, status, COUNT(*) as count
            FROM findings
            GROUP BY severity, status
        """)
        summary = cursor.fetchall()
        return {f"{row['severity']}_{row['status']}": row['count'] for row in summary}

def get_open_findings():
    """Retrieves all open or new findings from the database."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE status IN ('new', 'open') ORDER BY severity, last_seen DESC")
        return cursor.fetchall()

if __name__ == '__main__':
    # Initialize the database when the script is run directly
    init_db()
