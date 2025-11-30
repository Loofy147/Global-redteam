import pytest
import os
from src.redteam.scanners.sast_scanner import SASTScanner, VulnerabilityPattern
from src.redteam.core.finding import Severity


@pytest.fixture
def vulnerable_code_file():
    vulnerable_code = """
import sqlite3
from flask import Flask, request, Markup

def get_user(user_id: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()

app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q")
    return Markup(f"<h1>Search results for: {query}</h1>")
"""
    file_path = "test_vulnerable_code.py"
    with open(file_path, "w") as f:
        f.write(vulnerable_code)
    yield file_path
    os.remove(file_path)


def test_sast_scanner_integration(vulnerable_code_file):
    scanner = SASTScanner(config={"path": vulnerable_code_file})
    findings = scanner.scan()

    assert len(findings) >= 2

    sql_injection_finding = [f for f in findings if f.title == VulnerabilityPattern.SQL_INJECTION.value][0]
    assert sql_injection_finding.severity == Severity.CRITICAL

    xss_finding = [f for f in findings if f.title == VulnerabilityPattern.XSS.value][0]
    assert xss_finding.severity == Severity.HIGH
