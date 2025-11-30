import pytest
from src.redteam.scanners.sast_scanner import SASTScanner, VulnerabilityPattern
from src.redteam.core.finding import Severity


def test_fstring_sql_injection_is_found():
    """
    Tests that the fixed engine correctly detects SQL injection in f-strings.
    This test will fail until the fix is implemented.
    """
    vulnerable_code = """
import sqlite3

def get_user(user_id: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()
"""
    scanner = SASTScanner(config={"path": "."})
    vulnerabilities = scanner.analyze_code(vulnerable_code, "test.py")
    assert len(vulnerabilities) >= 1
    sql_injection_vuln = [v for v in vulnerabilities if v.pattern == VulnerabilityPattern.SQL_INJECTION][0]
    assert sql_injection_vuln.pattern == VulnerabilityPattern.SQL_INJECTION
    assert sql_injection_vuln.severity == Severity.CRITICAL


def test_xss_vulnerability_is_found():
    """
    Tests that the engine correctly detects a reflected XSS vulnerability.
    """
    vulnerable_code = """
from flask import Flask, request, Markup

app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q")
    return Markup(f"<h1>Search results for: {query}</h1>")
"""
    scanner = SASTScanner(config={"path": "."})
    vulnerabilities = scanner.analyze_code(vulnerable_code, "test.py")
    assert len(vulnerabilities) > 0
    xss_vuln = [
        v for v in vulnerabilities if v.pattern == VulnerabilityPattern.XSS
    ]
    assert len(xss_vuln) > 0
    assert xss_vuln[0].severity == Severity.HIGH


def test_hardcoded_secret_with_high_entropy():
    """
    Tests that a hardcoded secret with high entropy is detected, even with a non-obvious variable name.
    """
    vulnerable_code = 'signing_key = "Z8a2b$d_3e-f^g!h@i#j(k)l<m>n?o%p_q-r*s+t&u/v\\w{x}y[z]0|1~2`3"'
    scanner = SASTScanner(config={"path": "."})
    vulnerabilities = scanner.analyze_code(vulnerable_code, "test.py")
    assert len(vulnerabilities) == 1
    secret_vuln = vulnerabilities[0]
    assert secret_vuln.pattern == VulnerabilityPattern.HARDCODED_SECRETS
    assert secret_vuln.severity == Severity.HIGH
