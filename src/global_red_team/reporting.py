"""
This module contains the ReportGenerator class, which is responsible for
generating all the reports for the Red Team Orchestrator.
"""

import json
import csv
import hashlib
from typing import List
from .database import SecureDatabase
from .models import Finding, Severity, TestSuite, generate_finding_hash


class ReportGenerator:
    """
    Generates reports for the Red Team Orchestrator.
    """

    def __init__(
        self,
        target_system: str,
        findings: List[Finding],
        stats: dict,
        test_suites: List[TestSuite],
        db: SecureDatabase,
    ):
        self.target_system = target_system
        self.findings = findings
        self.stats = stats
        self.test_suites = test_suites
        self.db = db

    def calculate_risk_score(self) -> float:
        """
        Calculate overall risk score (0-100)
        Higher score = higher risk
        """
        weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 5.0,
            Severity.MEDIUM: 2.0,
            Severity.LOW: 0.5,
        }

        total_score = 0
        for finding in self.findings:
            total_score += weights.get(finding.severity, 0)

        # Normalize to 0-100 scale
        max_score = len(self.findings) * weights[Severity.CRITICAL]
        risk_score = min(100, (total_score / max_score * 100) if max_score > 0 else 0)

        return risk_score

    def generate_executive_summary(self) -> str:
        """Generate executive-level summary"""
        risk_score = self.calculate_risk_score()

        risk_level = "LOW"
        if risk_score >= 75:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"

        summary = []
        summary.append("=" * 80)
        summary.append("EXECUTIVE SUMMARY")
        summary.append("=" * 80)
        summary.append(f"\nTarget System: {self.target_system}")
        summary.append(
            f"Assessment Date: {self.stats['start_time'].strftime('%Y-%m-%d')}"
        )
        summary.append(f"\nOVERALL RISK SCORE: {risk_score:.1f}/100 [{risk_level}]")

        summary.append(f"\nKEY FINDINGS:")
        summary.append(
            f"  • Critical Vulnerabilities: {self.stats['critical_findings']}"
        )
        summary.append(f"  • High Vulnerabilities: {self.stats['high_findings']}")
        summary.append(f"  • Medium Vulnerabilities: {self.stats['medium_findings']}")
        summary.append(f"  • Low Vulnerabilities: {self.stats['low_findings']}")

        summary.append(f"\nTOP CONCERNS:")
        critical_findings = [
            f for f in self.findings if f.severity == Severity.CRITICAL
        ]
        for i, finding in enumerate(critical_findings[:3], 1):
            summary.append(f"  {i}. {finding.title}")
            summary.append(f"     Impact: {finding.description}")

        exploited_vulns = [f for f in self.findings if f.threat_intel]
        if exploited_vulns:
            summary.append("\n**[!] ACTIVELY EXPLOITED VULNERABILITIES DETECTED**")
            for vuln in exploited_vulns:
                summary.append(f"  - {vuln.title} ({vuln.cve_id})")

        summary.append(f"\nRECOMMENDATIONS:")
        if self.stats["critical_findings"] > 0:
            summary.append(
                "  • IMMEDIATE ACTION REQUIRED: Address all critical vulnerabilities within 24-48 hours"
            )
        if self.stats["high_findings"] > 0:
            summary.append("  • Address high-severity vulnerabilities within 1 week")
        if self.stats["medium_findings"] > 0:
            summary.append(
                "  • Plan remediation for medium-severity issues within 30 days"
            )

        summary.append(f"\nCOMPLIANCE IMPACT:")
        summary.append(
            "  • PCI-DSS: "
            + ("NON-COMPLIANT" if critical_findings else "REVIEW REQUIRED")
        )
        summary.append(
            "  • GDPR: "
            + ("HIGH RISK" if self.stats["critical_findings"] > 0 else "MODERATE RISK")
        )
        summary.append(
            "  • SOC 2: "
            + ("FINDINGS REQUIRE REMEDIATION" if len(self.findings) > 0 else "ON TRACK")
        )

        summary.append("\n" + "=" * 80)
        return "\n".join(summary)

    def generate_technical_report(self) -> str:
        """Generate detailed technical report"""
        report = []
        report.append("=" * 80)
        report.append("TECHNICAL SECURITY ASSESSMENT REPORT")
        report.append("=" * 80)

        report.append(f"\n1. ASSESSMENT OVERVIEW")
        report.append(f"   Target: {self.target_system}")
        report.append(f"   Start: {self.stats['start_time']}")
        report.append(f"   End: {self.stats['end_time']}")
        report.append(
            f"   Duration: {(self.stats['end_time'] - self.stats['start_time']).total_seconds():.2f}s"
        )
        report.append(f"   Total Tests: {self.stats['total_tests']}")

        report.append(f"\n2. METHODOLOGY")
        for suite in self.test_suites:
            report.append(f"   • {suite.name} ({suite.category.value})")
            report.append(f"     {suite.description}")

        report.append(f"\n3. DETAILED FINDINGS")

        # Group findings by severity
        for severity in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]:
            findings = [f for f in self.findings if f.severity == severity]

            if findings:
                report.append(
                    f"\n   {severity.value.upper()} SEVERITY ({len(findings)} findings)"
                )
                report.append("   " + "-" * 76)

                for i, finding in enumerate(findings, 1):
                    finding_hash = generate_finding_hash(finding)
                    db_finding = self.db.get_finding_by_hash(finding_hash)
                    status = "New"
                    if db_finding:
                        if db_finding["is_regression"]:
                            status = (
                                f"Regression (First seen: {db_finding['first_seen']})"
                            )
                        elif db_finding["status"] == "open":
                            status = f"Ongoing (First seen: {db_finding['first_seen']})"

                    report.append(f"\n   Finding #{i}: {finding.title} [{status}]")
                    report.append(f"   ID: {finding.id}")
                    report.append(f"   Category: {finding.category.value}")
                    report.append(f"   Component: {finding.affected_component}")
                    if finding.cvss_score > 0:
                        report.append(f"   CVSS Score: {finding.cvss_score}")
                    if finding.cwe_id:
                        report.append(f"   CWE: {finding.cwe_id}")
                    if finding.cve_id:
                        report.append(f"   CVE: {finding.cve_id}")

                    if finding.threat_intel:
                        report.append(
                            "\n   **[!] THREAT INTELLIGENCE: ACTIVELY EXPLOITED**"
                        )
                        summary = finding.threat_intel.get("summary", "N/A")
                        report.append(f"   Summary: {summary}")

                    report.append(f"\n   Description:")
                    report.append(f"   {finding.description}")

                    report.append(f"\n   Evidence:")
                    report.append(f"   {finding.evidence}")

                    report.append(f"\n   Remediation:")
                    report.append(f"   {finding.remediation}")

                    if finding.references:
                        report.append(f"\n   References:")
                        for ref in finding.references:
                            report.append(f"   • {ref}")

                    report.append("")

        report.append(f"\n4. ATTACK SURFACE ANALYSIS")
        categories = {}
        for finding in self.findings:
            cat = finding.category.value
            categories[cat] = categories.get(cat, 0) + 1

        for category, count in sorted(
            categories.items(), key=lambda x: x[1], reverse=True
        ):
            report.append(f"   • {category}: {count} findings")

        report.append(f"\n5. RISK ASSESSMENT")
        risk_score = self.calculate_risk_score()
        report.append(f"   Overall Risk Score: {risk_score:.1f}/100")
        report.append(f"   Critical Findings: {self.stats['critical_findings']}")
        report.append(f"   High Findings: {self.stats['high_findings']}")
        report.append(f"   Total Findings: {len(self.findings)}")

        report.append(f"\n6. REMEDIATION ROADMAP")
        report.append("   Phase 1 (Immediate - 0-7 days):")
        report.append("   • Fix all CRITICAL vulnerabilities")
        report.append("   • Implement emergency controls for HIGH vulnerabilities")

        report.append("\n   Phase 2 (Short-term - 7-30 days):")
        report.append("   • Fix all HIGH vulnerabilities")
        report.append("   • Begin addressing MEDIUM vulnerabilities")

        report.append("\n   Phase 3 (Medium-term - 30-90 days):")
        report.append("   • Complete MEDIUM vulnerability remediation")
        report.append("   • Address LOW vulnerabilities")
        report.append("   • Implement preventive controls")

        report.append("\n   Phase 4 (Long-term - 90+ days):")
        report.append("   • Security architecture improvements")
        report.append("   • Continuous monitoring enhancement")
        report.append("   • Security training and culture")

        report.append("\n" + "=" * 80)
        return "\n".join(report)

    def export_json(self, filepath: str):
        """Export findings as JSON"""
        data = {
            "target_system": self.target_system,
            "assessment_date": self.stats["start_time"].isoformat(),
            "risk_score": self.calculate_risk_score(),
            "statistics": {
                "total_tests": self.stats["total_tests"],
                "tests_passed": self.stats["tests_passed"],
                "tests_failed": self.stats["tests_failed"],
                "critical_findings": self.stats["critical_findings"],
                "high_findings": self.stats["high_findings"],
                "medium_findings": self.stats["medium_findings"],
                "low_findings": self.stats["low_findings"],
            },
            "findings": [
                {
                    "id": f.id,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "affected_component": f.affected_component,
                    "evidence": str(f.evidence),
                    "remediation": f.remediation,
                    "cvss_score": f.cvss_score,
                    "cwe_id": f.cwe_id,
                    "references": f.references,
                    "discovered_at": f.discovered_at.isoformat(),
                }
                for f in self.findings
            ],
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        print(f"[+] Report exported to {filepath}")

    def export_csv(self, filepath: str):
        """Export findings as CSV"""
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "ID",
                    "Severity",
                    "Category",
                    "Title",
                    "Component",
                    "CVSS",
                    "CWE",
                    "Description",
                    "Remediation",
                ]
            )

            for finding in self.findings:
                writer.writerow(
                    [
                        finding.id,
                        finding.severity.value,
                        finding.category.value,
                        finding.title,
                        finding.affected_component,
                        finding.cvss_score,
                        finding.cwe_id or "",
                        finding.description,
                        finding.remediation,
                    ]
                )

        print(f"[+] CSV exported to {filepath}")

    def export_html(self, filepath: str):
        """Export findings as a standalone HTML report"""
        html = (
            """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF--8">
            <title>Red Team Security Report</title>
            <style>
                body { font-family: sans-serif; }
                h1, h2 { color: #333; }
                .finding { border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; }
                .CRITICAL { border-left: 5px solid red; }
                .HIGH { border-left: 5px solid orange; }
                .MEDIUM { border-left: 5px solid yellow; }
                .LOW { border-left: 5px solid lightblue; }
            </style>
        </head>
        <body>
            <h1>Red Team Security Report for """
            + self.target_system
            + """</h1>
            <h2>Summary</h2>
            <p>Total Findings: """
            + str(len(self.findings))
            + """</p>
            <ul>
                <li>Critical: """
            + str(self.stats["critical_findings"])
            + """</li>
                <li>High: """
            + str(self.stats["high_findings"])
            + """</li>
                <li>Medium: """
            + str(self.stats["medium_findings"])
            + """</li>
                <li>Low: """
            + str(self.stats["low_findings"])
            + """</li>
            </ul>
            <h2>Detailed Findings</h2>
        """
        )

        for f in self.findings:
            html += f"""
            <div class="finding {f.severity.value.upper()}">
                <h3>[{f.severity.value.upper()}] {f.title}</h3>
                <p><strong>Category:</strong> {f.category.value}</p>
                <p><strong>Component:</strong> {f.affected_component}</p>
                <p><strong>Description:</strong> {f.description}</p>
                <p><strong>Evidence:</strong> <pre><code>{f.evidence}</code></pre></p>
                <p><strong>Remediation:</strong> {f.remediation}</p>
            </div>
            """

        html += """
        </body>
        </html>
        """
        with open(filepath, "w") as f:
            f.write(html)
        print(f"[+] HTML report exported to {filepath}")
