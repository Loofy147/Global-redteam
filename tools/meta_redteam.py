"""
Meta Red Team Self-Assessment Framework
Tests the red team framework against itself to find vulnerabilities and improvements.
"""

import ast
import os
import json
import subprocess
from typing import List, Dict, Any, Set
from dataclasses import dataclass, field
from pathlib import Path
import re


@dataclass
class MetaFinding:
    """A finding from the meta-assessment"""
    category: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    evidence: str
    remediation: str
    cvss_score: float = 0.0


class MetaRedTeamAssessor:
    """Assess the red team framework itself for vulnerabilities and improvements"""

    def __init__(self, framework_path: str = "."):
        self.framework_path = Path(framework_path)
        self.findings: List[MetaFinding] = []
        self.stats = {
            "files_analyzed": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

    def analyze_architecture(self) -> List[MetaFinding]:
        """Analyze the architectural decisions"""
        findings = []

        # Check for separation of concerns
        if not (self.framework_path / "src" / "global_red_team").exists():
            findings.append(MetaFinding(
                category="Architecture",
                severity="medium",
                title="Code organization could be improved",
                description="Python package structure exists but could be more modular",
                file_path="src/",
                line_number=0,
                evidence="Monolithic modules detected",
                remediation="Split large modules into smaller, focused components",
                cvss_score=4.0
            ))

        # Check for proper error handling patterns
        config_file = self.framework_path / "src" / "global_red_team" / "config.py"
        if config_file.exists():
            with open(config_file) as f:
                content = f.read()
                if "try:" not in content and "except" not in content:
                    findings.append(MetaFinding(
                        category="Error Handling",
                        severity="medium",
                        title="Configuration lacks error handling",
                        description="Config module should handle missing/invalid environment variables",
                        file_path=str(config_file),
                        line_number=0,
                        evidence="No try-except blocks in config.py",
                        remediation="Add validation and error handling for config values",
                        cvss_score=5.0
                    ))

        return findings

    def analyze_security_practices(self) -> List[MetaFinding]:
        """Check if the framework follows its own security principles"""
        findings = []

        # Check for hardcoded secrets
        for py_file in self.framework_path.rglob("*.py"):
            if "venv" in str(py_file) or "__pycache__" in str(py_file):
                continue

            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines, 1):
                        # Check for potential secrets
                        if re.search(r'(password|secret|key)\s*=\s*["\'][^"\']+["\']', line.lower()):
                            if "nosec" not in line and "example" not in line.lower():
                                findings.append(MetaFinding(
                                    category="Security",
                                    severity="high",
                                    title="Potential hardcoded secret",
                                    description=f"Line contains potential hardcoded credential",
                                    file_path=str(py_file),
                                    line_number=i,
                                    evidence=line.strip(),
                                    remediation="Use environment variables or secrets management",
                                    cvss_score=7.5
                                ))
            except Exception:
                pass

        # Check for SQL injection in own code
        for py_file in self.framework_path.rglob("*.py"):
            if "venv" in str(py_file):
                continue
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if "execute(" in content and "%" in content or "f\"" in content:
                        tree = ast.parse(content)
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Call):
                                if hasattr(node.func, 'attr') and node.func.attr == 'execute':
                                    findings.append(MetaFinding(
                                        category="Security",
                                        severity="critical",
                                        title="Potential SQL injection in framework code",
                                        description="Database execute() may use string formatting",
                                        file_path=str(py_file),
                                        line_number=node.lineno,
                                        evidence=f"Line {node.lineno}",
                                        remediation="Use parameterized queries exclusively",
                                        cvss_score=9.0
                                    ))
            except Exception:
                pass

        return findings

    def analyze_testing_coverage(self) -> List[MetaFinding]:
        """Check test coverage and quality"""
        findings = []

        # Check if tests exist
        test_dir = self.framework_path / "tests"
        if not test_dir.exists():
            findings.append(MetaFinding(
                category="Testing",
                severity="high",
                title="No test directory found",
                description="Framework lacks comprehensive test suite",
                file_path="tests/",
                line_number=0,
                evidence="Missing tests/ directory",
                remediation="Create comprehensive test suite with >80% coverage",
                cvss_score=6.0
            ))
            return findings

        # Count test files vs source files
        test_files = list(test_dir.rglob("test_*.py"))
        src_files = list((self.framework_path / "src").rglob("*.py"))

        coverage_ratio = len(test_files) / max(len(src_files), 1)

        if coverage_ratio < 0.5:
            findings.append(MetaFinding(
                category="Testing",
                severity="medium",
                title="Low test coverage",
                description=f"Only {len(test_files)} test files for {len(src_files)} source files",
                file_path="tests/",
                line_number=0,
                evidence=f"Test coverage ratio: {coverage_ratio:.2%}",
                remediation="Aim for at least 1 test file per source module",
                cvss_score=5.0
            ))

        return findings

    def analyze_dependency_security(self) -> List[MetaFinding]:
        """Check dependencies for known vulnerabilities"""
        findings = []

        req_file = self.framework_path / "requirements.txt"
        if req_file.exists():
            with open(req_file) as f:
                deps = f.readlines()

            # Check for unpinned versions
            unpinned = [d.strip() for d in deps if not re.search(r'==\d+', d)]
            if unpinned:
                findings.append(MetaFinding(
                    category="Dependencies",
                    severity="medium",
                    title="Unpinned dependency versions",
                    description="Some dependencies lack version pins",
                    file_path=str(req_file),
                    line_number=0,
                    evidence=f"Unpinned: {', '.join(unpinned)}",
                    remediation="Pin all dependency versions for reproducibility",
                    cvss_score=4.5
                ))

            # Check for potentially vulnerable packages
            vulnerable_patterns = ["pycrypto", "django<2", "flask<2"]
            for dep in deps:
                for pattern in vulnerable_patterns:
                    if pattern in dep.lower():
                        findings.append(MetaFinding(
                            category="Dependencies",
                            severity="high",
                            title="Potentially vulnerable dependency",
                            description=f"Dependency may have known vulnerabilities: {dep}",
                            file_path=str(req_file),
                            line_number=0,
                            evidence=dep.strip(),
                            remediation="Update to latest secure version",
                            cvss_score=7.0
                        ))

        return findings

    def analyze_code_quality(self) -> List[MetaFinding]:
        """Check code quality and maintainability"""
        findings = []

        for py_file in self.framework_path.rglob("*.py"):
            if "venv" in str(py_file) or "__pycache__" in str(py_file):
                continue

            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()

                # Check file length
                if len(lines) > 1000:
                    findings.append(MetaFinding(
                        category="Code Quality",
                        severity="low",
                        title="Large file detected",
                        description=f"File has {len(lines)} lines - consider splitting",
                        file_path=str(py_file),
                        line_number=0,
                        evidence=f"{len(lines)} lines of code",
                        remediation="Split into smaller, focused modules",
                        cvss_score=2.0
                    ))

                # Check for long functions
                try:
                    with open(py_file, 'r', encoding='utf-8') as f:
                        tree = ast.parse(f.read())
                        for node in ast.walk(tree):
                            if isinstance(node, ast.FunctionDef):
                                func_lines = node.end_lineno - node.lineno
                                if func_lines > 100:
                                    findings.append(MetaFinding(
                                        category="Code Quality",
                                        severity="low",
                                        title="Long function detected",
                                        description=f"Function '{node.name}' has {func_lines} lines",
                                        file_path=str(py_file),
                                        line_number=node.lineno,
                                        evidence=f"Function spans lines {node.lineno}-{node.end_lineno}",
                                        remediation="Break down into smaller functions",
                                        cvss_score=2.0
                                    ))
                except:
                    pass

            except Exception:
                pass

        return findings

    def analyze_documentation(self) -> List[MetaFinding]:
        """Check documentation quality"""
        findings = []

        readme = self.framework_path / "README.md"
        if not readme.exists():
            findings.append(MetaFinding(
                category="Documentation",
                severity="medium",
                title="Missing README",
                description="No README.md found at project root",
                file_path="README.md",
                line_number=0,
                evidence="File not found",
                remediation="Create comprehensive README with setup instructions",
                cvss_score=4.0
            ))
        else:
            with open(readme) as f:
                content = f.read()
                required_sections = ["Installation", "Usage", "Configuration"]
                missing = [s for s in required_sections if s.lower() not in content.lower()]
                if missing:
                    findings.append(MetaFinding(
                        category="Documentation",
                        severity="low",
                        title="Incomplete README",
                        description=f"README missing sections: {', '.join(missing)}",
                        file_path=str(readme),
                        line_number=0,
                        evidence=f"Missing: {missing}",
                        remediation="Add missing documentation sections",
                        cvss_score=3.0
                    ))

        return findings

    def check_best_practices(self) -> List[MetaFinding]:
        """Check adherence to Python best practices"""
        findings = []

        # Check for __init__.py files
        src_dir = self.framework_path / "src" / "global_red_team"
        if src_dir.exists():
            for subdir in src_dir.iterdir():
                if subdir.is_dir() and not (subdir / "__init__.py").exists():
                    findings.append(MetaFinding(
                        category="Best Practices",
                        severity="low",
                        title="Missing __init__.py",
                        description=f"Directory '{subdir.name}' lacks __init__.py",
                        file_path=str(subdir),
                        line_number=0,
                        evidence="No __init__.py file",
                        remediation="Add __init__.py to make it a proper Python package",
                        cvss_score=2.0
                    ))

        # Check for type hints
        for py_file in self.framework_path.rglob("*.py"):
            if "venv" in str(py_file):
                continue
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    tree = ast.parse(content)

                total_funcs = 0
                typed_funcs = 0

                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        total_funcs += 1
                        if node.returns or any(arg.annotation for arg in node.args.args):
                            typed_funcs += 1

                if total_funcs > 5:  # Only check files with substantial functions
                    type_coverage = typed_funcs / total_funcs if total_funcs > 0 else 0
                    if type_coverage < 0.3:
                        findings.append(MetaFinding(
                            category="Best Practices",
                            severity="low",
                            title="Low type hint coverage",
                            description=f"Only {type_coverage:.0%} of functions have type hints",
                            file_path=str(py_file),
                            line_number=0,
                            evidence=f"{typed_funcs}/{total_funcs} functions typed",
                            remediation="Add type hints for better code maintainability",
                            cvss_score=2.0
                        ))
            except:
                pass

        return findings

    def run_full_assessment(self) -> Dict[str, Any]:
        """Run complete meta-assessment"""
        print("=" * 80)
        print("META RED TEAM SELF-ASSESSMENT")
        print("Testing the framework against itself")
        print("=" * 80)

        # Run all analysis modules
        print("\n[1/7] Analyzing Architecture...")
        self.findings.extend(self.analyze_architecture())

        print("[2/7] Analyzing Security Practices...")
        self.findings.extend(self.analyze_security_practices())

        print("[3/7] Analyzing Test Coverage...")
        self.findings.extend(self.analyze_testing_coverage())

        print("[4/7] Analyzing Dependencies...")
        self.findings.extend(self.analyze_dependency_security())

        print("[5/7] Analyzing Code Quality...")
        self.findings.extend(self.analyze_code_quality())

        print("[6/7] Analyzing Documentation...")
        self.findings.extend(self.analyze_documentation())

        print("[7/7] Checking Best Practices...")
        self.findings.extend(self.check_best_practices())

        # Compile statistics
        for finding in self.findings:
            self.stats[finding.severity] += 1
            self.stats["files_analyzed"] += 1

        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive meta-assessment report"""
        report = {
            "summary": self.stats,
            "findings": []
        }

        print("\n" + "=" * 80)
        print("META-ASSESSMENT RESULTS")
        print("=" * 80)
        print(f"\nTotal Findings: {len(self.findings)}")
        print(f"  Critical: {self.stats['critical']}")
        print(f"  High: {self.stats['high']}")
        print(f"  Medium: {self.stats['medium']}")
        print(f"  Low: {self.stats['low']}")

        # Group by category
        by_category = {}
        for finding in self.findings:
            if finding.category not in by_category:
                by_category[finding.category] = []
            by_category[finding.category].append(finding)

        print("\n" + "=" * 80)
        print("FINDINGS BY CATEGORY")
        print("=" * 80)

        for category, findings in sorted(by_category.items()):
            print(f"\n{category} ({len(findings)} findings):")
            for finding in findings[:3]:  # Show top 3 per category
                print(f"  [{finding.severity.upper()}] {finding.title}")
                print(f"    File: {finding.file_path}:{finding.line_number}")
                print(f"    {finding.description}")
                print(f"    Remediation: {finding.remediation}\n")

                report["findings"].append({
                    "category": finding.category,
                    "severity": finding.severity,
                    "title": finding.title,
                    "description": finding.description,
                    "file": finding.file_path,
                    "line": finding.line_number,
                    "remediation": finding.remediation,
                    "cvss": finding.cvss_score
                })

        # Overall assessment
        print("\n" + "=" * 80)
        print("OVERALL ASSESSMENT")
        print("=" * 80)

        critical_issues = self.stats['critical']
        high_issues = self.stats['high']

        if critical_issues > 0:
            maturity = "NEEDS IMMEDIATE ATTENTION"
            score = 40
        elif high_issues > 5:
            maturity = "NEEDS IMPROVEMENT"
            score = 60
        elif high_issues > 0:
            maturity = "MODERATE MATURITY"
            score = 75
        else:
            maturity = "GOOD MATURITY"
            score = 85

        print(f"\nFramework Maturity: {maturity}")
        print(f"Security Score: {score}/100")

        print("\n" + "=" * 80)

        report["maturity"] = maturity
        report["score"] = score

        return report


# Production-Ready Improvements Module
class ProductionReadinessChecker:
    """Check if the framework is production-ready"""

    @staticmethod
    def check_production_readiness(framework_path: str) -> Dict[str, Any]:
        """Comprehensive production readiness check"""
        checklist = {
            "security": {
                "secrets_management": False,
                "input_validation": False,
                "error_handling": False,
                "rate_limiting": False,
                "authentication": False
            },
            "reliability": {
                "logging": False,
                "monitoring": False,
                "health_checks": False,
                "graceful_shutdown": False,
                "retry_logic": False
            },
            "scalability": {
                "async_operations": False,
                "connection_pooling": False,
                "caching": False,
                "load_balancing": False
            },
            "maintainability": {
                "documentation": False,
                "tests": False,
                "ci_cd": False,
                "version_control": False,
                "code_style": False
            },
            "compliance": {
                "license": False,
                "data_privacy": False,
                "audit_logging": False,
                "access_control": False
            }
        }

        path = Path(framework_path)

        # Check security
        if (path / ".env.example").exists():
            checklist["security"]["secrets_management"] = True

        # Check reliability
        if any(path.rglob("*logger*.py")):
            checklist["reliability"]["logging"] = True

        # Check maintainability
        if (path / "tests").exists():
            checklist["maintainability"]["tests"] = True
        if (path / ".github" / "workflows").exists():
            checklist["maintainability"]["ci_cd"] = True
        if (path / ".git").exists():
            checklist["maintainability"]["version_control"] = True

        # Calculate score
        total_checks = sum(len(v) for v in checklist.values())
        passed_checks = sum(sum(v.values()) for v in checklist.values())
        score = (passed_checks / total_checks) * 100

        return {
            "score": score,
            "checklist": checklist,
            "passed": passed_checks,
            "total": total_checks,
            "ready": score >= 80
        }


if __name__ == "__main__":
    # Run meta-assessment
    assessor = MetaRedTeamAssessor(".")
    report = assessor.run_full_assessment()

    # Save report
    with open("meta_assessment_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("\n[+] Full report saved to: meta_assessment_report.json")

    # Check production readiness
    print("\n" + "=" * 80)
    print("PRODUCTION READINESS CHECK")
    print("=" * 80)

    readiness = ProductionReadinessChecker.check_production_readiness(".")
    print(f"\nProduction Readiness Score: {readiness['score']:.1f}/100")
    print(f"Checks Passed: {readiness['passed']}/{readiness['total']}")
    print(f"Status: {'✓ READY' if readiness['ready'] else '✗ NOT READY'}")

    print("\nChecklist Status:")
    for category, checks in readiness["checklist"].items():
        print(f"\n{category.upper()}:")
        for check, status in checks.items():
            symbol = "✓" if status else "✗"
            print(f"  {symbol} {check.replace('_', ' ').title()}")
