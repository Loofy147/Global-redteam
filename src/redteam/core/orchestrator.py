from typing import List, Dict, Any
from src.redteam.scanners.base import BaseScanner
from src.redteam.storage.database import SecureDatabase
from src.redteam.utils.config import RedTeamConfig
from src.redteam.utils.logger import logger
from src.redteam.scanners.sast_scanner import SASTScanner
from src.redteam.scanners.api_scanner import APIScanner
from src.redteam.scanners.dependency_scanner import DependencyScanner
from src.redteam.scanners.fuzzer import CoverageGuidedFuzzer


class RedTeamOrchestrator:
    def __init__(self, config: RedTeamConfig, db: SecureDatabase):
        self.config = config
        self.db = db
        self.scanners: List[BaseScanner] = []
        self.findings: List[Dict[str, Any]] = []
        self.stats = {
            "files_analyzed": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

    def register_scanner(self, scanner: BaseScanner):
        self.scanners.append(scanner)

    def run_scans(self):
        for scanner in self.scanners:
            self.findings.extend(scanner.scan())

    def run_full_assessment(self) -> Dict[str, Any]:
        """Run complete meta-assessment"""
        logger.info("=" * 80)
        logger.info("META RED TEAM SELF-ASSESSMENT")
        logger.info("Testing the framework against itself")
        logger.info("=" * 80)

        self.run_scans()

        # Compile statistics
        for finding in self.findings:
            self.stats[finding.severity.value] += 1
            self.stats["files_analyzed"] += 1

        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive meta-assessment report"""
        report = {
            "summary": self.stats,
            "findings": [],
        }

        logger.info("\n" + "=" * 80)
        logger.info("META-ASSESSMENT RESULTS")
        logger.info("=" * 80)
        logger.info(f"\nTotal Findings: {len(self.findings)}")
        logger.info(f"  Critical: {self.stats['critical']}")
        logger.info(f"  High: {self.stats['high']}")
        logger.info(f"  Medium: {self.stats['medium']}")
        logger.info(f"  Low: {self.stats['low']}")

        # Group by category
        by_category = {}
        for finding in self.findings:
            if finding.title not in by_category:
                by_category[finding.title] = []
            by_category[finding.title].append(finding)

        logger.info("\n" + "=" * 80)
        logger.info("FINDINGS BY CATEGORY")
        logger.info("=" * 80)

        for category, findings in sorted(by_category.items()):
            logger.info(f"\n{category} ({len(findings)} findings):")
            for finding in findings[:3]:  # Show top 3 per category
                logger.info(f"  [{finding.severity.value.upper()}] {finding.title}")
                logger.info(f"    File: {finding.file_path}:{finding.line_number}")
                logger.info(f"    {finding.description}")
                logger.info(f"    Remediation: {finding.remediation}\n")

                report["findings"].append(
                    {
                        "category": finding.title,
                        "severity": finding.severity.value,
                        "title": finding.title,
                        "description": finding.description,
                        "file": finding.file_path,
                        "line": finding.line_number,
                        "remediation": finding.remediation
                    }
                )

        # Overall assessment
        logger.info("\n" + "=" * 80)
        logger.info("OVERALL ASSESSMENT")
        logger.info("=" * 80)

        critical_issues = self.stats["critical"]
        high_issues = self.stats["high"]

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

        logger.info(f"\nFramework Maturity: {maturity}")
        logger.info(f"Security Score: {score}/100")

        logger.info("\n" + "=" * 80)

        report["maturity"] = maturity
        report["score"] = score

        return report

if __name__ == "__main__":
    config = RedTeamConfig()
    db = SecureDatabase(config.database_url)
    orchestrator = RedTeamOrchestrator(config, db)

    # Register scanners
    sast_scanner = SASTScanner(config={"path": "."})
    orchestrator.register_scanner(sast_scanner)

    api_scanner = APIScanner(config={
        "api_url": config.api_url,
        "swagger_file": config.swagger_file,
        "primary_user_token": config.auth_token,
        "secondary_user_token": config.secondary_user_token,
        "secondary_user_resource_ids": config.secondary_user_resource_ids,
    })
    orchestrator.register_scanner(api_scanner)

    dependency_scanner = DependencyScanner(config={"path": "."})
    orchestrator.register_scanner(dependency_scanner)

    fuzzer = CoverageGuidedFuzzer(config={
        "target_function": config.fuzz_target_function,
        "max_iterations": config.fuzz_max_iterations,
        "timeout": config.fuzz_timeout,
    })
    orchestrator.register_scanner(fuzzer)


    # Run assessment
    orchestrator.run_full_assessment()
