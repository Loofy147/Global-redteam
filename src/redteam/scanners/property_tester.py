"""
Advanced Property-Based Testing Framework for Red Team Operations
Generates adversarial test cases that discover edge cases and vulnerabilities
"""

import random
import string
from typing import Any, Callable, List, Dict, Optional
from dataclasses import dataclass
from enum import Enum


class VulnerabilityType(Enum):
    """Categories of vulnerabilities to test for"""

    INJECTION = "injection"
    OVERFLOW = "overflow"
    RACE_CONDITION = "race_condition"
    LOGIC_ERROR = "logic_error"
    AUTH_BYPASS = "auth_bypass"
    DOS = "denial_of_service"
    DATA_LEAK = "data_leakage"


@dataclass
class TestResult:
    """Result of a property test"""

    passed: bool
    input_value: Any
    output_value: Any
    error: Optional[Exception] = None
    vulnerability_type: Optional[VulnerabilityType] = None
    severity: str = "unknown"
    reproduction_steps: List[str] = None


class AdversarialGenerator:
    """Generates adversarial inputs designed to break systems"""

    def __init__(self, seed: Optional[int] = None):
        self.random = random.Random(seed)
        self.vulnerability_patterns = self._load_vulnerability_patterns()

    def _load_vulnerability_patterns(self) -> Dict:
        """Load common vulnerability patterns"""
        return {
            "sql_injection": [
                "' OR '1'='1",
                "'; DROP TABLE users--",
                "1' UNION SELECT * FROM users--",
                "admin'--",
                "' OR 1=1--",
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg/onload=alert('XSS')>",
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32",
                "....//....//....//etc/passwd",
            ],
            "command_injection": [
                "; cat /etc/passwd",
                "| ls -la",
                "&& rm -rf /",
                "`whoami`",
            ],
            "xml_injection": [
                "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"
            ],
            "ldap_injection": ["*", "admin*", "*)(uid=*))(|(uid=*"],
            "nosql_injection": [
                "{'$gt': ''}",
                "{'$ne': null}",
                "{'$where': 'sleep(1000)'}",
            ],
        }

    def generate_string(self, min_len: int = 0, max_len: int = 100) -> str:
        """Generate random string"""
        length = self.random.randint(min_len, max_len)
        return "".join(
            self.random.choices(
                string.ascii_letters + string.digits + string.punctuation, k=length
            )
        )

    def generate_boundary_integer(self) -> int:
        """Generate boundary value integers"""
        boundaries = [
            -(2**63),
            -(2**31),
            -(2**15),
            -1,
            0,
            1,
            2**15 - 1,
            2**31 - 1,
            2**63 - 1,
            # Off-by-one
            -2,
            2,
            255,
            256,
            65535,
            65536,
        ]
        return self.random.choice(boundaries)

    def generate_malicious_string(self) -> str:
        """Generate strings with malicious patterns"""
        patterns = []
        for category in self.vulnerability_patterns.values():
            patterns.extend(category)
        return self.random.choice(patterns)

    def generate_unicode_attacks(self) -> str:
        """Generate unicode normalization attacks"""
        attacks = [
            "\u0041\u0301",  # Combining characters
            "\ufeff",  # Zero-width no-break space
            "\u200b",  # Zero-width space
            "\u202e",  # Right-to-left override
            "𝕿𝖊𝖘𝖙",  # Mathematical alphanumeric symbols
            "ᴛᴇꜱᴛ",  # Small caps
        ]
        return self.random.choice(attacks)

    def generate_overflow_string(self) -> str:
        """Generate strings designed to cause buffer overflows"""
        sizes = [2**10, 2**16, 2**20, 2**24]  # 1KB to 16MB
        size = self.random.choice(sizes)
        return "A" * size

    def generate_format_string_attack(self) -> str:
        """Generate format string vulnerability patterns"""
        patterns = ["%s" * 100, "%x" * 100, "%n" * 100, "%p" * 100]
        return self.random.choice(patterns)

    def generate_race_condition_inputs(self) -> List[Any]:
        """Generate inputs designed to trigger race conditions"""
        # Same operation, slightly different timing
        return [
            {"timestamp": i, "action": "withdraw", "amount": 1000} for i in range(100)
        ]

    def generate_polymorphic_inputs(self, base_type: type) -> Any:
        """Generate inputs that can be interpreted as multiple types"""
        polymorphic = {
            str: ["123", "true", "null", "[]", "{}", "1.23e10"],
            int: [-1, 0, 1, "123", True, False, None],
            bool: [0, 1, "true", "false", True, False, None, []],
            list: [[], {}, None, "", "[]"],
            dict: [{}, [], None, "", "{}"],
        }
        return self.random.choice(polymorphic.get(base_type, [None]))


from .base import BaseScanner
from ..core.finding import Finding, Severity, SecurityTestCategory
import hashlib

class PropertyTester(BaseScanner):
    """Advanced property-based testing framework"""

    def __init__(self, config: dict):
        super().__init__(config)
        self.iterations = config.get("iterations", 1000)
        self.generator = AdversarialGenerator()
        self.failures: List[TestResult] = []

    def test_idempotency(self, func: Callable, input_gen: Callable) -> List[TestResult]:
        """Test that f(f(x)) == f(x)"""
        results = []

        for _ in range(self.iterations):
            x = input_gen()
            try:
                first = func(x)
                second = func(first)

                passed = first == second
                result = TestResult(
                    passed=passed,
                    input_value=x,
                    output_value=(first, second),
                    vulnerability_type=(
                        VulnerabilityType.LOGIC_ERROR if not passed else None
                    ),
                )

                if not passed:
                    self.failures.append(result)
                results.append(result)

            except Exception as e:
                result = TestResult(
                    passed=False,
                    input_value=x,
                    output_value=None,
                    error=e,
                    vulnerability_type=VulnerabilityType.LOGIC_ERROR,
                )
                self.failures.append(result)
                results.append(result)

        return results

    def test_commutativity(
        self, func: Callable, input_gen: Callable
    ) -> List[TestResult]:
        """Test that order doesn't matter: f(a, b) == f(b, a)"""
        results = []

        for _ in range(self.iterations):
            a, b = input_gen(), input_gen()
            try:
                result_ab = func(a, b)
                result_ba = func(b, a)

                passed = result_ab == result_ba
                result = TestResult(
                    passed=passed,
                    input_value=(a, b),
                    output_value=(result_ab, result_ba),
                    vulnerability_type=(
                        VulnerabilityType.LOGIC_ERROR if not passed else None
                    ),
                )

                if not passed:
                    self.failures.append(result)
                results.append(result)

            except Exception as e:
                result = TestResult(
                    passed=False, input_value=(a, b), output_value=None, error=e
                )
                self.failures.append(result)
                results.append(result)

        return results

    def test_injection_resistance(self, func: Callable) -> List[TestResult]:
        """Test resistance to injection attacks"""
        results = []

        injection_inputs = [
            self.generator.generate_malicious_string() for _ in range(self.iterations)
        ]

        for malicious_input in injection_inputs:
            try:
                output_val = func(malicious_input)

                # Check if input was executed or escaped properly
                is_vulnerable = self._detect_injection_success(
                    malicious_input, output_val
                )

                result = TestResult(
                    passed=not is_vulnerable,
                    input_value=malicious_input,
                    output_value=output_val,
                    vulnerability_type=(
                        VulnerabilityType.INJECTION if is_vulnerable else None
                    ),
                    severity="critical" if is_vulnerable else "none",
                )

                if is_vulnerable:
                    self.failures.append(result)
                results.append(result)

            except Exception as e:
                # Exception is actually good - means injection was blocked
                result = TestResult(
                    passed=True, input_value=malicious_input, output_value=None, error=e
                )
                results.append(result)

        return results

    def test_resource_exhaustion(self, func: Callable) -> List[TestResult]:
        """Test for DoS via resource exhaustion"""
        results = []

        exhaustion_inputs = [
            self.generator.generate_overflow_string(),
            [i for i in range(10**6)],  # Large list
            {"key" + str(i): i for i in range(10**5)},  # Large dict
            self.generator.generate_format_string_attack(),
        ]

        for dos_input in exhaustion_inputs:
            import time

            start = time.time()

            try:
                func(dos_input)
                elapsed = time.time() - start

                # If processing took > 5 seconds, potential DoS
                is_vulnerable = elapsed > 5.0

                result = TestResult(
                    passed=not is_vulnerable,
                    input_value=f"Large input (type: {type(dos_input).__name__})",
                    output_value=f"Completed in {elapsed:.2f}s",
                    vulnerability_type=VulnerabilityType.DOS if is_vulnerable else None,
                    severity="high" if is_vulnerable else "none",
                )

                if is_vulnerable:
                    self.failures.append(result)
                results.append(result)

            except Exception as e:
                elapsed = time.time() - start
                result = TestResult(
                    passed=False,
                    input_value=f"Large input (type: {type(dos_input).__name__})",
                    output_value=None,
                    error=e,
                    vulnerability_type=VulnerabilityType.DOS,
                )
                self.failures.append(result)
                results.append(result)

        return results

    def test_boundary_conditions(self, func: Callable) -> List[TestResult]:
        """Test boundary conditions comprehensively"""
        results = []

        boundary_inputs = [
            None,
            "",
            0,
            -1,
            1,
            self.generator.generate_boundary_integer(),
            float("inf"),
            float("-inf"),
            float("nan"),
            [],
            {},
            set(),
            self.generator.generate_unicode_attacks(),
        ]

        for boundary_input in boundary_inputs:
            try:
                output = func(boundary_input)

                result = TestResult(
                    passed=True, input_value=boundary_input, output_value=output
                )
                results.append(result)

            except Exception as e:
                result = TestResult(
                    passed=False,
                    input_value=boundary_input,
                    output_value=None,
                    error=e,
                    vulnerability_type=VulnerabilityType.OVERFLOW,
                )
                self.failures.append(result)
                results.append(result)

        return results

    def test_concurrent_execution(
        self, func: Callable, input_val: Any, threads: int = 100
    ) -> TestResult:
        """Test for race conditions"""
        import threading

        results = []
        lock = threading.Lock()

        def worker():
            try:
                result = func(input_val)
                with lock:
                    results.append(result)
            except Exception as e:
                with lock:
                    results.append(e)

        threads_list = [threading.Thread(target=worker) for _ in range(threads)]

        for t in threads_list:
            t.start()

        for t in threads_list:
            t.join()

        # Check if all results are consistent
        unique_results = set(str(r) for r in results)
        is_vulnerable = len(unique_results) > 1

        result = TestResult(
            passed=not is_vulnerable,
            input_value=input_val,
            output_value=f"{len(unique_results)} unique results from {threads} threads",
            vulnerability_type=(
                VulnerabilityType.RACE_CONDITION if is_vulnerable else None
            ),
            severity="high" if is_vulnerable else "none",
        )

        if is_vulnerable:
            self.failures.append(result)

        return result

    def _detect_injection_success(self, input_val: str, output: Any) -> bool:
        """Heuristic to detect if injection was successful"""
        output_str = str(output).lower()

        # Check for common injection success indicators
        indicators = [
            "root:",
            "admin",
            "password",
            "/etc/passwd",
            "table",
            "database",
            "select",
            "union",
            "alert",
            "script",
            "onerror",
            "system32",
            "windows",
            "cmd.exe",
        ]

        return any(indicator in output_str for indicator in indicators)

    def generate_report(self) -> str:
        """Generate comprehensive test report"""
        report = []
        report.append("=" * 80)
        report.append("RED TEAM PROPERTY-BASED TESTING REPORT")
        report.append("=" * 80)
        report.append(f"\nTotal Failures: {len(self.failures)}\n")

        # Group by vulnerability type
        by_type = {}
        for failure in self.failures:
            vtype = failure.vulnerability_type or VulnerabilityType.LOGIC_ERROR
            if vtype not in by_type:
                by_type[vtype] = []
            by_type[vtype].append(failure)

        for vtype, failures in by_type.items():
            report.append(f"\n{vtype.value.upper()} ({len(failures)} findings):")
            report.append("-" * 80)

            for i, failure in enumerate(failures[:5], 1):  # Show top 5
                report.append(f"\n  Finding #{i}:")
                report.append(f"    Input: {failure.input_value}")
                report.append(f"    Output: {failure.output_value}")
                if failure.error:
                    report.append(f"    Error: {failure.error}")
                report.append(f"    Severity: {failure.severity}")

        report.append("\n" + "=" * 80)
        return "\n".join(report)

    def scan(self) -> List[Finding]:
        """Run the property tester and return a list of findings."""

        def vulnerable_sql_query(user_input: str):
            if "'" in user_input:
                return "SQL error"
            return "OK"

        self.test_injection_resistance(vulnerable_sql_query)
        findings = []
        for failure in self.failures:
            unique_str = f"{failure.vulnerability_type.value}:{failure.input_value}"
            finding_id = f"prop-{hashlib.sha256(unique_str.encode()).hexdigest()[:16]}"
            finding = Finding(
                id=finding_id,
                category=SecurityTestCategory.PROPERTY_BASED,
                severity=Severity.HIGH,
                title=f"Property test failed: {failure.vulnerability_type.value}",
                description=f"Input: {failure.input_value}, Output: {failure.output_value}",
                affected_component="vulnerable_sql_query",
                evidence=failure.input_value,
                remediation="Fix the code to satisfy the tested property.",
            )
            findings.append(finding)
        return findings


# Example usage and test cases
if __name__ == "__main__":
    # Example vulnerable functions to test

    def vulnerable_sql_query(user_input: str) -> str:
        """Simulated vulnerable SQL function"""
        # WARNING: This is intentionally vulnerable for demonstration
        query = f"SELECT * FROM users WHERE username = '{user_input}'"
        return query  # nosec

    def vulnerable_balance_update(amount: int) -> int:
        """Simulated race condition in balance update"""
        # This would be vulnerable in real concurrent scenario
        global balance
        balance = getattr(vulnerable_balance_update, "balance", 1000)
        balance -= amount
        vulnerable_balance_update.balance = balance
        return balance

    # Run tests
    tester = PropertyTester(iterations=100)

    print("Testing SQL Injection Resistance...")
    injection_results = tester.test_injection_resistance(vulnerable_sql_query)

    print("\nTesting Race Conditions...")
    race_result = tester.test_concurrent_execution(
        lambda x: vulnerable_balance_update(100), None, threads=50
    )

    print("\nTesting Boundary Conditions...")
    boundary_results = tester.test_boundary_conditions(lambda x: str(x).upper())

    # Generate report
    print("\n" + tester.generate_report())
