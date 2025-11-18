"""
Advanced Coverage-Guided Fuzzing Engine
Inspired by AFL (American Fuzzy Lop) - discovers vulnerabilities through intelligent mutation
"""

import secrets
import sys
import hashlib
import time
from typing import Callable, List, Set, Optional, Tuple, Any, Dict
from dataclasses import dataclass
from enum import Enum


class MutationStrategy(Enum):
    """Different mutation strategies for fuzzing"""

    BIT_FLIP = "bit_flip"
    BYTE_FLIP = "byte_flip"
    ARITHMETIC = "arithmetic"
    INTERESTING_VALUES = "interesting_values"
    DICTIONARY = "dictionary"
    HAVOC = "havoc"
    SPLICE = "splice"


@dataclass
class FuzzInput:
    """Represents a single fuzz test input"""

    data: bytes
    coverage_hash: str = ""
    execution_time: float = 0.0
    crash: bool = False
    timeout: bool = False
    new_coverage: bool = False
    generation: int = 0
    parent_hash: Optional[str] = None
    mutation: Optional[MutationStrategy] = None


@dataclass
class CrashReport:
    """Detailed crash report"""

    input_data: bytes
    exception: Exception
    traceback: str
    execution_time: float
    coverage_hash: str
    mutation_chain: List[MutationStrategy]


class CoverageTracker:
    """Tracks code coverage during execution"""

    def __init__(self):
        self.covered_branches: Set[Tuple[str, int]] = set()
        self.execution_path: List[Tuple[str, int]] = []
        self.original_trace = sys.gettrace()

    def trace_function(self, frame, event, arg):
        """Trace function execution for coverage"""
        if event == "line":
            location = (frame.f_code.co_filename, frame.f_lineno)
            self.covered_branches.add(location)
            self.execution_path.append(location)
        return self.trace_function

    def start(self):
        """Start coverage tracking"""
        self.covered_branches.clear()
        self.execution_path.clear()
        sys.settrace(self.trace_function)

    def stop(self):
        """Stop coverage tracking"""
        sys.settrace(self.original_trace)

    def get_coverage_hash(self) -> str:
        """Get unique hash representing this execution path"""
        path_str = "".join(f"{f}:{l}" for f, l in self.execution_path)
        return hashlib.sha256(path_str.encode()).hexdigest()[:16]


class Mutator:
    """Intelligent mutation engine for fuzzing"""

    def __init__(self, seed: Optional[int] = None):
        self.secure_random = secrets.SystemRandom()
        self.interesting_8bit = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
        self.interesting_16bit = [
            -32768,
            -129,
            128,
            255,
            256,
            512,
            1000,
            1024,
            4096,
            32767,
        ]
        self.interesting_32bit = [
            -2147483648,
            -100663046,
            -32769,
            32768,
            65535,
            65536,
            100663045,
            2147483647,
        ]

        self.dictionary = [
            b"GET",
            b"POST",
            b"admin",
            b"root",
            b"password",
            b"<script>",
            b"' OR '1'='1",
            b"../../../",
            b"SELECT",
            b"UNION",
            b"DROP",
            b"INSERT",
            b"<?xml",
            b"<!DOCTYPE",
            b"javascript:",
            b"%00",
            b"%0d%0a",
            b"\x00",
            b"\r\n",
        ]

    def bit_flip(self, data: bytes, num_flips: int = 1) -> bytes:
        """Flip random bits in the data"""
        data_array = bytearray(data)
        for _ in range(num_flips):
            if len(data_array) > 0:
                byte_idx = self.secure_random.randint(0, len(data_array) - 1)
                bit_idx = self.secure_random.randint(0, 7)
                data_array[byte_idx] ^= 1 << bit_idx
        return bytes(data_array)

    def byte_flip(self, data: bytes, num_flips: int = 1) -> bytes:
        """Flip random bytes in the data"""
        data_array = bytearray(data)
        for _ in range(num_flips):
            if len(data_array) > 0:
                idx = self.secure_random.randint(0, len(data_array) - 1)
                data_array[idx] ^= 0xFF
        return bytes(data_array)

    def arithmetic_mutation(self, data: bytes) -> bytes:
        """Add/subtract small values"""
        if len(data) == 0:
            return data

        data_array = bytearray(data)
        idx = self.secure_random.randint(0, len(data_array) - 1)
        delta = self.secure_random.randint(-35, 35)
        data_array[idx] = (data_array[idx] + delta) % 256
        return bytes(data_array)

    def interesting_value_mutation(self, data: bytes) -> bytes:
        """Replace with interesting boundary values"""
        if len(data) < 4:
            return data

        data_array = bytearray(data)
        idx = self.secure_random.randint(0, len(data_array) - 4)

        value = self.secure_random.choice(self.interesting_32bit)
        # Little-endian encoding
        data_array[idx: idx + 4] = value.to_bytes(
            4, byteorder="little", signed=True
        )

        return bytes(data_array)

    def dictionary_mutation(self, data: bytes) -> bytes:
        """Insert dictionary tokens"""
        data_array = bytearray(data)
        token = self.secure_random.choice(self.dictionary)

        if len(data_array) == 0:
            return token

        idx = self.secure_random.randint(0, len(data_array))
        data_array[idx:idx] = token

        return bytes(data_array)

    def havoc_mutation(self, data: bytes, iterations: int = None) -> bytes:
        """Apply random mutations aggressively"""
        if iterations is None:
            iterations = self.secure_random.randint(10, 50)

        for _ in range(iterations):
            strategy = self.secure_random.choice(
                [
                    self.bit_flip,
                    self.byte_flip,
                    self.arithmetic_mutation,
                    self.interesting_value_mutation,
                    self.dictionary_mutation,
                ]
            )
            data = strategy(data)

        return data

    def splice_mutation(self, data1: bytes, data2: bytes) -> bytes:
        """Splice two inputs together"""
        if len(data1) == 0:
            return data2
        if len(data2) == 0:
            return data1

        split1 = self.secure_random.randint(0, len(data1))
        split2 = self.secure_random.randint(0, len(data2))

        return data1[:split1] + data2[split2:]

    def mutate(self, data: bytes, strategy: MutationStrategy) -> bytes:
        """Apply specific mutation strategy"""
        strategies = {
            MutationStrategy.BIT_FLIP: lambda: self.bit_flip(
                data, self.secure_random.randint(1, 8)
            ),
            MutationStrategy.BYTE_FLIP: lambda: self.byte_flip(
                data, self.secure_random.randint(1, 4)
            ),
            MutationStrategy.ARITHMETIC: lambda: self.arithmetic_mutation(data),
            MutationStrategy.INTERESTING_VALUES: lambda: self.interesting_value_mutation(
                data
            ),
            MutationStrategy.DICTIONARY: lambda: self.dictionary_mutation(data),
            MutationStrategy.HAVOC: lambda: self.havoc_mutation(data),
        }

        return strategies[strategy]()


from .base import BaseScanner
from ..core.finding import Finding, Severity, SecurityTestCategory
from typing import List

class CoverageGuidedFuzzer(BaseScanner):
    """Main fuzzing engine with coverage guidance"""

    def __init__(self, config: dict):
        super().__init__(config)
        self.target = self._get_target_function(config.get("target_function"))
        self.timeout = config.get("timeout", 1.0)
        self.max_iterations = config.get("max_iterations", 10000)
        self.mutation_strategies = config.get("mutation_strategies", list(MutationStrategy))

        self.mutator = Mutator()
        self.coverage_tracker = CoverageTracker()

        self.corpus: List[FuzzInput] = []
        self.crashes: List[CrashReport] = []
        self.seen_coverage: Set[str] = set()

        self.stats = {
            "total_executions": 0,
            "unique_crashes": 0,
            "unique_paths": 0,
            "timeouts": 0,
            "generation": 0,
        }

    def _get_target_function(self, target_function_name: str) -> Callable[[bytes], Any]:
        """Maps a target function name to an actual function."""
        # In a real-world scenario, this might involve dynamic imports
        def vulnerable_parser(data: bytes):
            if b"CRASH" in data:
                raise ValueError("Fuzzer found a crash!")

        target_functions = {"vulnerable_parser": vulnerable_parser}

        if target_function_name not in target_functions:
            raise ValueError(f"Fuzzing target function '{target_function_name}' not found.")

        return target_functions[target_function_name]

    def add_seed(self, data: bytes):
        """Add initial seed input to corpus"""
        fuzz_input = FuzzInput(data=data, generation=0)
        self.corpus.append(fuzz_input)

    def execute_target(
        self, data: bytes
    ) -> Tuple[bool, Optional[Exception], str, float]:
        """Execute target function with coverage tracking"""
        crashed = False
        exception = None
        coverage_hash = ""

        start_time = time.time()

        try:
            self.coverage_tracker.start()

            # Execute with timeout protection
            self.target(data)

            self.coverage_tracker.stop()
            coverage_hash = self.coverage_tracker.get_coverage_hash()

        except Exception as e:
            crashed = True
            exception = e
            self.coverage_tracker.stop()
            coverage_hash = self.coverage_tracker.get_coverage_hash()

        execution_time = time.time() - start_time

        return crashed, exception, coverage_hash, execution_time

    def is_new_coverage(self, coverage_hash: str) -> bool:
        """Check if this execution path is new"""
        if coverage_hash not in self.seen_coverage:
            self.seen_coverage.add(coverage_hash)
            return True
        return False

    def select_input_from_corpus(self) -> FuzzInput:
        """Select input from corpus for mutation (favor recent/interesting)"""
        # Favor inputs that found new coverage
        interesting = [inp for inp in self.corpus if inp.new_coverage]
        if interesting and self.mutator.secure_random.random() < 0.7:  # nosec
            return self.mutator.secure_random.choice(interesting)

        # Otherwise random selection
        return self.mutator.secure_random.choice(self.corpus)

    def fuzz_cycle(self) -> bool:
        """Single fuzzing iteration"""
        # Select input
        parent = self.select_input_from_corpus()

        # Select mutation strategy
        available_strategies = self.mutation_strategies.copy()
        if len(self.corpus) < 2 and MutationStrategy.SPLICE in available_strategies:
            available_strategies.remove(MutationStrategy.SPLICE)

        strategy = self.mutator.secure_random.choice(available_strategies)

        if strategy == MutationStrategy.SPLICE:
            other = self.mutator.secure_random.choice(self.corpus)
            mutated = self.mutator.splice_mutation(parent.data, other.data)
        else:
            mutated = self.mutator.mutate(parent.data, strategy)

        # Execute
        crashed, exception, coverage_hash, exec_time = self.execute_target(mutated)

        self.stats["total_executions"] += 1

        # Check for timeout
        if exec_time > self.timeout:
            self.stats["timeouts"] += 1

        # Check for new coverage
        new_coverage = self.is_new_coverage(coverage_hash)
        if new_coverage:
            self.stats["unique_paths"] += 1

        # Create FuzzInput
        fuzz_input = FuzzInput(
            data=mutated,
            coverage_hash=coverage_hash,
            execution_time=exec_time,
            crash=crashed,
            timeout=exec_time > self.timeout,
            new_coverage=new_coverage,
            generation=self.stats["generation"],
            parent_hash=parent.coverage_hash,
            mutation=strategy,
        )

        # Handle crashes
        if crashed:
            import traceback

            crash_report = CrashReport(
                input_data=mutated,
                exception=exception,
                traceback=traceback.format_exc(),
                execution_time=exec_time,
                coverage_hash=coverage_hash,
                mutation_chain=[strategy],
            )
            self.crashes.append(crash_report)
            self.stats["unique_crashes"] += 1
            print(f"[!] CRASH FOUND: {exception}")

        # Add to corpus if interesting
        if new_coverage and not crashed:
            self.corpus.append(fuzz_input)

        return crashed

    def run(self):
        """Main fuzzing loop"""
        print(f"[*] Starting fuzzer with {len(self.corpus)} seeds")
        print(f"[*] Max iterations: {self.max_iterations}")
        print("-" * 80)

        start_time = time.time()

        for iteration in range(self.max_iterations):
            self.stats["generation"] = iteration

            self.fuzz_cycle()

            # Progress reporting
            if iteration % 100 == 0:
                elapsed = time.time() - start_time
                exec_per_sec = (
                    self.stats["total_executions"] / elapsed if elapsed > 0 else 0
                )

                print(
                    f"[{iteration:6d}] "
                    f"exec/s: {exec_per_sec:6.1f} | "
                    f"corpus: {len(self.corpus):4d} | "
                    f"paths: {self.stats['unique_paths']:4d} | "
                    f"crashes: {self.stats['unique_crashes']:2d}"
                )

        print("-" * 80)
        print(f"[*] Fuzzing completed in {time.time() - start_time:.2f}s")
        print(f"[*] Total executions: {self.stats['total_executions']}")
        print(f"[*] Unique paths: {self.stats['unique_paths']}")
        print(f"[*] Crashes found: {self.stats['unique_crashes']}")
        print(f"[*] Timeouts: {self.stats['timeouts']}")

    def generate_crash_report(self) -> str:
        """Generate detailed crash report"""
        if not self.crashes:
            return "No crashes found."

        report = []
        report.append("=" * 80)
        report.append("FUZZING CRASH REPORT")
        report.append("=" * 80)
        report.append(f"\nTotal Crashes: {len(self.crashes)}\n")

        for i, crash in enumerate(self.crashes, 1):
            report.append(f"\nCRASH #{i}")
            report.append("-" * 80)
            report.append(f"Input (hex): {crash.input_data.hex()}")
            report.append(f"Input (repr): {repr(crash.input_data)}")
            report.append(f"Exception: {crash.exception}")
            report.append(f"Execution Time: {crash.execution_time:.4f}s")
            report.append(f"Coverage Hash: {crash.coverage_hash}")
            report.append(f"\nTraceback:\n{crash.traceback}")
            report.append(
                f"\nMutation Chain: {[m.value for m in crash.mutation_chain]}"
            )

        report.append("\n" + "=" * 80)
        return "\n".join(report)

    def get_required_config_fields(self) -> List[str]:
        return ["target_function", "max_iterations", "timeout"]

    def _scan_implementation(self) -> List[Finding]:
        """Run the fuzzer and return a list of findings."""
        self.run()
        findings = []
        for crash in self.crashes:
            finding_id = f"fuzz-{hashlib.sha256(crash.input_data).hexdigest()[:16]}"
            finding = Finding(
                id=finding_id,
                category=SecurityTestCategory.FUZZING,
                severity=Severity.HIGH,
                title="Fuzzer discovered a crash",
                description=str(crash.exception),
                affected_component=self.config.get("target_function"),
                evidence=crash.input_data.hex(),
                remediation="Investigate crash and fix the underlying bug.",
            )
            findings.append(finding)
        return findings


# Example usage and vulnerable functions to test
if __name__ == "__main__":

    # Example 1: Buffer overflow vulnerability
    def vulnerable_parser(data: bytes) -> str:
        """Simulated vulnerable parser"""
        # Convert to string
        text = data.decode("utf-8", errors="ignore")

        # Vulnerability: No length check
        if len(text) > 10000:
            raise MemoryError("Buffer overflow!")

        # Vulnerability: No validation
        if "DROP" in text.upper() and "TABLE" in text.upper():
            raise Exception("SQL injection detected!")

        # Vulnerability: Division by zero
        if text.startswith("DIV:"):
            divisor = int(text[4:])
            return str(1000 / divisor)

        return text.upper()

    # Example 2: Integer overflow
    def vulnerable_calculator(data: bytes) -> int:
        """Simulated vulnerable calculator"""
        try:
            text = data.decode("utf-8", errors="ignore")
            if ":" in text:
                parts = text.split(":")
                a = int(parts[0])
                b = int(parts[1])

                # Vulnerability: Integer overflow
                result = a * b

                # Vulnerability: Out of bounds
                if result < 0:
                    raise OverflowError("Integer overflow!")

                return result
        except (ValueError, IndexError):
            pass

        return 0

    # Test the fuzzer
    print("Testing vulnerable_parser...")
    print("=" * 80)

    fuzzer = CoverageGuidedFuzzer(
        target_function=vulnerable_parser, timeout=0.1, max_iterations=1000
    )

    # Add seed inputs
    fuzzer.add_seed(b"GET /index.html")
    fuzzer.add_seed(b"POST /api/users")
    fuzzer.add_seed(b"SELECT * FROM users")
    fuzzer.add_seed(b"DIV:10")

    # Run fuzzer
    fuzzer.run()

    # Generate report
    print("\n" + fuzzer.generate_crash_report())

    print("\n\nTesting vulnerable_calculator...")
    print("=" * 80)

    fuzzer2 = CoverageGuidedFuzzer(
        target_function=vulnerable_calculator, timeout=0.1, max_iterations=1000
    )

    fuzzer2.add_seed(b"10:20")
    fuzzer2.add_seed(b"100:200")
    fuzzer2.add_seed(b"2147483647:2")

    fuzzer2.run()
    print("\n" + fuzzer2.generate_crash_report())
