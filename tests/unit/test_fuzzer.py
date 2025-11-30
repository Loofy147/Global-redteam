import pytest
from src.redteam.scanners.fuzzer import CoverageGuidedFuzzer, MutationStrategy
from src.redteam.core.finding import Severity


def test_fuzzer_initialization():
    def dummy_target(data):
        pass

    fuzzer = CoverageGuidedFuzzer(config={
        "target_function": dummy_target,
        "max_iterations": 100,
        "timeout": 0.1,
    })
    assert fuzzer.max_iterations == 100
    assert fuzzer.timeout == 0.1


def test_fuzzer_discovers_crash():
    def crash_target(data):
        if b"CRASH" in data:
            raise ValueError("Fuzzer found a crash!")

    fuzzer = CoverageGuidedFuzzer(config={
        "target_function": crash_target,
        "max_iterations": 1000,
        "timeout": 0.1,
        "mutation_strategies": [MutationStrategy.DICTIONARY]
    })
    fuzzer.mutator.dictionary = [b"CRASH"]
    fuzzer.add_seed(b"")

    findings = fuzzer.scan()

    assert len(findings) > 0
    assert findings[0].severity == Severity.HIGH
    assert "Fuzzer discovered a crash" in findings[0].title
