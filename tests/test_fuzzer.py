import pytest
from global_red_team.red_team_fuzzer import Mutator


@pytest.fixture
def mutator():
    return Mutator(seed=42)


def test_bit_flip(mutator):
    data = b"hello"
    mutated = mutator.bit_flip(data)
    assert data != mutated
    assert len(data) == len(mutated)


def test_byte_flip(mutator):
    data = b"hello"
    mutated = mutator.byte_flip(data)
    assert data != mutated
    assert len(data) == len(mutated)


def test_arithmetic_mutation(mutator):
    data = b"\x00\x00\x00\x00"
    mutated = mutator.arithmetic_mutation(data)
    assert data != mutated
    assert len(data) == len(mutated)


def test_interesting_value_mutation(mutator):
    data = b"A" * 16
    mutated = mutator.interesting_value_mutation(data)
    assert data != mutated
    assert len(data) == len(mutated)


def test_dictionary_mutation(mutator):
    data = b""
    mutated = mutator.dictionary_mutation(data)
    assert mutated in mutator.dictionary


def test_havoc_mutation(mutator):
    data = b"hello world"
    mutated = mutator.havoc_mutation(data)
    assert data != mutated


def test_splice_mutation(mutator):
    data1 = b"hello"
    data2 = b"world"
    # Run multiple times to reduce chance of random failure
    for _ in range(10):
        mutated = mutator.splice_mutation(data1, data2)
        if mutated != data1 and mutated != data2:
            assert True
            return
    assert False, "Splice mutation failed to produce a new value"
