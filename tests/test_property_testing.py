import pytest
from global_red_team.red_team_property_testing import AdversarialGenerator


@pytest.fixture
def generator():
    return AdversarialGenerator(seed=42)


def test_generate_string(generator):
    s = generator.generate_string(min_len=10, max_len=20)
    assert 10 <= len(s) <= 20


def test_generate_boundary_integer(generator):
    i = generator.generate_boundary_integer()
    assert isinstance(i, int)


def test_generate_malicious_string(generator):
    s = generator.generate_malicious_string()
    assert isinstance(s, str)
    assert len(s) > 0


def test_generate_unicode_attacks(generator):
    s = generator.generate_unicode_attacks()
    assert isinstance(s, str)
    assert len(s) > 0


def test_generate_overflow_string(generator):
    s = generator.generate_overflow_string()
    assert len(s) in [2**10, 2**16, 2**20, 2**24]


def test_generate_format_string_attack(generator):
    s = generator.generate_format_string_attack()
    assert "%" in s
