import time
from src.redteam.utils.rate_limiter import RateLimiter


def test_rate_limiter_allows_requests_within_limit():
    limiter = RateLimiter(max_requests=5, time_window=1)
    for _ in range(5):
        assert limiter.acquire() is True


def test_rate_limiter_blocks_requests_exceeding_limit():
    limiter = RateLimiter(max_requests=2, time_window=1)
    assert limiter.acquire() is True
    assert limiter.acquire() is True
    assert limiter.acquire(block=False) is False


def test_rate_limiter_allows_requests_after_window():
    limiter = RateLimiter(max_requests=1, time_window=0.1)
    assert limiter.acquire() is True
    assert limiter.acquire(block=False) is False
    time.sleep(0.1)
    assert limiter.acquire() is True
