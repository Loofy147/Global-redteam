import pytest
import time
from src.redteam.utils.rate_limiter import RateLimiter


def test_rate_limiter():
    """Tests that the rate limiter correctly limits the number of requests."""
    rate_limiter = RateLimiter(max_requests=5, time_window=1)

    # First 5 requests should be allowed
    for _ in range(5):
        assert rate_limiter.acquire() is True

    # 6th request should be blocked
    start_time = time.time()
    assert rate_limiter.acquire() is True
    end_time = time.time()

    # Check that the 6th request was delayed
    assert end_time - start_time >= 1.0
