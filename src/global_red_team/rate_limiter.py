import time
from collections import deque
from threading import Lock


class RateLimiter:
    """Token bucket rate limiter"""

    def __init__(self, max_requests: int, time_window: int):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()
        self.lock = Lock()

    def acquire(self, block: bool = True) -> bool:
        """Acquire permission to make a request"""
        with self.lock:
            now = time.time()

            # Remove old requests
            while self.requests and self.requests[0] < now - self.time_window:
                self.requests.popleft()

            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True

            if not block:
                return False

            # Wait until we can make a request
            sleep_time = self.time_window - (now - self.requests[0])
            if sleep_time > 0:
                time.sleep(sleep_time)

            self.requests.popleft()
            self.requests.append(time.time())
            return True
