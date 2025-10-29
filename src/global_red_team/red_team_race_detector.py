import time
import threading
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Any, List
import requests


@dataclass
class RaceConditionResult:
    is_vulnerable: bool
    details: str
    unique_outcomes: int
    severity: str = "medium"


class RaceConditionDetector:
    def __init__(self, threads: int = 10, iterations: int = 2):
        self.threads = threads
        self.iterations = iterations

    def test_concurrent_execution(
        self, target_function: Callable[[], Any]
    ) -> RaceConditionResult:
        outcomes = defaultdict(int)
        for _ in range(self.iterations):
            threads = []
            results = [None] * self.threads

            def wrapper(index):
                results[index] = target_function()

            for i in range(self.threads):
                thread = threading.Thread(target=wrapper, args=(i,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            for result in results:
                outcomes[str(result)] += 1

        if len(outcomes) > 1:
            return RaceConditionResult(
                is_vulnerable=True,
                details=f"Detected {len(outcomes)} unique outcomes during concurrent execution.",
                unique_outcomes=len(outcomes),
                severity="high",
            )

        return RaceConditionResult(
            is_vulnerable=False,
            details="Concurrent execution yielded consistent results.",
            unique_outcomes=1,
        )

    def test_api_endpoint(
        self, url: str, method: str, headers: dict = None, json: dict = None
    ) -> RaceConditionResult:

        def make_request():
            try:
                response = requests.request(
                    method, url, headers=headers, json=json, timeout=5
                )
                return response.status_code, response.text
            except requests.RequestException as e:
                return None, str(e)

        return self.test_concurrent_execution(make_request)
