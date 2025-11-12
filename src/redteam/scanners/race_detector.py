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


from .base import BaseScanner
from ..core.finding import Finding, Severity, SecurityTestCategory
import hashlib

class RaceConditionDetector(BaseScanner):
    def __init__(self, config: dict):
        super().__init__(config)
        self.threads = config.get("threads", 10)
        self.iterations = config.get("iterations", 2)

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

    def scan(self) -> List[Finding]:
        """Run the race condition detector and return a list of findings."""
        url = f"{self.config.get('api_url')}/api/payments/withdraw"
        headers = {"Authorization": f"Bearer {self.config.get('auth_token')}"}
        json_payload = {"amount": 100}
        result = self.test_api_endpoint(
            url, "POST", headers=headers, json=json_payload
        )
        if result.is_vulnerable:
            finding = Finding(
                id="RACE-API-WITHDRAW",
                category=SecurityTestCategory.RACE_CONDITIONS,
                severity=Severity(result.severity),
                title="Race Condition in Withdrawal API (Double Spend)",
                description=f"Concurrent requests to the withdrawal API resulted in multiple outcomes, "
                f"indicating a race condition. This could allow for 'double spending'. "
                f"Details: {result.details}",
                affected_component="POST /api/payments/withdraw",
                evidence=f"{result.unique_outcomes} unique outcomes observed.",
                remediation="Implement a pessimistic lock (e.g., a mutex or database-level lock) "
                "around the balance check and withdrawal operation.",
            )
            return [finding]
        return []
