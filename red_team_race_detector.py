"""
Advanced Race Condition Detector
Finds TOCTOU (Time-of-Check-Time-of-Use) and concurrent execution vulnerabilities
"""

import threading
import time
import hashlib
from typing import Callable, List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict
import queue


@dataclass
class RaceConditionResult:
    """Result of race condition testing"""
    function_name: str
    input_data: Any
    thread_count: int
    unique_outcomes: int
    outcomes: List[Any]
    is_vulnerable: bool
    severity: str
    details: str
    timing_analysis: Dict[str, float]


class RaceConditionDetector:
    """Detects race conditions through concurrent execution analysis"""
    
    def __init__(self, threads: int = 100, iterations: int = 10):
        self.threads = threads
        self.iterations = iterations
        self.results: List[RaceConditionResult] = []
    
    def test_concurrent_execution(self, 
                                   func: Callable,
                                   args: tuple = (),
                                   kwargs: dict = None) -> RaceConditionResult:
        """
        Execute function concurrently and analyze outcomes
        """
        if kwargs is None:
            kwargs = {}
        
        outcomes = []
        exceptions = []
        timings = []
        lock = threading.Lock()
        
        def worker():
            """Worker thread"""
            start = time.time()
            try:
                result = func(*args, **kwargs)
                with lock:
                    outcomes.append(result)
                    timings.append(time.time() - start)
            except Exception as e:
                with lock:
                    exceptions.append(str(e))
        
        # Create and start threads
        threads_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=worker)
            threads_list.append(t)
        
        # Start all threads simultaneously
        for t in threads_list:
            t.start()
        
        # Wait for completion
        for t in threads_list:
            t.join()
        
        # Analyze results
        unique_outcomes = self._count_unique_outcomes(outcomes)
        
        is_vulnerable = unique_outcomes > 1 or len(exceptions) > 0
        
        severity = "none"
        if is_vulnerable:
            if len(exceptions) > 0:
                severity = "high"
            elif unique_outcomes > self.threads * 0.1:  # >10% variance
                severity = "critical"
            else:
                severity = "medium"
        
        details = f"Found {unique_outcomes} different outcomes from {self.threads} concurrent executions"
        if exceptions:
            details += f", {len(exceptions)} exceptions raised"
        
        result = RaceConditionResult(
            function_name=func.__name__,
            input_data=args,
            thread_count=self.threads,
            unique_outcomes=unique_outcomes,
            outcomes=outcomes,
            is_vulnerable=is_vulnerable,
            severity=severity,
            details=details,
            timing_analysis={
                'min': min(timings) if timings else 0,
                'max': max(timings) if timings else 0,
                'avg': sum(timings) / len(timings) if timings else 0
            }
        )
        
        self.results.append(result)
        return result
    
    def _count_unique_outcomes(self, outcomes: List[Any]) -> int:
        """Count unique outcomes, handling various data types"""
        if not outcomes:
            return 0
        
        # Convert to hashable types
        hashable_outcomes = set()
        for outcome in outcomes:
            try:
                if isinstance(outcome, (list, dict, set)):
                    hashable_outcomes.add(str(sorted(str(outcome))))
                else:
                    hashable_outcomes.add(outcome)
            except:
                hashable_outcomes.add(str(outcome))
        
        return len(hashable_outcomes)
    
    def test_toctou(self, 
                    check_func: Callable[[], bool],
                    use_func: Callable[[], Any],
                    delay_ms: int = 1) -> RaceConditionResult:
        """
        Test Time-of-Check-Time-of-Use vulnerability
        
        Args:
            check_func: Function that checks condition
            use_func: Function that uses resource
            delay_ms: Artificial delay between check and use
        """
        outcomes = []
        lock = threading.Lock()
        
        def toctou_sequence():
            """Execute TOCTOU sequence"""
            # Time of Check
            if check_func():
                # Artificial delay to increase race window
                time.sleep(delay_ms / 1000.0)
                
                # Time of Use
                result = use_func()
                with lock:
                    outcomes.append(result)
        
        # Run multiple threads
        threads_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=toctou_sequence)
            threads_list.append(t)
            t.start()
        
        for t in threads_list:
            t.join()
        
        unique_outcomes = self._count_unique_outcomes(outcomes)
        is_vulnerable = unique_outcomes > 1
        
        result = RaceConditionResult(
            function_name=f"{check_func.__name__} -> {use_func.__name__}",
            input_data="TOCTOU test",
            thread_count=self.threads,
            unique_outcomes=unique_outcomes,
            outcomes=outcomes,
            is_vulnerable=is_vulnerable,
            severity="critical" if is_vulnerable else "none",
            details=f"TOCTOU: {unique_outcomes} different outcomes (expected 1)",
            timing_analysis={'delay_ms': delay_ms}
        )
        
        self.results.append(result)
        return result
    
    def test_stateful_operations(self, 
                                  operations: List[Callable],
                                  initial_state: Any) -> RaceConditionResult:
        """
        Test race conditions in stateful operations
        
        Args:
            operations: List of operations that modify state
            initial_state: Initial state value
        """
        final_states = []
        lock = threading.Lock()
        
        def worker():
            """Execute random operations on shared state"""
            import random
            state = initial_state
            
            # Execute random sequence of operations
            for _ in range(10):
                op = random.choice(operations)
                state = op(state)
            
            with lock:
                final_states.append(state)
        
        threads_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=worker)
            threads_list.append(t)
            t.start()
        
        for t in threads_list:
            t.join()
        
        unique_states = self._count_unique_outcomes(final_states)
        is_vulnerable = unique_states > 1
        
        result = RaceConditionResult(
            function_name="stateful_operations",
            input_data=initial_state,
            thread_count=self.threads,
            unique_outcomes=unique_states,
            outcomes=final_states,
            is_vulnerable=is_vulnerable,
            severity="high" if is_vulnerable else "none",
            details=f"State divergence: {unique_states} different final states",
            timing_analysis={}
        )
        
        self.results.append(result)
        return result
    
    def test_idempotency(self, func: Callable, args: tuple = ()) -> RaceConditionResult:
        """
        Test if function is idempotent under concurrent execution
        f(x) should equal f(f(x)) even with concurrent calls
        """
        outcomes_first = []
        outcomes_second = []
        lock = threading.Lock()
        
        def worker():
            """Execute function twice"""
            result1 = func(*args)
            result2 = func(result1) if result1 is not None else func(*args)
            
            with lock:
                outcomes_first.append(result1)
                outcomes_second.append(result2)
        
        threads_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=worker)
            threads_list.append(t)
            t.start()
        
        for t in threads_list:
            t.join()
        
        # Check if f(f(x)) == f(x) for all executions
        violations = 0
        for first, second in zip(outcomes_first, outcomes_second):
            if first != second:
                violations += 1
        
        is_vulnerable = violations > 0
        
        result = RaceConditionResult(
            function_name=func.__name__,
            input_data=args,
            thread_count=self.threads,
            unique_outcomes=violations,
            outcomes=list(zip(outcomes_first, outcomes_second)),
            is_vulnerable=is_vulnerable,
            severity="medium" if is_vulnerable else "none",
            details=f"Idempotency violations: {violations}/{self.threads}",
            timing_analysis={}
        )
        
        self.results.append(result)
        return result
    
    def test_atomic_operations(self, 
                                read_func: Callable,
                                write_func: Callable,
                                initial_value: Any) -> RaceConditionResult:
        """
        Test atomicity of read-modify-write operations
        """
        outcomes = []
        lock = threading.Lock()
        
        def read_modify_write():
            """Non-atomic read-modify-write"""
            # Read
            value = read_func()
            
            # Modify (simulate some processing)
            modified = value + 1 if isinstance(value, int) else value
            
            # Write
            write_func(modified)
            
            with lock:
                outcomes.append(modified)
        
        # Initialize
        write_func(initial_value)
        
        threads_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=read_modify_write)
            threads_list.append(t)
            t.start()
        
        for t in threads_list:
            t.join()
        
        # Final value should be initial_value + threads if atomic
        final_value = read_func()
        expected_value = initial_value + self.threads
        
        is_vulnerable = final_value != expected_value
        
        result = RaceConditionResult(
            function_name=f"{read_func.__name__} / {write_func.__name__}",
            input_data=initial_value,
            thread_count=self.threads,
            unique_outcomes=len(set(outcomes)),
            outcomes=outcomes,
            is_vulnerable=is_vulnerable,
            severity="critical" if is_vulnerable else "none",
            details=f"Atomicity: Expected {expected_value}, got {final_value}",
            timing_analysis={}
        )
        
        self.results.append(result)
        return result
    
    def test_double_spending(self, 
                             check_balance: Callable[[str], int],
                             withdraw: Callable[[str, int], bool],
                             account_id: str,
                             initial_balance: int,
                             withdraw_amount: int) -> RaceConditionResult:
        """
        Test for double-spending vulnerabilities (classic race condition)
        """
        successful_withdrawals = []
        lock = threading.Lock()
        
        def attempt_withdrawal():
            """Attempt to withdraw funds"""
            # Check balance
            balance = check_balance(account_id)
            
            if balance >= withdraw_amount:
                # Simulate network delay
                time.sleep(0.001)
                
                # Withdraw
                success = withdraw(account_id, withdraw_amount)
                
                with lock:
                    if success:
                        successful_withdrawals.append(withdraw_amount)
        
        threads_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=attempt_withdrawal)
            threads_list.append(t)
            t.start()
        
        for t in threads_list:
            t.join()
        
        total_withdrawn = sum(successful_withdrawals)
        num_withdrawals = len(successful_withdrawals)
        
        # Vulnerability if more withdrawn than balance allows
        max_possible = initial_balance // withdraw_amount
        is_vulnerable = num_withdrawals > max_possible
        
        result = RaceConditionResult(
            function_name="double_spending",
            input_data={'account': account_id, 'balance': initial_balance, 'amount': withdraw_amount},
            thread_count=self.threads,
            unique_outcomes=num_withdrawals,
            outcomes=successful_withdrawals,
            is_vulnerable=is_vulnerable,
            severity="critical" if is_vulnerable else "none",
            details=f"Double-spend: {num_withdrawals} withdrawals (max allowed: {max_possible}), total: {total_withdrawn}",
            timing_analysis={}
        )
        
        self.results.append(result)
        return result
    
    def generate_report(self) -> str:
        """Generate comprehensive race condition report"""
        report = []
        report.append("=" * 80)
        report.append("RACE CONDITION DETECTION REPORT")
        report.append("=" * 80)
        
        total_tests = len(self.results)
        vulnerable = sum(1 for r in self.results if r.is_vulnerable)
        
        report.append(f"\nTotal Tests: {total_tests}")
        report.append(f"Vulnerabilities Found: {vulnerable}")
        report.append(f"Pass Rate: {((total_tests - vulnerable) / total_tests * 100) if total_tests > 0 else 0:.1f}%")
        
        # Group by severity
        by_severity = defaultdict(list)
        for result in self.results:
            if result.is_vulnerable:
                by_severity[result.severity].append(result)
        
        for severity in ['critical', 'high', 'medium', 'low']:
            findings = by_severity[severity]
            if findings:
                report.append(f"\n{severity.upper()} SEVERITY ({len(findings)} findings):")
                report.append("-" * 80)
                
                for finding in findings:
                    report.append(f"\nFunction: {finding.function_name}")
                    report.append(f"Details: {finding.details}")
                    report.append(f"Thread Count: {finding.thread_count}")
                    report.append(f"Unique Outcomes: {finding.unique_outcomes}")
                    
                    if finding.timing_analysis:
                        report.append(f"Timing: {finding.timing_analysis}")
                    
                    # Show sample outcomes
                    if finding.outcomes:
                        sample_size = min(5, len(finding.outcomes))
                        report.append(f"Sample Outcomes (first {sample_size}):")
                        for i, outcome in enumerate(finding.outcomes[:sample_size], 1):
                            report.append(f"  {i}. {outcome}")
                    
                    report.append("\nRemediation:")
                    report.append("  - Use proper synchronization (locks, mutexes)")
                    report.append("  - Implement atomic operations")
                    report.append("  - Use database transactions with proper isolation")
                    report.append("  - Consider optimistic locking or versioning")
        
        report.append("\n" + "=" * 80)
        return "\n".join(report)


# Example usage and vulnerable functions
if __name__ == "__main__":
    
    # Example 1: Vulnerable balance update (classic race condition)
    class BankAccount:
        def __init__(self):
            self.balance = 1000
        
        def check_balance(self, account_id: str) -> int:
            return self.balance
        
        def withdraw(self, account_id: str, amount: int) -> bool:
            # VULNERABLE: No locking
            if self.balance >= amount:
                time.sleep(0.001)  # Simulate processing
                self.balance -= amount
                return True
            return False
    
    # Example 2: Vulnerable counter (non-atomic increment)
    class Counter:
        def __init__(self):
            self.value = 0
        
        def increment(self):
            # VULNERABLE: Read-modify-write is not atomic
            current = self.value
            time.sleep(0.0001)
            self.value = current + 1
            return self.value
    
    # Example 3: TOCTOU vulnerability
    resources_available = [True]
    
    def check_resource():
        """Check if resource is available"""
        return len(resources_available) > 0
    
    def use_resource():
        """Use the resource"""
        if resources_available:
            resource = resources_available.pop()
            return f"Used resource: {resource}"
        return "No resource available"
    
    # Run tests
    detector = RaceConditionDetector(threads=50, iterations=5)
    
    print("Testing Bank Account Double-Spending...")
    print("=" * 80)
    bank = BankAccount()
    result1 = detector.test_double_spending(
        check_balance=bank.check_balance,
        withdraw=bank.withdraw,
        account_id="ACC123",
        initial_balance=1000,
        withdraw_amount=100
    )
    print(f"Result: {result1.details}\n")
    
    print("Testing Counter Race Condition...")
    print("=" * 80)
    counter = Counter()
    result2 = detector.test_concurrent_execution(counter.increment)
    print(f"Result: {result2.details}\n")
    
    print("Testing TOCTOU Vulnerability...")
    print("=" * 80)
    result3 = detector.test_toctou(check_resource, use_resource, delay_ms=5)
    print(f"Result: {result3.details}\n")
    
    print("Testing Atomic Operations...")
    print("=" * 80)
    
    shared_value = {'count': 0}
    
    def read_value():
        return shared_value['count']
    
    def write_value(val):
        shared_value['count'] = val
    
    result4 = detector.test_atomic_operations(read_value, write_value, 0)
    print(f"Result: {result4.details}\n")
    
    # Generate comprehensive report
    print("\n" + detector.generate_report())
