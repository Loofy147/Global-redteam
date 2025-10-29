"""
This module contains the data classes used by the Red Team Orchestrator.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Callable, Optional, Any


class TestCategory(Enum):
    """Categories of security tests"""

    PROPERTY_BASED = "property_based"
    FUZZING = "fuzzing"
    API_SECURITY = "api_security"
    RACE_CONDITIONS = "race_conditions"
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHY = "cryptography"
    BUSINESS_LOGIC = "business_logic"
    INFRASTRUCTURE = "infrastructure"


class Severity(Enum):
    """Severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a security finding"""

    id: str
    category: TestCategory
    severity: Severity
    title: str
    description: str
    affected_component: str
    evidence: Any
    remediation: str
    cvss_score: float = 0.0
    cwe_id: Optional[str] = None
    references: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.now)


@dataclass
class TestSuite:
    """A collection of related tests"""

    name: str
    category: TestCategory
    tests: List[Callable]
    description: str = ""
    enabled: bool = True
