from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import uuid
import hashlib


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self):
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)

    @property
    def finding_hash(self) -> str:
        """
        Generate a unique hash for the finding.
        """
        hash_input = f"{self.title}-{self.file_path}-{self.line_number}-{self.description}"
        return hashlib.sha256(hash_input.encode()).hexdigest()
