from abc import ABC, abstractmethod
from typing import List
from ..core.finding import Finding

class BaseScanner(ABC):
    """Abstract base class for all scanners."""

    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def scan(self) -> List[Finding]:
        """Run the scanner and return a list of findings."""
        pass
