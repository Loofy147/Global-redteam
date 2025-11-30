from abc import ABC, abstractmethod
from typing import List, Optional
import logging
from src.redteam.core.finding import Finding
from src.redteam.core.exceptions import ScannerException, ConfigurationError

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """Abstract base scanner with built-in error handling"""

    def __init__(self, config: dict):
        self.config = config
        self.findings: List[Finding] = []
        self._validate_config()

    def _validate_config(self):
        """Validate scanner configuration"""
        required_fields = self.get_required_config_fields()
        missing = [f for f in required_fields if f not in self.config]
        if missing:
            raise ConfigurationError(
                f"{self.__class__.__name__} missing config: {missing}"
            )

    @abstractmethod
    def get_required_config_fields(self) -> List[str]:
        """Return required configuration fields"""
        pass

    @abstractmethod
    def _scan_implementation(self) -> List[Finding]:
        """Implement actual scanning logic"""
        pass

    def scan(self) -> List[Finding]:
        """Execute scan with error handling"""
        try:
            logger.info(f"Starting {self.__class__.__name__}")
            findings = self._scan_implementation()
            logger.info(f"Completed: {len(findings)} findings")
            return findings
        except Exception as e:
            logger.error(f"Scanner failed: {e}", exc_info=True)
            raise ScannerException(
                f"{self.__class__.__name__} failed: {str(e)}"
            ) from e
