class RedTeamException(Exception):
    """Base exception for red team framework"""
    pass


class ScannerException(RedTeamException):
    """Raised when scanner encounters an error"""
    pass


class ConfigurationError(RedTeamException):
    """Raised for configuration issues"""
    pass


class IntegrationError(RedTeamException):
    """Raised for external integration failures"""
    pass
