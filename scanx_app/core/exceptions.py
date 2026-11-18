"""Application-specific exceptions."""

class ScanXError(Exception):
    """Base exception for expected SCAN-X failures."""

class ConfigurationError(ScanXError):
    """Invalid or unreadable configuration."""

class TargetError(ScanXError):
    """Invalid scan target."""

class EngineUnavailableError(ScanXError):
    """A requested engine or dependency is unavailable."""
