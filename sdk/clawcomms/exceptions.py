class ClawCommsError(Exception):
    """Base exception for all ClawComms SDK errors."""

class EnrollmentError(ClawCommsError):
    """Enrollment or refresh failed."""

class CredentialExpiredError(ClawCommsError):
    """Bot Credential expired and could not be refreshed."""

class PolicyBlockedError(ClawCommsError):
    """Outbound message blocked by Policy Gate."""
    def __init__(self, reason: str, action: str):
        self.reason = reason
        self.action = action
        super().__init__(f"Policy Gate [{action}]: {reason}")

class RevocationError(ClawCommsError):
    """Bot or session has been revoked."""
