"""ClawComms SDK — embed in any bot to join the relay mesh."""
from .client import ClawCommsClient
from .exceptions import (
    ClawCommsError, EnrollmentError, CredentialExpiredError,
    PolicyBlockedError, RevocationError
)

__version__ = "1.0.0"
__all__ = [
    "ClawCommsClient",
    "ClawCommsError", "EnrollmentError", "CredentialExpiredError",
    "PolicyBlockedError", "RevocationError",
]
