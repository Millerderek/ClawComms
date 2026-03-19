"""ClawComms SDK — embed in any bot to join the relay mesh."""
from .client import ClawCommsClient
from .relay  import RELAY
from .anomaly import AnomalyMonitor, AnomalyConfig, AnomalyEvent
from .policy  import PolicyRule, scan_injection
from .exceptions import (
    ClawCommsError, EnrollmentError, CredentialExpiredError,
    PolicyBlockedError, RevocationError
)

__version__ = "1.0.0"
__all__ = [
    "ClawCommsClient",
    "RELAY",
    "AnomalyMonitor", "AnomalyConfig", "AnomalyEvent",
    "PolicyRule", "scan_injection",
    "ClawCommsError", "EnrollmentError", "CredentialExpiredError",
    "PolicyBlockedError", "RevocationError",
]
