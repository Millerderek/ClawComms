"""
ClawComms relay config — pre-filled with the production relay endpoints.

Usage:
    from clawcomms.relay import RELAY

    client = ClawCommsClient(
        enrollment_url=RELAY.enrollment_url,
        nats_url=RELAY.nats_url,
        nats_ca_cert=RELAY.ca_cert_path,
        wrk_fingerprint=RELAY.wrk_fingerprint,
        ...
    )
"""

import os
from pathlib import Path
from dataclasses import dataclass


@dataclass(frozen=True)
class RelayConfig:
    enrollment_url:  str
    nats_url:        str
    wrk_fingerprint: str
    ca_cert_path:    str


# CA cert is bundled with the SDK package
_BUNDLED_CA = str(Path(__file__).parent / "ca.crt")

# Production relay (ClawComms @ 217.216.85.157)
RELAY = RelayConfig(
    enrollment_url  = os.getenv("CLAWCOMMS_ENROLLMENT_URL",  "https://dev.clawcomms.com"),
    nats_url        = os.getenv("CLAWCOMMS_NATS_URL",        "tls://217.216.85.157:4222"),
    wrk_fingerprint = os.getenv("CLAWCOMMS_WRK_FINGERPRINT", "df100808ff0353e720a266036794c5bc19cacf57a9b994c2992c0a3b39b0d5b9"),
    ca_cert_path    = os.getenv("CLAWCOMMS_CA_CERT",          _BUNDLED_CA),
)
