"""
Message Handler — builds and validates canonical ClawComms message envelopes.
Enforces schema, signs with bot identity, validates incoming signatures.
"""

import json
import uuid
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from .identity import IdentityManager

logger = logging.getLogger("clawcomms.messaging")

PROTOCOL_VERSION = "1.0"
CLOCK_SKEW_TOLERANCE = 60   # seconds


class MessageHandler:
    def __init__(self, identity: IdentityManager, bot_id: str):
        self._identity   = identity
        self._bot_id     = bot_id
        self._seq: dict  = {}   # session_id → sequence_no

    def build(
        self,
        to: str | list[str],
        payload,
        message_type: str,
        credential: dict,
        classification: Optional[dict] = None,
        reply_to: Optional[str] = None,
        conversation_id: Optional[str] = None,
        ttl_ms: int = 30000,
    ) -> dict:
        """Build a signed outbound message envelope."""
        session_id = credential["session_id"]
        seq        = self._next_seq(session_id)

        msg = {
            "protocol_version": PROTOCOL_VERSION,
            "message_id":       str(uuid.uuid4()),
            "conversation_id":  conversation_id or str(uuid.uuid4()),
            "session_id":       session_id,
            "workspace_id":     credential["workspace_id"],
            "from_bot":         self._bot_id,
            "to":               to if isinstance(to, list) else [to],
            "reply_to":         reply_to,
            "message_type":     message_type,
            "classification":   classification or {
                "level": credential.get("classification", "INTERNAL"),
                "tags": [],
            },
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "ttl_ms":           ttl_ms,
            "dedup_key":        str(uuid.uuid4()),
            "sequence_no":      seq,
            "payload":          payload,
            "ext":              {},
            "signature":        None,   # filled below
        }

        # Sign over all fields except signature itself
        payload_to_sign = {k: v for k, v in msg.items() if k != "signature"}
        canonical = json.dumps(payload_to_sign, sort_keys=True, separators=(',', ':')).encode()
        msg["signature"] = self._identity.sign(canonical).hex()

        return msg

    def validate_inbound(self, message: dict, sender_public_key_hex: str) -> bool:
        """Verify signature and clock skew on an inbound message."""
        sig_hex = message.get("signature")
        if not sig_hex:
            logger.warning("Inbound message missing signature: %s", message.get("message_id"))
            return False

        # Clock skew check
        try:
            ts = datetime.fromisoformat(message["timestamp"])
            skew = abs((datetime.now(timezone.utc) - ts).total_seconds())
            if skew > CLOCK_SKEW_TOLERANCE:
                logger.warning("Message clock skew %.0fs exceeds tolerance", skew)
                return False
        except Exception:
            return False

        # Signature check
        payload_to_verify = {k: v for k, v in message.items() if k != "signature"}
        canonical = json.dumps(payload_to_verify, sort_keys=True, separators=(',', ':')).encode()

        try:
            raw = bytes.fromhex(sender_public_key_hex)
            pub = Ed25519PublicKey.from_public_bytes(raw)
            pub.verify(bytes.fromhex(sig_hex), canonical)
            return True
        except (InvalidSignature, Exception) as e:
            logger.warning("Inbound signature invalid: %s", e)
            return False

    def reset_sequence(self, session_id: str):
        """Reset sequence counter on reconnect."""
        self._seq[session_id] = 0

    def _next_seq(self, session_id: str) -> int:
        self._seq[session_id] = self._seq.get(session_id, 0) + 1
        return self._seq[session_id]
