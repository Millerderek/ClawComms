"""
ClawCommsClient — the single object a bot imports and uses.

Usage:
    client = ClawCommsClient(
        enrollment_url="https://dev.clawcomms.com",
        nats_url="nats://localhost:4222",
        bot_id="openclaw-prod",
        role="assistant",
        wrk_fingerprint="df100808...",
    )

    await client.start(grant=grant_dict)
    await client.publish("target-bot", {"text": "Hello"}, message_type="chat")
    await client.subscribe("my.subject", handler)
    await client.stop()
"""

import asyncio
import json
import logging
from typing import Callable, Awaitable, Optional

import nats
from nats.errors import ConnectionClosedError, TimeoutError as NatsTimeoutError

from .identity   import IdentityManager
from .enrollment import EnrollmentClient
from .policy     import PolicyGate, DEFAULT_DEV_RULES
from .messaging  import MessageHandler
from .exceptions import ClawCommsError, EnrollmentError, PolicyBlockedError

logger = logging.getLogger("clawcomms.client")


class ClawCommsClient:
    def __init__(
        self,
        enrollment_url: str,
        nats_url: str,
        bot_id: str,
        role: str,
        wrk_fingerprint: str,
        classification: str = "INTERNAL",
        use_default_policy_rules: bool = True,
    ):
        self.bot_id      = bot_id
        self._nats_url   = nats_url
        self._wrk_fp     = wrk_fingerprint

        # Core components
        self._identity   = IdentityManager()
        self._enrollment = EnrollmentClient(
            enrollment_url=enrollment_url,
            wrk_fingerprint=wrk_fingerprint,
            bot_id=bot_id,
            role=role,
            classification=classification,
        )
        self._policy     = PolicyGate(workspace_classification=classification)
        self._messaging  = MessageHandler(self._identity, bot_id)

        if use_default_policy_rules:
            self._policy.load_rules(DEFAULT_DEV_RULES)

        self._nc: Optional[nats.NATS] = None
        self._subscriptions: list     = []

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def start(self, grant: dict):
        """Enroll with the grant, then connect to NATS."""
        # Validate WRK fingerprint matches genesis (belt-and-suspenders)
        if grant.get("wrk_fingerprint") != self._wrk_fp:
            raise EnrollmentError(
                f"Grant WRK fingerprint mismatch. "
                f"Expected {self._wrk_fp}, got {grant.get('wrk_fingerprint')}"
            )

        # Inject our public key into the grant before submitting
        grant = dict(grant)
        grant["bot_public_key_hex"] = self._identity.public_key_hex

        credential = await self._enrollment.enroll(grant)
        logger.info("ClawComms online: bot=%s session=%s", self.bot_id,
                    credential["session_id"])

        # Connect to NATS
        await self._connect_nats()

    async def stop(self):
        """Graceful shutdown — cancel refresh loop, drain NATS, zeroize identity."""
        await self._enrollment.shutdown()
        if self._nc:
            try:
                await self._nc.drain()
            except Exception:
                pass
        self._identity.zeroize()
        logger.info("ClawComms shutdown: bot=%s", self.bot_id)

    # ── Messaging ──────────────────────────────────────────────────────────

    async def publish(
        self,
        to: str | list[str],
        payload,
        message_type: str = "message",
        subject: Optional[str] = None,
        conversation_id: Optional[str] = None,
        reply_to: Optional[str] = None,
        ttl_ms: int = 30000,
    ) -> dict:
        """
        Build, policy-check, sign, and publish a message.
        Returns the sent envelope.
        """
        if not self._enrollment.is_enrolled():
            raise ClawCommsError("Not enrolled. Call start() first.")
        if not self._enrollment.is_valid():
            raise ClawCommsError("Credential expired — refresh pending.")

        credential = self._enrollment.credential

        envelope = self._messaging.build(
            to=to,
            payload=payload,
            message_type=message_type,
            credential=credential,
            conversation_id=conversation_id,
            reply_to=reply_to,
            ttl_ms=ttl_ms,
        )

        # Policy Gate — may raise PolicyBlockedError
        envelope = await self._policy.check(envelope)

        # Determine NATS subject
        nats_subject = subject or f"relay.{credential['workspace_id']}.{to if isinstance(to, str) else to[0]}"

        if self._nc:
            await self._nc.publish(nats_subject, json.dumps(envelope).encode())
            logger.debug("Published: type=%s to=%s subject=%s", message_type, to, nats_subject)

        return envelope

    async def subscribe(
        self,
        subject: str,
        handler: Callable[[dict], Awaitable[None]],
        validate_signatures: bool = True,
    ):
        """Subscribe to a NATS subject with an async message handler."""
        if not self._nc:
            raise ClawCommsError("Not connected to NATS. Call start() first.")

        async def _wrapper(msg):
            try:
                envelope = json.loads(msg.data.decode())

                # Validate signature if sender public key is available
                if validate_signatures:
                    sender_pubkey = envelope.get("ext", {}).get("sender_public_key")
                    if sender_pubkey:
                        if not self._messaging.validate_inbound(envelope, sender_pubkey):
                            logger.warning("Dropping message with invalid signature: %s",
                                           envelope.get("message_id"))
                            return

                await handler(envelope)
            except Exception as e:
                logger.error("Message handler error on %s: %s", subject, e)

        sub = await self._nc.subscribe(subject, cb=_wrapper)
        self._subscriptions.append(sub)
        logger.info("Subscribed: %s", subject)
        return sub

    # ── Policy ─────────────────────────────────────────────────────────────

    def set_policy_rules(self, rules):
        """Replace the active policy rule set."""
        self._policy.load_rules(rules)

    def set_approval_handler(self, handler: Callable):
        """Set the handler for require_approval policy actions."""
        self._policy.set_approval_handler(handler)

    # ── Properties ─────────────────────────────────────────────────────────

    @property
    def credential(self) -> Optional[dict]:
        return self._enrollment.credential

    @property
    def session_id(self) -> Optional[str]:
        return self._enrollment.session_id

    @property
    def public_key_hex(self) -> str:
        return self._identity.public_key_hex

    @property
    def is_enrolled(self) -> bool:
        return self._enrollment.is_enrolled() and self._enrollment.is_valid()

    # ── Internal ───────────────────────────────────────────────────────────

    async def _connect_nats(self, max_retries: int = 5):
        import tempfile, os

        # Write .creds to a temp file if we have NATS credentials
        creds_file = None
        nats_creds = self._enrollment.nats_creds
        if nats_creds:
            tmp = tempfile.NamedTemporaryFile(
                mode='w', suffix='.creds', delete=False
            )
            tmp.write(nats_creds)
            tmp.close()
            creds_file = tmp.name
            logger.info("NATS: using issued credentials (JWT+NKey)")
        else:
            logger.info("NATS: connecting without auth (no NATS creds issued)")

        try:
            for attempt in range(1, max_retries + 1):
                try:
                    connect_kwargs = dict(
                        name=self.bot_id,
                        reconnect_time_wait=2,
                        max_reconnect_attempts=10,
                        error_cb=self._nats_error_cb,
                        disconnected_cb=self._nats_disconnected_cb,
                        reconnected_cb=self._nats_reconnected_cb,
                    )
                    if creds_file:
                        connect_kwargs["user_credentials"] = creds_file

                    self._nc = await nats.connect(self._nats_url, **connect_kwargs)
                    logger.info("NATS connected: %s", self._nats_url)
                    return
                except Exception as e:
                    logger.warning("NATS connect attempt %d/%d failed: %s",
                                   attempt, max_retries, e)
                    if attempt < max_retries:
                        await asyncio.sleep(2 ** attempt)
            raise ClawCommsError(f"Could not connect to NATS at {self._nats_url}")
        finally:
            if creds_file and os.path.exists(creds_file):
                os.unlink(creds_file)   # Zeroize temp creds file

    async def _nats_error_cb(self, e):
        logger.error("NATS error: %s", e)

    async def _nats_disconnected_cb(self):
        logger.warning("NATS disconnected — sequence counters reset for session %s",
                       self._enrollment.session_id)
        if self._enrollment.session_id:
            self._messaging.reset_sequence(self._enrollment.session_id)

    async def _nats_reconnected_cb(self):
        logger.info("NATS reconnected")
