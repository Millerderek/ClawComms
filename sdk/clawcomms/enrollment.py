"""
Enrollment Client — handles /enroll, /refresh, /refresh/ack against
the ClawComms Enrollment Service.
"""

import json
import logging
import asyncio
import random
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx

from .exceptions import EnrollmentError, CredentialExpiredError, RevocationError

logger = logging.getLogger("clawcomms.enrollment")

REFRESH_JITTER = 0.2   # ±20% jitter on refresh timing


class EnrollmentClient:
    def __init__(
        self,
        enrollment_url: str,
        wrk_fingerprint: str,
        bot_id: str,
        role: str,
        classification: str = "INTERNAL",
        http_timeout: float = 30.0,
    ):
        self.enrollment_url  = enrollment_url.rstrip("/")
        self.wrk_fingerprint = wrk_fingerprint
        self.bot_id          = bot_id
        self.role            = role
        self.classification  = classification
        self._timeout        = http_timeout
        self._credential: Optional[dict] = None
        self._session_id: Optional[str]  = None
        self._refresh_task: Optional[asyncio.Task] = None
        self.nats_creds: Optional[str]   = None   # .creds string, refreshed alongside BC

    # ── Public ──────────────────────────────────────────────────────────────

    async def enroll(self, grant: dict) -> dict:
        """
        Submit a WRK-signed Enrollment Grant and receive a Bot Credential.
        Starts the background refresh loop on success.
        """
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self.enrollment_url}/enroll",
                json={"grant": grant},
            )
            self._raise_for_status(resp, "enroll")

        data = resp.json()
        self._credential    = data["credential"]
        self._session_id    = data["session_id"]
        self.nats_creds     = data.get("nats_credentials")   # .creds string or None

        logger.info(
            "Enrolled: bot=%s session=%s role=%s expires=%s nats=%s",
            self.bot_id, self._session_id,
            self._credential["role"], self._credential["expires_at"],
            "yes" if self.nats_creds else "no",
        )

        self._start_refresh_loop()
        return self._credential

    async def refresh(self) -> dict:
        """Manually trigger a credential refresh."""
        if not self._credential or not self._session_id:
            raise EnrollmentError("Not enrolled — call enroll() first.")

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self.enrollment_url}/refresh",
                json={
                    "credential": self._credential,
                    "session_id": self._session_id,
                },
            )
            self._raise_for_status(resp, "refresh")

        data        = resp.json()
        old_cred_id = self._credential["credential_id"]
        self._credential = data["credential"]
        if data.get("nats_credentials"):
            self.nats_creds = data["nats_credentials"]

        logger.info("Refreshed: session=%s new_cred=%s", self._session_id,
                    self._credential["credential_id"])

        # Ack immediately
        await self._ack_refresh(old_cred_id, self._credential["credential_id"])
        return self._credential

    @property
    def credential(self) -> Optional[dict]:
        return self._credential

    @property
    def session_id(self) -> Optional[str]:
        return self._session_id

    def is_enrolled(self) -> bool:
        return self._credential is not None

    def is_valid(self) -> bool:
        """Check if current credential is still within its TTL."""
        if not self._credential:
            return False
        expires = datetime.fromisoformat(self._credential["expires_at"])
        return datetime.now(timezone.utc) < expires

    async def shutdown(self):
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
        self._credential = None
        self._session_id = None

    # ── Internal ─────────────────────────────────────────────────────────────

    def _start_refresh_loop(self):
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()
        self._refresh_task = asyncio.create_task(self._refresh_loop())

    async def _refresh_loop(self):
        """Background loop — refreshes credential at 20–30% TTL remaining."""
        while True:
            try:
                if not self._credential:
                    break

                expires    = datetime.fromisoformat(self._credential["expires_at"])
                ttl        = self._credential["ttl_seconds"]
                now        = datetime.now(timezone.utc)
                remaining  = (expires - now).total_seconds()

                # Refresh when 20–30% TTL remains (with jitter)
                refresh_at_remaining = ttl * 0.25
                jitter = refresh_at_remaining * REFRESH_JITTER * (random.random() * 2 - 1)
                refresh_at_remaining += jitter

                sleep_for = max(remaining - refresh_at_remaining, 1)
                logger.debug("Next refresh in %.0fs (%.0fs remaining)", sleep_for, remaining)
                await asyncio.sleep(sleep_for)

                if not self._credential:
                    break

                await self.refresh()

            except asyncio.CancelledError:
                break
            except RevocationError as e:
                logger.error("Revocation during refresh — stopping: %s", e)
                self._credential = None
                break
            except Exception as e:
                logger.warning("Refresh failed: %s — retrying in 30s", e)
                await asyncio.sleep(30)

    async def _ack_refresh(self, old_id: str, new_id: str):
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(
                    f"{self.enrollment_url}/refresh/ack",
                    json={
                        "old_credential_id": old_id,
                        "new_credential_id": new_id,
                        "session_id": self._session_id,
                    },
                )
        except Exception as e:
            logger.warning("Refresh ack failed (non-fatal): %s", e)

    @staticmethod
    def _raise_for_status(resp: httpx.Response, op: str):
        if resp.status_code == 403:
            raise RevocationError(f"Bot revoked during {op}.")
        if resp.status_code == 401:
            raise EnrollmentError(f"Authentication failed during {op}: {resp.text}")
        if resp.status_code == 409:
            raise EnrollmentError(f"Grant already used.")
        if resp.status_code == 429:
            raise EnrollmentError(f"Rate limit hit during {op}.")
        if resp.status_code >= 400:
            raise EnrollmentError(
                f"{op} failed [{resp.status_code}]: {resp.text}"
            )
