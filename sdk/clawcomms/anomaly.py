"""
Anomaly Monitor — behavioral detection for ClawComms message traffic.

Security Addendum v1.0 coverage:
  §7.1  — Message burst detection (rate anomaly per bot)
  §7.2  — Off-hours activity flagging
  §7.3  — Role-based target restrictions
  §7.4  — Unknown/revoked sender alerting
  §9.1  — Audit trail for anomalous events

Design:
  - In-memory sliding windows (no Redis dependency from SDK)
  - Pluggable alert handler (log, Telegram, webhook — set by host)
  - Non-blocking: anomalies log + alert but don't block messages
    (policy.py handles blocking; anomaly.py handles detection)
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Awaitable, Optional, Literal

logger = logging.getLogger("clawcomms.anomaly")

AnomalyLevel = Literal["info", "warning", "critical"]


@dataclass
class AnomalyEvent:
    """A detected anomaly."""
    level: AnomalyLevel
    category: str          # burst, off_hours, target_violation, unknown_sender
    bot_id: str
    message: str
    details: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class AnomalyConfig:
    """Tunable thresholds for anomaly detection."""
    # Burst detection: max messages per bot per window
    burst_max_messages: int = 30
    burst_window_seconds: int = 60

    # Off-hours detection (UTC)
    off_hours_start: int = 2    # 2:00 AM UTC
    off_hours_end: int = 6      # 6:00 AM UTC
    off_hours_enabled: bool = False  # Disabled by default — most bots run 24/7

    # Target restrictions: roles that cannot message certain other roles
    # Format: {"monitor": ["orchestrator"]}  — monitor can't message orchestrator
    role_target_deny: dict = field(default_factory=dict)

    # Known bot IDs — messages from unknown bots trigger alerts
    known_bots: set = field(default_factory=set)
    alert_on_unknown_sender: bool = True


class AnomalyMonitor:
    """
    Tracks message patterns and detects anomalous behavior.

    Usage:
        monitor = AnomalyMonitor(config=AnomalyConfig(...))
        monitor.set_alert_handler(my_alert_fn)

        # In message receive path:
        await monitor.check_inbound(envelope, receiver_credential)

        # In message send path:
        await monitor.check_outbound(envelope, sender_credential)
    """

    def __init__(self, config: Optional[AnomalyConfig] = None):
        self._config = config or AnomalyConfig()
        self._alert_handler: Optional[Callable[[AnomalyEvent], Awaitable[None]]] = None

        # Sliding window: bot_id -> list of timestamps
        self._msg_timestamps: dict[str, list[float]] = defaultdict(list)

        # Audit log (in-memory ring buffer, last 1000 events)
        self._audit_log: list[AnomalyEvent] = []
        self._audit_max = 1000

    def set_alert_handler(self, handler: Callable[[AnomalyEvent], Awaitable[None]]):
        """Set async handler called on every anomaly detection."""
        self._alert_handler = handler

    def update_known_bots(self, bot_ids: set[str]):
        """Update the set of known/trusted bot IDs."""
        self._config.known_bots = bot_ids

    # ── Inbound check ────────────────────────────────────────────────────────

    async def check_inbound(
        self,
        envelope: dict,
        receiver_credential: Optional[dict] = None,
    ) -> list[AnomalyEvent]:
        """
        Analyze an inbound message for anomalous patterns.
        Returns list of detected anomalies (may be empty).
        Does NOT block — that's policy.py's job.
        """
        events = []
        from_bot = envelope.get("from_bot", "unknown")
        now = time.time()

        # ── 1. Burst detection (§7.1) ────────────────────────────────────────
        burst = self._check_burst(from_bot, now, direction="inbound")
        if burst:
            events.append(burst)

        # ── 2. Off-hours activity (§7.2) ──────────────────────────────────────
        off_hours = self._check_off_hours(from_bot, now)
        if off_hours:
            events.append(off_hours)

        # ── 3. Unknown sender (§7.4) ─────────────────────────────────────────
        if (self._config.alert_on_unknown_sender
                and self._config.known_bots
                and from_bot not in self._config.known_bots):
            events.append(AnomalyEvent(
                level="warning",
                category="unknown_sender",
                bot_id=from_bot,
                message=f"Message from unknown bot: {from_bot}",
                details={
                    "message_id": envelope.get("message_id"),
                    "message_type": envelope.get("message_type"),
                },
            ))

        # ── Fire alerts ──────────────────────────────────────────────────────
        for event in events:
            await self._record_and_alert(event)

        return events

    # ── Outbound check ───────────────────────────────────────────────────────

    async def check_outbound(
        self,
        envelope: dict,
        sender_credential: Optional[dict] = None,
    ) -> list[AnomalyEvent]:
        """
        Analyze an outbound message for anomalous patterns.
        Returns list of detected anomalies.
        """
        events = []
        to_bot = envelope.get("to", "unknown")
        if isinstance(to_bot, list):
            to_bot = to_bot[0] if to_bot else "unknown"
        from_bot = envelope.get("from_bot", "unknown")
        now = time.time()

        # ── 1. Burst detection (§7.1) ────────────────────────────────────────
        burst = self._check_burst(from_bot, now, direction="outbound")
        if burst:
            events.append(burst)

        # ── 2. Role-based target restrictions (§7.3) ─────────────────────────
        if sender_credential and self._config.role_target_deny:
            sender_role = sender_credential.get("role", "unknown")
            denied_targets = self._config.role_target_deny.get(sender_role, [])

            # We need the target's role — check envelope ext if available
            target_role = envelope.get("ext", {}).get("target_role")
            if target_role and target_role in denied_targets:
                events.append(AnomalyEvent(
                    level="warning",
                    category="target_violation",
                    bot_id=from_bot,
                    message=(
                        f"Role '{sender_role}' attempted to message "
                        f"restricted role '{target_role}' (target: {to_bot})"
                    ),
                    details={
                        "sender_role": sender_role,
                        "target_role": target_role,
                        "target_bot": to_bot,
                    },
                ))

        # ── Fire alerts ──────────────────────────────────────────────────────
        for event in events:
            await self._record_and_alert(event)

        return events

    # ── Internal detectors ───────────────────────────────────────────────────

    def _check_burst(
        self, bot_id: str, now: float, direction: str
    ) -> Optional[AnomalyEvent]:
        """Sliding window burst detection."""
        key = f"{direction}:{bot_id}"
        window = self._config.burst_window_seconds
        max_msgs = self._config.burst_max_messages

        # Prune old timestamps
        timestamps = self._msg_timestamps[key]
        cutoff = now - window
        self._msg_timestamps[key] = [t for t in timestamps if t > cutoff]
        self._msg_timestamps[key].append(now)

        count = len(self._msg_timestamps[key])
        if count > max_msgs:
            return AnomalyEvent(
                level="warning",
                category="burst",
                bot_id=bot_id,
                message=(
                    f"Burst detected: {count} {direction} messages from "
                    f"{bot_id} in {window}s (limit: {max_msgs})"
                ),
                details={
                    "direction": direction,
                    "count": count,
                    "window_seconds": window,
                    "limit": max_msgs,
                },
            )
        return None

    def _check_off_hours(
        self, bot_id: str, now: float
    ) -> Optional[AnomalyEvent]:
        """Flag activity during configured off-hours (UTC)."""
        if not self._config.off_hours_enabled:
            return None

        import datetime
        hour = datetime.datetime.fromtimestamp(now, tz=datetime.timezone.utc).hour

        start = self._config.off_hours_start
        end = self._config.off_hours_end

        in_off_hours = False
        if start < end:
            in_off_hours = start <= hour < end
        else:  # wraps midnight (e.g., 22 to 6)
            in_off_hours = hour >= start or hour < end

        if in_off_hours:
            return AnomalyEvent(
                level="info",
                category="off_hours",
                bot_id=bot_id,
                message=f"Off-hours activity from {bot_id} at {hour:02d}:xx UTC",
                details={"hour_utc": hour},
            )
        return None

    # ── Recording & alerting ─────────────────────────────────────────────────

    async def _record_and_alert(self, event: AnomalyEvent):
        """Log, store in audit ring buffer, and fire alert handler."""
        # Log
        log_fn = {
            "info": logger.info,
            "warning": logger.warning,
            "critical": logger.critical,
        }.get(event.level, logger.warning)

        log_fn(
            "ANOMALY [%s/%s] bot=%s: %s",
            event.level, event.category, event.bot_id, event.message
        )

        # Audit trail (§9.1)
        self._audit_log.append(event)
        if len(self._audit_log) > self._audit_max:
            self._audit_log = self._audit_log[-self._audit_max:]

        # Alert handler
        if self._alert_handler:
            try:
                await self._alert_handler(event)
            except Exception as e:
                logger.error("Anomaly alert handler error: %s", e)

    # ── Query API ────────────────────────────────────────────────────────────

    def get_recent_anomalies(
        self,
        limit: int = 50,
        category: Optional[str] = None,
        level: Optional[AnomalyLevel] = None,
    ) -> list[AnomalyEvent]:
        """Query the in-memory audit log."""
        results = self._audit_log
        if category:
            results = [e for e in results if e.category == category]
        if level:
            results = [e for e in results if e.level == level]
        return results[-limit:]

    def get_stats(self) -> dict:
        """Summary stats for monitoring dashboards."""
        from collections import Counter
        cats = Counter(e.category for e in self._audit_log)
        levels = Counter(e.level for e in self._audit_log)
        return {
            "total_anomalies": len(self._audit_log),
            "by_category": dict(cats),
            "by_level": dict(levels),
            "active_tracked_bots": len(self._msg_timestamps),
        }
