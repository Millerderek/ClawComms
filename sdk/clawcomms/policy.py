"""
Policy Gate — intercepts all outbound messages.
Actions: allow, redact, summarize, block, require_approval.

Rules are evaluated in order. First match wins.
Rules are loaded from a WRK-signed policy profile JSON file,
or can be set programmatically for dev/testing.
"""

import re
import json
import logging
from dataclasses import dataclass, field
from typing import Callable, Awaitable, Literal, Optional

from .exceptions import PolicyBlockedError

logger = logging.getLogger("clawcomms.policy")

PolicyAction = Literal["allow", "redact", "summarize", "block", "require_approval"]


@dataclass
class PolicyRule:
    name: str
    action: PolicyAction
    # At least one matcher required
    contains: list[str]        = field(default_factory=list)  # substring match
    regex: list[str]           = field(default_factory=list)  # regex match
    classification_above: Optional[str] = None                # classification ceiling check
    target: Optional[str]     = None   # "payload", "all" (default: "payload")
    redact_with: str           = "[REDACTED]"
    reason: str                = ""


# Classification order for ceiling checks
_CLASS_ORDER = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "SECRET": 3}


class PolicyGate:
    def __init__(self, workspace_classification: str = "INTERNAL"):
        self._rules: list[PolicyRule] = []
        self._workspace_ceiling       = workspace_classification
        # Pluggable approval interface — set by the bot host
        self._approval_handler: Optional[Callable] = None

    def load_rules(self, rules: list[PolicyRule]):
        self._rules = rules
        logger.info("Policy Gate: loaded %d rules", len(rules))

    def set_approval_handler(self, handler: Callable[[dict], Awaitable[bool]]):
        """
        Handler receives the full message dict.
        Should return True to approve, False to block.
        """
        self._approval_handler = handler

    async def check(self, message: dict) -> dict:
        """
        Evaluate outbound message against policy rules.
        Returns (possibly modified) message if allowed.
        Raises PolicyBlockedError if blocked.
        """
        # Always enforce classification ceiling
        msg_class = message.get("classification", {})
        msg_level = msg_class.get("level", "INTERNAL") if isinstance(msg_class, dict) else "INTERNAL"
        if _CLASS_ORDER.get(msg_level, 0) > _CLASS_ORDER.get(self._workspace_ceiling, 1):
            raise PolicyBlockedError(
                reason=f"Message classification {msg_level} exceeds workspace ceiling {self._workspace_ceiling}",
                action="block"
            )

        payload_str = json.dumps(message.get("payload", ""))

        for rule in self._rules:
            if not self._matches(rule, payload_str, message):
                continue

            logger.info("Policy rule '%s' matched — action: %s", rule.name, rule.action)

            if rule.action == "allow":
                return message

            elif rule.action == "block":
                raise PolicyBlockedError(reason=rule.reason or rule.name, action="block")

            elif rule.action == "redact":
                message = self._apply_redaction(rule, message, payload_str)
                return message

            elif rule.action == "summarize":
                message = self._apply_summary(rule, message)
                return message

            elif rule.action == "require_approval":
                approved = await self._request_approval(message)
                if not approved:
                    raise PolicyBlockedError(
                        reason=f"Approval denied: {rule.reason or rule.name}",
                        action="require_approval"
                    )
                return message

        return message  # No rules matched — allow by default

    # ── Matchers ─────────────────────────────────────────────────────────────

    def _matches(self, rule: PolicyRule, payload_str: str, message: dict) -> bool:
        for substr in rule.contains:
            if substr.lower() in payload_str.lower():
                return True
        for pattern in rule.regex:
            if re.search(pattern, payload_str, re.IGNORECASE):
                return True
        return False

    # ── Actions ──────────────────────────────────────────────────────────────

    def _apply_redaction(self, rule: PolicyRule, message: dict, payload_str: str) -> dict:
        for substr in rule.contains:
            payload_str = payload_str.replace(substr, rule.redact_with)
        for pattern in rule.regex:
            payload_str = re.sub(pattern, rule.redact_with, payload_str, flags=re.IGNORECASE)
        try:
            message["payload"] = json.loads(payload_str)
        except Exception:
            message["payload"] = payload_str
        message.setdefault("ext", {})["policy_redacted"] = True
        return message

    def _apply_summary(self, rule: PolicyRule, message: dict) -> dict:
        message["payload"] = f"[SUMMARIZED: {rule.reason or 'policy rule applied'}]"
        message.setdefault("ext", {})["policy_summarized"] = True
        return message

    async def _request_approval(self, message: dict) -> bool:
        if not self._approval_handler:
            logger.warning("No approval handler set — blocking by default")
            return False
        try:
            return await self._approval_handler(message)
        except Exception as e:
            logger.error("Approval handler error: %s — blocking", e)
            return False


# ── Default dev rules (non-production) ───────────────────────────────────────

DEFAULT_DEV_RULES = [
    PolicyRule(
        name="block-credentials",
        action="block",
        regex=[r"(password|secret|api.?key|token)\s*[:=]\s*\S+"],
        reason="Credential pattern detected in outbound message",
    ),
    PolicyRule(
        name="block-pii-ssn",
        action="redact",
        regex=[r"\b\d{3}-\d{2}-\d{4}\b"],
        reason="SSN pattern",
    ),
    PolicyRule(
        name="block-pii-cc",
        action="redact",
        regex=[r"\b(?:\d[ -]?){13,16}\b"],
        reason="Credit card pattern",
    ),
]
