"""
Round-trip infra test — two bots, one message, verify echo.

bot-a sends a message to bot-b.
bot-b echoes it back.
bot-a receives the echo.

Run: python3 tests/test_roundtrip.py
"""

import asyncio
import json
import logging
import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from clawcomms import ClawCommsClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
)
log = logging.getLogger("roundtrip-test")

CLAWCOMMS_DIR      = os.getenv("CLAWCOMMS_DIR",      "/root/clawcomms")
CLAWCOMMS_HOST_DIR = os.getenv("CLAWCOMMS_HOST_DIR", "/root/clawcomms")  # HOST path for docker vol mounts
WRK_PASSPHRASE  = os.getenv("RELAY_WRK_PASSPHRASE", "D3cPRMKHkfuQyXEinRtcCneDLmDzC8zukEQbBtUP")
ENROLLMENT_URL  = os.getenv("CLAWCOMMS_ENROLLMENT_URL", "http://127.0.0.1:8001")
NATS_URL        = os.getenv("CLAWCOMMS_NATS_URL",        "nats://127.0.0.1:4222")
CA_CERT         = os.getenv("CLAWCOMMS_CA_CERT",          "/root/clawcomms/nats/certs/ca.crt")
WRK_FINGERPRINT = os.getenv("CLAWCOMMS_WRK_FINGERPRINT", "df100808ff0353e720a266036794c5bc19cacf57a9b994c2992c0a3b39b0d5b9")


def issue_grant(bot_id: str, pubkey_hex: str, role: str = "assistant") -> dict:
    """Issue a grant for a bot via bootstrap-cli Docker container."""
    log.info("Issuing grant for %s ...", bot_id)
    result = subprocess.run(
        [
            "docker", "run", "--rm",
            "--network", "none",
            "-e", f"RELAY_WRK_PASSPHRASE={WRK_PASSPHRASE}",
            "-v", f"{CLAWCOMMS_HOST_DIR}/keys:/keys",
            "clawcomms-bootstrap-cli:latest",
            "issue-grant",
            "--bot-id",         bot_id,
            "--bot-public-key", pubkey_hex,
            "--role",           role,
            "--ttl",            "300",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"issue-grant failed:\n{result.stderr}")

    # Parse JSON block from stdout
    lines = result.stdout.strip().split("\n")
    json_lines, in_json = [], False
    for line in lines:
        if line.strip().startswith("{"):
            in_json = True
        if in_json:
            json_lines.append(line)
        if in_json and line.strip() == "}":
            break

    grant = json.loads("\n".join(json_lines))
    log.info("Grant issued: grant_id=%s expires=%s", grant["grant_id"], grant["expires_at"])
    return grant


async def run():
    echo_received = asyncio.Event()
    echo_payload  = {}

    # ── Create clients (generates Ed25519 keypairs) ──────────────────────
    bot_a = ClawCommsClient(
        enrollment_url  = ENROLLMENT_URL,
        nats_url        = NATS_URL,
        nats_ca_cert    = CA_CERT,
        wrk_fingerprint = WRK_FINGERPRINT,
        bot_id          = "test-bot-a",
        role            = "assistant",
        use_default_policy_rules=False,
    )
    bot_b = ClawCommsClient(
        enrollment_url  = ENROLLMENT_URL,
        nats_url        = NATS_URL,
        nats_ca_cert    = CA_CERT,
        wrk_fingerprint = WRK_FINGERPRINT,
        bot_id          = "test-bot-b",
        role            = "assistant",
        use_default_policy_rules=False,
    )

    # ── Issue grants using each bot's fresh public key ───────────────────
    grant_a = issue_grant("test-bot-a", bot_a.public_key_hex)
    grant_b = issue_grant("test-bot-b", bot_b.public_key_hex)

    # ── Enroll both bots ─────────────────────────────────────────────────
    log.info("Enrolling bot-a ...")
    await bot_a.start(grant=grant_a)
    log.info("Enrolling bot-b ...")
    await bot_b.start(grant=grant_b)

    workspace_id = bot_b.credential["workspace_id"]

    # ── bot-b subscribes to its inbox ────────────────────────────────────
    b_inbox = f"relay.{workspace_id}.test-bot-b.>"

    async def bot_b_handler(envelope: dict):
        sender  = envelope.get("from_bot")
        payload = envelope.get("payload")
        log.info("[bot-b] ← from=%s payload=%s", sender, payload)

        # Echo back to sender
        await bot_b.publish(
            to           = sender,
            payload      = {"echo": payload, "from": "test-bot-b"},
            message_type = "response",
            reply_to     = envelope.get("message_id"),
        )
        log.info("[bot-b] → echoed to %s", sender)

    await bot_b.subscribe(b_inbox, bot_b_handler)
    log.info("bot-b listening on %s", b_inbox)

    # ── bot-a subscribes to its inbox (to catch the echo) ────────────────
    a_inbox = f"relay.{workspace_id}.test-bot-a.>"

    async def bot_a_handler(envelope: dict):
        sender = envelope.get("from_bot")
        payload = envelope.get("payload")
        log.info("[bot-a] ← from=%s payload=%s", sender, payload)
        echo_payload.update({"received": payload, "from": sender})
        echo_received.set()

    await bot_a.subscribe(a_inbox, bot_a_handler)

    # ── bot-a sends a message to bot-b ───────────────────────────────────
    await asyncio.sleep(0.5)   # brief settle
    log.info("[bot-a] → sending to test-bot-b ...")
    await bot_a.publish(
        to           = "test-bot-b",
        payload      = {"hello": "ClawComms round-trip test", "seq": 1},
        message_type = "chat",
    )

    # ── Wait for echo (10s timeout) ───────────────────────────────────────
    log.info("Waiting for echo ...")
    try:
        await asyncio.wait_for(echo_received.wait(), timeout=10.0)
        log.info("✓ ROUND TRIP COMPLETE")
        log.info("  Echo payload: %s", echo_payload)
        result = True
    except asyncio.TimeoutError:
        log.error("✗ TIMEOUT — no echo received within 10s")
        result = False
    finally:
        await bot_a.stop()
        await bot_b.stop()

    return result


if __name__ == "__main__":
    ok = asyncio.run(run())
    sys.exit(0 if ok else 1)
