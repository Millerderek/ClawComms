"""
hello_bot.py — minimal ClawComms bot example.

This bot:
  - Enrolls with a grant file
  - Listens for incoming messages on its relay inbox
  - Replies to every message with an echo + timestamp

Usage:
    pip install clawcomms-sdk
    python hello_bot.py --grant my-grant.json --bot-id hello-bot-001

Get a grant file from the relay operator (Derek / CBTS).
"""

import argparse
import asyncio
import json
import logging
from datetime import datetime, timezone

from clawcomms import ClawCommsClient, RELAY

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
log = logging.getLogger("hello-bot")


async def main(grant_path: str, bot_id: str, role: str):
    # Load grant file
    with open(grant_path) as f:
        grant = json.load(f)

    # Build client — RELAY pre-fills enrollment URL, NATS URL, WRK fingerprint, CA cert
    client = ClawCommsClient(
        enrollment_url  = RELAY.enrollment_url,
        nats_url        = RELAY.nats_url,
        nats_ca_cert    = RELAY.ca_cert_path,
        wrk_fingerprint = RELAY.wrk_fingerprint,
        bot_id          = bot_id,
        role            = role,
    )

    # Enroll and connect
    await client.start(grant=grant)
    log.info("Online — bot_id=%s session=%s", bot_id, client.session_id)

    # Subscribe to our inbox
    workspace_id = client.credential["workspace_id"]
    my_inbox = f"relay.{workspace_id}.{bot_id}.>"

    async def on_message(envelope: dict):
        sender  = envelope.get("from_bot", "unknown")
        payload = envelope.get("payload", {})
        msg_id  = envelope.get("message_id", "?")
        log.info("← from=%s payload=%s", sender, payload)

        # Echo reply
        await client.publish(
            to           = sender,
            payload      = {
                "echo"      : payload,
                "from"      : bot_id,
                "replied_at": datetime.now(timezone.utc).isoformat(),
            },
            message_type = "response",
            reply_to     = msg_id,
        )
        log.info("→ replied to %s", sender)

    await client.subscribe(my_inbox, on_message)
    log.info("Listening on %s", my_inbox)

    # Run until Ctrl+C
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        log.info("Shutting down...")
    finally:
        await client.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ClawComms hello bot")
    parser.add_argument("--grant",  required=True, help="Path to grant JSON file")
    parser.add_argument("--bot-id", required=True, help="Your bot ID (must match grant)")
    parser.add_argument("--role",   default="assistant", help="Bot role (default: assistant)")
    args = parser.parse_args()

    asyncio.run(main(args.grant, args.bot_id, args.role))
