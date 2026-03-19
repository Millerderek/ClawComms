"""
Live integration test — hits the real enrollment service at dev.clawcomms.com.
Requires: CLAWCOMMS_WRK_PASSPHRASE env var and key material in /root/clawcomms/keys/

Run: pytest tests/test_enrollment_live.py -v
"""

import os
import json
import asyncio
import subprocess
import pytest
import httpx

ENROLLMENT_URL  = "https://dev.clawcomms.com"
KEYS_DIR        = "/root/clawcomms"
WRK_FINGERPRINT = "df100808ff0353e720a266036794c5bc19cacf57a9b994c2992c0a3b39b0d5b9"
TEST_BOT_ID     = "test-bot-sdk-001"


def issue_test_grant(bot_pubkey_hex: str) -> dict:
    """Use bootstrap CLI to issue a short-lived test grant."""
    passphrase = os.environ.get("RELAY_WRK_PASSPHRASE", "")
    result = subprocess.run(
        [
            "docker", "compose", "--profile", "tools", "run", "--rm",
            "-e", f"RELAY_WRK_PASSPHRASE={passphrase}",
            "bootstrap-cli", "issue-grant",
            "--bot-id", TEST_BOT_ID,
            "--bot-public-key", bot_pubkey_hex,
            "--role", "assistant",
            "--ttl", "300",
        ],
        cwd=KEYS_DIR,
        capture_output=True, text=True
    )
    # Output is JSON grant followed by info lines — extract the JSON block
    lines = result.stdout.strip().split("\n")
    json_lines = []
    in_json = False
    for line in lines:
        if line.startswith("{"):
            in_json = True
        if in_json:
            json_lines.append(line)
        if in_json and line == "}":
            break
    return json.loads("\n".join(json_lines))


@pytest.mark.asyncio
async def test_status_endpoint():
    """Enrollment service /status should return ok."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{ENROLLMENT_URL}/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["iek_valid"] is True
    assert data["redis_connected"] is True
    assert data["workspace_id"] == "clawcomms-dev-20260318"
    print(f"\n✓ Status: {data}")


@pytest.mark.asyncio
async def test_full_enrollment_flow():
    """Issue a grant via bootstrap CLI, enroll, check credential."""
    from clawcomms import ClawCommsClient

    client = ClawCommsClient(
        enrollment_url=ENROLLMENT_URL,
        nats_url="nats://localhost:4222",
        bot_id=TEST_BOT_ID,
        role="assistant",
        wrk_fingerprint=WRK_FINGERPRINT,
        use_default_policy_rules=False,
    )

    # Issue grant with bot's fresh public key
    grant = issue_test_grant(client.public_key_hex)
    assert grant["bot_id"] == TEST_BOT_ID
    print(f"\n✓ Grant issued: {grant['grant_id'][:8]}...")

    # Enroll
    await client._enrollment.enroll(grant)
    cred = client.credential
    assert cred is not None
    assert cred["bot_id"] == TEST_BOT_ID
    assert cred["role"] == "assistant"
    assert cred["workspace_id"] == "clawcomms-dev-20260318"
    assert "iek_signature" in cred
    print(f"✓ Enrolled: session={cred['session_id'][:8]}... cred={cred['credential_id'][:8]}...")

    # Verify credential is valid
    assert client._enrollment.is_valid()
    print(f"✓ Credential valid, expires: {cred['expires_at']}")

    # Test double-use grant rejection
    async with httpx.AsyncClient() as http:
        resp = await http.post(
            f"{ENROLLMENT_URL}/enroll",
            json={"grant": grant}
        )
    assert resp.status_code == 409
    print("✓ Double-use grant correctly rejected (409)")

    await client.stop()
    print("✓ Shutdown clean")


@pytest.mark.asyncio
async def test_expired_grant_rejected():
    """Grant with past expiry should be rejected."""
    fake_grant = {
        "schema_version": "1.0",
        "grant_type": "enrollment_grant",
        "grant_id": "00000000-0000-0000-0000-000000000000",
        "workspace_id": "clawcomms-dev-20260318",
        "wrk_fingerprint": WRK_FINGERPRINT,
        "bot_id": "fake-bot",
        "bot_public_key_hex": "a" * 64,
        "role": "assistant",
        "classification": "INTERNAL",
        "issued_at": "2020-01-01T00:00:00+00:00",
        "expires_at": "2020-01-01T00:10:00+00:00",
        "ttl_seconds": 600,
        "single_use": True,
        "wrk_signature": "a" * 128,
    }
    async with httpx.AsyncClient() as http:
        resp = await http.post(f"{ENROLLMENT_URL}/enroll", json={"grant": fake_grant})
    assert resp.status_code == 400
    print("\n✓ Expired grant correctly rejected (400)")
