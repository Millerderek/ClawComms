"""
NATS JWT v2 implementation.
Creates Operator, Account, and User JWTs signed with NKeys.
"""

import base64
import hashlib
import json
import os
import time
import uuid

import nkeys


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _make_jti() -> str:
    return base64.b32encode(os.urandom(16)).decode().rstrip('=')


_HEADER = _b64url(json.dumps(
    {"typ": "JWT", "alg": "ed25519-nkey"}, separators=(',', ':')
).encode())


def _sign_jwt(kp: nkeys.KeyPair, claims: dict) -> str:
    payload_b64 = _b64url(json.dumps(claims, separators=(',', ':')).encode())
    signing_input = f"{_HEADER}.{payload_b64}".encode()
    sig = kp.sign(signing_input)
    return f"{_HEADER}.{payload_b64}.{_b64url(sig)}"


def create_operator_jwt(
    op_kp: nkeys.KeyPair,
    name: str = "clawcomms-operator",
    system_account_pub: str | None = None,
) -> str:
    pub = op_kp.public_key.decode()
    nats_claims = {
        "type": "operator",
        "version": 2,
    }
    if system_account_pub:
        nats_claims["system_account"] = system_account_pub
    claims = {
        "jti": _make_jti(),
        "iat": int(time.time()),
        "iss": pub,
        "sub": pub,
        "name": name,
        "nats": nats_claims,
    }
    return _sign_jwt(op_kp, claims)


def create_account_jwt(
    op_kp: nkeys.KeyPair,
    ac_kp: nkeys.KeyPair,
    name: str = "relay-workspace",
) -> str:
    claims = {
        "jti": _make_jti(),
        "iat": int(time.time()),
        "iss": op_kp.public_key.decode(),
        "sub": ac_kp.public_key.decode(),
        "name": name,
        "nats": {
            "type": "account",
            "version": 2,
            "limits": {
                "subs": -1,
                "data": -1,
                "payload": -1,
                "imports": -1,
                "exports": -1,
                "wildcards": True,
                "conn": -1,
                "leaf": -1,
            },
        },
    }
    return _sign_jwt(op_kp, claims)


def create_user_jwt(
    ac_kp: nkeys.KeyPair,
    us_kp: nkeys.KeyPair,
    bot_id: str,
    workspace_id: str,
    ttl_seconds: int = 900,
) -> str:
    """Issue a User JWT with per-bot subject permissions."""
    now = int(time.time())
    # Subject ACLs — bot can only pub/sub to its own namespace + workspace broadcast
    bot_subject  = f"relay.{workspace_id}.{bot_id}.>"
    inbox_sub    = "_INBOX.>"
    broadcast    = f"relay.{workspace_id}.broadcast.>"
    claims = {
        "jti": _make_jti(),
        "iat": now,
        "exp": now + ttl_seconds,
        "iss": ac_kp.public_key.decode(),
        "sub": us_kp.public_key.decode(),
        "name": bot_id,
        "nats": {
            "type": "user",
            "version": 2,
            "pub": {
                "allow": [bot_subject],
            },
            "sub": {
                "allow": [bot_subject, broadcast, inbox_sub],
            },
            "bearer_token": False,
            "subs": -1,
            "data": -1,
            "payload": -1,
        },
    }
    return _sign_jwt(ac_kp, claims)


def format_credentials(user_jwt: str, user_seed: bytes) -> str:
    """Format a .creds file (nats-py compatible)."""
    return (
        "-----BEGIN NATS USER JWT-----\n"
        f"{user_jwt}\n"
        "------END NATS USER JWT------\n"
        "\n"
        "-----BEGIN USER NKEY SEED-----\n"
        f"{user_seed.decode()}\n"
        "------END USER NKEY SEED------\n"
    )
