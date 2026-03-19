#!/usr/bin/env python3
"""
relay-bootstrap — ClawComms Bootstrap CLI
Handles all WRK private key operations. No network access.

Usage:
  docker compose run --rm bootstrap-cli <command> [options]

Commands:
  init              Generate WRK keypair + partial Genesis Record
  issue-iek         Generate IEK keypair + WRK-signed IEK certificate
  finalize-genesis  Add IEK fields to Genesis Record, produce final WRK-signed record
  issue-grant       Issue a WRK-signed Enrollment Grant for a bot
  sign-policy       Sign a policy profile with WRK
  revoke-iek        Produce WRK-signed IEK revocation manifest
  revoke-bot        Produce WRK-signed bot global revocation manifest
  revoke-grant      Mark a specific grant as revoked
  sign-rollback     Produce WRK-signed policy rollback manifest
  verify            Verify WRK signature on any artifact (read-only)
  status            Show current key material status
"""

import os
import sys
import json
import time
import uuid
import hashlib
import secrets
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

import click
import nkeys as nk
from nats_jwt import (
    create_operator_jwt, create_account_jwt, format_credentials
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

import argon2.low_level as argon2_ll

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

KEYS_DIR = Path("/keys")
WRK_DIR  = KEYS_DIR / "wrk"
IEK_DIR  = KEYS_DIR / "iek"
GEN_DIR  = KEYS_DIR / "genesis"
AUDIT_LOG = KEYS_DIR / "audit.jsonl"

ARGON2_TIME_COST    = 3
ARGON2_MEMORY_COST  = 65536   # 64 MB
ARGON2_PARALLELISM  = 4
ARGON2_HASH_LEN     = 32
ARGON2_SALT_LEN     = 32

GRANT_TTL_MIN = 300    # 5 minutes
GRANT_TTL_MAX = 900    # 15 minutes


# ─────────────────────────────────────────────────────────────────────────────
# Crypto helpers
# ─────────────────────────────────────────────────────────────────────────────

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Argon2id KDF — derives 32-byte AES key from passphrase."""
    return argon2_ll.hash_secret_raw(
        secret=passphrase.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=argon2_ll.Type.ID,
    )


def _encrypt_private_key(private_key: Ed25519PrivateKey, passphrase: str) -> dict:
    """Encrypt Ed25519 private key with AES-256-GCM + Argon2id."""
    raw = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption()
    )
    salt  = secrets.token_bytes(ARGON2_SALT_LEN)
    nonce = secrets.token_bytes(12)
    key   = _derive_key(passphrase, salt)
    ct    = AESGCM(key).encrypt(nonce, raw, None)
    return {
        "kdf": "argon2id",
        "kdf_params": {
            "time_cost": ARGON2_TIME_COST,
            "memory_cost": ARGON2_MEMORY_COST,
            "parallelism": ARGON2_PARALLELISM,
        },
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
    }


def _decrypt_private_key(blob: dict, passphrase: str) -> Ed25519PrivateKey:
    """Decrypt and return Ed25519 private key."""
    salt  = bytes.fromhex(blob["salt"])
    nonce = bytes.fromhex(blob["nonce"])
    ct    = bytes.fromhex(blob["ciphertext"])
    key   = _derive_key(passphrase, salt)
    try:
        raw = AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        raise click.ClickException("Decryption failed — wrong passphrase or corrupted key file.")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _public_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _fingerprint(pub: Ed25519PublicKey) -> str:
    raw = _public_bytes(pub)
    return hashlib.sha256(raw).hexdigest()


def _sign(private_key: Ed25519PrivateKey, payload: dict) -> str:
    """Sign canonical JSON payload, return hex signature."""
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    sig = private_key.sign(canonical)
    return sig.hex()


def _verify_sig(pub: Ed25519PublicKey, payload: dict, sig_hex: str) -> bool:
    """Verify signature over canonical JSON payload."""
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    try:
        pub.verify(bytes.fromhex(sig_hex), canonical)
        return True
    except InvalidSignature:
        return False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _audit(event: str, details: dict):
    entry = {"ts": _now_iso(), "event": event, **details}
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _get_passphrase(confirm: bool = False) -> str:
    pp = os.environ.get("RELAY_WRK_PASSPHRASE")
    if pp:
        return pp
    pp = click.prompt("WRK passphrase", hide_input=True)
    if confirm:
        pp2 = click.prompt("Confirm passphrase", hide_input=True)
        if pp != pp2:
            raise click.ClickException("Passphrases do not match.")
    return pp


def _load_wrk(passphrase: str) -> Ed25519PrivateKey:
    enc_path = WRK_DIR / "wrk_private.enc.json"
    if not enc_path.exists():
        raise click.ClickException(f"WRK private key not found at {enc_path}. Run 'init' first.")
    blob = json.loads(enc_path.read_text())
    return _decrypt_private_key(blob, passphrase)


def _load_wrk_pub() -> Ed25519PublicKey:
    pub_path = WRK_DIR / "wrk_public.json"
    if not pub_path.exists():
        raise click.ClickException("WRK public key not found. Run 'init' first.")
    data = json.loads(pub_path.read_text())
    raw = bytes.fromhex(data["public_key_hex"])
    return Ed25519PublicKey.from_public_bytes(raw)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """relay-bootstrap — ClawComms offline key management CLI."""
    for d in (WRK_DIR, IEK_DIR, GEN_DIR):
        d.mkdir(parents=True, exist_ok=True)


# ── init ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--workspace-id", default=None, help="Workspace ID (UUID generated if omitted)")
@click.option("--classification-ceiling", default="INTERNAL",
              type=click.Choice(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"]),
              help="Maximum classification level for this workspace")
@click.option("--allowed-roles", default="assistant,orchestrator,monitor",
              help="Comma-separated list of allowed bot roles")
def init(workspace_id, classification_ceiling, allowed_roles):
    """Generate WRK keypair and partial Genesis Record."""
    enc_path = WRK_DIR / "wrk_private.enc.json"
    if enc_path.exists():
        if not click.confirm("WRK keypair already exists. Overwrite?", default=False):
            raise click.Abort()

    click.echo("Generating WRK Ed25519 keypair...")
    passphrase = _get_passphrase(confirm=True)

    private_key = Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()
    fp = _fingerprint(public_key)

    # Encrypt and save private key
    enc_blob = _encrypt_private_key(private_key, passphrase)
    enc_path.write_text(json.dumps(enc_blob, indent=2))
    click.echo(f"  WRK private key (encrypted) → {enc_path}")

    # Save public key
    pub_data = {
        "key_type": "wrk_public",
        "public_key_hex": _public_bytes(public_key).hex(),
        "fingerprint": fp,
        "created_at": _now_iso(),
    }
    pub_path = WRK_DIR / "wrk_public.json"
    pub_path.write_text(json.dumps(pub_data, indent=2))
    click.echo(f"  WRK public key              → {pub_path}")

    # Partial Genesis Record (IEK fields added by finalize-genesis)
    ws_id = workspace_id or str(uuid.uuid4())
    roles = [r.strip() for r in allowed_roles.split(",")]
    partial_genesis = {
        "schema_version": "1.0",
        "workspace_id": ws_id,
        "wrk_public_fingerprint": fp,
        "classification_ceiling": classification_ceiling,
        "allowed_roles": roles,
        "iek_fingerprint": None,       # filled by finalize-genesis
        "iek_cert_path": None,
        "next_root_key_hash": None,    # always null in v1
        "created_at": _now_iso(),
        "status": "partial",
    }
    genesis_path = GEN_DIR / "genesis_record.partial.json"
    genesis_path.write_text(json.dumps(partial_genesis, indent=2))
    click.echo(f"  Partial Genesis Record      → {genesis_path}")

    _audit("wrk_init", {"workspace_id": ws_id, "wrk_fingerprint": fp})

    click.echo("")
    click.echo(f"WRK fingerprint: {fp}")
    click.echo(f"Workspace ID:    {ws_id}")
    click.echo("")
    click.echo("Next: run 'issue-iek' to generate the Intermediate Enrollment Key.")


# ── issue-iek ─────────────────────────────────────────────────────────────────

@cli.command("issue-iek")
@click.option("--scope", default="workspace",
              type=click.Choice(["workspace", "global"]),
              help="IEK scope")
@click.option("--role-ceiling", default="assistant",
              help="Maximum role this IEK can sign credentials for")
def issue_iek(scope, role_ceiling):
    """Generate IEK keypair and produce WRK-signed IEK certificate."""
    iek_enc_path = IEK_DIR / "iek_private.enc.json"
    if iek_enc_path.exists():
        if not click.confirm("IEK keypair already exists. Overwrite?", default=False):
            raise click.Abort()

    # Load partial genesis to get workspace_id
    partial_path = GEN_DIR / "genesis_record.partial.json"
    if not partial_path.exists():
        raise click.ClickException("Partial Genesis Record not found. Run 'init' first.")
    partial = json.loads(partial_path.read_text())

    passphrase = _get_passphrase()
    wrk_priv   = _load_wrk(passphrase)
    wrk_pub    = wrk_priv.public_key()

    click.echo("Generating IEK Ed25519 keypair...")
    iek_priv = Ed25519PrivateKey.generate()
    iek_pub  = iek_priv.public_key()
    iek_fp   = _fingerprint(iek_pub)

    # Encrypt IEK private key with same passphrase (operator can use different one)
    iek_passphrase = os.environ.get("RELAY_IEK_PASSPHRASE", passphrase)
    iek_enc = _encrypt_private_key(iek_priv, iek_passphrase)
    iek_enc_path.write_text(json.dumps(iek_enc, indent=2))
    click.echo(f"  IEK private key (encrypted) → {iek_enc_path}")

    # Save IEK public key
    iek_pub_data = {
        "key_type": "iek_public",
        "public_key_hex": _public_bytes(iek_pub).hex(),
        "fingerprint": iek_fp,
        "created_at": _now_iso(),
    }
    (IEK_DIR / "iek_public.json").write_text(json.dumps(iek_pub_data, indent=2))

    # WRK-signed IEK certificate
    cert_payload = {
        "schema_version": "1.0",
        "cert_type": "iek_cert",
        "cert_id": str(uuid.uuid4()),
        "workspace_id": partial["workspace_id"],
        "wrk_fingerprint": partial["wrk_public_fingerprint"],
        "iek_fingerprint": iek_fp,
        "iek_public_key_hex": _public_bytes(iek_pub).hex(),
        "scope": scope,
        "role_ceiling": role_ceiling,
        "issued_at": _now_iso(),
        "revoked": False,
    }
    cert_payload["wrk_signature"] = _sign(wrk_priv, cert_payload)

    cert_path = IEK_DIR / "iek_cert.json"
    cert_path.write_text(json.dumps(cert_payload, indent=2))
    click.echo(f"  IEK certificate (WRK-signed)→ {cert_path}")

    _audit("iek_issued", {
        "workspace_id": partial["workspace_id"],
        "iek_fingerprint": iek_fp,
        "cert_id": cert_payload["cert_id"],
    })

    click.echo("")
    click.echo(f"IEK fingerprint: {iek_fp}")
    click.echo("")
    click.echo("Next: run 'finalize-genesis' to produce the final signed Genesis Record.")


# ── finalize-genesis ──────────────────────────────────────────────────────────

@cli.command("finalize-genesis")
def finalize_genesis():
    """Finalize and WRK-sign the Genesis Record."""
    partial_path = GEN_DIR / "genesis_record.partial.json"
    if not partial_path.exists():
        raise click.ClickException("Partial Genesis Record not found. Run 'init' first.")

    cert_path = IEK_DIR / "iek_cert.json"
    if not cert_path.exists():
        raise click.ClickException("IEK certificate not found. Run 'issue-iek' first.")

    partial = json.loads(partial_path.read_text())
    cert    = json.loads(cert_path.read_text())

    passphrase = _get_passphrase()
    wrk_priv   = _load_wrk(passphrase)

    genesis = {
        "schema_version": "1.0",
        "record_type": "genesis",
        "workspace_id": partial["workspace_id"],
        "wrk_public_fingerprint": partial["wrk_public_fingerprint"],
        "classification_ceiling": partial["classification_ceiling"],
        "allowed_roles": partial["allowed_roles"],
        "iek_fingerprint": cert["iek_fingerprint"],
        "iek_cert_id": cert["cert_id"],
        "next_root_key_hash": None,
        "created_at": partial["created_at"],
        "finalized_at": _now_iso(),
        "status": "active",
    }
    genesis["wrk_signature"] = _sign(wrk_priv, genesis)

    final_path = GEN_DIR / "genesis_record.json"
    final_path.write_text(json.dumps(genesis, indent=2))

    # Archive partial
    partial_path.rename(GEN_DIR / "genesis_record.partial.json.bak")

    _audit("genesis_finalized", {
        "workspace_id": genesis["workspace_id"],
        "iek_fingerprint": genesis["iek_fingerprint"],
    })

    click.echo(f"Genesis Record finalized → {final_path}")
    click.echo("")
    click.echo("Bootstrap ceremony complete. Distribute:")
    click.echo(f"  - {final_path}  (to Enrollment Service + bots that need to pin WRK)")
    click.echo(f"  - {IEK_DIR / 'iek_cert.json'}     (to Enrollment Service)")
    click.echo(f"  - {IEK_DIR / 'iek_private.enc.json'}  (to Enrollment Service only)")
    click.echo("")
    click.echo("Keep WRK private key OFFLINE. Do not copy it to any running service.")


# ── issue-grant ───────────────────────────────────────────────────────────────

@cli.command("issue-grant")
@click.option("--bot-id", required=True, help="Unique bot identifier")
@click.option("--bot-public-key", required=True, help="Bot's Ed25519 public key (hex)")
@click.option("--role", required=True, help="Bot role (must be in allowed_roles)")
@click.option("--classification", default="INTERNAL",
              type=click.Choice(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"]))
@click.option("--ttl", default=600, type=int,
              help=f"Grant TTL in seconds ({GRANT_TTL_MIN}–{GRANT_TTL_MAX})")
def issue_grant(bot_id, bot_public_key, role, classification, ttl):
    """Issue a WRK-signed Enrollment Grant for a bot."""
    if not (GRANT_TTL_MIN <= ttl <= GRANT_TTL_MAX):
        raise click.ClickException(
            f"TTL must be between {GRANT_TTL_MIN} and {GRANT_TTL_MAX} seconds."
        )

    genesis_path = GEN_DIR / "genesis_record.json"
    if not genesis_path.exists():
        raise click.ClickException("Genesis Record not found. Run 'finalize-genesis' first.")
    genesis = json.loads(genesis_path.read_text())

    if role not in genesis["allowed_roles"]:
        raise click.ClickException(
            f"Role '{role}' not in allowed_roles: {genesis['allowed_roles']}"
        )

    passphrase = _get_passphrase()
    wrk_priv   = _load_wrk(passphrase)

    now     = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=ttl)

    grant = {
        "schema_version": "1.0",
        "grant_type": "enrollment_grant",
        "grant_id": str(uuid.uuid4()),
        "workspace_id": genesis["workspace_id"],
        "wrk_fingerprint": genesis["wrk_public_fingerprint"],
        "bot_id": bot_id,
        "bot_public_key_hex": bot_public_key,
        "role": role,
        "classification": classification,
        "issued_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "ttl_seconds": ttl,
        "single_use": True,
    }
    grant["wrk_signature"] = _sign(wrk_priv, grant)

    grants_dir = KEYS_DIR / "grants"
    grants_dir.mkdir(exist_ok=True)
    grant_path = grants_dir / f"grant_{grant['grant_id'][:8]}.json"
    grant_path.write_text(json.dumps(grant, indent=2))

    _audit("grant_issued", {
        "grant_id": grant["grant_id"],
        "bot_id": bot_id,
        "role": role,
        "expires_at": grant["expires_at"],
    })

    click.echo(json.dumps(grant, indent=2))
    click.echo("")
    click.echo(f"Grant saved → {grant_path}")
    click.echo(f"Expires: {expires.isoformat()} (TTL: {ttl}s)")
    click.echo("Deliver this grant to the bot out-of-band. It is single-use.")


# ── verify ────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("artifact_path", type=click.Path(exists=True))
def verify(artifact_path):
    """Verify WRK signature on any artifact JSON file."""
    artifact = json.loads(Path(artifact_path).read_text())
    sig_hex  = artifact.pop("wrk_signature", None)
    if not sig_hex:
        raise click.ClickException("No 'wrk_signature' field found in artifact.")

    wrk_pub = _load_wrk_pub()
    ok = _verify_sig(wrk_pub, artifact, sig_hex)

    if ok:
        click.echo(f"✓ Signature VALID  (WRK fingerprint: {_fingerprint(wrk_pub)})")
    else:
        click.echo("✗ Signature INVALID", err=True)
        sys.exit(1)


# ── revoke-bot ────────────────────────────────────────────────────────────────

@cli.command("revoke-bot")
@click.option("--bot-id", required=True, help="Bot ID to revoke globally")
@click.option("--reason", default="", help="Revocation reason")
def revoke_bot(bot_id, reason):
    """Produce WRK-signed global bot revocation manifest."""
    genesis_path = GEN_DIR / "genesis_record.json"
    if not genesis_path.exists():
        raise click.ClickException("Genesis Record not found.")
    genesis = json.loads(genesis_path.read_text())

    passphrase = _get_passphrase()
    wrk_priv   = _load_wrk(passphrase)

    manifest = {
        "schema_version": "1.0",
        "manifest_type": "bot_revocation",
        "revocation_id": str(uuid.uuid4()),
        "workspace_id": genesis["workspace_id"],
        "wrk_fingerprint": genesis["wrk_public_fingerprint"],
        "scope": "global",
        "bot_id": bot_id,
        "reason": reason,
        "issued_at": _now_iso(),
    }
    manifest["wrk_signature"] = _sign(wrk_priv, manifest)

    rev_dir = KEYS_DIR / "revocations"
    rev_dir.mkdir(exist_ok=True)
    rev_path = rev_dir / f"revoke_bot_{bot_id}_{manifest['revocation_id'][:8]}.json"
    rev_path.write_text(json.dumps(manifest, indent=2))

    _audit("bot_revoked", {"bot_id": bot_id, "revocation_id": manifest["revocation_id"]})

    click.echo(json.dumps(manifest, indent=2))
    click.echo(f"\nRevocation manifest saved → {rev_path}")
    click.echo("Deliver to Enrollment Service /revoke endpoint.")


# ── status ────────────────────────────────────────────────────────────────────

@cli.command()
def status():
    """Show current key material status."""
    wrk_pub_path  = WRK_DIR / "wrk_public.json"
    wrk_enc_path  = WRK_DIR / "wrk_private.enc.json"
    iek_cert_path = IEK_DIR / "iek_cert.json"
    iek_enc_path  = IEK_DIR / "iek_private.enc.json"
    genesis_path  = GEN_DIR / "genesis_record.json"
    partial_path  = GEN_DIR / "genesis_record.partial.json"

    def _chk(p): return "✓" if p.exists() else "✗"

    click.echo("ClawComms Bootstrap Key Status")
    click.echo("─" * 40)
    click.echo(f"  {_chk(wrk_pub_path)}  WRK public key       {wrk_pub_path}")
    click.echo(f"  {_chk(wrk_enc_path)}  WRK private key (enc){wrk_enc_path}")
    click.echo(f"  {_chk(iek_cert_path)}  IEK certificate      {iek_cert_path}")
    click.echo(f"  {_chk(iek_enc_path)}  IEK private key (enc){iek_enc_path}")
    click.echo(f"  {_chk(genesis_path)}  Genesis Record       {genesis_path}")

    if wrk_pub_path.exists():
        pub = json.loads(wrk_pub_path.read_text())
        click.echo(f"\n  WRK fingerprint: {pub['fingerprint']}")
        click.echo(f"  Created:         {pub['created_at']}")

    if genesis_path.exists():
        g = json.loads(genesis_path.read_text())
        click.echo(f"\n  Workspace ID:    {g['workspace_id']}")
        click.echo(f"  Classification:  {g['classification_ceiling']}")
        click.echo(f"  Allowed roles:   {', '.join(g['allowed_roles'])}")
        click.echo(f"  IEK fingerprint: {g['iek_fingerprint']}")
        click.echo(f"  Status:          {g['status']}")
    elif partial_path.exists():
        click.echo("\n  Genesis Record: partial (run finalize-genesis)")

    grants_dir = KEYS_DIR / "grants"
    if grants_dir.exists():
        grants = list(grants_dir.glob("grant_*.json"))
        click.echo(f"\n  Grants issued:   {len(grants)}")

    click.echo("")


# ── init-nats ─────────────────────────────────────────────────────────────────

@cli.command("init-nats")
@click.option("--workspace-name", default="relay-workspace", help="NATS account name")
def init_nats(workspace_name):
    """Generate NATS Operator + System Account + Relay Account NKeys/JWTs, update nats.conf."""
    nats_dir = KEYS_DIR / "nats"
    nats_dir.mkdir(exist_ok=True)

    passphrase = _get_passphrase(confirm=False)

    # ── Generate Operator NKey ────────────────────────────────────────────────
    click.echo("Generating NATS Operator NKey...")
    op_seed = nk.encode_seed(os.urandom(32), nk.PREFIX_BYTE_OPERATOR)
    op_kp   = nk.from_seed(op_seed)
    op_pub  = op_kp.public_key.decode()

    op_enc = _encrypt_private_key_raw(op_seed, passphrase)
    (nats_dir / "operator_seed.enc.json").write_text(json.dumps(op_enc, indent=2))
    (nats_dir / "operator_public.txt").write_text(op_pub)
    click.echo(f"  Operator NKey: {op_pub[:12]}...")

    # ── Generate System Account NKey ──────────────────────────────────────────
    click.echo("Generating NATS System Account NKey...")
    sys_seed = nk.encode_seed(os.urandom(32), nk.PREFIX_BYTE_ACCOUNT)
    sys_kp   = nk.from_seed(sys_seed)
    sys_pub  = sys_kp.public_key.decode()

    sys_enc = _encrypt_private_key_raw(sys_seed, passphrase)
    (nats_dir / "system_account_seed.enc.json").write_text(json.dumps(sys_enc, indent=2))
    (nats_dir / "system_account_public.txt").write_text(sys_pub)
    click.echo(f"  System Account NKey: {sys_pub[:12]}...")

    # ── Generate Relay Account NKey ───────────────────────────────────────────
    click.echo("Generating NATS Relay Account NKey...")
    ac_seed = nk.encode_seed(os.urandom(32), nk.PREFIX_BYTE_ACCOUNT)
    ac_kp   = nk.from_seed(ac_seed)
    ac_pub  = ac_kp.public_key.decode()

    ac_enc = _encrypt_private_key_raw(ac_seed, passphrase)
    (nats_dir / "account_seed.enc.json").write_text(json.dumps(ac_enc, indent=2))
    (nats_dir / "account_public.txt").write_text(ac_pub)
    click.echo(f"  Relay Account NKey:  {ac_pub[:12]}...")

    # ── Create JWTs ───────────────────────────────────────────────────────────
    # Operator JWT embeds the system account public key
    op_jwt  = create_operator_jwt(op_kp, system_account_pub=sys_pub)
    # System account JWT (minimal — no extra limits)
    sys_jwt = create_account_jwt(op_kp, sys_kp, name="SYS")
    # Relay account JWT
    ac_jwt  = create_account_jwt(op_kp, ac_kp, name=workspace_name)

    (nats_dir / "operator.jwt").write_text(op_jwt)
    (nats_dir / "system_account.jwt").write_text(sys_jwt)
    (nats_dir / "account.jwt").write_text(ac_jwt)
    click.echo(f"  Operator JWT         → {nats_dir / 'operator.jwt'}")
    click.echo(f"  System Account JWT   → {nats_dir / 'system_account.jwt'}")
    click.echo(f"  Relay Account JWT    → {nats_dir / 'account.jwt'}")

    # ── Write JWT preload directory ───────────────────────────────────────────
    # NATS CACHE resolver reads JWTs from this dir (filename = account pub key)
    jwt_dir = nats_dir / "jwt-accounts"
    jwt_dir.mkdir(exist_ok=True)
    (jwt_dir / f"{sys_pub}.jwt").write_text(sys_jwt)
    (jwt_dir / f"{ac_pub}.jwt").write_text(ac_jwt)
    click.echo(f"  JWT accounts dir     → {jwt_dir}")

    # ── Write nats.conf fragment ──────────────────────────────────────────────
    nats_conf = f"""# ClawComms NATS Configuration — JWT Auth
# Generated by relay-bootstrap init-nats

port: 4222
http_port: 8222

operator: "{op_jwt}"

# CACHE resolver: reads account JWTs from disk, no push/JetStream required
resolver {{
  type: CACHE
  dir: "/etc/nats/jwt-accounts"
  ttl: "1h"
}}

system_account: "{sys_pub}"

max_payload: 1MB
max_connections: 1000
ping_interval: "30s"
ping_max: 3

debug: false
trace: false
"""
    conf_path = Path("/keys/nats/nats.conf")
    conf_path.write_text(nats_conf)
    click.echo(f"  nats.conf            → {conf_path}")

    _audit("nats_init", {
        "operator_pub": op_pub,
        "system_account_pub": sys_pub,
        "account_pub": ac_pub,
        "workspace_name": workspace_name,
    })

    click.echo("")
    click.echo(f"Operator:       {op_pub}")
    click.echo(f"System Account: {sys_pub}")
    click.echo(f"Relay Account:  {ac_pub}")
    click.echo("")
    click.echo("Next steps:")
    click.echo("  1. Copy keys/nats/nats.conf → nats/nats.conf")
    click.echo("  2. Copy keys/nats/jwt-accounts/ → nats/jwt-accounts/")
    click.echo("  3. Mount nats/jwt-accounts/ into NATS container at /etc/nats/jwt-accounts")
    click.echo("  4. Restart NATS")
    click.echo("  5. Mount keys/nats/account_seed.enc.json into enrollment-service")


def _encrypt_private_key_raw(raw_bytes: bytes, passphrase: str) -> dict:
    """Encrypt arbitrary bytes (NKey seed) with AES-256-GCM + Argon2id."""
    salt  = secrets.token_bytes(ARGON2_SALT_LEN)
    nonce = secrets.token_bytes(12)
    key   = _derive_key(passphrase, salt)
    ct    = AESGCM(key).encrypt(nonce, raw_bytes, None)
    return {
        "kdf": "argon2id",
        "kdf_params": {
            "time_cost": ARGON2_TIME_COST,
            "memory_cost": ARGON2_MEMORY_COST,
            "parallelism": ARGON2_PARALLELISM,
        },
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
    }


if __name__ == "__main__":
    cli()
