#!/bin/bash
set -e
echo "Starting ClawComms round-trip test..."
docker run --rm \
  --network clawcomms_relay_net \
  --add-host=host.docker.internal:host-gateway \
  -v /root/clawcomms:/clawcomms:ro \
  -e CLAWCOMMS_DIR="/clawcomms" \
  -e RELAY_WRK_PASSPHRASE="D3cPRMKHkfuQyXEinRtcCneDLmDzC8zukEQbBtUP" \
  -e CLAWCOMMS_NATS_URL="nats://clawcomms-nats:4222" \
  -e CLAWCOMMS_ENROLLMENT_URL="http://host.docker.internal:8001" \
  -e CLAWCOMMS_CA_CERT="/clawcomms/nats/certs/ca.crt" \
  -e CLAWCOMMS_WRK_FINGERPRINT="df100808ff0353e720a266036794c5bc19cacf57a9b994c2992c0a3b39b0d5b9" \
  python:3.12-slim bash -c "
    pip install -q httpx nats-py cryptography &&
    python3 /clawcomms/sdk/tests/test_roundtrip.py
  "
