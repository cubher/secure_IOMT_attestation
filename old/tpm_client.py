#!/usr/bin/env python3
"""
tpm_client.py
- Simulates sensor data
- Uses tpm2_sign to sign the payload with TPM-protected key (key.ctx)
- Sends JSON {payload, signature_b64, pubkey_pem} to server endpoint
"""

import subprocess
import base64
import json
import time
import requests
from datetime import datetime
from pathlib import Path

# Server endpoint (change to your cloud address or http://localhost:5000/ingest)
SERVER_URL = "http://10.208.164.159:5000/ingest"

# Paths (adjust if you stored keys elsewhere)
BASE = Path.home() / "tpm_demo"
KEY_CTX = BASE / "key.ctx"
PUBKEY_PEM = BASE / "device_pub.pem"
MSG_FILE = BASE / "payload.json"
SIG_FILE = BASE / "sig.bin"

def ensure_keys():
    """Create primary and signing key if not present. Requires sudo."""
    if KEY_CTX.exists() and PUBKEY_PEM.exists():
        print("TPM key context and public key already exist.")
        return

    print("Creating keys (requires tpm2-tools installed).")
    # create primary if missing
    if not (BASE / "primary.ctx").exists():
        subprocess.run(["sudo", "tpm2_createprimary", "-C", "o", "-g", "sha256",
                        "-G", "rsa", "-c", str(BASE / "primary.ctx")], check=True)
    # create signing key (if not created)
    if not (BASE / "key.pub").exists():
        subprocess.run(["sudo", "tpm2_create", "-C", str(BASE / "primary.ctx"),
                        "-G", "rsa", "-u", str(BASE / "key.pub"), "-r", str(BASE / "key.priv")], check=True)
    # load key
    subprocess.run(["sudo", "tpm2_load", "-C", str(BASE / "primary.ctx"),
                    "-u", str(BASE / "key.pub"), "-r", str(BASE / "key.priv"), "-c", str(KEY_CTX)], check=True)
    # export public key PEM for verifier
    subprocess.run(["sudo", "tpm2_readpublic", "-c", str(KEY_CTX), "-f", "PEM", "-o", str(PUBKEY_PEM)], check=True)
    # fix ownership to allow reading by non-root if desired (optional)
    subprocess.run(["sudo", "chown", f"{subprocess.check_output(['whoami']).decode().strip()}:{subprocess.check_output(['whoami']).decode().strip()}", str(PUBKEY_PEM)], check=False)

def simulate_sensor():
    """Return simulated EHR/heart-rate payload (dictionary)."""
    now = datetime.utcnow().isoformat() + "Z"
    payload = {
        "device_id": "raspi-01",
        "timestamp": now,
        # simulate heart rate etc.
        "heart_rate_bpm": 60 + int(15 * (0.5 - (time.time() % 1))),  # simple varying value
        "spo2": 95 + int(2 * (0.5 - (time.time() % 1))),
        "notes": "simulated payload"
    }
    return payload

def sign_payload(payload: dict):
    """Write payload to file, call tpm2_sign, return signature bytes (binary)."""
    payload_json = json.dumps(payload, sort_keys=True).encode()
    MSG_FILE.write_bytes(payload_json)

    # tpm2_sign requires a digest or message; using -m reads the message and signs a hashed form
    # Use sha256 as the hash algorithm (-g sha256)
    # Output signature to SIG_FILE
    subprocess.run(["sudo", "tpm2_sign", "-c", str(KEY_CTX), "-g", "sha256", "-o", str(SIG_FILE), str(MSG_FILE)],
                   check=True)

    sig = SIG_FILE.read_bytes()
    return sig

def post_to_server(payload: dict, sig: bytes):
    b64sig = base64.b64encode(sig).decode()
    pubkey_pem = PUBKEY_PEM.read_text()
    body = {
        "payload": payload,
        "signature_b64": b64sig,
        "pubkey_pem": pubkey_pem
    }
    # send over HTTPS in production; here example uses HTTP local server
    r = requests.post(SERVER_URL, json=body)
    print("Server response:", r.status_code, r.text)

def main():
    BASE.mkdir(parents=True, exist_ok=True)
    ensure_keys()
    payload = simulate_sensor()
    sig = sign_payload(payload)
    print("Payload:", payload)
    print("Signature (base64):", base64.b64encode(sig).decode())
    post_to_server(payload, sig)

if __name__ == "__main__":
    main()
