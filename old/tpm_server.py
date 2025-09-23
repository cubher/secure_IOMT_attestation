#!/usr/bin/env python3
"""
tpm_server.py
- Accepts POST /ingest with JSON: payload, signature_b64
- Verifies signature using preloaded TPM public key
"""

from flask import Flask, request, jsonify
import base64
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

# Load TPM public key from PEM file once
try:
    with open("key.pem", "rb") as f:  # make sure key.pem is in the same folder
        pubkey_data = f.read()
        tpm_pubkey = serialization.load_pem_public_key(pubkey_data)
except Exception as e:
    print(f"Failed to load TPM public key: {e}")
    raise SystemExit(1)

@app.route("/ingest", methods=["POST"])
def ingest():
    data = request.get_json()
    if not data:
        return jsonify({"ok": False, "error": "no json"}), 400

    payload = data.get("payload")
    signature_b64 = data.get("signature_b64")

    if not payload or not signature_b64:
        return jsonify({"ok": False, "error": "missing fields"}), 400

    # Canonicalize payload (client must use same method)
    message = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    sig = base64.b64decode(signature_b64)

    # Verify signature
    try:
        tpm_pubkey.verify(
            sig,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except InvalidSignature:
        return jsonify({"ok": False, "error": "signature invalid"}), 403
    except Exception as e:
        return jsonify({"ok": False, "error": f"verify error: {e}"}), 500

    # Valid signature — process payload
    print("Accepted payload:", payload)
    return jsonify({"ok": True, "msg": "payload accepted"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
