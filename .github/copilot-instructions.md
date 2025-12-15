# Copilot instructions for secure_IOMT_attestation

This repository implements a small TPM-based attestation demo for IoMT devices.
These instructions give an AI coding agent the immediately actionable knowledge needed
to modify, extend, and debug the project.

Key concepts (big picture)
- Host (verifier) tools live on the operator workstation: `tpm_host_server.py`.
- Device (Raspberry Pi) exposes a simple HTTP API (Flask) to return a PCR quote and to
  download firmware images: `tpm_slave.py` (runs on Pi). The older client/server demos are
  in the `old/` folder (`old/tpm_client.py`, `old/tpm_server.py`) and are useful reference
  implementations for payload signing and ingestion.
- Trust model: device computes a TPM quote (PCRs + signature using an Attestation Key).
  The host fetches the quote, verifies the signature with an AK public key (`ak_pub.pem`),
  and compares PCR values to `golden_pcrs.json`. Only whitelist PCR indices are compared.

Files to inspect for examples and patterns
- `tpm_host_server.py` — host-side CLI utilities: fetch quote, verify signature (RSA PKCS1v15 + SHA256),
  compare PCRs against `golden_pcrs.json`, trigger OTA. Note: the signature verification call
  is present but commented out in the sample flow — if you change verification behavior, update this file.
- `tpm_slave.py` — Flask app on the Raspberry Pi. Uses `tpm2_quote`, `tpm2_pcrread` (via subprocess)
  and returns JSON {pcr_values, quote, signature}. Also implements `/api/update_firmware`.
- `old/tpm_client.py` — example of canonical JSON signing used by ingestion service; uses
  json.dumps(..., sort_keys=True, separators=(",",":")) before signing with `tpm2_sign`.
- `old/tpm_server.py` — ingestion endpoint showing how signature verification is performed
  (loads a PEM public key and verifies using PKCS1v15 + SHA256). Use this as the canonical
  verifier behavior for payloads.
- `ak_pub.pem`, `golden_pcrs.json` — repository artifacts used by the host verifier.

Project-specific conventions & patterns
- PCR whitelist: the demo only compares PCR indices 0 and 7. See `PCR_WHITELIST` in `tpm_host_server.py` and
  `-l sha256:0,7` usage in `tpm_slave.py`. Any change to which PCRs are compared requires updating both sides.
- Signature formats: TPM quote and signatures are base64-encoded in transport JSON. For payload signatures the
  repo uses base64-encoded binary signatures plus an exported PEM public key for verification.
- Canonicalization: payloads are canonicalized using json.dumps(..., sort_keys=True, separators=(",",":")) on both
  client and server sides. Preserve this exact method when adding or changing signed payloads.
- TPM tooling: the Pi code expects `tpm2-tools` binaries (`tpm2_quote`, `tpm2_pcrread`, `tpm2_sign`, `tpm2_readpublic`).
  The code uses shutil.which to find binaries; tests and CI should either mock subprocess calls or run on a system with these tools.

Developer workflows and commands (concrete)
- Install Python deps locally (developer machine / host):
  - pip install -r requirements.txt
- Run host menu (interactive):
  - python tpm_host_server.py
- Run Pi Flask service (device):
  - python tpm_slave.py
  - The service binds to port 5000 by default. Endpoints:
    - GET /api/get_pcr_quote  => returns {pcr_values, quote, signature}
    - GET /api/update_firmware => downloads image (see code) and (optionally) reboots
- Quick network check for integration debugging:
  - curl http://<PI_IP>:5000/api/get_pcr_quote

Integration points & external dependencies
- tpm2-tools (on Raspberry Pi / device) — required for TPM operations.
- requests, flask, cryptography (Python libs) — see `requirements.txt`.
- Network: host and Pi must be reachable (default port 5000). The OTA image URL is hard-coded in `tpm_slave.py`.

Debugging tips and gotchas
- If `tpm2_*` commands fail on the Pi, check PATH and that tpm2-tools are installed; the code will use the
  path returned by shutil.which or the plain command name.
- Signature verification between quote and AK pub: the host expects an exported AK public key in `ak_pub.pem`.
  Ensure the AK was exported in PEM format compatible with cryptography.load_pem_public_key.
- Golden PCRs: `golden_pcrs.json` must contain entries for the PCR indices in `PCR_WHITELIST`. If missing, the host
  prints a warning and skips those PCRs.
- Permission/Sudo: many tpm2-tools operations require sudo/root on Linux (see `old/tpm_client.py` logic and comments).

When editing code, prefer small, testable changes
- For changes touching TPM subprocess calls, add a small shim or wrapper to allow unit-testing without a real TPM.
- Preserve canonical JSON signing and verification behavior. If you modify canonicalization, update both client and server.

If anything is ambiguous or you need run credentials or a Pi image, ask for the target device details and preferred test harness.

— End of instructions —