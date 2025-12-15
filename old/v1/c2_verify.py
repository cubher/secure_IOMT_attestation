#!/usr/bin/env python3
"""
c2_verify_quote_verbose.py

Fetches quote from Pi (POST nonce), saves files, runs tpm2_verifysignature and checks nonce presence.
Requires: python-requests on C2 and tpm2-tools installed (tpm2_verifysignature, tpm2_print).
"""

import os, base64, requests, subprocess, tempfile, sys

PI_IP = "10.250.149.152"    # change to your Pi IP
PI_PORT = 4000
AK_PUB = "ak_pub.pem"       # local file (exported earlier from Pi)

QUOTE_FILE = "quote.bin"
SIG_FILE = "sig.bin"
NONCE_FILE = "nonce.bin"

def run(cmd):
    print("[C2 CMD]", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    print("[C2 OUT]\n", r.stdout)
    if r.stderr:
        print("[C2 ERR]\n", r.stderr)
    return r

def generate_nonce(nbytes=20):
    return os.urandom(nbytes)

def fetch_quote(nonce_b64):
    url = f"http://{PI_IP}:{PI_PORT}/quote"
    j = {"nonce": nonce_b64}
    print("[C2] POSTing nonce to Pi")
    r = requests.post(url, json=j, timeout=10)
    r.raise_for_status()
    return r.json()

def save_base64_to_file(b64str, filename):
    data = base64.b64decode(b64str)
    with open(filename, "wb") as f:
        f.write(data)
    print(f"[C2] Wrote {filename} ({len(data)} bytes)")

def verify_signature_with_tpm(ak_pub, quote_file, sig_file):
    # tpm2_verifysignature -c <pem|handle> -m quote.bin -s sig.bin
    # Note: newer tpm2-tools accept -c <pub.pem> to verify
    res = run(["tpm2_verifysignature", "-c", ak_pub, "-m", quote_file, "-s", sig_file])
    # check stdout/stderr for success
    if res.returncode == 0:
        print("[C2] tpm2_verifysignature returned 0 (OK).")
        return True
    else:
        print("[C2] tpm2_verifysignature failed.")
        return False

def check_nonce_in_attestation(quote_file, nonce_bytes):
    # Use tpm2_print (or tpm2_attest) to dump TPMS_ATTEST and check extraData
    out = run(["tpm2_print", "-t", "TPMS_ATTEST", "-i", quote_file])
    txt = out.stdout + (out.stderr or "")
    # Look for hex bytes of nonce in output
    hex_nonce = nonce_bytes.hex()
    if hex_nonce in txt.replace(" ", "").lower():
        print("[C2] Nonce found inside attestation (hex match).")
        return True
    else:
        print("[C2] Nonce NOT found in attestation output. (Searching hex)")
        # also try raw search
        with open(quote_file, "rb") as f:
            if nonce_bytes in f.read():
                print("[C2] Nonce found by raw byte search in quote.bin.")
                return True
        return False

def main():
    if not os.path.exists(AK_PUB):
        print(f"[C2] Missing AK public file: {AK_PUB}. Copy it from Pi first.")
        sys.exit(1)

    # 1. generate nonce
    nonce = generate_nonce(20)
    nonce_b64 = base64.b64encode(nonce).decode()
    print("[C2] Generated nonce (base64):", nonce_b64)

    # 2. request quote
    data = fetch_quote(nonce_b64)
    if "error" in data:
        print("[C2] Pi returned error:", data["error"])
        sys.exit(1)

    # 3. save quote & sig
    save_base64_to_file(data["quote"], QUOTE_FILE)
    save_base64_to_file(data["signature"], SIG_FILE)

    # 4. verify signature using tpm2_verifysignature (handles TPM signature structure)
    ok = verify_signature_with_tpm(AK_PUB, QUOTE_FILE, SIG_FILE)
    if not ok:
        print("[C2] Signature verification FAILED. Aborting.")
        sys.exit(2)
    print("[C2] Signature verification OK.")

    # 5. check nonce presence inside quote (attestation.extraData)
    if not check_nonce_in_attestation(QUOTE_FILE, nonce):
        print("[C2] Nonce check FAILED. Possible replay or mismatch.")
        sys.exit(3)
    print("[C2] Nonce check OK.")

    print("[C2] All checks passed. Quote is valid and fresh.")

if __name__ == "__main__":
    main()
