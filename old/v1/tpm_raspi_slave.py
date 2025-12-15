#!/usr/bin/env python3
import os, json, tempfile, base64, subprocess
from pathlib import Path
from flask import Flask, request

app = Flask(__name__)

# ================= FLAGS =================
SIGN = 0          # enable/disable signature verification
ENCRYPT = 0       # enable/disable hybrid encryption
B64_TRANSPORT = 0 # always base64 for transport reliability

# ================= CONFIG =================
TPM_KEY_HANDLE = "tpm.key"
C2_PUB_PEM = "c2_pub.pem"
RASPI_PUB_PEM = "tpm.pem"
PCR_TOOL = "tpm2_pcrread"
OPENSSL = "openssl"
PCR_INDICES = "sha256:0,7"
DEFAULT_OTA_URL = "http://10.250.149.159:9000/kernel8.img"
OTA_DEST_PATH = "/home/kali/updates/new_image.img"

# ================= HELPER FUNCTIONS =================
def run_check(cmd, input_bytes=None):
    proc = subprocess.run(cmd, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\nstdout:{proc.stdout.decode()}\nstderr:{proc.stderr.decode()}")
    return proc.stdout

def tpm_decrypt_rsa(cipher_bytes):
    with tempfile.TemporaryDirectory() as td:
        cfn = Path(td)/"cipher.bin"
        outfn = Path(td)/"plain.bin"
        cfn.write_bytes(cipher_bytes)
        run_check([OPENSSL, "pkeyutl", "-engine", "tpm2tss", "-keyform", "engine", "-inkey", TPM_KEY_HANDLE, "-decrypt", "-in", str(cfn), "-out", str(outfn)])
        return outfn.read_bytes()

def tpm_sign_bytes(data):
    with tempfile.TemporaryDirectory() as td:
        inf = Path(td)/"in.bin"
        sfn = Path(td)/"sig.bin"
        inf.write_bytes(data)
        run_check([OPENSSL, "pkeyutl", "-engine", "tpm2tss", "-keyform", "engine", "-inkey", TPM_KEY_HANDLE, "-sign", "-in", str(inf), "-out", str(sfn)])
        return sfn.read_bytes()

def verify_sig_with_pub(pub_pem, payload, sig):
    with tempfile.TemporaryDirectory() as td:
        pfn = Path(td)/"plain.bin"
        sfn = Path(td)/"sig.bin"
        pfn.write_bytes(payload)
        sfn.write_bytes(sig)
        proc = subprocess.run([OPENSSL, "pkeyutl", "-pubin", "-inkey", pub_pem, "-verify", "-in", str(pfn), "-sigfile", str(sfn)])
        return proc.returncode == 0

def encrypt_with_pubkey(pub_pem, data):
    with tempfile.TemporaryDirectory() as td:
        inf = Path(td)/"in.bin"
        cfn = Path(td)/"cipher.bin"
        inf.write_bytes(data)
        run_check([OPENSSL, "pkeyutl", "-encrypt", "-pubin", "-inkey", pub_pem, "-in", str(inf), "-out", str(cfn)])
        return cfn.read_bytes()

def aes_encrypt(data, key, iv):
    with tempfile.TemporaryDirectory() as td:
        inf = Path(td)/"in.bin"
        outf = Path(td)/"out.bin"
        inf.write_bytes(data)
        run_check([OPENSSL, "enc", "-aes-256-cbc", "-in", str(inf), "-out", str(outf), "-K", key.hex(), "-iv", iv.hex()])
        return outf.read_bytes()

def aes_decrypt(cipher, key, iv):
    with tempfile.TemporaryDirectory() as td:
        inf = Path(td)/"in.bin"
        outf = Path(td)/"out.bin"
        inf.write_bytes(cipher)
        run_check([OPENSSL, "enc", "-d", "-aes-256-cbc", "-in", str(inf), "-out", str(outf), "-K", key.hex(), "-iv", iv.hex()])
        return outf.read_bytes()

# ================= WRAP/UNWRAP =================
def unwrap_request(payload_bytes):
    if not ENCRYPT and not SIGN:
        return payload_bytes

    sig = b""
    ptr = 0
    if SIGN:
        sig_len = int.from_bytes(payload_bytes[:4], "big")
        sig = payload_bytes[4:4+sig_len]
        ptr = 4 + sig_len

    aes_key_len = int.from_bytes(payload_bytes[ptr:ptr+4], "big")
    ptr += 4
    rsa_aes_key = payload_bytes[ptr:ptr+aes_key_len]
    ptr += aes_key_len
    aes_payload = payload_bytes[ptr:]

    if ENCRYPT:
        aes_key_iv = tpm_decrypt_rsa(rsa_aes_key)
        key = aes_key_iv[:32]
        iv = aes_key_iv[32:48]
        plain = aes_decrypt(aes_payload, key, iv)
    else:
        plain = aes_payload

    if SIGN:
        if not verify_sig_with_pub(C2_PUB_PEM, plain, sig):
            raise ValueError("Signature verification failed")
    return plain

def create_secure_response(payload_bytes):
    if not ENCRYPT and not SIGN:
        return base64.b64encode(payload_bytes) if B64_TRANSPORT else payload_bytes

    sig = tpm_sign_bytes(payload_bytes) if SIGN else b""
    if ENCRYPT:
        key, iv = os.urandom(32), os.urandom(16)
        cipher = aes_encrypt(payload_bytes, key, iv)
        aes_key_iv = key + iv
        rsa_enc_key = encrypt_with_pubkey(C2_PUB_PEM, aes_key_iv)
        pkt = (len(sig).to_bytes(4,"big")+sig) + len(rsa_enc_key).to_bytes(4,"big")+rsa_enc_key + cipher
    else:
        pkt = payload_bytes

    return base64.b64encode(pkt) if B64_TRANSPORT else pkt

# ================= API =================
@app.route("/api/get_pcr_quote", methods=["POST"])
def api_get_pcr_quote():
    try:
        payload = request.get_data()
        if B64_TRANSPORT:
            payload = base64.b64decode(payload)
        plain = unwrap_request(payload)
        out = run_check([PCR_TOOL, PCR_INDICES])
        return create_secure_response(json.dumps({"pcr_values": out.decode()}).encode())
    except Exception as e:
        return str(e), 400

@app.route("/api/update_pcr", methods=["POST"])
def api_update_pcr():
    try:
        payload = request.get_data()
        if B64_TRANSPORT:
            payload = base64.b64decode(payload)
        _ = unwrap_request(payload)
        out = run_check([PCR_TOOL, PCR_INDICES])
        return create_secure_response(json.dumps({"updated": out.decode()}).encode())
    except Exception as e:
        return str(e), 400

@app.route("/api/update_firmware", methods=["POST"])
def api_update_firmware():
    try:
        payload = request.get_data()
        if B64_TRANSPORT:
            payload = base64.b64decode(payload)
        plain = unwrap_request(payload)
        obj = json.loads(plain.decode()) if plain else {}
        image_url = obj.get("image_url", DEFAULT_OTA_URL)
        Path(OTA_DEST_PATH).parent.mkdir(parents=True, exist_ok=True)
        run_check(["curl","-fsSL", image_url, "-o", OTA_DEST_PATH])
        return create_secure_response(json.dumps({"status":"ok","message":f"Downloaded {image_url}"}).encode())
    except Exception as e:
        return str(e), 400

@app.route("/api/rsa_decrypt_test", methods=["POST"])
def api_rsa_decrypt_test():
    try:
        payload = request.get_data()
        if B64_TRANSPORT:
            payload = base64.b64decode(payload)
        plain = unwrap_request(payload)
        return create_secure_response(plain)
    except Exception as e:
        return str(e), 400

if __name__=="__main__":
    app.run(host="0.0.0.0", port=4000)
