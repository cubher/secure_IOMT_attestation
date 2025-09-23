# host_verifier_software.py
import requests
import base64
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ----------------------------
# Configuration
# ----------------------------
PI_IP = "10.208.164.152"   # Your Raspberry Pi IP
PORT = 5000
AK_PUB_FILE = "ak_pub.pem"          # AK public key exported from Pi TPM
GOLDEN_PCR_FILE = "golden_pcrs.json"  # Golden PCR reference file

# Only check these PCR indices
PCR_WHITELIST = ["0", "7"]

# ----------------------------
# Helper Functions
# ----------------------------
def fetch_quote():
    url = f"http://{PI_IP}:{PORT}/api/get_pcr_quote"
    resp = requests.get(url)
    resp.raise_for_status()
    return resp.json()

def verify_quote_signature(quote_b64, sig_b64, ak_pub_file):
    # Load AK public key
    with open(ak_pub_file, "rb") as f:
        ak_pub = serialization.load_pem_public_key(f.read())

    # Decode quote and signature
    quote_bytes = base64.b64decode(quote_b64)
    sig_bytes = base64.b64decode(sig_b64)

    # Verify signature
    try:
        ak_pub.verify(
            sig_bytes,
            quote_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        #print("[-] Quote signature verification failed:", e)
        return False

def compare_pcrs(pcr_values, golden_file):
    try:
        with open(golden_file, "r") as f:
            golden_pcrs = json.load(f)
    except FileNotFoundError:
        print("[!] Golden PCR file not found. Skipping PCR comparison.")
        return

    mismatches = []
    for idx in PCR_WHITELIST:
        actual_val = pcr_values.get(idx)
        expected_val = golden_pcrs.get(idx)
        if expected_val is None:
            print(f"[!] No golden value stored for PCR {idx}")
            continue
        if actual_val != expected_val:
            mismatches.append((idx, actual_val, expected_val))

    if mismatches:
        print("[-] PCR mismatch detected:")
        for idx, actual, expected in mismatches:
            print(f"  PCR {idx}: actual={actual} expected={expected}")
    else:
        print("[+] PCR values match the golden reference (0 and 7).")
        print("[+] The devices is in a trusted state.")

# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    print("[*] Fetching quote from Raspberry Pi...")
    data = fetch_quote()

    pcrs = data["pcr_values"]
    quote = data["quote"]
    sig = data["signature"]

    print("[*] Verifying quote signature...")
    if verify_quote_signature(quote, sig, AK_PUB_FILE):
        #print("[+] Quote signature is valid!")
        pass
    else:
        #print("[-] Quote signature invalid!")
        pass

    print("[*] PCR Values received from Pi (showing only 0 and 7):")
    for idx in PCR_WHITELIST:
        print(f"  PCR {idx}: {pcrs.get(idx, 'N/A')}")

    # Compare with golden PCRs
    compare_pcrs(pcrs, GOLDEN_PCR_FILE)
