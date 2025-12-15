# raspberrypi_slave.py
from flask import Flask, jsonify
import subprocess
import base64
import os
import shutil
import requests

app = Flask(__name__)

AK_CTX = "0x81000002"  # Persistent handle of Attestation Key on Pi

TPM2_QUOTE = shutil.which("tpm2_quote") or "tpm2_quote"
TPM2_PCRREAD = shutil.which("tpm2_pcrread") or "tpm2_pcrread"

def get_pcr_quote():
    # Clean up old files
    for f in ["quote.msg", "sig.dat"]:
        if os.path.exists(f):
            os.remove(f)

    # Only PCR 0 and 7 in quote
    subprocess.run([
        TPM2_QUOTE, "-c", AK_CTX,
        "-l", "sha256:0,7",
        "-m", "quote.msg",
        "-s", "sig.dat"
    ], check=True)

    # PCR read only PCR 0 and 7
    result = subprocess.run(
        [TPM2_PCRREAD, "sha256:0,7"],
        capture_output=True, text=True, check=True
    )

    # Base64 encode quote + signature
    with open("quote.msg", "rb") as f:
        quote = base64.b64encode(f.read()).decode("utf-8")
    with open("sig.dat", "rb") as f:
        sig = base64.b64encode(f.read()).decode("utf-8")

    # Parse PCR values
    pcr_values = {}
    for line in result.stdout.splitlines():
        if ":" in line:
            idx, val = line.split(":", 1)
            pcr_values[idx.strip()] = val.strip()

    return pcr_values, quote, sig

@app.route("/api/get_pcr_quote", methods=["GET"])
def pcr_quote():
    try:
        pcrs, quote, sig = get_pcr_quote()
        return jsonify({
            "pcr_values": pcrs,
            "quote": quote,
            "signature": sig
        })
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"TPM command failed: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# OTA Update
@app.route("/api/update_firmware", methods=["GET"])
def update_firmware():
    try:
        image_url = "http://10.250.149.159:9000/kernel8.img"
        dest_path = "/home/kali/updates/new_image.img"
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)

        print(f"[+] Downloading update from {image_url}...")
        with requests.get(image_url, stream=True) as r:
            r.raise_for_status()
            with open(dest_path, 'wb') as f:
                shutil.copyfileobj(r.raw, f)

        print("[+] Download complete. Preparing to reboot...")
        # Optional: verify checksum or signature here
        # Reboot system
        # subprocess.run(["sudo", "mv","/boot/firmware/kernel8.img","/boot/firmware/kernel8.img_old_v1"], check=False)
        # subprocess.run(["sudo", "mv","./new_image.img","/boot/firmware/kernel8.img"], check=False)
        # subprocess.run(["sudo", "reboot"], check=False)

        return jsonify({"status": "success", "message": "Image downloaded and reboot initiated."})
    except Exception as e:
        print("[-] OTA update failed:", e)
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    # Run plain HTTP for now
    app.run(host="0.0.0.0", port=5000)
