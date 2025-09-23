# raspberrypi_slave.py
from flask import Flask, jsonify
import subprocess
import base64
import os
import shutil

app = Flask(__name__)

AK_CTX = "0x81000002"  # Persistent handle of Attestation Key on Pi

# Optional: full paths to tpm2 tools (makes it more robust in Flask)
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

if __name__ == "__main__":
    # Run plain HTTP for now
    app.run(host="0.0.0.0", port=5000)
