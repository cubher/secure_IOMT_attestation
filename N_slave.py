import os
import json
import base64
import subprocess
import tempfile
import hashlib
import shutil
from typing import Dict, Any, Optional, Tuple
from flask import Flask, request, jsonify
import threading
import time

# Install cryptography library if not already installed: pip3 install cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ============================================
# CONFIGURATION
# ============================================
HOST = "0.0.0.0"
PORT = 4000

# TPM Configuration - Using tpm.key file
TPM_KEY_FILE = "tpm.key"  # TPM private key context created by tpm2tss-genkey
TPM_ENGINE = "tpm2tss"    # TPM2TSS OpenSSL engine

# Key paths
PI_PUBLIC_KEY = "tpm.pem"  # Exported public key (for C2 to verify)
C2_PUBLIC_KEY = "c2_pub.pem"  # C2 server's public key

# TPM2 tools
TPM2_QUOTE = shutil.which("tpm2_quote") or "tpm2_quote"
TPM2_PCRREAD = shutil.which("tpm2_pcrread") or "tpm2_pcrread"
TPM2_READPUBLIC = shutil.which("tpm2_readpublic") or "tpm2_readpublic"

app = Flask(__name__)

# ============================================
# TPM OPERATIONS USING TPM.KEY FILE
# ============================================

def tpm_rsa_sign(data: bytes) -> bytes:
    """
    Sign data using TPM private key via OpenSSL tpm2tss engine
    Uses tpm.key file
    """
    # Create digest of data
    digest = hashlib.sha256(data).digest()
    
    cmd = [
        "openssl", "pkeyutl",
        "-engine", TPM_ENGINE,
        "-keyform", "engine",
        "-inkey", TPM_KEY_FILE,
        "-sign",
        "-pkeyopt", "digest:sha256"
    ]
    
    try:
        result = subprocess.run(
            cmd,
            input=digest,
            capture_output=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"TPM signing error: {e.stderr.decode()}")
        raise

def tpm_rsa_decrypt(encrypted_data: bytes) -> bytes:
    """
    Decrypt data using TPM private key via OpenSSL tpm2tss engine
    Uses tpm.key file
    """
    cmd = [
        "openssl", "pkeyutl",
        "-engine", TPM_ENGINE,
        "-keyform", "engine",
        "-inkey", TPM_KEY_FILE,
        "-decrypt",
        "-pkeyopt", "rsa_padding_mode:oaep",
        "-pkeyopt", "rsa_oaep_md:sha256",
        "-pkeyopt", "rsa_mgf1_md:sha256"
    ]
    
    try:
        result = subprocess.run(
            cmd,
            input=encrypted_data,
            capture_output=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"TPM decryption error: {e.stderr.decode()}")
        raise Exception(f"TPM decryption failed: {e.stderr.decode()}")

def get_pcr_quote(nonce: Optional[str] = None) -> Tuple[Dict[str, str], str, bytes]:
    """
    Get PCR quote from TPM (PCRs 0 and 7)
    Returns: (pcr_values, nonce_used, signature)
    """
    # Generate nonce if not provided
    if nonce is None:
        nonce_bytes = os.urandom(32)
    else:
        # Handle hex string
        if isinstance(nonce, str):
            nonce_bytes = bytes.fromhex(nonce)
        else:
            nonce_bytes = nonce
    
    # Create nonce file
    nonce_file = "nonce.bin"
    with open(nonce_file, "wb") as f:
        f.write(nonce_bytes)
    
    try:
        # Get PCR values first
        print("[*] Reading PCR values...")
        pcr_result = subprocess.run(
            [TPM2_PCRREAD, "sha256:0,7"],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse PCR values
        pcr_values = {}
        for line in pcr_result.stdout.splitlines():
            line = line.strip()
            if ":" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    idx, value = parts
                    pcr_values[idx.strip()] = value.strip()
        
        print(f"[*] PCR values: {pcr_values}")
        
        # For signing the PCR values with nonce (alternative to TPM quote if quote doesn't work)
        # We'll use TPM to sign the concatenated PCR values and nonce
        print("[*] Creating data to sign...")
        data_to_sign = json.dumps({
            "pcr_values": pcr_values,
            "nonce": nonce_bytes.hex()
        }).encode()
        
        print("[*] Signing PCR data with TPM...")
        signature = tpm_rsa_sign(data_to_sign)
        
        # Cleanup
        if os.path.exists(nonce_file):
            try:
                os.unlink(nonce_file)
            except:
                pass
        
        return pcr_values, nonce_bytes.hex(), signature
        
    except Exception as e:
        # Cleanup on error
        if os.path.exists(nonce_file):
            try:
                os.unlink(nonce_file)
            except:
                pass
        raise

# ============================================
# CRYPTO FUNCTIONS (USING C2 PUBLIC KEY)
# ============================================

def rsa_encrypt(data: bytes, public_key_path: str) -> bytes:
    """
    Encrypt data using RSA-OAEP with standard OpenSSL
    """
    cmd = [
        "openssl", "pkeyutl",
        "-encrypt",
        "-pubin",
        "-inkey", public_key_path,
        "-pkeyopt", "rsa_padding_mode:oaep",
        "-pkeyopt", "rsa_oaep_md:sha256",
        "-pkeyopt", "rsa_mgf1_md:sha256"
    ]
    
    result = subprocess.run(
        cmd,
        input=data,
        capture_output=True,
        check=True
    )
    
    return result.stdout

def rsa_verify(data: bytes, signature: bytes, public_key_path: str) -> bool:
    """
    Verify RSA signature using standard OpenSSL
    """
    # Create digest of data
    digest = hashlib.sha256(data).digest()
    
    # Write signature to temp file
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.sig') as sig_file:
        sig_file.write(signature)
        sig_file_path = sig_file.name
    
    try:
        cmd = [
            "openssl", "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey", public_key_path,
            "-pkeyopt", "digest:sha256",
            "-sigfile", sig_file_path
        ]
        
        result = subprocess.run(
            cmd,
            input=digest,
            capture_output=True
        )
        
        return result.returncode == 0
    finally:
        try:
            os.unlink(sig_file_path)
        except:
            pass

# ============================================
# SESSION KEY MANAGEMENT (AES-GCM) - USING CRYPTOGRAPHY LIBRARY
# ============================================

def generate_aes_key() -> bytes:
    """Generate 256-bit AES key"""
    return os.urandom(32)

def aes_gcm_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt using AES-GCM - Using cryptography library (same as C2 server)"""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def aes_gcm_decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt AES-GCM - Using cryptography library (same as C2 server)"""
    nonce = encrypted_data[:12]
    ciphertext_with_tag = encrypted_data[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return plaintext

# ============================================
# SECURE MESSAGE HANDLING
# ============================================

def process_encrypted_message(encrypted_message: Dict[str, str]) -> Dict[str, Any]:
    """
    Process incoming encrypted message:
    1. Decrypt session key with TPM private key
    2. Verify signature with C2 public key
    3. Decrypt data with session key
    """
    # Decode base64 fields
    encrypted_session_key = base64.b64decode(encrypted_message["encrypted_session_key"])
    encrypted_data = base64.b64decode(encrypted_message["encrypted_data"])
    signature = base64.b64decode(encrypted_message["signature"])
    
    # Step 1: Decrypt session key with TPM
    print("[*] Decrypting session key with TPM...")
    session_key = tpm_rsa_decrypt(encrypted_session_key)
    print(f"[+] Session key decrypted: {session_key.hex()[:16]}...")
    
    # Step 2: Verify signature with C2 public key
    print("[*] Verifying signature...")
    if not rsa_verify(encrypted_data, signature, C2_PUBLIC_KEY):
        raise ValueError("Signature verification failed!")
    print("[+] Signature verified")
    
    # Step 3: Decrypt data with session key
    print("[*] Decrypting message...")
    data_bytes = aes_gcm_decrypt(encrypted_data, session_key)
    print(f"[+] Message decrypted: {len(data_bytes)} bytes")
    
    return json.loads(data_bytes)

def create_encrypted_response(data: Dict[str, Any], 
                            request_nonce: Optional[str] = None) -> Dict[str, str]:
    """
    Create encrypted response:
    1. Generate session key
    2. Encrypt session key with C2 public key
    3. Encrypt data with session key
    4. Sign encrypted data with TPM private key
    """
    # Generate session key
    print("[*] Generating session key...")
    session_key = generate_aes_key()
    print(f"[+] Session key: {session_key.hex()[:16]}...")
    
    # Encrypt session key with C2 public key
    print("[*] Encrypting session key...")
    encrypted_session_key = rsa_encrypt(session_key, C2_PUBLIC_KEY)
    print(f"[+] Encrypted session key: {len(encrypted_session_key)} bytes")
    
    # Add nonce to data if provided
    if request_nonce:
        data["nonce"] = request_nonce
    
    # Encrypt data
    print("[*] Encrypting response data...")
    data_bytes = json.dumps(data, separators=(",", ":")).encode()
    print(f"[+] Data to encrypt: {len(data_bytes)} bytes")
    encrypted_data = aes_gcm_encrypt(data_bytes, session_key)
    print(f"[+] Encrypted data: {len(encrypted_data)} bytes")
    
    # Sign with TPM
    print("[*] Signing response...")
    signature = tpm_rsa_sign(encrypted_data)
    print(f"[+] Response signed: {len(signature)} bytes")
    
    return {
        "encrypted_session_key": base64.b64encode(encrypted_session_key).decode(),
        "encrypted_data": base64.b64encode(encrypted_data).decode(),
        "signature": base64.b64encode(signature).decode()
    }

# ============================================
# FLASK API ENDPOINTS
# ============================================

@app.route("/api/attestation", methods=["POST"])
def attestation():
    """Handle attestation requests"""
    print("\n" + "="*50)
    print("Received attestation request")
    print("="*50)
    
    try:
        # Process encrypted request
        encrypted_request = request.json
        print("[*] Processing encrypted message...")
        decrypted_request = process_encrypted_message(encrypted_request)
        
        print(f"[+] Decrypted request keys: {list(decrypted_request.keys())}")
        print(f"[+] Request command: {decrypted_request.get('command')}")
        print(f"[+] Nonce: {decrypted_request.get('nonce', 'No nonce')}")
        
        # Check command
        if decrypted_request.get("command") != "get_pcr_quote":
            return jsonify({"error": "Invalid command"}), 400
        
        # Get PCR quote
        nonce = decrypted_request.get("nonce")
        print("[*] Getting PCR quote from TPM...")
        pcr_values, nonce_used, signature = get_pcr_quote(nonce)
        
        print(f"[+] PCR 0: {pcr_values.get('0', 'N/A')}")
        print(f"[+] PCR 7: {pcr_values.get('7', 'N/A')}")
        print(f"[+] Nonce used: {nonce_used}")
        print(f"[+] Signature length: {len(signature)} bytes")
        
        # Prepare response data
        response_data = {
            "command": "pcr_quote_response",
            "data": {
                "pcr_values": pcr_values,
                "nonce": nonce_used,
                "signature": base64.b64encode(signature).decode()
            },
            "status": "success"
        }
        
        # Create encrypted response
        print("[*] Creating encrypted response...")
        encrypted_response = create_encrypted_response(
            response_data,
            decrypted_request.get("nonce")
        )
        
        print("[+] Response ready")
        return jsonify(encrypted_response)
        
    except Exception as e:
        print(f"[-] Attestation error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/api/ota", methods=["POST"])
def ota_update():
    """Handle OTA update requests"""
    print("\n" + "="*50)
    print("Received OTA update request")
    print("="*50)
    
    try:
        # Process encrypted request
        encrypted_request = request.json
        print("[*] Processing encrypted message...")
        decrypted_request = process_encrypted_message(encrypted_request)
        
        print(f"[+] Decrypted request: {decrypted_request}")
        
        # Check command
        if decrypted_request.get("command") != "ota_update":
            return jsonify({"error": "Invalid command"}), 400
        
        update_id = decrypted_request.get("update_id")
        firmware_url = decrypted_request.get("firmware_url")
        
        print(f"[+] OTA update requested: {update_id}")
        print(f"[+] Firmware URL: {firmware_url}")
        
        # Start OTA update in background thread
        thread = threading.Thread(
            target=perform_ota_update,
            args=(update_id, firmware_url)
        )
        thread.daemon = True
        thread.start()
        
        # Prepare immediate response
        response_data = {
            "command": "ota_response",
            "update_id": update_id,
            "status": "success",
            "message": "OTA update initiated"
        }
        
        # Create encrypted response
        print("[*] Creating encrypted response...")
        encrypted_response = create_encrypted_response(
            response_data,
            decrypted_request.get("nonce")
        )
        
        print("[+] Response ready")
        return jsonify(encrypted_response)
        
    except Exception as e:
        print(f"[-] OTA error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ============================================
# OTA UPDATE FUNCTION
# ============================================

def perform_ota_update(update_id: str, firmware_url: str):
    """Perform OTA update in background"""
    try:
        print(f"[*] Starting OTA update {update_id}")
        
        # Download firmware
        print(f"[*] Downloading firmware from {firmware_url}")
        
        # Create updates directory
        os.makedirs("/home/kali/updates", exist_ok=True)
        dest_path = "/home/kali/updates/new_image.img"
        
        # Download using curl (more reliable)
        download_cmd = ["curl", "-L", "-o", dest_path, firmware_url]
        print(f"[*] Running: {' '.join(download_cmd)}")
        result = subprocess.run(download_cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"[-] Download failed: {result.stderr}")
            return
        
        print(f"[+] Download complete: {dest_path}")
        
        # Verify the file was downloaded
        if not os.path.exists(dest_path):
            print(f"[-] Downloaded file not found: {dest_path}")
            return
        
        file_size = os.path.getsize(dest_path)
        print(f"[+] File size: {file_size} bytes")
        
        # Backup current kernel
        print("[*] Backing up current kernel...")
        if os.path.exists("/boot/firmware/kernel8.img"):
            backup_cmd = ["sudo", "cp", "/boot/firmware/kernel8.img", "/boot/firmware/kernel8.img.backup"]
            subprocess.run(backup_cmd, capture_output=True)
        
        # Apply update
        print("[*] Applying firmware update...")
        apply_cmd = ["sudo", "cp", dest_path, "/boot/firmware/kernel8.img"]
        result = subprocess.run(apply_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[+] Firmware update applied successfully")
            
            # Verify the update
            verify_cmd = ["ls", "-la", "/boot/firmware/kernel8.img"]
            subprocess.run(verify_cmd)
            
            print("[*] Update complete. System ready for reboot.")
            # Uncomment to reboot: subprocess.run(["sudo", "reboot"])
        else:
            print(f"[-] Failed to apply update: {result.stderr}")
        
    except Exception as e:
        print(f"[-] OTA update failed: {e}")
        import traceback
        traceback.print_exc()

# ============================================
# HEALTH CHECK ENDPOINT
# ============================================

@app.route("/api/health", methods=["GET"])
def health_check():
    """Simple health check endpoint"""
    return jsonify({
        "status": "online",
        "service": "tpm_remote_attestation",
        "timestamp": time.time(),
        "tpm_available": True,
        "endpoints": ["/api/attestation", "/api/ota", "/api/test", "/api/export_public_key"]
    })

# ============================================
# TEST ENDPOINTS
# ============================================

@app.route("/api/test", methods=["GET"])
def test_endpoint():
    """Test endpoint for debugging"""
    try:
        # Test PCR read
        pcr_result = subprocess.run(
            [TPM2_PCRREAD, "sha256:0,7"],
            capture_output=True,
            text=True
        )
        
        # Test TPM signing
        test_data = b"test message"
        try:
            signature = tpm_rsa_sign(test_data)
            signing_ok = True
        except:
            signing_ok = False
        
        return jsonify({
            "status": "success",
            "tpm_available": True,
            "pcr_read_ok": pcr_result.returncode == 0,
            "tpm_signing_ok": signing_ok,
            "pcr_0_7": pcr_result.stdout if pcr_result.returncode == 0 else pcr_result.stderr
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route("/api/export_public_key", methods=["GET"])
def export_public_key():
    """Export TPM public key for C2 server"""
    try:
        # Extract public key from tpm.key using openssl
        cmd = [
            "openssl", "rsa",
            "-engine", TPM_ENGINE,
            "-keyform", "engine",
            "-in", TPM_KEY_FILE,
            "-pubout"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Save the public key
            with open(PI_PUBLIC_KEY, "w") as f:
                f.write(result.stdout)
            
            return jsonify({
                "status": "success",
                "public_key": result.stdout,
                "message": f"Public key saved to {PI_PUBLIC_KEY}"
            })
        else:
            return jsonify({
                "status": "error",
                "message": result.stderr
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route("/api/test_aes", methods=["GET"])
def test_aes():
    """Test AES-GCM encryption/decryption"""
    try:
        test_key = generate_aes_key()
        test_data = b"Hello, this is a test message!"
        
        # Encrypt
        encrypted = aes_gcm_encrypt(test_data, test_key)
        
        # Decrypt
        decrypted = aes_gcm_decrypt(encrypted, test_key)
        
        if test_data == decrypted:
            return jsonify({
                "status": "success",
                "message": "AES-GCM test passed",
                "original": test_data.decode(),
                "decrypted": decrypted.decode()
            })
        else:
            return jsonify({
                "status": "error",
                "message": "AES-GCM test failed - data mismatch"
            })
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# ============================================
# DEBUG ENDPOINT FOR DIRECT TESTING
# ============================================

@app.route("/api/debug_pcr", methods=["GET"])
def debug_pcr():
    """Direct PCR reading for debugging"""
    try:
        nonce = request.args.get("nonce")
        pcr_values, nonce_used, signature = get_pcr_quote(nonce)
        
        return jsonify({
            "status": "success",
            "pcr_values": pcr_values,
            "nonce_used": nonce_used,
            "signature_b64": base64.b64encode(signature).decode(),
            "signature_length": len(signature)
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# ============================================
# MAIN
# ============================================

def setup_environment() -> bool:
    """Setup required environment"""
    
    print("[*] Setting up environment...")
    
    # Check for required files
    if not os.path.exists(TPM_KEY_FILE):
        print(f"[-] Missing TPM key file: {TPM_KEY_FILE}")
        print("\nYou need to create tpm.key using:")
        print("  tpm2tss-genkey -a rsa -o tpm.key")
        print("\nOr if you already have a TPM key loaded at a handle, use:")
        print(f"  tpm2tss-genkey -a rsa -o tpm.key <handle>")
        return False
    
    if not os.path.exists(C2_PUBLIC_KEY):
        print(f"[-] Missing C2 public key: {C2_PUBLIC_KEY}")
        print("   Copy c2_pub.pem from C2 server to this directory")
        return False
    
    # Check for TPM tools
    required_tools = ["openssl", TPM2_PCRREAD]
    missing_tools = []
    
    for tool in required_tools:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"[-] Missing required tools: {missing_tools}")
        print("   Install with: sudo apt-get install tpm2-tools tpm2-tss-engine openssl")
        return False
    
    # Export public key if not exists
    if not os.path.exists(PI_PUBLIC_KEY):
        print(f"[*] Exporting TPM public key to {PI_PUBLIC_KEY}...")
        try:
            # Extract public key from tpm.key
            cmd = [
                "openssl", "rsa",
                "-engine", TPM_ENGINE,
                "-keyform", "engine",
                "-in", TPM_KEY_FILE,
                "-pubout",
                "-out", PI_PUBLIC_KEY
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"[-] Failed to export public key: {result.stderr}")
                return False
            
            print(f"[+] Public key exported to {PI_PUBLIC_KEY}")
        except Exception as e:
            print(f"[-] Failed to export public key: {e}")
            return False
    
    # Test TPM signing
    print("[*] Testing TPM signing...")
    try:
        test_data = b"test"
        signature = tpm_rsa_sign(test_data)
        print(f"[+] TPM signing test passed (signature length: {len(signature)} bytes)")
    except Exception as e:
        print(f"[-] TPM signing test failed: {e}")
        print("   Make sure tpm2tss engine is properly installed and tpm.key is valid")
        return False
    
    print("[+] Environment setup complete")
    return True

if __name__ == "__main__":
    print("\n" + "="*50)
    print("       RASPBERRY PI - TPM REMOTE ATTESTATION")
    print("="*50)
    
    if not setup_environment():
        print("[-] Setup failed. Please fix the issues above.")
        exit(1)
    
    print(f"[+] Starting server on {HOST}:{PORT}")
    print(f"[+] TPM key file: {TPM_KEY_FILE}")
    print("[+] TPM integration ready")
    print("[*] Available endpoints:")
    print("    - POST /api/attestation - Get PCR quote")
    print("    - POST /api/ota - Trigger OTA update")
    print("    - GET  /api/health - Health check")
    print("    - GET  /api/test - Test endpoint")
    print("    - GET  /api/export_public_key - Export public key")
    print("    - GET  /api/test_aes - Test AES encryption")
    print("    - GET  /api/debug_pcr - Debug PCR reading")
    
    try:
        app.run(host=HOST, port=PORT, debug=False)  # Set debug=False for production
    except Exception as e:
        print(f"[-] Failed to start server: {e}")