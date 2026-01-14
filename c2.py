import os
import json
import base64
import subprocess
import tempfile
import hashlib
import time
from typing import Dict, Any, Optional, Tuple
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # For AES-GCM

# ============================================
# CONFIGURATION
# ============================================
PI_IP = "10.196.192.152"
PI_PORT = 4000
BASE_URL = f"http://{PI_IP}:{PI_PORT}"

# Key paths - using standard PEM format
C2_PRIVATE_KEY = "c2_priv.pem"
C2_PUBLIC_KEY = "c2_pub.pem"  # To be shared with Raspberry Pi
PI_PUBLIC_KEY = "tpm.pem"  # Raspberry Pi's public key (from TPM)

GOLDEN_PCR_FILE = "golden_pcrs.json"
PCR_WHITELIST = ["0", "7"]

# ============================================
# HELPER FUNCTIONS FOR OPENSSL OPERATIONS (FIXED FOR WINDOWS)
# ============================================

def rsa_encrypt(data: bytes, public_key_path: str) -> bytes:
    """
    Encrypt data using RSA-OAEP with OpenSSL - FIXED for Windows
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
    
    # Use stdin to pass data, avoiding temp files
    result = subprocess.run(
        cmd,
        input=data,
        capture_output=True,
        check=True
    )
    
    return result.stdout

def rsa_decrypt(encrypted_data: bytes, private_key_path: str) -> bytes:
    """
    Decrypt data using RSA-OAEP with OpenSSL - FIXED for Windows
    """
    cmd = [
        "openssl", "pkeyutl",
        "-decrypt",
        "-inkey", private_key_path,
        "-pkeyopt", "rsa_padding_mode:oaep",
        "-pkeyopt", "rsa_oaep_md:sha256",
        "-pkeyopt", "rsa_mgf1_md:sha256"
    ]
    
    # Use stdin to pass data
    result = subprocess.run(
        cmd,
        input=encrypted_data,
        capture_output=True,
        check=True
    )
    
    return result.stdout

def rsa_sign(data: bytes, private_key_path: str) -> bytes:
    """
    Sign data using RSA-PKCS1.5 with OpenSSL - FIXED for Windows
    """
    # Create digest of data
    digest = hashlib.sha256(data).digest()
    
    cmd = [
        "openssl", "pkeyutl",
        "-sign",
        "-inkey", private_key_path,
        "-pkeyopt", "digest:sha256"
    ]
    
    # Use stdin to pass hash
    result = subprocess.run(
        cmd,
        input=digest,
        capture_output=True,
        check=True
    )
    
    return result.stdout

def rsa_verify(data: bytes, signature: bytes, public_key_path: str) -> bool:
    """
    Verify RSA signature using OpenSSL - FIXED for Windows
    """
    # Create digest of data
    digest = hashlib.sha256(data).digest()
    
    # Write signature to a temporary file (needed for openssl verify)
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
        # Clean up temp file
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
    """Encrypt using AES-GCM - Using cryptography library"""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def aes_gcm_decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt AES-GCM - Using cryptography library"""
    nonce = encrypted_data[:12]
    ciphertext_with_tag = encrypted_data[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return plaintext

# ============================================
# SECURE COMMUNICATION FUNCTIONS
# ============================================

def encrypt_and_sign_message(data: Dict[str, Any], 
                           recipient_public_key: str,
                           sender_private_key: str) -> Dict[str, str]:
    """
    1. Generate session key
    2. Encrypt session key with recipient's public key
    3. Encrypt data with session key (AES-GCM)
    4. Sign encrypted data with sender's private key
    """
    
    # Step 1: Generate session key
    print("[*] Generating session key...")
    session_key = generate_aes_key()
    
    # Step 2: Encrypt session key with recipient's RSA public key
    print("[*] Encrypting session key...")
    encrypted_session_key = rsa_encrypt(session_key, recipient_public_key)
    
    # Step 3: Encrypt data with session key
    print("[*] Encrypting data...")
    data_bytes = json.dumps(data, separators=(",", ":")).encode()
    encrypted_data = aes_gcm_encrypt(data_bytes, session_key)
    
    # Step 4: Sign the encrypted data
    print("[*] Signing data...")
    signature = rsa_sign(encrypted_data, sender_private_key)
    
    # Prepare final message
    return {
        "encrypted_session_key": base64.b64encode(encrypted_session_key).decode(),
        "encrypted_data": base64.b64encode(encrypted_data).decode(),
        "signature": base64.b64encode(signature).decode(),
        "timestamp": str(time.time())
    }

def decrypt_and_verify_message(encrypted_message: Dict[str, str],
                             sender_public_key: str,
                             recipient_private_key: str) -> Dict[str, Any]:
    """
    1. Decrypt session key with recipient's private key
    2. Verify signature with sender's public key
    3. Decrypt data with session key
    """
    
    # Decode base64 fields
    encrypted_session_key = base64.b64decode(encrypted_message["encrypted_session_key"])
    encrypted_data = base64.b64decode(encrypted_message["encrypted_data"])
    signature = base64.b64decode(encrypted_message["signature"])
    
    # Step 1: Decrypt session key
    print("[*] Decrypting session key...")
    session_key = rsa_decrypt(encrypted_session_key, recipient_private_key)
    
    # Step 2: Verify signature
    print("[*] Verifying signature...")
    if not rsa_verify(encrypted_data, signature, sender_public_key):
        raise ValueError("Signature verification failed!")
    print("[+] Signature verified")
    
    # Step 3: Decrypt data
    print("[*] Decrypting data...")
    data_bytes = aes_gcm_decrypt(encrypted_data, session_key)
    
    return json.loads(data_bytes)

# ============================================
# TPM ATTESTATION FUNCTIONS
# ============================================

def verify_pcr_attestation(pcr_data: Dict[str, Any]) -> bool:
    """Verify PCR attestation from Raspberry Pi"""
    
    # Check required fields
    required_fields = ["pcr_values", "signature", "nonce"]
    for field in required_fields:
        if field not in pcr_data:
            print(f"[-] Missing required field: {field}")
            return False
    
    # Load golden PCR values
    try:
        with open(GOLDEN_PCR_FILE, 'r') as f:
            golden_pcrs = json.load(f)
    except FileNotFoundError:
        print(f"[-] Golden PCR file not found: {GOLDEN_PCR_FILE}")
        return False
    
    # Compare PCR values
    pcr_values = pcr_data["pcr_values"]
    for pcr_index in PCR_WHITELIST:
        if pcr_index not in pcr_values:
            print(f"[-] Missing PCR {pcr_index}")
            return False
        
        golden_value = golden_pcrs.get(pcr_index)
        if not golden_value:
            print(f"[-] No golden value for PCR {pcr_index}")
            return False
        
        if pcr_values[pcr_index] != golden_value:
            print(f"[-] PCR {pcr_index} mismatch!")
            print(f"    Device: {pcr_values[pcr_index]}")
            print(f"    Golden: {golden_value}")
            return False
    
    print("[+] PCR values match golden reference")
    
    # Verify the quote signature using Raspberry Pi's public key
    quote_data = json.dumps({
        "pcr_values": pcr_values,
        "nonce": pcr_data["nonce"]
    }).encode()
    
    signature = base64.b64decode(pcr_data["signature"])
    
    if rsa_verify(quote_data, signature, PI_PUBLIC_KEY):
        print("[+] Quote signature verified successfully")
        return True
    else:
        print("[-] Quote signature verification failed")
        return False

# ============================================
# API FUNCTIONS
# ============================================

def request_pcr_quote() -> Optional[Dict[str, Any]]:
    """Request PCR quote from Raspberry Pi"""
    
    # Generate nonce for freshness
    nonce = os.urandom(32).hex()
    
    # Prepare request data
    request_data = {
        "command": "get_pcr_quote",
        "nonce": nonce,
        "timestamp": str(time.time())
    }
    
    # Encrypt and sign request
    print("[*] Encrypting and signing request...")
    encrypted_request = encrypt_and_sign_message(
        request_data,
        PI_PUBLIC_KEY,  # Encrypt with Raspberry Pi's public key
        C2_PRIVATE_KEY  # Sign with C2's private key
    )
    
    try:
        # Send request
        print(f"[*] Sending request to {BASE_URL}/api/attestation")
        response = requests.post(
            f"{BASE_URL}/api/attestation",
            json=encrypted_request,
            timeout=10
        )
        
        print(f"[*] Response status: {response.status_code}")
        
        if response.status_code != 200:
            print(f"[-] Server error: {response.status_code}")
            print(f"[-] Response: {response.text}")
            return None
        
        # Decrypt and verify response
        print("[*] Processing encrypted response...")
        encrypted_response = response.json()
        decrypted_response = decrypt_and_verify_message(
            encrypted_response,
            PI_PUBLIC_KEY,  # Verify with Raspberry Pi's public key
            C2_PRIVATE_KEY  # Decrypt with C2's private key
        )
        
        print(f"[+] Decrypted response command: {decrypted_response.get('command')}")
        
        # Verify nonce matches
        response_data = decrypted_response.get("data", {})
        if response_data.get("nonce") != nonce:
            print("[-] Nonce mismatch - possible replay attack!")
            return None
        
        return response_data
        
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection failed. Is Raspberry Pi running at {PI_IP}:{PI_PORT}?")
        return None
    except requests.exceptions.Timeout:
        print("[-] Request timed out")
        return None
    except Exception as e:
        print(f"[-] Error requesting PCR quote: {e}")
        import traceback
        traceback.print_exc()
        return None

def trigger_ota_update() -> bool:
    """Trigger OTA update on Raspberry Pi"""
    
    # Generate update command with unique ID
    update_id = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    
    request_data = {
        "command": "ota_update",
        "update_id": update_id,
        "firmware_url": "http://10.250.149.159:9000/kernel8.img",
        "checksum": "",
        "timestamp": str(time.time())
    }
    
    # Encrypt and sign request
    encrypted_request = encrypt_and_sign_message(
        request_data,
        PI_PUBLIC_KEY,
        C2_PRIVATE_KEY
    )
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/ota",
            json=encrypted_request,
            timeout=30
        )
        
        if response.status_code != 200:
            print(f"[-] OTA trigger failed: {response.status_code}")
            return False
        
        # Verify response
        encrypted_response = response.json()
        decrypted_response = decrypt_and_verify_message(
            encrypted_response,
            PI_PUBLIC_KEY,
            C2_PRIVATE_KEY
        )
        
        if decrypted_response.get("status") == "success":
            print(f"[+] OTA update triggered successfully (ID: {update_id})")
            return True
        else:
            print(f"[-] OTA update failed: {decrypted_response.get('message', 'Unknown error')}")
            return False
            
    except Exception as e:
        print(f"[-] Error triggering OTA: {e}")
        return False

def update_golden_pcrs(pcr_values: Dict[str, str]) -> bool:
    """Update golden PCR values file"""
    
    # Filter only whitelisted PCRs
    golden_data = {idx: pcr_values[idx] for idx in PCR_WHITELIST if idx in pcr_values}
    
    try:
        with open(GOLDEN_PCR_FILE, 'w') as f:
            json.dump(golden_data, f, indent=2)
        print("[+] Golden PCR values updated")
        return True
    except Exception as e:
        print(f"[-] Failed to update golden PCRs: {e}")
        return False

# ============================================
# UTILITY FUNCTIONS
# ============================================

def test_connection() -> bool:
    """Test basic connection to Raspberry Pi"""
    try:
        print(f"[*] Testing connection to {BASE_URL}/api/health")
        response = requests.get(f"{BASE_URL}/api/health", timeout=5)
        if response.status_code == 200:
            print(f"[+] Connection successful: {response.json()}")
            return True
        else:
            print(f"[-] Connection failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"[-] Connection test failed: {e}")
        return False

def generate_keys_if_needed():
    """Generate C2 server keys if they don't exist"""
    if not os.path.exists(C2_PRIVATE_KEY):
        print(f"[*] Generating C2 server RSA key pair...")
        try:
            # Generate private key
            cmd_gen = ["openssl", "genrsa", "-out", C2_PRIVATE_KEY, "2048"]
            subprocess.run(cmd_gen, check=True, capture_output=True)
            
            # Extract public key
            cmd_pub = ["openssl", "rsa", "-in", C2_PRIVATE_KEY, "-pubout", "-out", C2_PUBLIC_KEY]
            subprocess.run(cmd_pub, check=True, capture_output=True)
            
            print(f"[+] Generated {C2_PRIVATE_KEY} and {C2_PUBLIC_KEY}")
        except Exception as e:
            print(f"[-] Failed to generate keys: {e}")
            return False
    return True

# ============================================
# MAIN APPLICATION
# ============================================

def main():
    """Main menu for C2 server"""
    
    print("\n" + "="*50)
    print("       SECURE C2 SERVER - TPM REMOTE ATTESTATION")
    print("="*50)
    
    # Generate keys if needed
    if not generate_keys_if_needed():
        return
    
    # Check for Raspberry Pi public key
    if not os.path.exists(PI_PUBLIC_KEY):
        print(f"[-] Missing Raspberry Pi public key: {PI_PUBLIC_KEY}")
        print("   Please copy pi_pub.pem from Raspberry Pi to this directory")
        return
    
    # Test connection first
    print("[*] Testing connection to Raspberry Pi...")
    if not test_connection():
        print(f"[-] Cannot connect to Raspberry Pi at {PI_IP}:{PI_PORT}")
        print("Please check:")
        print(f"  1. Raspberry Pi is running on {PI_IP}")
        print(f"  2. Port {PI_PORT} is open")
        print("  3. Raspberry Pi server is started")
    
    # Create golden PCR file if it doesn't exist
    if not os.path.exists(GOLDEN_PCR_FILE):
        print(f"[*] Creating empty golden PCR file: {GOLDEN_PCR_FILE}")
        with open(GOLDEN_PCR_FILE, 'w') as f:
            json.dump({}, f)
    
    while True:
        print("\nMenu:")
        print("1. Request PCR Attestation")
        print("2. Trigger OTA Update")
        print("3. Update Golden PCR Values (from current device)")
        print("4. Test Connection")
        print("5. Exit")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == "1":
            print("\n[*] Requesting PCR attestation...")
            pcr_data = request_pcr_quote()
            
            if pcr_data:
                print(f"\n[*] PCR data received")
                print(f"    PCR 0: {pcr_data.get('pcr_values', {}).get('0', 'N/A')}")
                print(f"    PCR 7: {pcr_data.get('pcr_values', {}).get('7', 'N/A')}")
                
                if verify_pcr_attestation(pcr_data):
                    print("\n[+] Device is trusted!")
                    
                    # Ask if user wants to update golden PCRs
                    update = input("\nUpdate golden PCRs with current values? (y/n): ").lower()
                    if update == 'y':
                        update_golden_pcrs(pcr_data["pcr_values"])
                else:
                    print("\n[-] Device attestation failed!")
            else:
                print("\n[-] Failed to get PCR data!")
                
        elif choice == "2":
            print("\n[*] Triggering OTA update...")
            if trigger_ota_update():
                print("[+] OTA update initiated successfully")
            else:
                print("[-] OTA update failed")
                
        elif choice == "3":
            print("\n[*] Fetching current PCR values...")
            pcr_data = request_pcr_quote()
            if pcr_data:
                if update_golden_pcrs(pcr_data["pcr_values"]):
                    print("[+] Golden PCR values updated")
                else:
                    print("[-] Failed to update golden PCRs")
            else:
                print("[-] Failed to fetch PCR values")
                
        elif choice == "4":
            test_connection()
                
        elif choice == "5":
            print("\n[+] Exiting...")
            break
            
        else:
            print("[-] Invalid choice")

if __name__ == "__main__":
    main()