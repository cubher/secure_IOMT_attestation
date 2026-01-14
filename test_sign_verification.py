import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
from typing import Dict, Any
import requests

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


TARGET_URL = "http://10.250.149.152:4000"
PUBLIC_KEY_PATH = "c2_pub.pem" # raspi public key
PRIVATE_KEY_PATH = "c2_priv.pem" #c2 private key

def encrypt_message(message: bytes, session_key: bytes) -> bytes:
    print("[*] Encrypting message using AES-GCM")

    nonce = os.urandom(12)
    print(f"[+] Nonce generated (12 bytes): {nonce.hex()}")

    aesgcm = AESGCM(session_key)

    ciphertext = aesgcm.encrypt(
        nonce,
        message,
        None
    )

    print("[+] Message encrypted successfully")

    encrypted_blob = nonce + ciphertext
    encrypted_b64 = base64.b64encode(encrypted_blob)

    print("[*] Ciphertext Base64 encoded")

    return encrypted_b64



def decrypt_message(encrypted_b64: bytes, session_key: bytes) -> bytes:
    print("[*] Decrypting message using AES-GCM")

    encrypted_blob = base64.b64decode(encrypted_b64)
    print("[*] Base64 decoded")

    nonce = encrypted_blob[:12]
    ciphertext = encrypted_blob[12:]

    print(f"[+] Extracted nonce: {nonce.hex()}")

    aesgcm = AESGCM(session_key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    )

    print("[+] Message decrypted successfully")

    return plaintext



def generate_and_encrypt_session_key():
    print("[*] Generating AES-256 session key")

    session_key = os.urandom(32)
    print("[+] Session key generated (32 bytes)")

    print(f"[*] Loading public key from: {PUBLIC_KEY_PATH}")
    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    print("[*] Encrypting session key using RSA-OAEP (SHA256)")
    encrypted_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("[+] Session key encrypted successfully")

    return session_key, encrypted_key



def decrypt_session_key(encrypted_key: bytes) -> bytes:
    print(f"[*] Loading private key from: {PRIVATE_KEY_PATH}")

    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    print("[*] Decrypting session key using RSA-OAEP (SHA256)")
    session_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("[+] Session key decrypted successfully")

    return session_key



def sign_message(message: bytes) -> bytes:
    """
    Signs a message using an RSA private key.

    Args:
        message (bytes): Message to sign

    Returns:
        bytes: Signature
    """

    # Load private key
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None  # set if your key is encrypted
        )

    # Sign the message
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return signature



def verify_signature(message: bytes, signature: bytes) -> bool:
    """
    Verifies an RSA signature using a public key.

    Args:
        message (bytes): Original message data
        signature (bytes): Signature to verify

    Returns:
        bool: True if signature is valid, False otherwise
    """

    try:
        # Load public key
        with open(PUBLIC_KEY_PATH, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )

        # Verify signature
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        return True

    except InvalidSignature:
        return False

    except Exception as e:
        print(f"[!] Verification error: {e}")
        return False


def prepare_secure_payload(data: Dict[str, Any]) -> Dict[str, str]:
    """
    1. Serialize data
    2. Sign data
    3. Wrap {data, sig}
    4. Encrypt using AES session key
    5. Base64 encode encrypted payload
    """

    # ----------------------------
    # Step 1: Serialize data
    # ----------------------------
    data_bytes = json.dumps(data, separators=(",", ":")).encode()
    
    # ----------------------------
    # Step 2: Sign original data
    # ----------------------------
    signature = sign_message(data_bytes)
    signature_b64 = base64.b64encode(signature).decode()

    # ----------------------------
    # Step 3: Construct signed body
    # ----------------------------
    signed_body = {
        "data": data,
        "sig": signature_b64
    }

    signed_body_bytes = json.dumps(signed_body, separators=(",", ":")).encode()

    # ----------------------------
    # Step 4: Generate + encrypt session key
    # ----------------------------
    session_key, encrypted_session_key = generate_and_encrypt_session_key()

    encrypted_session_key_b64 = base64.b64encode(encrypted_session_key).decode()

    # ----------------------------
    # Step 5: Encrypt signed body
    # ----------------------------
    encrypted_payload_b64 = encrypt_message(
        signed_body_bytes,
        session_key
    ).decode()

    # ----------------------------
    # Final message format
    # ----------------------------
    final_payload = {
        "session_key_b64": encrypted_session_key_b64,
        "data_b64": encrypted_payload_b64
    }

    return final_payload


def send_secure_message(data: Dict[str, Any], url: str = TARGET_URL) -> None:
    """
    Sends encrypted + signed message to target server via POST
    """

    payload = prepare_secure_payload(data)

    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(
        url,
        json=payload,
        headers=headers,
        timeout=5
    )

    response.raise_for_status()

    print("[+] Secure message sent successfully")
    print(f"[+] Server response: {response.text}")



# def main():
#     print("\n================ START FLOW ================\n")

#     # Original message
#     message = b"hello from raspberry pi"
#     print("[*] Original message:", message)

#     # ------------------------------------------------
#     # 1. SIGN MESSAGE
#     # ------------------------------------------------
#     print("\n=== STEP 1: SIGN MESSAGE ===")
#     signature = sign_message(message)
#     print("[+] Message signed")

#     with open("sig.bin", "wb") as f:
#         f.write(signature)
#     print("[+] Signature written to sig.bin")

#     # ------------------------------------------------
#     # 2. SESSION KEY EXCHANGE
#     # ------------------------------------------------
#     print("\n=== STEP 2: SESSION KEY EXCHANGE ===")
#     session_key_sender, encrypted_key = generate_and_encrypt_session_key()
#     print("[+] Encrypted session key generated")

#     session_key_receiver = decrypt_session_key(encrypted_key)
#     print("[+] Session key decrypted on receiver side")

#     # Sanity check (debug only)
#     if session_key_sender == session_key_receiver:
#         print("[DEBUG] Session keys MATCH")
#     else:
#         print("[ERROR] Session keys DO NOT MATCH")
#         return

#     # ------------------------------------------------
#     # 3. ENCRYPT MESSAGE
#     # ------------------------------------------------
#     print("\n=== STEP 3: ENCRYPT MESSAGE ===")
#     encrypted_msg = encrypt_message(message, session_key_sender)
#     print("[+] Message encrypted")

#     # ------------------------------------------------
#     # 4. DECRYPT MESSAGE
#     # ------------------------------------------------
#     print("\n=== STEP 4: DECRYPT MESSAGE ===")
#     decrypted_msg = decrypt_message(encrypted_msg, session_key_receiver)
#     print("[+] Message decrypted")
#     print("[*] Decrypted message:", decrypted_msg)

#     # ------------------------------------------------
#     # 5. VERIFY SIGNATURE
#     # ------------------------------------------------
#     print("\n=== STEP 5: VERIFY SIGNATURE ===")

#     if verify_signature(decrypted_msg, signature):
#         print("[SUCCESS] Signature VALID")
#     else:
#         print("[FAILURE] Signature INVALID")

#     print("\n================ END FLOW ==================\n") 

# if __name__ == "__main__":
#     main()