# -*- coding: utf-8 -*-
"""
verify.py - Digital Signature Verification using RSA-PSS + SHA-256
Part of: Open-Source PKI Cryptographic Tool (ST6051CEM Coursework)

Also performs anti-replay validation using the .meta file.
"""

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os, json, time, hashlib

MAX_SIGNATURE_AGE = 3600  # seconds (1 hour)


def verify_signature(file_path, sig_path, public_key_path, check_replay=True):
    """
    Verify an RSA-PSS signature. Optionally checks anti-replay metadata.
    Returns: True if valid, False otherwise.
    """
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}"); return False
    if not os.path.exists(sig_path):
        print(f"[!] Signature not found: {sig_path}"); return False

    with open(public_key_path, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    with open(file_path, "rb") as f:
        data = f.read()
    with open(sig_path, "rb") as f:
        signature = f.read()

    # Cryptographic verification
    try:
        pub_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        print("[✗] SIGNATURE INVALID — file may be tampered or wrong key used.")
        return False
    except Exception as e:
        print(f"[✗] Verification error: {e}")
        return False

    print("[✓] Signature cryptographically VALID.")

    # Anti-replay check
    if check_replay:
        meta_path = sig_path + ".meta"
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                meta = json.load(f)
            age = time.time() - meta.get("timestamp", 0)
            if age > MAX_SIGNATURE_AGE:
                print(f"[!] REPLAY ATTACK — signature is {age:.0f}s old (max {MAX_SIGNATURE_AGE}s).")
                return False
            stored_hash = meta.get("sha256", "")
            actual_hash = hashlib.sha256(data).hexdigest()
            if stored_hash != actual_hash:
                print("[!] Hash mismatch in metadata — possible tampering.")
                return False
            print(f"[+] Anti-replay check PASSED (age: {age:.1f}s)")
        else:
            print("[~] No metadata — skipping replay check.")
    return True


if __name__ == "__main__":
    result = verify_signature(
        "encrypted_image.enc",
        "encrypted_image.enc.sig",
        "keys/alice_public.pem"
    )
    print("\n[Result]", "VERIFIED" if result else "FAILED")
