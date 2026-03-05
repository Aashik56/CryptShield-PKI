# -*- coding: utf-8 -*-
"""
sign.py - Digital Signature Creation using RSA-PSS + SHA-256
Part of: Open-Source PKI Cryptographic Tool (ST6051CEM Coursework)

RSA-PSS is used instead of PKCS#1 v1.5 because PSS provides
provable security and resistance to chosen-message attacks.
Anti-replay metadata (timestamp + file hash) is stored alongside signatures.
"""

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os, json, time, hashlib


def sign_file(file_path, private_key_path, sig_output=None):
    """
    Sign a file with RSA-PSS (SHA-256). Also writes anti-replay metadata.
    Args:
        file_path (str): File to sign
        private_key_path (str): Signer's private key PEM
        sig_output (str): Output .sig path
    Returns:
        str: Path to .sig file
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"[!] File not found: {file_path}")
    if sig_output is None:
        sig_output = file_path + ".sig"

    with open(private_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    with open(file_path, "rb") as f:
        data = f.read()

    # Compute SHA-256 hash for metadata reference
    sha256_hex = hashlib.sha256(data).hexdigest()

    # Sign with RSA-PSS
    signature = priv_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Write signature file
    with open(sig_output, "wb") as f:
        f.write(signature)

    # Write anti-replay metadata
    metadata = {
        "file": os.path.basename(file_path),
        "sha256": sha256_hex,
        "timestamp": time.time(),
        "signer_key": os.path.basename(private_key_path),
    }
    with open(sig_output + ".meta", "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[+] Signed             : {file_path}")
    print(f"[+] Signature saved    : {sig_output}")
    print(f"[+] Anti-replay meta   : {sig_output}.meta")
    print(f"[+] SHA-256            : {sha256_hex}")
    return sig_output


if __name__ == "__main__":
    sign_file("encrypted_image.enc", "keys/alice_private.pem", "encrypted_image.enc.sig")
