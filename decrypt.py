# -*- coding: utf-8 -*-
"""
decrypt.py - Hybrid Decryption: RSA-OAEP (key unwrap) + AES-256-GCM (data)
Part of: Open-Source PKI Cryptographic Tool (ST6051CEM Coursework)

AES-GCM automatically verifies the authentication tag — any modification
to the ciphertext raises an InvalidTag exception, detecting tampering.
"""

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os, struct


def decrypt_file(encrypted_path, private_key_path, output_path=None):
    """
    Decrypt a hybrid RSA-OAEP + AES-256-GCM encrypted file.
    Args:
        encrypted_path (str): Path to .enc file
        private_key_path (str): Recipient's RSA private key PEM
        output_path (str): Output path for decrypted file
    Returns:
        str: Path to decrypted file
    """
    if not os.path.exists(encrypted_path):
        raise FileNotFoundError(f"[!] Encrypted file not found: {encrypted_path}")
    if output_path is None:
        output_path = encrypted_path.replace(".enc", ".decrypted")

    with open(private_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    with open(encrypted_path, "rb") as f:
        key_len    = struct.unpack(">H", f.read(2))[0]
        enc_aes_key = f.read(key_len)
        nonce       = f.read(12)
        ciphertext  = f.read()           # includes 16-byte GCM tag at end

    # Step 1: Unwrap AES key with RSA private key
    try:
        aes_key = priv_key.decrypt(
            enc_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"[!] RSA decryption failed — wrong key or corrupted data: {e}")

    # Step 2: Decrypt and verify integrity with AES-256-GCM
    aesgcm = AESGCM(aes_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("[!] AES-GCM authentication FAILED — data has been tampered with!")

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"[+] Decrypted  : {encrypted_path} → {output_path}")
    print(f"[+] GCM integrity check PASSED — data is authentic and unmodified")
    return output_path


if __name__ == "__main__":
    decrypt_file("encrypted_image.enc", "keys/bob_private.pem", "decrypted_image.png")
