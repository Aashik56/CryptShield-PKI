# -*- coding: utf-8 -*-
"""
encrypt.py - Hybrid Encryption: RSA-OAEP (key wrap) + AES-256-GCM (data encryption)
Part of: Open-Source PKI Cryptographic Tool (ST6051CEM Coursework)

WHY HYBRID ENCRYPTION?
  - RSA can only encrypt small payloads — it wraps the AES session key only
  - AES-256-GCM encrypts the actual data: fast, authenticated (tamper-proof)
  - A fresh AES key is generated per file (provides forward secrecy per session)

OUTPUT FILE FORMAT:
  [2B: len(enc_key)] | [enc_key bytes] | [12B: GCM nonce] | [16B: GCM tag] | [ciphertext]
"""

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os, struct, secrets


def encrypt_file(input_path, recipient_public_key_path, output_path=None):
    """
    Encrypt a file for a recipient using hybrid RSA-OAEP + AES-256-GCM.
    Args:
        input_path (str): File to encrypt
        recipient_public_key_path (str): Recipient RSA public key PEM
        output_path (str): Output .enc file path (auto-named if None)
    Returns:
        str: Path to encrypted file
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"[!] File not found: {input_path}")
    if output_path is None:
        output_path = input_path + ".enc"

    with open(recipient_public_key_path, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    with open(input_path, "rb") as f:
        plaintext = f.read()

    # Step 1: Generate ephemeral 256-bit AES session key
    aes_key = secrets.token_bytes(32)

    # Step 2: Wrap AES key with RSA-OAEP (SHA-256)
    enc_aes_key = pub_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 3: Encrypt data with AES-256-GCM
    nonce = secrets.token_bytes(12)          # 96-bit GCM nonce
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # last 16 bytes = GCM tag

    # Step 4: Write structured output
    with open(output_path, "wb") as f:
        f.write(struct.pack(">H", len(enc_aes_key)))   # 2B key length
        f.write(enc_aes_key)                            # RSA-encrypted AES key
        f.write(nonce)                                  # 12B nonce
        f.write(ciphertext)                             # ciphertext + GCM tag (appended by AESGCM)

    print(f"[+] Encrypted  : {input_path} → {output_path}")
    print(f"[+] Method     : RSA-OAEP(SHA-256) + AES-256-GCM")
    print(f"[+] Enc key len: {len(enc_aes_key)} bytes")
    return output_path


if __name__ == "__main__":
    encrypt_file("original_image.png", "keys/bob_public.pem", "encrypted_image.enc")
