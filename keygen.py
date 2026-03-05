# -*- coding: utf-8 -*-
"""
keygen.py - RSA Key Pair Generation
Part of: Open-Source PKI Cryptographic Tool (ST6051CEM Coursework)
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os


def generate_rsa_keypair(bits=2048, output_dir="keys", key_name="user"):
    """
    Generate an RSA key pair and save as PEM files.
    Args:
        bits (int): Key size (2048 or 4096 recommended)
        output_dir (str): Folder to store key files
        key_name (str): Name prefix for files
    Returns:
        tuple: (private_key_path, public_key_path)
    """
    os.makedirs(output_dir, exist_ok=True)
    print(f"[*] Generating {bits}-bit RSA key pair for '{key_name}'...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    )
    pub_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    priv_path = os.path.join(output_dir, f"{key_name}_private.pem")
    pub_path  = os.path.join(output_dir, f"{key_name}_public.pem")

    with open(priv_path, "wb") as f: f.write(priv_pem)
    with open(pub_path,  "wb") as f: f.write(pub_pem)

    try: os.chmod(priv_path, 0o600)
    except Exception: pass

    print(f"[+] Private key saved : {priv_path}")
    print(f"[+] Public  key saved : {pub_path}")
    return priv_path, pub_path


def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


if __name__ == "__main__":
    generate_rsa_keypair(2048, "keys", "alice")
    generate_rsa_keypair(2048, "keys", "bob")
    print("\n[+] Key generation complete.")
