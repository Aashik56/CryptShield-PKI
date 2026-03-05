# -*- coding: utf-8 -*-
"""
certificates.py - Self-Signed X.509 Certificate Generation & Validation
Part of: Open-Source PKI Cryptographic Tool (ST6051CEM Coursework)

Implements a minimal Certificate Authority (CA) flow:
  1. CA generates its own self-signed root certificate
  2. Users/entities get certificates signed by the CA
  3. Certificates can be validated against the CA
  4. A Certificate Revocation List (CRL) is maintained
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import datetime
import os
import json


CRL_FILE = "certs/revoked_certs.json"


def _load_revoked():
    if os.path.exists(CRL_FILE):
        with open(CRL_FILE) as f:
            return json.load(f)
    return []


def _save_revoked(revoked):
    os.makedirs("certs", exist_ok=True)
    with open(CRL_FILE, "w") as f:
        json.dump(revoked, f, indent=2)


def generate_ca_certificate(output_dir="certs"):
    """
    Generate a self-signed CA root certificate and key pair.
    Returns: (ca_key, ca_cert) as cryptography objects
    """
    os.makedirs(output_dir, exist_ok=True)

    print("[*] Generating CA key pair and self-signed root certificate...")

    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI-Tool CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "PKI-Tool Root CA"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    # Save CA key
    with open(os.path.join(output_dir, "ca_key.pem"), "wb") as f:
        f.write(ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    # Save CA certificate
    with open(os.path.join(output_dir, "ca_cert.pem"), "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] CA key saved        : {output_dir}/ca_key.pem")
    print(f"[+] CA certificate saved: {output_dir}/ca_cert.pem")
    return ca_key, ca_cert


def issue_certificate(common_name, ca_key, ca_cert, output_dir="certs"):
    """
    Issue a certificate for an entity, signed by the CA.
    Args:
        common_name (str): Entity name (e.g. 'alice')
        ca_key: CA private key object
        ca_cert: CA certificate object
    Returns:
        (entity_key, entity_cert)
    """
    os.makedirs(output_dir, exist_ok=True)

    entity_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI-Tool Users"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    entity_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(entity_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    key_path  = os.path.join(output_dir, f"{common_name}_key.pem")
    cert_path = os.path.join(output_dir, f"{common_name}_cert.pem")

    with open(key_path, "wb") as f:
        f.write(entity_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    with open(cert_path, "wb") as f:
        f.write(entity_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Certificate issued for '{common_name}'")
    print(f"    Key : {key_path}")
    print(f"    Cert: {cert_path}")
    return entity_key, entity_cert


def validate_certificate(cert_path, ca_cert_path):
    """
    Validate a certificate against the CA, checking:
    - Signature validity (signed by CA)
    - Expiry date
    - Not on CRL (revocation list)
    Returns: True if valid
    """
    from cryptography.hazmat.primitives.asymmetric import padding as apad

    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # Check expiry
    now = datetime.datetime.now(datetime.timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        print(f"[✗] Certificate EXPIRED or not yet valid")
        return False

    # Check revocation list
    serial_hex = hex(cert.serial_number)
    if serial_hex in _load_revoked():
        print(f"[✗] Certificate is REVOKED (serial: {serial_hex})")
        return False

    # Verify CA signature
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            apad.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        print(f"[✓] Certificate VALID — signed by CA, not expired, not revoked")
        return True
    except Exception as e:
        print(f"[✗] Certificate signature INVALID: {e}")
        return False


def revoke_certificate(cert_path):
    """Add a certificate's serial number to the CRL."""
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    serial_hex = hex(cert.serial_number)
    revoked = _load_revoked()
    if serial_hex not in revoked:
        revoked.append(serial_hex)
        _save_revoked(revoked)
        print(f"[+] Certificate revoked (serial: {serial_hex})")
    else:
        print(f"[~] Certificate already revoked")


if __name__ == "__main__":
    ca_key, ca_cert = generate_ca_certificate()
    issue_certificate("alice", ca_key, ca_cert)
    issue_certificate("bob",   ca_key, ca_cert)
    validate_certificate("certs/alice_cert.pem", "certs/ca_cert.pem")
