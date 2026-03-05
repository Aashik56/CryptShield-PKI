# -*- coding: utf-8 -*-
"""
demo.py - End-to-End Demonstration (3 Real-World Use Cases)
Part of: Open-Source PKI Cryptographic Tool (ST6051CEM Coursework)
"""

import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from keygen       import generate_rsa_keypair
from encrypt      import encrypt_file
from decrypt      import decrypt_file
from sign         import sign_file
from verify       import verify_signature
from certificates import generate_ca_certificate, issue_certificate, validate_certificate, revoke_certificate
import certificates as cert_module

def banner(t): print(f"\n{'='*60}\n  {t}\n{'='*60}")

def make_sample(path, size=4000):
    data = bytes([137,80,78,71,13,10,26,10]) + b"PIXEL_DATA_" * size
    with open(path,"wb") as f: f.write(data)
    print(f"[*] Created sample file: {path} ({len(data)} bytes)")
    return path

# ─── USE CASE 1: Confidential File Sharing ────────────────────────────────────
def use_case_1():
    banner("USE CASE 1: Confidential Image Sharing (Alice → Bob)")
    print("  PROBLEM: Alice must send a medical image to Bob securely.")
    print("  SOLUTION: Hybrid RSA-OAEP + AES-256-GCM encryption.\n")

    os.makedirs("demo_keys", exist_ok=True)
    generate_rsa_keypair(2048,"demo_keys","alice")
    generate_rsa_keypair(2048,"demo_keys","bob")

    img = make_sample("demo_orig.png")
    print("\n[Alice] Encrypting image for Bob using his public key...")
    enc = encrypt_file(img, "demo_keys/bob_public.pem", "demo_enc.enc")

    print("\n[Bob] Decrypting received image with his private key...")
    dec = decrypt_file(enc, "demo_keys/bob_private.pem", "demo_dec.png")

    with open(img,"rb") as f: o=f.read()
    with open(dec,"rb") as f: d=f.read()
    print(f"\n[✓] Round-trip integrity: {'MATCH' if o==d else 'MISMATCH'}")

    print("\n[Attacker] Tampering ciphertext in transit (MITM simulation)...")
    with open(enc,"rb") as f: data=bytearray(f.read())
    data[-1]^=0xFF
    with open("demo_mitm.enc","wb") as f: f.write(data)
    try:
        decrypt_file("demo_mitm.enc", "demo_keys/bob_private.pem", "demo_mitm_dec.png")
        print("[!] MITM undetected (bad)")
    except ValueError as e:
        print(f"[✓] MITM blocked: {e}")

# ─── USE CASE 2: Document Signing ────────────────────────────────────────────
def use_case_2():
    banner("USE CASE 2: Contract Signing & Forgery Prevention")
    print("  PROBLEM: Company needs tamper-proof signed contracts.")
    print("  SOLUTION: RSA-PSS digital signatures with SHA-256.\n")

    contract = "demo_contract.txt"
    with open(contract,"w") as f:
        f.write("SERVICES CONTRACT\nParty A: Alice Corp\nParty B: Bob Ltd\nAmount: $50,000\n")

    print("[Alice] Signing contract...")
    sign_file(contract, "demo_keys/alice_private.pem", contract+".sig")

    print("\n[Verifier] Verifying Alice's signature...")
    r = verify_signature(contract, contract+".sig", "demo_keys/alice_public.pem", check_replay=False)
    print(f"[{'✓' if r else '✗'}] Result: {'VALID' if r else 'INVALID'}")

    print("\n[Bob] Trying to verify with his own (wrong) key...")
    r2 = verify_signature(contract, contract+".sig", "demo_keys/bob_public.pem", check_replay=False)
    print(f"[{'✗' if r2 else '✓'}] Forgery: {'undetected (BAD)' if r2 else 'blocked'}")

    print("\n[Attacker] Modifying contract amount after signing...")
    with open(contract,"a") as f: f.write("MODIFIED AMOUNT: $999,999\n")
    r3 = verify_signature(contract, contract+".sig", "demo_keys/alice_public.pem", check_replay=False)
    print(f"[{'✗' if r3 else '✓'}] Tamper: {'undetected (BAD)' if r3 else 'detected — modification caught!'}")

# ─── USE CASE 3: PKI Certificate Authentication ───────────────────────────────
def use_case_3():
    banner("USE CASE 3: Certificate-Based Identity Authentication")
    print("  PROBLEM: Organisation needs to authenticate only verified employees.")
    print("  SOLUTION: X.509 certificates with CA, validation, and revocation.\n")

    os.makedirs("demo_certs", exist_ok=True)
    print("[CA] Creating root Certificate Authority...")
    ca_key, ca_cert = generate_ca_certificate("demo_certs")

    print("\n[CA] Issuing certificates to Alice and Mallory...")
    issue_certificate("alice",   ca_key, ca_cert, "demo_certs")
    issue_certificate("mallory", ca_key, ca_cert, "demo_certs")

    print("\n[Server] Validating Alice's certificate...")
    validate_certificate("demo_certs/alice_cert.pem", "demo_certs/ca_cert.pem")

    print("\n[CA] Revoking Mallory's certificate (security breach detected)...")
    from cryptography import x509; from cryptography.hazmat.backends import default_backend
    with open("demo_certs/mallory_cert.pem","rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    with open("demo_certs/revoked_certs.json","w") as f:
        json.dump([hex(cert.serial_number)], f)

    orig = cert_module.CRL_FILE
    cert_module.CRL_FILE = "demo_certs/revoked_certs.json"
    print("\n[Server] Validating Mallory's (now revoked) certificate...")
    validate_certificate("demo_certs/mallory_cert.pem", "demo_certs/ca_cert.pem")
    cert_module.CRL_FILE = orig


if __name__ == "__main__":
    use_case_1()
    use_case_2()
    use_case_3()
    banner("ALL USE CASES COMPLETE")
