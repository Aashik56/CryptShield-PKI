# -*- coding: utf-8 -*-
"""
tests/test_all.py - Comprehensive Test Suite (9 tests)
Part of: Open-Source PKI Cryptographic Tool (ST6051CEM Coursework)
"""

import sys, os, time, shutil, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keygen       import generate_rsa_keypair
from encrypt      import encrypt_file
from decrypt      import decrypt_file
from sign         import sign_file
from verify       import verify_signature
from certificates import generate_ca_certificate, issue_certificate, validate_certificate, revoke_certificate
import certificates as cert_module

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
results = []

def ok(name):   print(f"{PASS} {name}"); results.append((name, True))
def fail(name, r=""): print(f"{FAIL} {name}  {r}"); results.append((name, False))

def make_test_file(path, content=None):
    data = content or (b"TEST_IMAGE_DATA_" * 200)
    with open(path, "wb") as f: f.write(data)
    return path

def test_keygen():
    generate_rsa_keypair(2048, "test_keys", "alice")
    generate_rsa_keypair(2048, "test_keys", "bob")
    assert os.path.exists("test_keys/alice_private.pem")
    assert os.path.exists("test_keys/bob_public.pem")
    ok("Key Generation (Alice + Bob, 2048-bit RSA)")

def test_encrypt_decrypt():
    f = make_test_file("t_orig.png")
    encrypt_file(f, "test_keys/bob_public.pem", "t_enc.enc")
    decrypt_file("t_enc.enc", "test_keys/bob_private.pem", "t_dec.png")
    with open(f,"rb") as x: orig=x.read()
    with open("t_dec.png","rb") as x: dec=x.read()
    assert orig == dec
    ok("Hybrid Encrypt/Decrypt Round-Trip (AES-256-GCM + RSA-OAEP)")

def test_tamper_detection():
    with open("t_enc.enc","rb") as f: data=bytearray(f.read())
    data[-1] ^= 0xFF
    with open("t_tampered.enc","wb") as f: f.write(data)
    try:
        decrypt_file("t_tampered.enc", "test_keys/bob_private.pem", "t_tamper_dec.png")
        fail("Tamper Detection")
    except ValueError:
        ok("Tamper Detection (GCM tag rejects modified ciphertext)")

def test_sign_verify_valid():
    f = make_test_file("t_sign.png")
    sign_file(f, "test_keys/alice_private.pem", "t_sign.png.sig")
    assert verify_signature(f, "t_sign.png.sig", "test_keys/alice_public.pem", check_replay=False)
    ok("Sign + Verify (valid RSA-PSS signature)")

def test_wrong_key_rejection():
    f = make_test_file("t_sign2.png")
    sign_file(f, "test_keys/alice_private.pem", "t_sign2.png.sig")
    result = verify_signature(f, "t_sign2.png.sig", "test_keys/bob_public.pem", check_replay=False)
    assert result is False
    ok("Unauthorized Key Rejection (Bob cannot verify Alice's signature)")

def test_modified_file_rejection():
    f = make_test_file("t_integ.png")
    sign_file(f, "test_keys/alice_private.pem", "t_integ.png.sig")
    with open(f, "ab") as x: x.write(b"\x00TAMPERED")
    result = verify_signature(f, "t_integ.png.sig", "test_keys/alice_public.pem", check_replay=False)
    assert result is False
    ok("File Integrity (modified file fails signature verification)")

def test_certificate_flow():
    ca_key, ca_cert = generate_ca_certificate("test_certs")
    issue_certificate("alice", ca_key, ca_cert, "test_certs")
    valid = validate_certificate("test_certs/alice_cert.pem", "test_certs/ca_cert.pem")
    assert valid is True
    ok("Certificate Issuance + CA Validation")

def test_certificate_revocation():
    ca_key, ca_cert = generate_ca_certificate("test_certs2")
    issue_certificate("mallory", ca_key, ca_cert, "test_certs2")
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    with open("test_certs2/mallory_cert.pem","rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    with open("test_certs2/revoked_certs.json","w") as f:
        json.dump([hex(cert.serial_number)], f)
    orig = cert_module.CRL_FILE
    cert_module.CRL_FILE = "test_certs2/revoked_certs.json"
    valid = validate_certificate("test_certs2/mallory_cert.pem", "test_certs2/ca_cert.pem")
    cert_module.CRL_FILE = orig
    assert valid is False
    ok("Certificate Revocation (revoked cert correctly rejected)")

def test_replay_attack():
    f = make_test_file("t_replay.png")
    sign_file(f, "test_keys/alice_private.pem", "t_replay.png.sig")
    meta_path = "t_replay.png.sig.meta"
    with open(meta_path) as x: meta=json.load(x)
    meta["timestamp"] = time.time() - 7200  # backdate 2 hours
    with open(meta_path,"w") as x: json.dump(meta, x)
    result = verify_signature(f, "t_replay.png.sig", "test_keys/alice_public.pem", check_replay=True)
    assert result is False
    ok("Replay Attack Prevention (backdated signature rejected)")

def cleanup():
    for d in ["test_keys","test_certs","test_certs2"]:
        shutil.rmtree(d, ignore_errors=True)
    for fn in ["t_orig.png","t_enc.enc","t_dec.png","t_tampered.enc","t_tamper_dec.png",
               "t_sign.png","t_sign.png.sig","t_sign.png.sig.meta",
               "t_sign2.png","t_sign2.png.sig","t_sign2.png.sig.meta",
               "t_integ.png","t_integ.png.sig","t_integ.png.sig.meta",
               "t_replay.png","t_replay.png.sig","t_replay.png.sig.meta"]:
        try: os.remove(fn)
        except: pass


if __name__ == "__main__":
    print("=" * 60)
    print("  PKI Cryptographic Tool — Full Test Suite")
    print("=" * 60)
    for t in [test_keygen, test_encrypt_decrypt, test_tamper_detection,
              test_sign_verify_valid, test_wrong_key_rejection, test_modified_file_rejection,
              test_certificate_flow, test_certificate_revocation, test_replay_attack]:
        try: t()
        except Exception as e: fail(t.__name__, str(e))
    cleanup()
    passed = sum(1 for _,v in results if v)
    print(f"\n{'='*60}\n  Results: {passed}/{len(results)} tests passed\n{'='*60}")
    sys.exit(0 if passed == len(results) else 1)
