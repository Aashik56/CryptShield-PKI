# Open-Source PKI Cryptographic Tool
**Module ST6051CEM — Practical Cryptography | Softwarica College / Coventry University**

## Features
- **RSA-2048 Key Pair Generation** (PKCS#8 PEM format)
- **Hybrid Encryption**: RSA-OAEP + AES-256-GCM (authenticated encryption)
- **Digital Signatures**: RSA-PSS + SHA-256 with anti-replay metadata
- **X.509 Certificate Management**: CA creation, certificate issuance, validation, revocation (CRL)
- **Attack Mitigations**: MITM detection (GCM tag), replay attack prevention (timestamp), forgery detection

## Installation
```bash
pip install -r requirements.txt
```

## Quick Start
```bash
# Generate keys
python keygen.py

# Encrypt an image
python encrypt.py

# Decrypt the image
python decrypt.py

# Sign a file
python sign.py

# Verify a signature
python verify.py

# Run full demo (all 3 use cases)
python demo.py

# Run all tests
python tests/test_all.py
```

## File Descriptions
| File | Description |
|------|-------------|
| `keygen.py` | RSA-2048 key pair generation |
| `encrypt.py` | Hybrid RSA-OAEP + AES-256-GCM file encryption |
| `decrypt.py` | Hybrid decryption with GCM integrity verification |
| `sign.py` | RSA-PSS digital signature creation |
| `verify.py` | Signature verification with anti-replay check |
| `certificates.py` | X.509 certificate CA, issuance, validation, revocation |
| `demo.py` | End-to-end demonstration of all 3 use cases |
| `tests/test_all.py` | Full test suite (9 tests) |

## License
MIT License — open-source, freely extensible.
