# Crypto Calculator

An interactive command-line hash and encryption calculator, built for learning
how real cryptography fits together.

```
  1) SHA-256 hash
  2) AES-256-GCM encrypt
  3) AES-256-GCM decrypt
  4) RSA generate key pair
  5) RSA encrypt
  6) RSA decrypt
  7) RSA key internals (p, q, n, e, d)
  0) Exit
```

## Features

- **SHA-256** — hash text or files, output in hex and base64
- **AES-256-GCM** — authenticated encryption with three key options:
  passphrase (PBKDF2-HMAC-SHA256, 600,000 iterations), your own raw
  256-bit key (hex or base64), or a freshly generated random key.
  Passphrase mode is `salt ∥ nonce ∥ ciphertext+tag`; raw and generated
  key mode is `nonce ∥ ciphertext+tag`.
- **RSA-OAEP (SHA-256)** — generate 2048/3072/4096-bit key pairs as PEM
  files, encrypt with a public key, decrypt with a private key.
  Enforces and explains the OAEP plaintext size limit.
- **Key internals viewer** — prints `p`, `q`, `n`, `e`, and `d` from any
  RSA private key, with a live `p × q == n` check. For learning only.

Wrong keys, wrong passphrases, and tampered ciphertexts are all rejected
with clear error messages — GCM's authentication tag makes silent
corruption impossible.

## Install & run

```bash
pip install cryptography
python3 crypto_calculator.py
```

Requires Python 3.9+.

## Security notes

- Salts, nonces, and generated AES keys come from `secrets.token_bytes`.
  RSA keys come from `rsa.generate_private_key` (OpenSSL RNG).
- Passphrases are read with `getpass` (hidden input) and stretched with
  PBKDF2 — never used directly as keys.
- Generated private key files are written with mode `600`.
- The key internals viewer prints secret values by design — it exists to
  teach how RSA works. Never do that in a real system.

## Layout of the code

`crypto_calculator.py` is organised in three layers:

1. **Crypto helpers** — SHA-256, AES-256-GCM, and RSA-OAEP
2. **Prompt helpers** — reusable input/PEM-reading utilities
3. **Menu actions** — one `do_*` function per menu item

Built on [`cryptography`](https://cryptography.io), the OpenSSL-backed
standard library for Python crypto.
