#!/usr/bin/env python3
"""Interactive hash & encryption calculator.

Supports:
  - SHA-256 hashing (text or file)
  - AES-256-GCM encrypt/decrypt (passphrase-derived or raw key)
  - RSA-OAEP encrypt/decrypt with key pair generation

Requires: pip install cryptography
"""

import base64
import binascii
import getpass
import hashlib
import secrets
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 600_000
SALT_LEN = 16   # bytes, PBKDF2 salt
NONCE_LEN = 12  # bytes, GCM nonce
KEY_LEN = 32    # bytes, AES-256


# ---------------------------------------------------------------------------
# Core crypto operations (pure functions, no I/O)
# ---------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def aes_encrypt_passphrase(passphrase: str, plaintext: bytes) -> bytes:
    """Returns salt || nonce || ciphertext+tag."""
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key(passphrase, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return salt + nonce + ct


def aes_decrypt_passphrase(passphrase: str, token: bytes) -> bytes:
    if len(token) < SALT_LEN + NONCE_LEN + 16:
        raise ValueError("Token too short to be a valid passphrase-mode message.")
    salt, nonce, ct = (
        token[:SALT_LEN],
        token[SALT_LEN:SALT_LEN + NONCE_LEN],
        token[SALT_LEN + NONCE_LEN:],
    )
    key = derive_key(passphrase, salt)
    return AESGCM(key).decrypt(nonce, ct, None)


def aes_encrypt_raw(key: bytes, plaintext: bytes) -> bytes:
    """Returns nonce || ciphertext+tag."""
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ct


def aes_decrypt_raw(key: bytes, token: bytes) -> bytes:
    if len(token) < NONCE_LEN + 16:
        raise ValueError("Token too short to be a valid raw-key message.")
    nonce, ct = token[:NONCE_LEN], token[NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, None)


def parse_raw_key(text: str) -> bytes:
    """Accept a 256-bit key as 64 hex chars or base64."""
    text = text.strip()
    try:
        if len(text) == 64:
            key = bytes.fromhex(text)
        else:
            key = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Key must be 64 hex characters or base64 for 32 bytes.")
    if len(key) != KEY_LEN:
        raise ValueError(f"Key must be exactly 32 bytes, got {len(key)}.")
    return key


def rsa_generate(bits: int):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def oaep_max_len(public_key) -> int:
    return public_key.key_size // 8 - 2 * 32 - 2  # SHA-256 OAEP overhead


def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    limit = oaep_max_len(public_key)
    if len(plaintext) > limit:
        raise ValueError(
            f"Message is {len(plaintext)} bytes but RSA-OAEP with a "
            f"{public_key.key_size}-bit key caps out at {limit} bytes. "
            "For bigger data, encrypt it with AES-256-GCM and use RSA "
            "only to encrypt the AES key."
        )
    return public_key.encrypt(plaintext, OAEP)


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(ciphertext, OAEP)


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------

def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def ask_choice(prompt: str, choices: dict) -> str:
    """choices: {'1': 'label', ...} — returns the chosen key."""
    print(f"\n{prompt}")
    for key, label in choices.items():
        print(f"  {key}) {label}")
    while True:
        pick = input("> ").strip()
        if pick in choices:
            return pick
        print(f"Please enter one of: {', '.join(choices)}")


def ask_secret(prompt: str) -> str:
    while True:
        value = getpass.getpass(f"{prompt}: ")
        if value:
            return value
        print("Cannot be empty.")


def read_pem(prompt: str, default_path: str) -> bytes:
    """Accept a file path, or a pasted PEM block starting with '-----'."""
    first = ask(f"{prompt} (file path, or paste PEM)", default_path)
    if not first.startswith("-----"):
        path = Path(first).expanduser()
        if not path.is_file():
            raise ValueError(f"No such file: {path}")
        return path.read_bytes()
    lines = [first]
    while not lines[-1].startswith("-----END"):
        lines.append(input())
    return "\n".join(lines).encode() + b"\n"


def show(label: str, value: str) -> None:
    print(f"\n{label}:\n{value}")


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------

def do_sha256() -> None:
    pick = ask_choice("Hash what?", {"1": "Text", "2": "File"})
    if pick == "1":
        data = input("Text to hash: ").encode("utf-8")
        source = f"{len(data)} bytes of text"
    else:
        path = Path(ask("File path")).expanduser()
        if not path.is_file():
            raise ValueError(f"No such file: {path}")
        data = path.read_bytes()
        source = f"{path.name} ({len(data):,} bytes)"
    digest = hashlib.sha256(data).digest()
    print(f"\nSHA-256 of {source}")
    show("Hex", digest.hex())
    show("Base64", base64.b64encode(digest).decode())


def get_aes_key_for_encrypt():
    """Returns (mode, key_or_passphrase). mode is 'pass' or 'raw'."""
    pick = ask_choice("Key options", {
        "1": "Passphrase (a key is derived with PBKDF2)",
        "2": "Raw 256-bit key (hex or base64)",
        "3": "Generate a random key for me",
    })
    if pick == "1":
        return "pass", ask_secret("Passphrase")
    if pick == "2":
        return "raw", parse_raw_key(input("Key: "))
    key = secrets.token_bytes(KEY_LEN)
    print("\nGenerated key — SAVE THIS, it will not be shown again:")
    show("Hex", key.hex())
    show("Base64", base64.b64encode(key).decode())
    return "raw", key


def do_aes_encrypt() -> None:
    mode, secret = get_aes_key_for_encrypt()
    plaintext = input("\nText to encrypt: ").encode("utf-8")
    if mode == "pass":
        token = aes_encrypt_passphrase(secret, plaintext)
        layout = f"salt({SALT_LEN}) || nonce({NONCE_LEN}) || ciphertext+tag"
    else:
        token = aes_encrypt_raw(secret, plaintext)
        layout = f"nonce({NONCE_LEN}) || ciphertext+tag"
    print(f"\nEncrypted. Token layout: base64( {layout} )")
    show("Token", base64.b64encode(token).decode())


def do_aes_decrypt() -> None:
    pick = ask_choice("How was it encrypted?", {
        "1": "With a passphrase",
        "2": "With a raw 256-bit key",
    })
    try:
        token = base64.b64decode(input("Token (base64): ").strip(), validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("That is not valid base64.")
    if pick == "1":
        plaintext = aes_decrypt_passphrase(ask_secret("Passphrase"), token)
    else:
        plaintext = aes_decrypt_raw(parse_raw_key(input("Key: ")), token)
    show("Decrypted text", plaintext.decode("utf-8", errors="replace"))


def do_rsa_keygen() -> None:
    pick = ask_choice("Key size", {
        "1": "2048-bit (fast, fine for most uses)",
        "2": "3072-bit",
        "3": "4096-bit (slow to generate)",
    })
    bits = {"1": 2048, "2": 3072, "3": 4096}[pick]
    print(f"\nGenerating {bits}-bit RSA key pair...")
    private_key = rsa_generate(bits)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    show("Public key", pub_pem.decode())
    show("Private key (keep secret!)", priv_pem.decode())
    if ask("Save to files? (y/n)", "y").lower().startswith("y"):
        pub_path = Path(ask("Public key file", "rsa_public.pem")).expanduser()
        priv_path = Path(ask("Private key file", "rsa_private.pem")).expanduser()
        pub_path.write_bytes(pub_pem)
        priv_path.write_bytes(priv_pem)
        priv_path.chmod(0o600)
        print(f"Saved {pub_path} and {priv_path} (private key mode 600).")


def do_rsa_encrypt() -> None:
    pem = read_pem("Public key", "rsa_public.pem")
    try:
        public_key = serialization.load_pem_public_key(pem)
    except ValueError:
        raise ValueError("Could not parse that as a PEM public key.")
    limit = oaep_max_len(public_key)
    plaintext = input(f"Text to encrypt (max {limit} bytes): ").encode("utf-8")
    ciphertext = rsa_encrypt(public_key, plaintext)
    show("Ciphertext (base64)", base64.b64encode(ciphertext).decode())


def load_private_key_interactive():
    pem = read_pem("Private key", "rsa_private.pem")
    try:
        private_key = serialization.load_pem_private_key(pem, password=None)
    except TypeError:
        pw = ask_secret("Private key passphrase")
        private_key = serialization.load_pem_private_key(pem, password=pw.encode())
    except ValueError:
        raise ValueError("Could not parse that as a PEM private key.")
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("That PEM is not an RSA private key.")
    return private_key


def do_rsa_decrypt() -> None:
    private_key = load_private_key_interactive()
    try:
        ciphertext = base64.b64decode(input("Ciphertext (base64): ").strip(), validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("That is not valid base64.")
    plaintext = rsa_decrypt(private_key, ciphertext)
    show("Decrypted text", plaintext.decode("utf-8", errors="replace"))


def do_rsa_inspect() -> None:
    """Print the raw numbers inside an RSA private key — for learning only."""
    private_key = load_private_key_interactive()
    nums = private_key.private_numbers()
    pub = nums.public_numbers

    def show_num(label: str, role: str, value: int) -> None:
        print(f"\n{label}  — {role}  [{value.bit_length()} bits]")
        print(value)

    print(f"\nRSA-{private_key.key_size} private key internals")
    print("=" * 46)
    show_num("n", "modulus = p * q (public, safe to share)", pub.n)
    show_num("e", "public exponent (public)", pub.e)
    show_num("p", "prime factor 1 (SECRET)", nums.p)
    show_num("q", "prime factor 2 (SECRET)", nums.q)
    show_num("d", "private exponent, derived from p and q (SECRET)", nums.d)
    print(f"\nSanity check p * q == n: {nums.p * nums.q == pub.n}")
    print("\nNote: anyone who learns p and q can recompute d in seconds —")
    print("this view is for learning; never print these in a real system.")


# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------

MENU = {
    "1": ("SHA-256 hash", do_sha256),
    "2": ("AES-256-GCM encrypt", do_aes_encrypt),
    "3": ("AES-256-GCM decrypt", do_aes_decrypt),
    "4": ("RSA generate key pair", do_rsa_keygen),
    "5": ("RSA encrypt", do_rsa_encrypt),
    "6": ("RSA decrypt", do_rsa_decrypt),
    "7": ("RSA key internals (p, q, n, e, d)", do_rsa_inspect),
    "0": ("Exit", None),
}


def main() -> None:
    print("=" * 46)
    print("  Crypto Calculator")
    print("  SHA-256 | AES-256-GCM | RSA-OAEP(SHA-256)")
    print("=" * 46)
    while True:
        print()
        for key, (label, _) in MENU.items():
            print(f"  {key}) {label}")
        pick = input("\nChoose an option > ").strip()
        if pick == "0":
            print("Bye!")
            return
        entry = MENU.get(pick)
        if entry is None:
            print(f"Unknown option {pick!r} — enter 0-7.")
            continue
        try:
            entry[1]()
        except InvalidTag:
            print("\nERROR: Decryption failed — wrong passphrase/key, or the "
                  "token was modified.")
        except (ValueError, OSError) as exc:
            print(f"\nERROR: {exc}")
        except KeyboardInterrupt:
            print("\n(cancelled)")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nBye!")
