"""
common/crypto.py — All cryptographic operations for FS-PKI Chat.
RSA identity keys, X25519 ECDH, HKDF, AES-256-GCM, signatures, certificates, PKCS#12.
"""

import os
import uuid
import time
import json
import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    pkcs12, Encoding, PrivateFormat, PublicFormat,
    NoEncryption, BestAvailableEncryption,
)
from cryptography.hazmat.backends import default_backend

# ─── Constants ────────────────────────────────────────────────────────────────
RSA_KEY_SIZE = 3072
RSA_PUBLIC_EXPONENT = 65537
CERT_VALIDITY_DAYS = 365
TIMESTAMP_SKEW_SECONDS = 120
KEY_ROTATION_INTERVAL = 5  # rotate after N messages

# ─── RSA Key Generation ──────────────────────────────────────────────────────
def generate_rsa_keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
        backend=default_backend(),
    )

def serialize_public_key(key: rsa.RSAPublicKey) -> bytes:
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

def serialize_private_key(key: rsa.RSAPrivateKey, password: Optional[bytes] = None) -> bytes:
    enc = BestAvailableEncryption(password) if password else NoEncryption()
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)

def load_public_key(data: bytes) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(data, default_backend())

def load_private_key(data: bytes, password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(data, password, default_backend())

# ─── X25519 ECDH ─────────────────────────────────────────────────────────────
def generate_x25519_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    private = x25519.X25519PrivateKey.generate()
    return private, private.public_key()

def serialize_x25519_public(key: x25519.X25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)

def load_x25519_public(data: bytes) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(data)

def serialize_x25519_private(key: x25519.X25519PrivateKey) -> bytes:
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

def load_x25519_private(data: bytes) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(data)

def x25519_derive_shared(private: x25519.X25519PrivateKey, peer_public: x25519.X25519PublicKey) -> bytes:
    return private.exchange(peer_public)

# ─── HKDF ────────────────────────────────────────────────────────────────────
def hkdf_derive(shared_secret: bytes, info: bytes, length: int = 32, salt: Optional[bytes] = None) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend(),
    ).derive(shared_secret)

def derive_session_keys(shared_secret: bytes, sender: str, recipient: str) -> Tuple[bytes, bytes]:
    """Derive directional send/recv keys from ECDH shared secret."""
    pair = tuple(sorted([sender, recipient]))
    send_info = f"send-{pair[0]}-{pair[1]}".encode()
    recv_info = f"recv-{pair[0]}-{pair[1]}".encode()
    if sender == pair[0]:
        send_key = hkdf_derive(shared_secret, send_info)
        recv_key = hkdf_derive(shared_secret, recv_info)
    else:
        send_key = hkdf_derive(shared_secret, recv_info)
        recv_key = hkdf_derive(shared_secret, send_info)
    return send_key, recv_key

def derive_next_epoch_key(current_key: bytes, epoch: int) -> bytes:
    """Ratchet forward: derive next epoch key from current key."""
    return hkdf_derive(current_key, f"epoch-{epoch}".encode())

# ─── AES-256-GCM ─────────────────────────────────────────────────────────────
def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Returns (nonce, ciphertext_with_tag)."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ct

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)

# ─── RSA-PSS Signatures ──────────────────────────────────────────────────────
def rsa_sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

def rsa_verify(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

# ─── X.509 Certificates (mini-CA) ────────────────────────────────────────────
def create_ca_certificate(ca_key: rsa.RSAPrivateKey, cn: str = "FS-PKI-Chat CA") -> x509.Certificate:
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FS-PKI-Chat"),
    ])
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=CERT_VALIDITY_DAYS * 5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

def create_csr(private_key: rsa.RSAPrivateKey, username: str) -> x509.CertificateSigningRequest:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, username),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FS-PKI-Chat"),
        ]))
        .sign(private_key, hashes.SHA256(), default_backend())
    )

def sign_csr(ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate,
             csr: x509.CertificateSigningRequest, serial: Optional[int] = None) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    serial = serial or x509.random_serial_number()
    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=CERT_VALIDITY_DAYS))
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(Encoding.PEM)

def pem_to_cert(data: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(data, default_backend())

def csr_to_pem(csr: x509.CertificateSigningRequest) -> bytes:
    return csr.public_bytes(Encoding.PEM)

def pem_to_csr(data: bytes) -> x509.CertificateSigningRequest:
    return x509.load_pem_x509_csr(data, default_backend())

def verify_certificate_chain(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """Verify cert was signed by CA and is within validity."""
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        now = datetime.now(timezone.utc)
        # Handle both old and new cryptography API versions
        if hasattr(cert, 'not_valid_before_utc'):
            valid_from = cert.not_valid_before_utc
            valid_to = cert.not_valid_after_utc
        else:
            valid_from = cert.not_valid_before.replace(tzinfo=timezone.utc)
            valid_to = cert.not_valid_after.replace(tzinfo=timezone.utc)
        if valid_from > now or valid_to < now:
            return False
        return True
    except Exception:
        return False

def get_cert_serial(cert: x509.Certificate) -> str:
    return str(cert.serial_number)

def get_cert_cn(cert: x509.Certificate) -> str:
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

# ─── PKCS#12 Keystore ────────────────────────────────────────────────────────
def create_keystore(private_key: rsa.RSAPrivateKey, cert: x509.Certificate,
                    password: bytes, name: str = "user") -> bytes:
    return pkcs12.serialize_key_and_certificates(
        name.encode(), private_key, cert, None,
        BestAvailableEncryption(password),
    )

def load_keystore(data: bytes, password: bytes):
    key, cert, _ = pkcs12.load_key_and_certificates(data, password, default_backend())
    return key, cert

# ─── CA key encryption at rest ────────────────────────────────────────────────
def encrypt_ca_key(ca_key: rsa.RSAPrivateKey, passphrase: str) -> dict:
    """Encrypt the CA private key with AES-GCM derived from passphrase."""
    salt = os.urandom(16)
    dk = hkdf_derive(passphrase.encode(), b"ca-key-encryption", 32, salt)
    key_bytes = serialize_private_key(ca_key)
    nonce, ct = aes_gcm_encrypt(dk, key_bytes)
    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }

def decrypt_ca_key(enc: dict, passphrase: str) -> rsa.RSAPrivateKey:
    salt = base64.b64decode(enc["salt"])
    nonce = base64.b64decode(enc["nonce"])
    ct = base64.b64decode(enc["ciphertext"])
    dk = hkdf_derive(passphrase.encode(), b"ca-key-encryption", 32, salt)
    key_bytes = aes_gcm_decrypt(dk, nonce, ct)
    return load_private_key(key_bytes)

# ─── Envelope helpers ─────────────────────────────────────────────────────────
def generate_message_id() -> str:
    return str(uuid.uuid4())

def current_timestamp() -> float:
    return time.time()

def check_timestamp_skew(ts: float, max_skew: float = TIMESTAMP_SKEW_SECONDS) -> bool:
    return abs(time.time() - ts) <= max_skew

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

def build_signature_payload(sender: str, recipient: str, message_id: str,
                            timestamp: float, nonce: bytes, ciphertext: bytes) -> bytes:
    """Build the canonical bytes that get signed."""
    return f"{sender}|{recipient}|{message_id}|{timestamp}|".encode() + nonce + ciphertext
