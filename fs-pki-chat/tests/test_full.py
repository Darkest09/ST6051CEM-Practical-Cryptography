"""
tests/test_full.py — Comprehensive test suite for FS-PKI Chat.
Covers: crypto primitives, e2e messaging, replay, revocation, key rotation, tamper, expired cert.
Uses unittest + Flask test client (no external dependencies needed).
"""

import os
import sys
import json
import time
import shutil
import unittest
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.crypto import (
    generate_rsa_keypair, create_ca_certificate, cert_to_pem, pem_to_cert,
    create_csr, csr_to_pem, sign_csr, pem_to_csr,
    generate_x25519_keypair, serialize_x25519_public, load_x25519_public,
    serialize_x25519_private, load_x25519_private,
    x25519_derive_shared, derive_session_keys, derive_next_epoch_key,
    aes_gcm_encrypt, aes_gcm_decrypt,
    rsa_sign, rsa_verify,
    encrypt_ca_key, decrypt_ca_key,
    create_keystore, load_keystore,
    verify_certificate_chain, get_cert_serial,
    build_signature_payload, generate_message_id, b64e, b64d,
    KEY_ROTATION_INTERVAL,
)


# ═══════════════════════════════════════════════════════════════════════════════
# CRYPTO UNIT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestRSA(unittest.TestCase):
    def test_keygen_and_sign_verify(self):
        key = generate_rsa_keypair()
        data = b"test data to sign"
        sig = rsa_sign(key, data)
        self.assertTrue(rsa_verify(key.public_key(), sig, data))

    def test_signature_wrong_data(self):
        key = generate_rsa_keypair()
        sig = rsa_sign(key, b"correct data")
        self.assertFalse(rsa_verify(key.public_key(), sig, b"wrong data"))

    def test_signature_wrong_key(self):
        key1 = generate_rsa_keypair()
        key2 = generate_rsa_keypair()
        sig = rsa_sign(key1, b"data")
        self.assertFalse(rsa_verify(key2.public_key(), sig, b"data"))


class TestX25519(unittest.TestCase):
    def test_ecdh_shared_secret(self):
        priv_a, pub_a = generate_x25519_keypair()
        priv_b, pub_b = generate_x25519_keypair()
        shared_a = x25519_derive_shared(priv_a, pub_b)
        shared_b = x25519_derive_shared(priv_b, pub_a)
        self.assertEqual(shared_a, shared_b)

    def test_session_keys_directional(self):
        priv_a, pub_a = generate_x25519_keypair()
        priv_b, pub_b = generate_x25519_keypair()
        shared = x25519_derive_shared(priv_a, pub_b)
        send_a, recv_a = derive_session_keys(shared, "alice", "bob")
        send_b, recv_b = derive_session_keys(shared, "bob", "alice")
        self.assertEqual(send_a, recv_b)  # Alice's send = Bob's receive
        self.assertEqual(recv_a, send_b)  # Alice's receive = Bob's send

    def test_serialize_roundtrip(self):
        priv, pub = generate_x25519_keypair()
        pub_bytes = serialize_x25519_public(pub)
        pub2 = load_x25519_public(pub_bytes)
        self.assertEqual(serialize_x25519_public(pub2), pub_bytes)


class TestAESGCM(unittest.TestCase):
    def test_encrypt_decrypt(self):
        key = os.urandom(32)
        plaintext = b"Hello, world!"
        nonce, ct = aes_gcm_encrypt(key, plaintext)
        result = aes_gcm_decrypt(key, nonce, ct)
        self.assertEqual(result, plaintext)

    def test_wrong_key_fails(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        nonce, ct = aes_gcm_encrypt(key1, b"secret")
        with self.assertRaises(Exception):
            aes_gcm_decrypt(key2, nonce, ct)

    def test_tampered_ciphertext_fails(self):
        key = os.urandom(32)
        nonce, ct = aes_gcm_encrypt(key, b"secret")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with self.assertRaises(Exception):
            aes_gcm_decrypt(key, nonce, bytes(tampered))

    def test_aad(self):
        key = os.urandom(32)
        aad = b"additional data"
        nonce, ct = aes_gcm_encrypt(key, b"msg", aad)
        self.assertEqual(aes_gcm_decrypt(key, nonce, ct, aad), b"msg")
        with self.assertRaises(Exception):
            aes_gcm_decrypt(key, nonce, ct, b"wrong aad")


class TestCertificates(unittest.TestCase):
    def test_ca_and_user_cert(self):
        ca_key = generate_rsa_keypair()
        ca_cert = create_ca_certificate(ca_key)
        user_key = generate_rsa_keypair()
        csr = create_csr(user_key, "testuser")
        user_cert = sign_csr(ca_key, ca_cert, csr)
        self.assertTrue(verify_certificate_chain(user_cert, ca_cert))

    def test_wrong_ca_fails(self):
        ca_key = generate_rsa_keypair()
        ca_cert = create_ca_certificate(ca_key)
        other_ca_key = generate_rsa_keypair()
        other_ca_cert = create_ca_certificate(other_ca_key)
        user_key = generate_rsa_keypair()
        csr = create_csr(user_key, "testuser")
        user_cert = sign_csr(ca_key, ca_cert, csr)
        self.assertFalse(verify_certificate_chain(user_cert, other_ca_cert))

    def test_cert_pem_roundtrip(self):
        ca_key = generate_rsa_keypair()
        ca_cert = create_ca_certificate(ca_key)
        pem = cert_to_pem(ca_cert)
        loaded = pem_to_cert(pem)
        self.assertEqual(loaded.serial_number, ca_cert.serial_number)


class TestKeystore(unittest.TestCase):
    def test_pkcs12_roundtrip(self):
        key = generate_rsa_keypair()
        ca_key = generate_rsa_keypair()
        ca_cert = create_ca_certificate(ca_key)
        csr = create_csr(key, "user1")
        cert = sign_csr(ca_key, ca_cert, csr)
        ks = create_keystore(key, cert, b"password123", "user1")
        loaded_key, loaded_cert = load_keystore(ks, b"password123")
        self.assertEqual(loaded_cert.serial_number, cert.serial_number)

    def test_wrong_password_fails(self):
        key = generate_rsa_keypair()
        ca_key = generate_rsa_keypair()
        ca_cert = create_ca_certificate(ca_key)
        csr = create_csr(key, "user1")
        cert = sign_csr(ca_key, ca_cert, csr)
        ks = create_keystore(key, cert, b"correct", "user1")
        with self.assertRaises(Exception):
            load_keystore(ks, b"wrong")


class TestCAKeyEncryption(unittest.TestCase):
    def test_encrypt_decrypt_ca_key(self):
        ca_key = generate_rsa_keypair()
        enc = encrypt_ca_key(ca_key, "passphrase")
        loaded = decrypt_ca_key(enc, "passphrase")
        data = b"test"
        sig = rsa_sign(ca_key, data)
        self.assertTrue(rsa_verify(loaded.public_key(), sig, data))


class TestKeyRotation(unittest.TestCase):
    def test_epoch_key_derivation(self):
        key = os.urandom(32)
        key1 = derive_next_epoch_key(key, 1)
        key2 = derive_next_epoch_key(key1, 2)
        self.assertNotEqual(key, key1)
        self.assertNotEqual(key1, key2)


class TestExpiredCertificate(unittest.TestCase):
    def test_expired_cert_rejected(self):
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend

        ca_key = generate_rsa_keypair()
        ca_cert = create_ca_certificate(ca_key)
        user_key = generate_rsa_keypair()
        now = datetime.now(timezone.utc)
        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired_user")]))
            .issuer_name(ca_cert.subject)
            .public_key(user_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=30))
            .not_valid_after(now - timedelta(days=1))
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        self.assertFalse(verify_certificate_chain(expired_cert, ca_cert))


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS (Server + Client via Flask test client & real client logic)
# ═══════════════════════════════════════════════════════════════════════════════

SERVER_PORT = 18321
_server_ready = False

def _start_server_once():
    global _server_ready
    if _server_ready:
        return

    for d in ["data", "test_alice_data", "test_bob_data"]:
        if os.path.exists(d):
            shutil.rmtree(d)
    os.makedirs("data", exist_ok=True)

    os.environ["FSPKI_DB_PATH"] = "data/test_fspki.db"
    os.environ["FSPKI_ADMIN_TOKEN"] = "testadmin"
    os.environ["FSPKI_CA_PASSPHRASE"] = "testpass"

    from server.database import _initialized
    _initialized.clear()

    from server.app import create_app
    flask_app = create_app(db_path="data/test_fspki.db")

    def run_server():
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        flask_app.run(host="127.0.0.1", port=SERVER_PORT, use_reloader=False)

    t = threading.Thread(target=run_server, daemon=True)
    t.start()

    import requests as req
    for _ in range(50):
        try:
            req.get(f"http://127.0.0.1:{SERVER_PORT}/health", timeout=1)
            break
        except Exception:
            time.sleep(0.2)

    # Init CA
    resp = req.post(f"http://127.0.0.1:{SERVER_PORT}/ca/init", json={"passphrase": "testpass"})
    if resp.status_code not in (200, 400):
        raise RuntimeError(f"CA init failed: {resp.text}")
    _server_ready = True


class IntegrationBase(unittest.TestCase):
    """Base class that starts a Flask server in a thread."""

    @classmethod
    def setUpClass(cls):
        _start_server_once()

    @classmethod
    def tearDownClass(cls):
        for d in ["test_alice_data", "test_bob_data"]:
            if os.path.exists(d):
                shutil.rmtree(d)

    def _make_client(self, username, password, data_dir):
        from client.core import ChatClient
        c = ChatClient(data_dir=data_dir, server_url=f"http://127.0.0.1:{SERVER_PORT}")
        result = c.init_user(username, password)
        self.assertNotIn("error", result, f"init_user failed: {result}")
        result = c.register()
        self.assertIn("status", result)
        result = c.publish_prekey()
        self.assertIn("status", result)
        return c


class TestEndToEnd(IntegrationBase):
    """Two users register and exchange messages."""

    def test_alice_sends_bob_receives(self):
        alice = self._make_client("alice_e2e", "alicepass", "test_alice_data")
        bob = self._make_client("bob_e2e", "bobpass", "test_bob_data")

        # Alice sends
        result = alice.send_message("bob_e2e", "Hello Bob, from Alice!")
        self.assertEqual(result.get("status"), "ok")

        # Bob establishes session and reads inbox
        bob.establish_session("alice_e2e")
        messages = bob.pull_inbox()
        self.assertTrue(len(messages) >= 1)
        self.assertEqual(messages[0].get("plaintext"), "Hello Bob, from Alice!")
        self.assertEqual(messages[0].get("sender"), "alice_e2e")

        alice.close()
        bob.close()

    def test_bidirectional(self):
        alice = self._make_client("alice_bi", "ap", "test_alice_data")
        bob = self._make_client("bob_bi", "bp", "test_bob_data")

        alice.establish_session("bob_bi")
        bob.establish_session("alice_bi")

        alice.send_message("bob_bi", "Hi Bob!")
        msgs = bob.pull_inbox()
        self.assertTrue(any(m.get("plaintext") == "Hi Bob!" for m in msgs))

        bob.send_message("alice_bi", "Hi Alice!")
        msgs = alice.pull_inbox()
        self.assertTrue(any(m.get("plaintext") == "Hi Alice!" for m in msgs))

        alice.close()
        bob.close()


class TestReplayDetection(IntegrationBase):
    """Replayed messages are rejected."""

    def test_server_rejects_replay(self):
        alice = self._make_client("alice_rp", "ap", "test_alice_data")
        bob = self._make_client("bob_rp", "bp", "test_bob_data")

        result = alice.send_message("bob_rp", "Test replay")
        self.assertEqual(result.get("status"), "ok")
        msg_id = result["message_id"]

        # Try replaying same message_id
        import requests
        resp = requests.post(f"http://127.0.0.1:{SERVER_PORT}/messages/send", json={
            "sender": "alice_rp", "recipient": "bob_rp",
            "message_id": msg_id, "timestamp": time.time(),
            "nonce": b64e(os.urandom(12)), "ciphertext": b64e(os.urandom(32)),
            "signature": b64e(os.urandom(64)), "epoch": 0,
        })
        self.assertEqual(resp.status_code, 409)

        alice.close()
        bob.close()

    def test_timestamp_skew_rejected(self):
        import requests
        # Register dummy users for this test
        alice = self._make_client("alice_ts", "ap", "test_alice_data")
        bob = self._make_client("bob_ts", "bp", "test_bob_data")

        resp = requests.post(f"http://127.0.0.1:{SERVER_PORT}/messages/send", json={
            "sender": "alice_ts", "recipient": "bob_ts",
            "message_id": generate_message_id(),
            "timestamp": time.time() - 300,  # 5 min ago
            "nonce": b64e(os.urandom(12)), "ciphertext": b64e(os.urandom(32)),
            "signature": b64e(os.urandom(64)), "epoch": 0,
        })
        self.assertEqual(resp.status_code, 400)

        alice.close()
        bob.close()


class TestRevocationIntegration(IntegrationBase):
    """Revoked certificate handling."""

    def test_revoke_and_check_crl(self):
        import requests
        serial = "123456789"
        resp = requests.post(f"http://127.0.0.1:{SERVER_PORT}/crl/revoke",
            json={"serial": serial, "reason": "test"},
            headers={"X-Admin-Token": "testadmin"})
        self.assertEqual(resp.status_code, 200)

        crl_resp = requests.get(f"http://127.0.0.1:{SERVER_PORT}/crl")
        serials = [e["serial"] for e in crl_resp.json()["crl"]]
        self.assertIn(serial, serials)

    def test_admin_token_required(self):
        import requests
        resp = requests.post(f"http://127.0.0.1:{SERVER_PORT}/crl/revoke",
            json={"serial": "999"}, headers={"X-Admin-Token": "wrongtoken"})
        self.assertEqual(resp.status_code, 403)


class TestKeyRotationIntegration(IntegrationBase):
    """Session continues with new keys after rotation."""

    def test_rotation_continues_session(self):
        alice = self._make_client("alice_kr", "ap", "test_alice_data")
        bob = self._make_client("bob_kr", "bp", "test_bob_data")

        alice.establish_session("bob_kr")
        bob.establish_session("alice_kr")

        # Send enough messages to trigger rotation
        for i in range(KEY_ROTATION_INTERVAL + 2):
            result = alice.send_message("bob_kr", f"msg-{i}")
            self.assertEqual(result.get("status"), "ok")

        messages = bob.pull_inbox()
        plaintexts = [m.get("plaintext") for m in messages if "plaintext" in m]
        self.assertEqual(len(plaintexts), KEY_ROTATION_INTERVAL + 2)

        alice.close()
        bob.close()


class TestTamperDetection(IntegrationBase):
    """Modified ciphertext/signature detection."""

    def test_wrong_signature_detected(self):
        key1 = generate_rsa_keypair()
        key2 = generate_rsa_keypair()
        data = b"authentic data"
        sig = rsa_sign(key1, data)
        self.assertFalse(rsa_verify(key2.public_key(), sig, data))

    def test_tampered_aes_ciphertext_fails(self):
        key = os.urandom(32)
        nonce, ct = aes_gcm_encrypt(key, b"secret message")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with self.assertRaises(Exception):
            aes_gcm_decrypt(key, nonce, bytes(tampered))


class TestCRLEndpoint(IntegrationBase):
    """CRL fetch and revoke endpoints."""

    def test_crl_accessible(self):
        import requests
        resp = requests.get(f"http://127.0.0.1:{SERVER_PORT}/crl")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("crl", resp.json())


if __name__ == "__main__":
    unittest.main(verbosity=2)
