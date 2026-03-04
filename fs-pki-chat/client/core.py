"""
client/core.py — Core client logic for FS-PKI Chat.
Manages identity, keystore, sessions, encryption, signatures, replay, CRL.
"""

import os
import json
import time
from pathlib import Path
from typing import Optional, Dict, Tuple, List

import requests

from common.crypto import (
    generate_rsa_keypair, create_csr, cert_to_pem, pem_to_cert, csr_to_pem,
    create_keystore, load_keystore,
    generate_x25519_keypair, serialize_x25519_public, serialize_x25519_private,
    load_x25519_public, load_x25519_private,
    x25519_derive_shared, derive_session_keys, derive_next_epoch_key,
    aes_gcm_encrypt, aes_gcm_decrypt,
    rsa_sign, rsa_verify,
    verify_certificate_chain, get_cert_serial, get_cert_cn,
    generate_message_id, current_timestamp, check_timestamp_skew,
    b64e, b64d, build_signature_payload,
    KEY_ROTATION_INTERVAL, TIMESTAMP_SKEW_SECONDS,
)


class SessionState:
    """Tracks session key state with a peer."""
    def __init__(self, send_key: bytes, recv_key: bytes, epoch: int = 0):
        self.send_key = send_key
        self.recv_key = recv_key
        self.epoch = epoch
        self.send_count = 0
        self.recv_count = 0

    def needs_rotation(self) -> bool:
        return self.send_count >= KEY_ROTATION_INTERVAL

    def rotate_send(self):
        self.epoch += 1
        self.send_key = derive_next_epoch_key(self.send_key, self.epoch)
        self.send_count = 0

    def rotate_recv(self, epoch: int):
        while self.epoch < epoch:
            self.epoch += 1
            self.recv_key = derive_next_epoch_key(self.recv_key, self.epoch)
        self.recv_count = 0


class ChatClient:
    """Full FS-PKI Chat client."""

    def __init__(self, data_dir: str = "client_data", server_url: str = "http://127.0.0.1:8000"):
        self.server_url = server_url.rstrip("/")
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()

        # Identity
        self.username: Optional[str] = None
        self.private_key = None
        self.certificate = None
        self.ca_cert = None

        # Session keys per peer
        self.sessions: Dict[str, SessionState] = {}

        # Peer certificate cache
        self.peer_certs: Dict[str, object] = {}

        # Replay cache: set of (sender, message_id)
        self.replay_cache: set = set()

        # X25519 ephemeral keys
        self.eph_private = None
        self.eph_public = None

    # ─── Identity & Keystore ──────────────────────────────────────────────
    def init_user(self, username: str, password: str) -> dict:
        """Generate RSA keypair, get cert signed by CA, save PKCS#12 keystore."""
        self.username = username

        # Fetch CA cert
        resp = self.session.get(f"{self.server_url}/ca/cert")
        if resp.status_code != 200:
            return {"error": f"Could not fetch CA cert: {resp.text}"}
        self.ca_cert = pem_to_cert(resp.json()["ca_cert_pem"].encode())

        # Generate RSA keypair
        self.private_key = generate_rsa_keypair()

        # Create CSR and get it signed
        csr = create_csr(self.private_key, username)
        resp = self.session.post(f"{self.server_url}/ca/sign",
                                 json={"csr_pem": csr_to_pem(csr).decode()})
        if resp.status_code != 200:
            return {"error": f"CSR signing failed: {resp.text}"}

        cert_pem = resp.json()["cert_pem"]
        self.certificate = pem_to_cert(cert_pem.encode())

        # Save keystore
        ks_data = create_keystore(self.private_key, self.certificate, password.encode(), username)
        ks_path = self.data_dir / f"{username}.p12"
        ks_path.write_bytes(ks_data)

        # Save CA cert
        ca_path = self.data_dir / "ca_cert.pem"
        ca_path.write_bytes(cert_to_pem(self.ca_cert))

        return {"status": "ok", "keystore": str(ks_path), "serial": get_cert_serial(self.certificate)}

    def load_user(self, username: str, password: str) -> dict:
        """Load existing user from keystore."""
        self.username = username
        ks_path = self.data_dir / f"{username}.p12"
        if not ks_path.exists():
            return {"error": f"Keystore not found: {ks_path}"}
        self.private_key, self.certificate = load_keystore(ks_path.read_bytes(), password.encode())

        ca_path = self.data_dir / "ca_cert.pem"
        if ca_path.exists():
            self.ca_cert = pem_to_cert(ca_path.read_bytes())
        else:
            resp = self.session.get(f"{self.server_url}/ca/cert")
            if resp.status_code == 200:
                self.ca_cert = pem_to_cert(resp.json()["ca_cert_pem"].encode())
                ca_path.write_bytes(cert_to_pem(self.ca_cert))
        return {"status": "ok", "username": username}

    # ─── Registration ─────────────────────────────────────────────────────
    def register(self) -> dict:
        if not self.certificate or not self.username:
            return {"error": "User not initialized"}
        resp = self.session.post(f"{self.server_url}/users/register", json={
            "username": self.username,
            "cert_pem": cert_to_pem(self.certificate).decode(),
        })
        return resp.json()

    def fetch_cert(self, username: str) -> dict:
        resp = self.session.get(f"{self.server_url}/users/{username}/cert")
        if resp.status_code != 200:
            return {"error": resp.text}
        cert = pem_to_cert(resp.json()["cert_pem"].encode())
        self.peer_certs[username] = cert
        return {"status": "ok", "serial": get_cert_serial(cert)}

    def list_users(self) -> list:
        resp = self.session.get(f"{self.server_url}/users")
        return resp.json().get("users", [])

    # ─── Prekeys & Sessions ───────────────────────────────────────────────
    def publish_prekey(self) -> dict:
        if not self.username or not self.private_key:
            return {"error": "User not initialized"}
        self.eph_private, self.eph_public = generate_x25519_keypair()
        pub_bytes = serialize_x25519_public(self.eph_public)
        ts = current_timestamp()
        sig_data = pub_bytes + str(ts).encode()
        signature = rsa_sign(self.private_key, sig_data)
        bundle = {
            "ephemeral_pub_b64": b64e(pub_bytes),
            "signature_b64": b64e(signature),
            "timestamp": ts,
        }
        # Save ephemeral private locally
        eph_path = self.data_dir / f"{self.username}_eph.key"
        eph_path.write_bytes(serialize_x25519_private(self.eph_private))

        resp = self.session.post(f"{self.server_url}/prekeys/publish", json={
            "username": self.username,
            "bundle": bundle,
        })
        return resp.json()

    def establish_session(self, peer_username: str) -> dict:
        """Fetch peer's prekey, perform ECDH, derive session keys."""
        resp = self.session.get(f"{self.server_url}/prekeys/{peer_username}")
        if resp.status_code != 200:
            return {"error": f"Could not fetch prekey for {peer_username}: {resp.text}"}
        bundle = resp.json()["bundle"]

        # Verify prekey signature with peer's certificate
        if peer_username not in self.peer_certs:
            fetch_result = self.fetch_cert(peer_username)
            if "error" in fetch_result:
                return fetch_result
        peer_cert = self.peer_certs[peer_username]

        # Verify CRL
        crl_check = self._check_crl(peer_cert)
        if crl_check:
            return crl_check

        peer_pub_bytes = b64d(bundle["ephemeral_pub_b64"])
        sig_bytes = b64d(bundle["signature_b64"])
        sig_data = peer_pub_bytes + str(bundle["timestamp"]).encode()
        if not rsa_verify(peer_cert.public_key(), sig_bytes, sig_data):
            return {"error": "Prekey signature verification failed"}

        peer_eph_pub = load_x25519_public(peer_pub_bytes)

        # Generate our own ephemeral if we don't have one
        if not self.eph_private:
            self.eph_private, self.eph_public = generate_x25519_keypair()
            self.publish_prekey()

        # ECDH shared secret
        shared = x25519_derive_shared(self.eph_private, peer_eph_pub)
        send_key, recv_key = derive_session_keys(shared, self.username, peer_username)
        self.sessions[peer_username] = SessionState(send_key, recv_key)
        return {"status": "ok", "peer": peer_username, "epoch": 0}

    # ─── Sending Messages ─────────────────────────────────────────────────
    def send_message(self, recipient: str, plaintext: str) -> dict:
        if not self.username or not self.private_key:
            return {"error": "User not initialized"}
        if recipient not in self.sessions:
            result = self.establish_session(recipient)
            if "error" in result:
                return result

        sess = self.sessions[recipient]

        # Check if rotation is needed
        if sess.needs_rotation():
            sess.rotate_send()

        # Encrypt
        msg_id = generate_message_id()
        ts = current_timestamp()
        nonce, ct = aes_gcm_encrypt(sess.send_key, plaintext.encode())

        # Sign
        sig_payload = build_signature_payload(self.username, recipient, msg_id, ts, nonce, ct)
        signature = rsa_sign(self.private_key, sig_payload)

        sess.send_count += 1

        # Send to server
        resp = self.session.post(f"{self.server_url}/messages/send", json={
            "sender": self.username,
            "recipient": recipient,
            "message_id": msg_id,
            "timestamp": ts,
            "nonce": b64e(nonce),
            "ciphertext": b64e(ct),
            "signature": b64e(signature),
            "epoch": sess.epoch,
        })
        if resp.status_code != 200:
            return {"error": f"Send failed: {resp.text}"}
        return {"status": "ok", "message_id": msg_id, "epoch": sess.epoch}

    # ─── Receiving Messages ───────────────────────────────────────────────
    def pull_inbox(self) -> List[dict]:
        if not self.username:
            return [{"error": "User not initialized"}]

        resp = self.session.get(f"{self.server_url}/messages/inbox/{self.username}")
        if resp.status_code != 200:
            return [{"error": resp.text}]

        messages = resp.json().get("messages", [])
        results = []
        for env in messages:
            result = self._process_envelope(env)
            results.append(result)
        return results

    def _process_envelope(self, env: dict) -> dict:
        sender = env["sender"]
        msg_id = env["message_id"]
        ts = env["timestamp"]
        epoch = env.get("epoch", 0)

        # Replay check
        cache_key = (sender, msg_id)
        if cache_key in self.replay_cache:
            return {"sender": sender, "error": "Replay detected (client cache)"}
        self.replay_cache.add(cache_key)

        # Timestamp check
        if not check_timestamp_skew(ts):
            return {"sender": sender, "error": f"Timestamp outside skew (±{TIMESTAMP_SKEW_SECONDS}s)"}

        # Fetch/verify sender cert
        if sender not in self.peer_certs:
            fetch_result = self.fetch_cert(sender)
            if "error" in fetch_result:
                return {"sender": sender, "error": f"Could not fetch cert: {fetch_result['error']}"}
        peer_cert = self.peer_certs[sender]

        # Verify chain + expiry
        if self.ca_cert and not verify_certificate_chain(peer_cert, self.ca_cert):
            return {"sender": sender, "error": "Certificate chain verification failed"}

        # CRL check
        crl_err = self._check_crl(peer_cert)
        if crl_err:
            return {"sender": sender, "error": crl_err["error"]}

        # Verify signature
        nonce = b64d(env["nonce"])
        ct = b64d(env["ciphertext"])
        sig = b64d(env["signature"])
        sig_payload = build_signature_payload(sender, self.username, msg_id, ts, nonce, ct)
        if not rsa_verify(peer_cert.public_key(), sig, sig_payload):
            return {"sender": sender, "error": "Signature verification failed"}

        # Decrypt
        if sender not in self.sessions:
            return {"sender": sender, "error": "No session established with sender (need prekey exchange)"}

        sess = self.sessions[sender]
        # Handle epoch advancement
        if epoch > sess.epoch:
            sess.rotate_recv(epoch)

        try:
            pt = aes_gcm_decrypt(sess.recv_key, nonce, ct)
            sess.recv_count += 1
        except Exception as e:
            return {"sender": sender, "error": f"Decryption failed: {e}"}

        return {
            "sender": sender,
            "message_id": msg_id,
            "timestamp": ts,
            "epoch": epoch,
            "plaintext": pt.decode(),
        }

    # ─── Key Rotation ─────────────────────────────────────────────────────
    def rotate_keys(self, peer: str) -> dict:
        if peer not in self.sessions:
            return {"error": f"No session with {peer}"}
        sess = self.sessions[peer]
        sess.rotate_send()
        return {"status": "ok", "new_epoch": sess.epoch}

    # ─── CRL ──────────────────────────────────────────────────────────────
    def _check_crl(self, cert) -> Optional[dict]:
        try:
            resp = self.session.get(f"{self.server_url}/crl")
            if resp.status_code == 200:
                crl = resp.json().get("crl", [])
                serial = get_cert_serial(cert)
                for entry in crl:
                    if entry["serial"] == serial:
                        return {"error": f"Certificate serial {serial} is revoked"}
        except Exception:
            pass
        return None

    def fetch_crl(self) -> list:
        resp = self.session.get(f"{self.server_url}/crl")
        if resp.status_code == 200:
            return resp.json().get("crl", [])
        return []

    def close(self):
        self.session.close()
