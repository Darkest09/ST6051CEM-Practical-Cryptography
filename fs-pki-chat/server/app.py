"""
server/app.py — Flask server for FS-PKI Chat.
Endpoints: CA init, CSR signing, user registration, cert fetch, prekey publish/fetch,
           message send/inbox, CRL get/revoke.
"""

import os
import json
import time

from flask import Flask, request, jsonify

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.crypto import (
    generate_rsa_keypair, create_ca_certificate, cert_to_pem, pem_to_cert,
    pem_to_csr, sign_csr, encrypt_ca_key, decrypt_ca_key,
    get_cert_serial, get_cert_cn, verify_certificate_chain,
    check_timestamp_skew, TIMESTAMP_SKEW_SECONDS,
)
from server.database import (
    init_db, save_ca, load_ca,
    save_user, get_user_cert, list_users,
    save_prekey, get_prekey,
    store_message, fetch_and_delete_messages,
    check_and_add_replay, clean_old_replay_entries,
    revoke_serial, get_crl, is_revoked,
)

ADMIN_TOKEN = os.environ.get("FSPKI_ADMIN_TOKEN", "supersecretadmin")
CA_PASSPHRASE = os.environ.get("FSPKI_CA_PASSPHRASE", "ca-passphrase-change-me")


def create_app(db_path=None):
    """Application factory."""
    app = Flask(__name__)

    if db_path:
        os.environ["FSPKI_DB_PATH"] = db_path
    init_db()

    # ─── CA Endpoints ─────────────────────────────────────────────────────
    @app.route("/ca/init", methods=["POST"])
    def ca_init():
        existing = load_ca()
        if existing:
            return jsonify({"error": "CA already initialized"}), 400
        data = request.get_json(force=True)
        passphrase = data.get("passphrase") or CA_PASSPHRASE
        ca_key = generate_rsa_keypair()
        ca_cert = create_ca_certificate(ca_key)
        enc_key = encrypt_ca_key(ca_key, passphrase)
        save_ca(cert_to_pem(ca_cert).decode(), json.dumps(enc_key))
        return jsonify({"status": "ok", "ca_cert_pem": cert_to_pem(ca_cert).decode()})

    @app.route("/ca/cert", methods=["GET"])
    def ca_cert_endpoint():
        ca_data = load_ca()
        if not ca_data:
            return jsonify({"error": "CA not initialized"}), 404
        return jsonify({"ca_cert_pem": ca_data["ca_cert_pem"]})

    @app.route("/ca/sign", methods=["POST"])
    def ca_sign_csr():
        ca_data = load_ca()
        if not ca_data:
            return jsonify({"error": "CA not initialized"}), 404
        ca_cert = pem_to_cert(ca_data["ca_cert_pem"].encode())
        ca_key = decrypt_ca_key(json.loads(ca_data["ca_key_enc"]), CA_PASSPHRASE)
        data = request.get_json(force=True)
        try:
            csr = pem_to_csr(data["csr_pem"].encode())
        except Exception as e:
            return jsonify({"error": f"Invalid CSR: {e}"}), 400
        signed_cert = sign_csr(ca_key, ca_cert, csr)
        return jsonify({"cert_pem": cert_to_pem(signed_cert).decode(), "serial": get_cert_serial(signed_cert)})

    # ─── User Registration ────────────────────────────────────────────────
    @app.route("/users/register", methods=["POST"])
    def register_user():
        ca_data = load_ca()
        if not ca_data:
            return jsonify({"error": "CA not initialized"}), 500
        ca_cert = pem_to_cert(ca_data["ca_cert_pem"].encode())
        data = request.get_json(force=True)
        username = data["username"]
        try:
            user_cert = pem_to_cert(data["cert_pem"].encode())
        except Exception:
            return jsonify({"error": "Invalid certificate PEM"}), 400
        if not verify_certificate_chain(user_cert, ca_cert):
            return jsonify({"error": "Certificate not valid or not signed by this CA"}), 400
        cn = get_cert_cn(user_cert)
        if cn != username:
            return jsonify({"error": f"Certificate CN '{cn}' does not match username '{username}'"}), 400
        serial = get_cert_serial(user_cert)
        if is_revoked(serial):
            return jsonify({"error": "Certificate is revoked"}), 403
        save_user(username, data["cert_pem"])
        return jsonify({"status": "ok", "username": username})

    @app.route("/users", methods=["GET"])
    def list_all_users():
        return jsonify({"users": list_users()})

    @app.route("/users/<username>/cert", methods=["GET"])
    def get_cert(username):
        cert_pem = get_user_cert(username)
        if not cert_pem:
            return jsonify({"error": f"User '{username}' not found"}), 404
        return jsonify({"username": username, "cert_pem": cert_pem})

    # ─── Prekey Bundles ───────────────────────────────────────────────────
    @app.route("/prekeys/publish", methods=["POST"])
    def publish_prekey():
        data = request.get_json(force=True)
        username = data["username"]
        cert_pem = get_user_cert(username)
        if not cert_pem:
            return jsonify({"error": f"User '{username}' not registered"}), 404
        save_prekey(username, json.dumps(data["bundle"]))
        return jsonify({"status": "ok"})

    @app.route("/prekeys/<username>", methods=["GET"])
    def fetch_prekey(username):
        bundle_json = get_prekey(username)
        if not bundle_json:
            return jsonify({"error": f"No prekey bundle for '{username}'"}), 404
        return jsonify({"username": username, "bundle": json.loads(bundle_json)})

    # ─── Message Send/Inbox ───────────────────────────────────────────────
    @app.route("/messages/send", methods=["POST"])
    def send_message():
        data = request.get_json(force=True)
        sender = data["sender"]
        recipient = data["recipient"]
        message_id = data["message_id"]
        timestamp = data["timestamp"]

        if not get_user_cert(recipient):
            return jsonify({"error": f"Recipient '{recipient}' not registered"}), 404
        if not get_user_cert(sender):
            return jsonify({"error": f"Sender '{sender}' not registered"}), 404
        if not check_timestamp_skew(timestamp):
            return jsonify({"error": f"Timestamp outside allowed skew (±{TIMESTAMP_SKEW_SECONDS}s)"}), 400
        if check_and_add_replay(sender, message_id, timestamp):
            return jsonify({"error": "Replay detected: duplicate (sender, message_id)"}), 409

        envelope = {
            "sender": sender,
            "recipient": recipient,
            "message_id": message_id,
            "timestamp": timestamp,
            "nonce": data["nonce"],
            "ciphertext": data["ciphertext"],
            "signature": data["signature"],
            "epoch": data.get("epoch", 0),
        }
        store_message(recipient, json.dumps(envelope))
        return jsonify({"status": "ok", "message_id": message_id})

    @app.route("/messages/inbox/<username>", methods=["GET"])
    def get_inbox(username):
        envelopes = fetch_and_delete_messages(username)
        return jsonify({"messages": [json.loads(e) for e in envelopes]})

    # ─── CRL ──────────────────────────────────────────────────────────────
    @app.route("/crl", methods=["GET"])
    def get_crl_endpoint():
        return jsonify({"crl": get_crl()})

    @app.route("/crl/revoke", methods=["POST"])
    def revoke_cert():
        token = request.headers.get("X-Admin-Token")
        if token != ADMIN_TOKEN:
            return jsonify({"error": "Invalid admin token"}), 403
        data = request.get_json(force=True)
        revoke_serial(data["serial"], data.get("reason", ""))
        return jsonify({"status": "ok", "serial": data["serial"]})

    # ─── Health ───────────────────────────────────────────────────────────
    @app.route("/health", methods=["GET"])
    def health_check():
        return jsonify({"status": "ok", "time": time.time()})

    return app


# Default app instance for direct run
app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
