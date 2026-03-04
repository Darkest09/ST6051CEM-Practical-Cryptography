"""
server/database.py — SQLite persistence for FS-PKI Chat server.
Stores: CA material, users, prekey bundles, messages, replay cache, CRL.
"""

import sqlite3
import os
import json
import time
import threading
from typing import Optional, List, Dict

DB_PATH = os.environ.get("FSPKI_DB_PATH", "data/fspki.db")

_local = threading.local()
_initialized = set()

def get_db() -> sqlite3.Connection:
    if not hasattr(_local, "conn") or _local.conn is None:
        os.makedirs(os.path.dirname(DB_PATH) if os.path.dirname(DB_PATH) else ".", exist_ok=True)
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
    # Auto-init tables if not done for this DB path
    if DB_PATH not in _initialized:
        _ensure_tables(_local.conn)
        _initialized.add(DB_PATH)
    return _local.conn

def _ensure_tables(db):
    db.executescript("""
        CREATE TABLE IF NOT EXISTS ca_store (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            ca_cert_pem TEXT NOT NULL,
            ca_key_enc TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            cert_pem TEXT NOT NULL,
            registered_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS prekey_bundles (
            username TEXT PRIMARY KEY,
            bundle_json TEXT NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            envelope_json TEXT NOT NULL,
            stored_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient);
        CREATE TABLE IF NOT EXISTS replay_cache (
            sender TEXT NOT NULL,
            message_id TEXT NOT NULL,
            timestamp REAL NOT NULL,
            PRIMARY KEY (sender, message_id)
        );
        CREATE TABLE IF NOT EXISTS crl (
            serial TEXT PRIMARY KEY,
            revoked_at REAL NOT NULL,
            reason TEXT DEFAULT ''
        );
    """)
    db.commit()

def init_db():
    """Ensure DB tables exist. Safe to call multiple times."""
    db = get_db()
    # Tables are auto-created by get_db/_ensure_tables

# ─── CA Store ─────────────────────────────────────────────────────────────────
def save_ca(cert_pem: str, key_enc: str):
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO ca_store (id, ca_cert_pem, ca_key_enc, created_at) VALUES (1, ?, ?, ?)",
        (cert_pem, key_enc, time.time()),
    )
    db.commit()

def load_ca() -> Optional[Dict]:
    db = get_db()
    row = db.execute("SELECT ca_cert_pem, ca_key_enc FROM ca_store WHERE id=1").fetchone()
    if row:
        return {"ca_cert_pem": row["ca_cert_pem"], "ca_key_enc": row["ca_key_enc"]}
    return None

# ─── Users ────────────────────────────────────────────────────────────────────
def save_user(username: str, cert_pem: str):
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO users (username, cert_pem, registered_at) VALUES (?, ?, ?)",
        (username, cert_pem, time.time()),
    )
    db.commit()

def get_user_cert(username: str) -> Optional[str]:
    db = get_db()
    row = db.execute("SELECT cert_pem FROM users WHERE username=?", (username,)).fetchone()
    return row["cert_pem"] if row else None

def list_users() -> List[str]:
    db = get_db()
    rows = db.execute("SELECT username FROM users").fetchall()
    return [r["username"] for r in rows]

# ─── Prekey Bundles ───────────────────────────────────────────────────────────
def save_prekey(username: str, bundle_json: str):
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO prekey_bundles (username, bundle_json, updated_at) VALUES (?, ?, ?)",
        (username, bundle_json, time.time()),
    )
    db.commit()

def get_prekey(username: str) -> Optional[str]:
    db = get_db()
    row = db.execute("SELECT bundle_json FROM prekey_bundles WHERE username=?", (username,)).fetchone()
    return row["bundle_json"] if row else None

# ─── Messages ─────────────────────────────────────────────────────────────────
def store_message(recipient: str, envelope_json: str):
    db = get_db()
    db.execute(
        "INSERT INTO messages (recipient, envelope_json, stored_at) VALUES (?, ?, ?)",
        (recipient, envelope_json, time.time()),
    )
    db.commit()

def fetch_and_delete_messages(recipient: str) -> List[str]:
    db = get_db()
    rows = db.execute(
        "SELECT id, envelope_json FROM messages WHERE recipient=? ORDER BY stored_at", (recipient,)
    ).fetchall()
    if rows:
        ids = [r["id"] for r in rows]
        placeholders = ",".join("?" * len(ids))
        db.execute(f"DELETE FROM messages WHERE id IN ({placeholders})", ids)
        db.commit()
    return [r["envelope_json"] for r in rows]

# ─── Replay Cache ─────────────────────────────────────────────────────────────
def check_and_add_replay(sender: str, message_id: str, timestamp: float) -> bool:
    """Returns True if this is a replay (duplicate). False if new."""
    db = get_db()
    row = db.execute(
        "SELECT 1 FROM replay_cache WHERE sender=? AND message_id=?", (sender, message_id)
    ).fetchone()
    if row:
        return True  # replay!
    db.execute(
        "INSERT INTO replay_cache (sender, message_id, timestamp) VALUES (?, ?, ?)",
        (sender, message_id, timestamp),
    )
    db.commit()
    return False

def clean_old_replay_entries(max_age: float = 3600):
    db = get_db()
    db.execute("DELETE FROM replay_cache WHERE timestamp < ?", (time.time() - max_age,))
    db.commit()

# ─── CRL ──────────────────────────────────────────────────────────────────────
def revoke_serial(serial: str, reason: str = ""):
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO crl (serial, revoked_at, reason) VALUES (?, ?, ?)",
        (serial, time.time(), reason),
    )
    db.commit()

def get_crl() -> List[Dict]:
    db = get_db()
    rows = db.execute("SELECT serial, revoked_at, reason FROM crl").fetchall()
    return [{"serial": r["serial"], "revoked_at": r["revoked_at"], "reason": r["reason"]} for r in rows]

def is_revoked(serial: str) -> bool:
    db = get_db()
    row = db.execute("SELECT 1 FROM crl WHERE serial=?", (serial,)).fetchone()
    return row is not None
