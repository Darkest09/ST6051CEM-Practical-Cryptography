# FS-PKI Chat — Forward-Secure PKI Messaging System

**ST6051CEM Practical Cryptography Coursework**

A complete secure messaging system demonstrating PKI, forward secrecy, authenticated encryption, and certificate management.

---

**Multi-machine deployment:** See [DEPLOYMENT.md](DEPLOYMENT.md) for running on two laptops + VPS across different networks.

---

## Quick Start (Single PC Testing)

### Prerequisites
```
pip install flask requests cryptography
```

### Launch the GUI
```
cd fs-pki-chat
python launcher.py
```
This opens the all-in-one GUI with built-in server, user management, messaging, and security tools.

---

## Step-by-Step Testing Guide

### Step 1 — Start Server & CA
1. Click **"Start Server"** in the sidebar (runs on port 8000)
2. Click **"Initialize CA"** (creates the Certificate Authority — one-time)
3. The top-right status turns green: `Server: Running (:8000)`

### Step 2 — Create User "alice"
1. Enter **Username:** `alice` and **Password:** `alicepass`
2. Click **"1. Create User"** — generates RSA-3072 keys, gets CA-signed X.509 certificate, saves PKCS#12 keystore
3. Click **"2. Register on Server"** — uploads alice's certificate
4. Click **"3. Publish Prekey"** — publishes X25519 ephemeral key bundle (signed with RSA-PSS)

### Step 3 — Create User "bob"
1. Enter **Username:** `bob` and **Password:** `bobpass`
2. Repeat: **1. Create → 2. Register → 3. Publish Prekey**

### Step 4 — Send a Message (alice → bob)
1. Enter **Username:** `alice`, **Password:** `alicepass`
2. Click **"Load Existing User"** — alice becomes the active user
3. Go to the **Messaging** tab
4. Set **To:** `bob`, type a message, click **Send** (or press Enter)
5. The message is: encrypted (AES-256-GCM), signed (RSA-PSS), and delivered via the server

### Step 5 — Receive as bob
1. Enter **Username:** `bob`, **Password:** `bobpass`
2. Click **"Load Existing User"**
3. In Messaging tab, set **To:** `alice`
4. Click **"Establish Session"** — performs X25519 ECDH key agreement
5. Click **"Pull Inbox"** — decrypts and verifies alice's message

### Step 6 — Test Forward Secrecy
- Send 6+ messages from alice → bob
- After every 5 messages, keys auto-rotate to a new epoch
- Check the system log for `[epoch 1]`, `[epoch 2]`, etc.
- Or click **"Rotate Keys"** to manually advance the epoch
- **Old epoch keys are destroyed** — past messages cannot be decrypted even if current keys are compromised

### Step 7 — Test Certificate Revocation
1. Go to **Security & CRL** tab
2. Click **"Show My Certificate"** — note the Serial number
3. Paste the serial into the Revoke field
4. Click **"Revoke"** (admin token: `supersecretadmin`)
5. Click **"Fetch CRL"** to see the revoked serial in the list
6. Messages from/to revoked users will be rejected

### Step 8 — Test Replay Protection
- The server rejects any message with a duplicate `(sender, message_id)` pair
- Messages with timestamps outside ±120 seconds are rejected
- Verified automatically in the test suite

---

## Running Automated Tests

```
cd fs-pki-chat
python -m unittest tests.test_full -v
```

Runs **28 tests** covering:

| Category | Tests | What's Verified |
|----------|-------|-----------------|
| RSA | 3 | Key generation, sign/verify, wrong key rejection |
| X25519 ECDH | 3 | Shared secret agreement, directional keys, serialization |
| AES-256-GCM | 4 | Encrypt/decrypt, wrong key, tamper detection, AAD |
| Certificates | 3 | CA signing, wrong CA rejection, PEM roundtrip |
| Keystore | 2 | PKCS#12 save/load, wrong password rejection |
| CA Key Encryption | 1 | AES-GCM at-rest protection |
| Key Rotation | 1 | Epoch-based key derivation |
| Expired Cert | 1 | Expired certificate rejection |
| End-to-End | 2 | Full alice↔bob messaging, bidirectional |
| Replay Detection | 2 | Duplicate message_id rejection, timestamp skew |
| Revocation | 2 | CRL revoke/check, admin token requirement |
| Key Rotation (E2E) | 1 | Session continues after auto-rotation |
| Tamper Detection | 2 | Wrong signature, modified ciphertext |
| CRL Endpoint | 1 | CRL fetch accessibility |

---

## Architecture

```
fs-pki-chat/
├── common/
│   └── crypto.py          # All cryptographic primitives
├── server/
│   ├── app.py             # Flask REST API
│   └── database.py        # SQLite persistence
├── client/
│   ├── core.py            # Client logic (sessions, encrypt, sign)
│   ├── cli.py             # Command-line interface
│   └── gui.py             # All-in-one Tkinter GUI
├── tests/
│   └── test_full.py       # 28-test comprehensive suite
├── launcher.py            # Entry point
├── requirements.txt
└── README.md
```

---

## Cryptographic Primitives Used

| Primitive | Implementation | Purpose |
|-----------|---------------|---------|
| RSA-3072 | `cryptography` lib | Identity keys, CSR signing |
| X25519 ECDH | `cryptography` lib | Ephemeral key agreement |
| AES-256-GCM | `cryptography` lib | Authenticated symmetric encryption |
| HKDF-SHA256 | `cryptography` lib | Key derivation from shared secrets |
| RSA-PSS | `cryptography` lib | Digital signatures (SHA-256) |
| X.509 | `cryptography` lib | Certificates, CA chain |
| PKCS#12 | `cryptography` lib | Password-protected keystores |

---

## Security Features

1. **Confidentiality** — AES-256-GCM with HKDF-derived session keys
2. **Authentication** — RSA-PSS signatures on every message envelope
3. **Forward Secrecy** — Ephemeral X25519 keys + epoch-based key ratcheting (every 5 messages)
4. **Replay Protection** — Unique UUID message_id + server replay cache + ±120s timestamp validation
5. **Revocation** — Certificate Revocation List (CRL) checked before every send/receive
6. **Key Protection** — PKCS#12 keystores (password-encrypted), CA private key AES-GCM encrypted at rest
7. **Certificate Validation** — Full CA chain verification + expiry checking

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ca/init` | POST | Initialize Certificate Authority |
| `/ca/cert` | GET | Fetch CA certificate |
| `/ca/sign` | POST | Sign a CSR |
| `/users/register` | POST | Register user with certificate |
| `/users` | GET | List registered users |
| `/users/<name>/cert` | GET | Fetch user certificate |
| `/prekeys/publish` | POST | Publish ephemeral prekey bundle |
| `/prekeys/<name>` | GET | Fetch user's prekey bundle |
| `/messages/send` | POST | Send encrypted message envelope |
| `/messages/inbox/<name>` | GET | Fetch and delete inbox messages |
| `/crl` | GET | Fetch Certificate Revocation List |
| `/crl/revoke` | POST | Revoke a certificate (admin) |
| `/health` | GET | Server health check |

---

## CLI Usage (Alternative to GUI)

```bash
# Terminal 1: Start server
python launcher.py server

# Terminal 2: Initialize CA
python launcher.py init-ca

# Create and register alice
python -m client.cli init-user alice --password alicepass
python -m client.cli register alice --password alicepass
python -m client.cli publish-prekey alice --password alicepass

# Create and register bob
python -m client.cli init-user bob --password bobpass
python -m client.cli register bob --password bobpass
python -m client.cli publish-prekey bob --password bobpass

# Send message
python -m client.cli send alice bob "Hello Bob!" --password alicepass

# Check inbox
python -m client.cli inbox bob --password bobpass

# Fetch CRL
python -m client.cli fetch-crl
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FSPKI_DB_PATH` | `data/fspki.db` | SQLite database path |
| `FSPKI_CA_PASSPHRASE` | `ca-passphrase-change-me` | CA private key passphrase |
| `FSPKI_ADMIN_TOKEN` | `supersecretadmin` | Admin token for CRL revocation |
