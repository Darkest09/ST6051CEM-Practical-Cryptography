# FS-PKI Chat — Multi-Machine Deployment Guide

Run FS-PKI Chat across **two laptops** (different networks) with the **server on a VPS**.

---

## Architecture

```
┌─────────────┐         ┌─────────────────┐         ┌─────────────┐
│  Laptop 1   │         │       VPS       │         │  Laptop 2   │
│  (alice)    │ ──────► │  FS-PKI Server   │ ◄────── │   (bob)     │
│  Client     │  HTTP   │  Port 8000       │  HTTP   │  Client     │
└─────────────┘         └─────────────────┘         └─────────────┘
     Network A                    Internet                    Network B
```

---

## Prerequisites

- **VPS**: Linux (Ubuntu/Debian recommended), public IP, Python 3.8+
- **Laptops**: Python 3.8+, copy of the `fs-pki-chat` project

---

## Step 1 — VPS Setup

### 1.1 Install Python and dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip -y

# Or use a venv (recommended)
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate  # Windows
```

### 1.2 Copy project to VPS

Upload the `fs-pki-chat` folder (e.g. via `scp`, `rsync`, or git):

```bash
scp -r fs-pki-chat user@YOUR_VPS_IP:~/
```

### 1.3 Install dependencies on VPS

```bash
cd ~/fs-pki-chat
pip install -r requirements.txt
```

### 1.4 Open firewall port 8000

```bash
# UFW (Ubuntu)
sudo ufw allow 8000/tcp
sudo ufw reload

# Or iptables, firewalld, or your cloud provider's security group
```

### 1.5 Start the server

```bash
cd ~/fs-pki-chat
python launcher.py server --port 8000
```

Or run in background (e.g. with `nohup` or `screen`):

```bash
nohup python launcher.py server --port 8000 > server.log 2>&1 &
```

### 1.6 Initialize the CA (one-time)

From the VPS (or any machine that can reach it):

```bash
python launcher.py init-ca --server http://127.0.0.1:8000
```

Or from a laptop (replace `YOUR_VPS_IP` with your VPS public IP):

```bash
python launcher.py init-ca --server http://YOUR_VPS_IP:8000
```

### 1.7 Note your VPS address

You need: `YOUR_VPS_IP` (e.g. `203.0.113.50`) or hostname (e.g. `chat.example.com`).

---

## Step 2 — Laptop 1 (alice)

### 2.1 Copy project and install

```bash
# Copy fs-pki-chat folder to laptop
cd fs-pki-chat
pip install -r requirements.txt
```

### 2.2 Option A: GUI

1. Run: `python launcher.py`
2. In **Server** field, enter: `YOUR_VPS_IP:8000` (e.g. `203.0.113.50:8000`)
3. Do **not** click "Start Server" (server runs on VPS)
4. Click **Initialize CA** (if not done on VPS)
5. Username: `alice`, Password: `alicepass`
6. Click **1. Create User** → **2. Register on Server** → **3. Publish Prekey**
7. In Messaging tab, set **To:** `bob`, type a message, click **Send**

### 2.3 Option B: CLI

```bash
# Replace YOUR_VPS_IP with your VPS public IP
export SERVER="http://YOUR_VPS_IP:8000"

python -m client.cli init-user alice --password alicepass --server $SERVER
python -m client.cli register alice --password alicepass --server $SERVER
python -m client.cli publish-prekey alice --password alicepass --server $SERVER

# Send message to bob
python -m client.cli send alice bob "Hello Bob!" --password alicepass --server $SERVER
```

---

## Step 3 — Laptop 2 (bob)

### 3.1 Copy project and install

Same as Laptop 1 — copy `fs-pki-chat` and run `pip install -r requirements.txt`.

### 3.2 Option A: GUI

1. Run: `python launcher.py`
2. In **Server** field, enter: `YOUR_VPS_IP:8000`
3. Username: `bob`, Password: `bobpass`
4. Click **1. Create User** → **2. Register on Server** → **3. Publish Prekey**
5. In Messaging tab, set **To:** `alice`
6. Click **Establish Session** → **Pull Inbox**
7. Bob should see alice's message

### 3.3 Option B: CLI

```bash
export SERVER="http://YOUR_VPS_IP:8000"

python -m client.cli init-user bob --password bobpass --server $SERVER
python -m client.cli register bob --password bobpass --server $SERVER
python -m client.cli publish-prekey bob --password bobpass --server $SERVER

# Receive messages
python -m client.cli inbox bob --password bobpass --server $SERVER
```

---

## Step 4 — Verify connectivity

From each laptop:

```bash
curl http://YOUR_VPS_IP:8000/health
```

Expected: `{"status":"ok","time":...}`

---

## Important notes

### Data directories

- Each user has a separate data directory: `client_data_alice`, `client_data_bob`, etc.
- On each laptop, only that laptop’s user data exists.
- Both laptops must use the **same server URL** (`YOUR_VPS_IP:8000`).

### Security (educational use)

- Traffic is **HTTP**, not HTTPS. Suitable for lab/testing only.
- Change default secrets in production:
  - `FSPKI_CA_PASSPHRASE`
  - `FSPKI_ADMIN_TOKEN`
- For production, put the server behind HTTPS (e.g. nginx + Let’s Encrypt).

### Firewall checklist

- VPS: allow inbound TCP 8000
- Laptops: outbound HTTP (usually allowed)
- Corporate/school networks: ensure port 8000 outbound is not blocked

### Troubleshooting

| Issue | Check |
|-------|-------|
| Connection refused | VPS firewall, server running, correct IP/port |
| CA not initialized | Run `init-ca` once on the server |
| User not found | User must Register and Publish Prekey |
| No messages | Recipient must Establish Session, then Pull Inbox |

---

## Quick reference

| Machine | Command |
|---------|---------|
| VPS | `python launcher.py server --port 8000` |
| VPS | `python launcher.py init-ca --server http://127.0.0.1:8000` |
| Laptop | Server URL: `http://YOUR_VPS_IP:8000` |
| Laptop (CLI) | Add `--server http://YOUR_VPS_IP:8000` to all commands |
