"""
client/gui.py — Full-featured Tkinter GUI for FS-PKI Chat.
All-in-one interface: server control, user management, messaging, security.
Designed for single-PC testing with multiple user sessions.
"""

import os
import sys
import json
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.core import ChatClient


# ══════════════════════════════════════════════════════════════════════════════
# COLOR / STYLE CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

BG = "#1e1e2e"
BG_LIGHT = "#2a2a3d"
BG_CARD = "#313147"
FG = "#e0e0f0"
FG_DIM = "#8888aa"
FG_BRIGHT = "#ffffff"
ACCENT = "#7c6ff7"
ACCENT_HOVER = "#9588ff"
GREEN = "#50c878"
RED = "#ff6b6b"
ORANGE = "#ffa64d"
BLUE = "#64b5f6"
BORDER = "#444466"
FONT = ("Segoe UI", 10)
FONT_SM = ("Segoe UI", 9)
FONT_LG = ("Segoe UI", 12, "bold")
FONT_MONO = ("Consolas", 9)
FONT_TITLE = ("Segoe UI", 16, "bold")


class ChatGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("FS-PKI Chat — Forward-Secure PKI Messaging")
        self.root.geometry("1100x780")
        self.root.minsize(950, 650)
        self.root.configure(bg=BG)

        # State
        self.server_running = False
        self.server_thread = None
        self.flask_app = None
        self.clients = {}        # username -> ChatClient
        self.active_user = None  # currently selected username

        self._apply_theme()
        self._build_ui()
        self._log("Welcome to FS-PKI Chat! Start the server, then create users to begin.")

    # ══════════════════════════════════════════════════════════════════════
    # THEME
    # ══════════════════════════════════════════════════════════════════════

    def _apply_theme(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background=BG, foreground=FG, font=FONT)
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=BG_CARD)
        style.configure("TLabel", background=BG, foreground=FG, font=FONT)
        style.configure("Title.TLabel", background=BG, foreground=FG_BRIGHT, font=FONT_LG)
        style.configure("Dim.TLabel", background=BG, foreground=FG_DIM, font=FONT_SM)
        style.configure("CardTitle.TLabel", background=BG_CARD, foreground=FG_BRIGHT, font=FONT_LG)
        style.configure("CardDim.TLabel", background=BG_CARD, foreground=FG_DIM, font=FONT_SM)
        style.configure("Card.TLabel", background=BG_CARD, foreground=FG, font=FONT)
        style.configure("Green.TLabel", background=BG, foreground=GREEN, font=FONT)
        style.configure("Red.TLabel", background=BG, foreground=RED, font=FONT)
        style.configure("Accent.TLabel", background=BG, foreground=ACCENT, font=FONT)

        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_LIGHT, foreground=FG_DIM,
                         padding=[14, 6], font=FONT)
        style.map("TNotebook.Tab",
                  background=[("selected", ACCENT)],
                  foreground=[("selected", FG_BRIGHT)])

        style.configure("TEntry", fieldbackground=BG_LIGHT, foreground=FG_BRIGHT,
                         insertcolor=FG_BRIGHT, borderwidth=1, relief="solid")

        style.configure("Accent.TButton", background=ACCENT, foreground=FG_BRIGHT,
                         font=FONT, padding=[12, 5], borderwidth=0)
        style.map("Accent.TButton",
                  background=[("active", ACCENT_HOVER), ("disabled", BORDER)])

        style.configure("Green.TButton", background=GREEN, foreground=BG,
                         font=FONT, padding=[12, 5], borderwidth=0)
        style.map("Green.TButton",
                  background=[("active", "#60d888"), ("disabled", BORDER)])

        style.configure("Red.TButton", background=RED, foreground=BG,
                         font=FONT, padding=[12, 5], borderwidth=0)
        style.map("Red.TButton",
                  background=[("active", "#ff8888"), ("disabled", BORDER)])

        style.configure("Secondary.TButton", background=BG_LIGHT, foreground=FG,
                         font=FONT, padding=[10, 4], borderwidth=1)
        style.map("Secondary.TButton",
                  background=[("active", BG_CARD)])

        style.configure("TLabelframe", background=BG_CARD, foreground=FG_BRIGHT,
                         borderwidth=1, relief="solid")
        style.configure("TLabelframe.Label", background=BG_CARD, foreground=ACCENT, font=FONT)

        style.configure("Treeview", background=BG_LIGHT, foreground=FG, fieldbackground=BG_LIGHT,
                         font=FONT_SM, rowheight=26, borderwidth=0)
        style.configure("Treeview.Heading", background=BG_CARD, foreground=FG_DIM,
                         font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", ACCENT)],
                  foreground=[("selected", FG_BRIGHT)])

        style.configure("TCombobox", fieldbackground=BG_LIGHT, foreground=FG_BRIGHT,
                         selectbackground=ACCENT)

    # ══════════════════════════════════════════════════════════════════════
    # UI LAYOUT
    # ══════════════════════════════════════════════════════════════════════

    def _build_ui(self):
        # Title bar
        title_frame = ttk.Frame(self.root)
        title_frame.pack(fill=tk.X, padx=15, pady=(12, 4))
        ttk.Label(title_frame, text="FS-PKI Chat", font=FONT_TITLE,
                  foreground=ACCENT, background=BG).pack(side=tk.LEFT)
        self.server_status_lbl = ttk.Label(title_frame, text="Server: Stopped",
                                           style="Red.TLabel")
        self.server_status_lbl.pack(side=tk.RIGHT, padx=10)
        self.user_status_lbl = ttk.Label(title_frame, text="No active user",
                                         style="Dim.TLabel")
        self.user_status_lbl.pack(side=tk.RIGHT, padx=10)

        # Main: left sidebar + right content
        main = ttk.Frame(self.root)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        left = ttk.Frame(main, width=310)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(5, 5), pady=5)
        left.pack_propagate(False)
        self._build_sidebar(left)

        sep = tk.Frame(main, bg=BORDER, width=1)
        sep.pack(side=tk.LEFT, fill=tk.Y, padx=2)

        right = ttk.Frame(main)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 5), pady=5)
        self._build_content(right)

        # Bottom log
        log_frame = ttk.Frame(self.root)
        log_frame.pack(fill=tk.X, padx=15, pady=(0, 8))
        ttk.Label(log_frame, text="System Log", style="Dim.TLabel").pack(anchor=tk.W)
        self.log_box = tk.Text(log_frame, height=6, bg=BG_LIGHT, fg=FG_DIM,
                               font=FONT_MONO, wrap=tk.WORD, bd=1, relief="solid",
                               insertbackground=FG, selectbackground=ACCENT)
        self.log_box.pack(fill=tk.X)
        self.log_box.config(state=tk.DISABLED)

    # ── SIDEBAR ──────────────────────────────────────────────────────────

    def _build_sidebar(self, parent):
        # Server Control
        srv_frame = ttk.LabelFrame(parent, text="  Server Control  ", padding=10)
        srv_frame.pack(fill=tk.X, pady=(0, 8))

        row = ttk.Frame(srv_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Server:", background=BG_CARD, foreground=FG).pack(side=tk.LEFT)
        self.server_var = tk.StringVar(value="127.0.0.1:8000")
        ttk.Entry(row, textvariable=self.server_var, width=24).pack(side=tk.LEFT, padx=5)
        ttk.Label(row, text="(host:port)", style="Dim.TLabel").pack(side=tk.LEFT, padx=2)

        row2 = ttk.Frame(srv_frame)
        row2.pack(fill=tk.X, pady=2)
        ttk.Label(row2, text="Port (local):", background=BG_CARD, foreground=FG).pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="8000")
        ttk.Entry(row2, textvariable=self.port_var, width=8).pack(side=tk.LEFT, padx=5)
        ttk.Label(row2, text="(for Start Server only)", style="Dim.TLabel").pack(side=tk.LEFT, padx=2)

        btn_row = ttk.Frame(srv_frame)
        btn_row.pack(fill=tk.X, pady=(6, 2))
        self.server_btn = ttk.Button(btn_row, text="Start Server",
                                     style="Green.TButton", command=self._toggle_server)
        self.server_btn.pack(fill=tk.X, pady=2)
        self.ca_btn = ttk.Button(btn_row, text="Initialize CA",
                                 style="Accent.TButton", command=self._init_ca)
        self.ca_btn.pack(fill=tk.X, pady=2)

        # User Management
        usr_frame = ttk.LabelFrame(parent, text="  User Management  ", padding=10)
        usr_frame.pack(fill=tk.X, pady=(0, 8))

        for lbl, var_name in [("Username:", "username_var"), ("Password:", "password_var")]:
            row = ttk.Frame(usr_frame)
            row.pack(fill=tk.X, pady=2)
            ttk.Label(row, text=lbl, width=10, background=BG_CARD, foreground=FG).pack(side=tk.LEFT)
            var = tk.StringVar()
            setattr(self, var_name, var)
            show = "*" if "password" in var_name.lower() else ""
            ttk.Entry(row, textvariable=var, show=show, width=18).pack(side=tk.LEFT, padx=4)

        btn_grid = ttk.Frame(usr_frame)
        btn_grid.pack(fill=tk.X, pady=(6, 0))

        ttk.Button(btn_grid, text="1. Create User",
                   style="Accent.TButton", command=self._create_user).pack(fill=tk.X, pady=2)
        ttk.Button(btn_grid, text="2. Register on Server",
                   style="Accent.TButton", command=self._register_user).pack(fill=tk.X, pady=2)
        ttk.Button(btn_grid, text="3. Publish Prekey",
                   style="Accent.TButton", command=self._publish_prekey).pack(fill=tk.X, pady=2)
        ttk.Button(btn_grid, text="Load Existing User",
                   style="Secondary.TButton", command=self._load_user).pack(fill=tk.X, pady=2)

        # Active Sessions
        sess_frame = ttk.LabelFrame(parent, text="  Registered Users  ", padding=8)
        sess_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 0))

        self.session_tree = ttk.Treeview(sess_frame, columns=("status",), show="tree headings",
                                          height=6, selectmode="browse")
        self.session_tree.heading("#0", text="User")
        self.session_tree.heading("status", text="Status")
        self.session_tree.column("#0", width=130)
        self.session_tree.column("status", width=120)
        self.session_tree.pack(fill=tk.BOTH, expand=True)
        self.session_tree.bind("<<TreeviewSelect>>", self._on_session_select)

        ttk.Button(sess_frame, text="Refresh Users",
                   style="Secondary.TButton", command=self._refresh_sessions).pack(fill=tk.X, pady=(4, 0))

    # ── CONTENT AREA ─────────────────────────────────────────────────────

    def _build_content(self, parent):
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self._build_messaging_tab()
        self._build_security_tab()
        self._build_help_tab()

    def _build_messaging_tab(self):
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text="  Messaging  ")

        top = ttk.Frame(frame)
        top.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(top, text="To:", foreground=FG_DIM).pack(side=tk.LEFT)
        self.recipient_var = tk.StringVar()
        self.recipient_combo = ttk.Combobox(top, textvariable=self.recipient_var, width=18, state="normal")
        self.recipient_combo.pack(side=tk.LEFT, padx=6)

        self.msg_entry = tk.Entry(top, bg=BG_LIGHT, fg=FG_BRIGHT, insertbackground=FG_BRIGHT,
                                  font=FONT, bd=1, relief="solid")
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        self.msg_entry.bind("<Return>", lambda e: self._send_message())

        ttk.Button(top, text="Send", style="Green.TButton",
                   command=self._send_message).pack(side=tk.LEFT, padx=(2, 0))

        # Chat display
        self.chat_display = tk.Text(frame, bg=BG_LIGHT, fg=FG, font=FONT,
                                     wrap=tk.WORD, bd=1, relief="solid",
                                     insertbackground=FG, selectbackground=ACCENT,
                                     padx=10, pady=8)
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        self.chat_display.config(state=tk.DISABLED)

        self.chat_display.tag_configure("sent", foreground=BLUE)
        self.chat_display.tag_configure("received", foreground=GREEN)
        self.chat_display.tag_configure("error", foreground=RED)
        self.chat_display.tag_configure("info", foreground=FG_DIM)
        self.chat_display.tag_configure("sender_label", foreground=ACCENT, font=("Segoe UI", 9, "bold"))
        self.chat_display.tag_configure("meta", foreground=FG_DIM, font=FONT_SM)

        bottom = ttk.Frame(frame)
        bottom.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(bottom, text="Pull Inbox",
                   style="Accent.TButton", command=self._pull_inbox).pack(side=tk.LEFT, padx=2)
        ttk.Button(bottom, text="Rotate Keys",
                   style="Secondary.TButton", command=self._rotate_keys).pack(side=tk.LEFT, padx=2)
        ttk.Button(bottom, text="Establish Session",
                   style="Secondary.TButton", command=self._establish_session).pack(side=tk.LEFT, padx=2)
        ttk.Button(bottom, text="Clear Chat",
                   style="Secondary.TButton", command=self._clear_chat).pack(side=tk.RIGHT, padx=2)

    def _build_security_tab(self):
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text="  Security & CRL  ")

        crl_frame = ttk.LabelFrame(frame, text="  Certificate Revocation List  ", padding=10)
        crl_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        self.crl_tree = ttk.Treeview(crl_frame, columns=("serial", "revoked_at", "reason"),
                                      show="headings", height=8)
        self.crl_tree.heading("serial", text="Serial Number")
        self.crl_tree.heading("revoked_at", text="Revoked At")
        self.crl_tree.heading("reason", text="Reason")
        self.crl_tree.column("serial", width=250)
        self.crl_tree.column("revoked_at", width=180)
        self.crl_tree.column("reason", width=200)
        self.crl_tree.pack(fill=tk.BOTH, expand=True)

        crl_btn = ttk.Frame(crl_frame)
        crl_btn.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(crl_btn, text="Fetch CRL",
                   style="Accent.TButton", command=self._fetch_crl).pack(side=tk.LEFT, padx=2)

        rev_frame = ttk.LabelFrame(frame, text="  Admin: Revoke Certificate  ", padding=10)
        rev_frame.pack(fill=tk.X, pady=(0, 8))

        row = ttk.Frame(rev_frame)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text="Serial:", background=BG_CARD, foreground=FG, width=12).pack(side=tk.LEFT)
        self.revoke_serial_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.revoke_serial_var, width=40).pack(side=tk.LEFT, padx=4)

        row2 = ttk.Frame(rev_frame)
        row2.pack(fill=tk.X, pady=2)
        ttk.Label(row2, text="Admin Token:", background=BG_CARD, foreground=FG, width=12).pack(side=tk.LEFT)
        self.admin_token_var = tk.StringVar(value="supersecretadmin")
        ttk.Entry(row2, textvariable=self.admin_token_var, show="*", width=30).pack(side=tk.LEFT, padx=4)
        ttk.Button(row2, text="Revoke", style="Red.TButton",
                   command=self._revoke_cert).pack(side=tk.LEFT, padx=8)

        info_frame = ttk.LabelFrame(frame, text="  Certificate Info  ", padding=10)
        info_frame.pack(fill=tk.X)

        self.cert_info_text = tk.Text(info_frame, height=5, bg=BG_LIGHT, fg=FG,
                                      font=FONT_MONO, wrap=tk.WORD, bd=1, relief="solid")
        self.cert_info_text.pack(fill=tk.X)
        self.cert_info_text.config(state=tk.DISABLED)

        btn_row = ttk.Frame(info_frame)
        btn_row.pack(fill=tk.X, pady=(4, 0))
        ttk.Button(btn_row, text="Show My Certificate",
                   style="Secondary.TButton", command=self._show_my_cert).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="Show CA Certificate",
                   style="Secondary.TButton", command=self._show_ca_cert).pack(side=tk.LEFT, padx=2)

    def _build_help_tab(self):
        frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(frame, text="  How to Test  ")

        help_text = tk.Text(frame, bg=BG_LIGHT, fg=FG, font=FONT, wrap=tk.WORD,
                            bd=1, relief="solid", padx=15, pady=12)
        help_text.pack(fill=tk.BOTH, expand=True)

        help_text.tag_configure("h1", foreground=ACCENT, font=("Segoe UI", 14, "bold"))
        help_text.tag_configure("h2", foreground=BLUE, font=("Segoe UI", 11, "bold"))
        help_text.tag_configure("step", foreground=GREEN, font=("Segoe UI", 10, "bold"))
        help_text.tag_configure("code", foreground=ORANGE, font=FONT_MONO)
        help_text.tag_configure("note", foreground=FG_DIM, font=("Segoe UI", 9, "italic"))

        def h1(t): help_text.insert(tk.END, t + "\n\n", "h1")
        def h2(t): help_text.insert(tk.END, t + "\n", "h2")
        def step(t): help_text.insert(tk.END, t + "\n", "step")
        def body(t): help_text.insert(tk.END, t + "\n", "")
        def code(t): help_text.insert(tk.END, "    " + t + "\n", "code")
        def gap(): help_text.insert(tk.END, "\n")

        h1("Testing FS-PKI Chat on a Single PC")
        gap()
        h2("STEP 1: Start the Server")
        step("  Click 'Start Server' in the sidebar")
        step("  Click 'Initialize CA' (one-time only)")
        body("  The status indicator at the top will turn green.")
        gap()

        h2("STEP 2: Create User 'alice'")
        step("  Enter Username: alice   Password: alicepass")
        step("  Click '1. Create User'")
        body("  This generates RSA-3072 keys, gets a CA-signed certificate,")
        body("  and saves a PKCS#12 keystore locally.")
        step("  Click '2. Register on Server'")
        step("  Click '3. Publish Prekey'")
        body("  Alice's X25519 ephemeral key is now on the server.")
        gap()

        h2("STEP 3: Create User 'bob'")
        step("  Enter Username: bob   Password: bobpass")
        step("  Repeat: 1. Create -> 2. Register -> 3. Publish Prekey")
        gap()

        h2("STEP 4: Send a Message (alice -> bob)")
        step("  Enter Username: alice   Password: alicepass")
        step("  Click 'Load Existing User' (alice is now active)")
        step("  In the Messaging tab, set To: bob")
        step("  Type a message and hit Send or press Enter")
        body("  The message is encrypted with AES-256-GCM, signed with RSA-PSS,")
        body("  and sent through the server.")
        gap()

        h2("STEP 5: Receive the Message as bob")
        step("  Enter Username: bob   Password: bobpass")
        step("  Click 'Load Existing User' (bob is now active)")
        step("  Click 'Establish Session' (with alice in the To field)")
        step("  Click 'Pull Inbox'")
        body("  Bob decrypts and verifies the message.")
        gap()

        h2("STEP 6: Test Forward Secrecy (Key Rotation)")
        step("  Send 6+ messages from alice to bob")
        body("  After every 5 messages, keys automatically rotate (new epoch).")
        body("  Old keys are destroyed for forward secrecy.")
        step("  Or click 'Rotate Keys' manually")
        gap()

        h2("STEP 7: Test Revocation")
        step("  Go to 'Security & CRL' tab")
        step("  Click 'Show My Certificate' to see the serial number")
        step("  Copy the serial, paste into Revoke field")
        step("  Click 'Revoke' (admin token: supersecretadmin)")
        step("  Click 'Fetch CRL' to confirm")
        body("  Revoked users' messages will be rejected.")
        gap()

        h2("STEP 8: Test Replay Protection")
        body("  The server rejects duplicate (sender, message_id) pairs.")
        body("  Timestamps outside +/-120 seconds are also rejected.")
        body("  This is verified in the automated test suite.")
        gap()

        h2("Security Features Demonstrated")
        code("RSA-3072 identity keys + X.509 certificates")
        code("X25519 ECDH ephemeral key agreement")
        code("AES-256-GCM authenticated encryption")
        code("HKDF-SHA256 key derivation")
        code("RSA-PSS digital signatures")
        code("PKCS#12 password-protected keystores")
        code("Forward secrecy via epoch-based key ratcheting")
        code("Replay protection (UUID + timestamp)")
        code("Certificate revocation (CRL)")
        code("CA chain validation + expiry checking")
        gap()

        h2("Running the Automated Test Suite")
        code("cd fs-pki-chat")
        code("python -m unittest tests.test_full -v")
        body("  Runs 28 tests covering all crypto and integration scenarios.")

        help_text.config(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════════════════
    # LOGGING
    # ══════════════════════════════════════════════════════════════════════

    def _log(self, msg, level="info"):
        self.log_box.config(state=tk.NORMAL)
        timestamp = time.strftime("%H:%M:%S")
        prefix = {"info": "i", "ok": "+", "warn": "!", "err": "x"}.get(level, ".")
        colors = {"info": FG_DIM, "ok": GREEN, "warn": ORANGE, "err": RED}
        tag = f"log_{level}"
        self.log_box.tag_configure(tag, foreground=colors.get(level, FG_DIM))
        self.log_box.insert(tk.END, f"[{timestamp}] [{prefix}] {msg}\n", tag)
        self.log_box.see(tk.END)
        self.log_box.config(state=tk.DISABLED)

    def _chat_msg(self, text, tag="info"):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, text + "\n", tag)
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════════════════
    # SERVER CONTROL
    # ══════════════════════════════════════════════════════════════════════

    def _get_server_url(self):
        s = self.server_var.get().strip()
        if not s:
            s = "127.0.0.1:8000"
        if not s.startswith("http"):
            s = "http://" + s
        return s

    def _toggle_server(self):
        if self.server_running:
            self._log("Server is already running. Restart the application to stop.", "warn")
            return
        self._start_server()

    def _start_server(self):
        port = int(self.port_var.get())
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_path = os.path.join(base_dir, "data", "fspki.db")
        os.environ["FSPKI_CA_PASSPHRASE"] = "ca-passphrase-change-me"
        os.environ["FSPKI_ADMIN_TOKEN"] = "supersecretadmin"
        os.environ["FSPKI_DB_PATH"] = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        from server.database import _initialized
        _initialized.clear()

        from server.app import create_app
        self.flask_app = create_app()

        def run():
            import logging
            log = logging.getLogger("werkzeug")
            log.setLevel(logging.ERROR)
            self.flask_app.run(host="127.0.0.1", port=port, use_reloader=False)

        self.server_thread = threading.Thread(target=run, daemon=True)
        self.server_thread.start()

        import requests
        for i in range(30):
            try:
                requests.get(f"http://127.0.0.1:{port}/health", timeout=0.5)
                break
            except Exception:
                time.sleep(0.2)

        self.server_running = True
        # Only switch to localhost if user was already on localhost (don't overwrite remote VPS address)
        s = self.server_var.get().strip().lower()
        if not s or "127.0.0.1" in s or "localhost" in s:
            self.server_var.set(f"127.0.0.1:{port}")
        self.server_status_lbl.config(text=f"Server: Running (:{port})", style="Green.TLabel")
        self.server_btn.config(text="Server Running", state="disabled")
        self._log(f"Server started on port {port}", "ok")

    def _init_ca(self):
        s = self.server_var.get().strip().lower()
        is_local = not s or "127.0.0.1" in s or "localhost" in s
        if is_local and not self.server_running:
            messagebox.showerror("Error", "Start the server first! (Or enter a remote server)")
            return
        import requests
        try:
            resp = requests.post(f"{self._get_server_url()}/ca/init",
                                 json={"passphrase": "ca-passphrase-change-me"}, timeout=5)
            data = resp.json()
            if resp.status_code == 200:
                self._log("CA initialized successfully", "ok")
            elif "already" in data.get("error", "").lower():
                self._log("CA already initialized (OK)", "info")
            else:
                self._log(f"CA init: {data.get('error', 'unknown error')}", "err")
        except Exception as e:
            self._log(f"CA init failed: {e}", "err")

    # ══════════════════════════════════════════════════════════════════════
    # USER MANAGEMENT
    # ══════════════════════════════════════════════════════════════════════

    def _get_or_create_client(self, username):
        if username not in self.clients:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            data_dir = os.path.join(base_dir, f"client_data_{username}")
            self.clients[username] = ChatClient(data_dir=data_dir,
                                                 server_url=self._get_server_url())
        return self.clients[username]

    def _set_active(self, username):
        self.active_user = username
        self.user_status_lbl.config(text=f"Active: {username}", style="Accent.TLabel")
        self._update_recipient_list()

    def _validate_input(self):
        u = self.username_var.get().strip()
        p = self.password_var.get().strip()
        if not u or not p:
            messagebox.showerror("Error", "Username and password are required.")
            return None, None
        s = self.server_var.get().strip().lower()
        is_local = not s or "127.0.0.1" in s or "localhost" in s
        if is_local and not self.server_running:
            messagebox.showerror("Error", "Start the server first! (Or enter a remote server in Server field)")
            return None, None
        return u, p

    def _create_user(self):
        u, p = self._validate_input()
        if not u:
            return
        client = self._get_or_create_client(u)
        result = client.init_user(u, p)
        if "error" in result:
            self._log(f"Create user '{u}' failed: {result['error']}", "err")
            messagebox.showerror("Error", result["error"])
        else:
            self._set_active(u)
            self._log(f"User '{u}' created. Serial: {result.get('serial', 'N/A')}", "ok")
            self._refresh_sessions()

    def _register_user(self):
        u, p = self._validate_input()
        if not u:
            return
        client = self._get_or_create_client(u)
        if not client.certificate:
            res = client.load_user(u, p)
            if "error" in res:
                messagebox.showerror("Error", "Create the user first (step 1)")
                return
        result = client.register()
        if "error" in result:
            self._log(f"Register '{u}' failed: {result.get('error', result)}", "err")
        else:
            self._set_active(u)
            self._log(f"User '{u}' registered on server", "ok")
            self._refresh_sessions()

    def _publish_prekey(self):
        u, p = self._validate_input()
        if not u:
            return
        client = self._get_or_create_client(u)
        if not client.certificate:
            res = client.load_user(u, p)
            if "error" in res:
                messagebox.showerror("Error", "Create or load the user first")
                return
        result = client.publish_prekey()
        if "error" in result:
            self._log(f"Publish prekey for '{u}' failed: {result.get('error', result)}", "err")
        else:
            self._set_active(u)
            self._log(f"Prekey published for '{u}'", "ok")

    def _load_user(self):
        u, p = self._validate_input()
        if not u:
            return
        client = self._get_or_create_client(u)
        result = client.load_user(u, p)
        if "error" in result:
            self._log(f"Load user '{u}' failed: {result['error']}", "err")
            messagebox.showerror("Error", result["error"])
        else:
            self._set_active(u)
            self._log(f"Loaded user '{u}'", "ok")

    def _refresh_sessions(self):
        for item in self.session_tree.get_children():
            self.session_tree.delete(item)
        s = self.server_var.get().strip().lower()
        is_local = not s or "127.0.0.1" in s or "localhost" in s
        if is_local and not self.server_running:
            return
        try:
            import requests
            resp = requests.get(f"{self._get_server_url()}/users", timeout=3)
            users = resp.json().get("users", [])
            for u in users:
                status = "Active" if u in self.clients and self.clients[u].certificate else "Registered"
                if u == self.active_user:
                    status = "* Active"
                self.session_tree.insert("", tk.END, text=u, values=(status,), iid=u)
            self._update_recipient_list()
        except Exception as e:
            self._log(f"Refresh failed: {e}", "warn")

    def _on_session_select(self, event):
        sel = self.session_tree.selection()
        if sel:
            self.recipient_var.set(sel[0])

    def _update_recipient_list(self):
        try:
            import requests
            resp = requests.get(f"{self._get_server_url()}/users", timeout=3)
            users = resp.json().get("users", [])
            others = [u for u in users if u != self.active_user]
            self.recipient_combo["values"] = others
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════════
    # MESSAGING
    # ══════════════════════════════════════════════════════════════════════

    def _get_active_client(self):
        if not self.active_user or self.active_user not in self.clients:
            messagebox.showerror("Error", "No active user. Create or load a user first.")
            return None
        c = self.clients[self.active_user]
        if not c.certificate:
            messagebox.showerror("Error", "User not fully loaded. Click 'Load Existing User'.")
            return None
        return c

    def _establish_session(self):
        client = self._get_active_client()
        if not client:
            return
        peer = self.recipient_var.get().strip()
        if not peer:
            messagebox.showerror("Error", "Enter a recipient username in the 'To' field.")
            return
        result = client.establish_session(peer)
        if "error" in result:
            self._log(f"Session with '{peer}' failed: {result['error']}", "err")
            self._chat_msg(f"Session failed: {result['error']}", "error")
        else:
            self._log(f"Session established: {self.active_user} <-> {peer} (epoch {result.get('epoch', 0)})", "ok")
            self._chat_msg(f"--- Session established with {peer} ---", "info")

    def _send_message(self):
        client = self._get_active_client()
        if not client:
            return
        peer = self.recipient_var.get().strip()
        msg = self.msg_entry.get().strip()
        if not peer or not msg:
            messagebox.showerror("Error", "Recipient and message required.")
            return

        result = client.send_message(peer, msg)
        if "error" in result:
            self._log(f"Send failed: {result['error']}", "err")
            self._chat_msg(f"Send failed: {result['error']}", "error")
        else:
            epoch = result.get("epoch", 0)
            self.chat_display.config(state=tk.NORMAL)
            self.chat_display.insert(tk.END, f"  {self.active_user} -> {peer}", "sender_label")
            self.chat_display.insert(tk.END, f"  [epoch {epoch}]\n", "meta")
            self.chat_display.insert(tk.END, f"  {msg}\n\n", "sent")
            self.chat_display.see(tk.END)
            self.chat_display.config(state=tk.DISABLED)
            self._log(f"Sent to {peer} (epoch {epoch}): {msg[:50]}{'...' if len(msg)>50 else ''}", "ok")
            self.msg_entry.delete(0, tk.END)

    def _pull_inbox(self):
        client = self._get_active_client()
        if not client:
            return
        messages = client.pull_inbox()
        if not messages:
            self._chat_msg("No new messages.", "info")
            self._log("Inbox empty", "info")
            return

        count_ok = 0
        count_err = 0
        for m in messages:
            if "plaintext" in m:
                count_ok += 1
                self.chat_display.config(state=tk.NORMAL)
                self.chat_display.insert(tk.END,
                    f"  {m['sender']} -> {self.active_user}", "sender_label")
                self.chat_display.insert(tk.END,
                    f"  [epoch {m.get('epoch', 0)}]\n", "meta")
                self.chat_display.insert(tk.END,
                    f"  {m['plaintext']}\n\n", "received")
                self.chat_display.see(tk.END)
                self.chat_display.config(state=tk.DISABLED)
            else:
                count_err += 1
                self._chat_msg(f"Error from {m.get('sender','?')}: {m.get('error','?')}", "error")

        self._log(f"Inbox: {count_ok} decrypted, {count_err} errors", "ok" if count_err == 0 else "warn")

    def _rotate_keys(self):
        client = self._get_active_client()
        if not client:
            return
        peer = self.recipient_var.get().strip()
        if not peer:
            messagebox.showerror("Error", "Enter a peer in the To field.")
            return
        result = client.rotate_keys(peer)
        if "error" in result:
            self._log(f"Rotation failed: {result['error']}", "err")
            self._chat_msg(f"Rotation failed: {result['error']}", "error")
        else:
            self._log(f"Keys rotated with {peer} -> epoch {result['new_epoch']}", "ok")
            self._chat_msg(f"--- Keys rotated with {peer} (epoch {result['new_epoch']}) ---", "info")

    def _clear_chat(self):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.delete("1.0", tk.END)
        self.chat_display.config(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════════════════
    # SECURITY / CRL
    # ══════════════════════════════════════════════════════════════════════

    def _fetch_crl(self):
        s = self.server_var.get().strip().lower()
        is_local = not s or "127.0.0.1" in s or "localhost" in s
        if is_local and not self.server_running:
            messagebox.showerror("Error", "Server not running. Start server or enter remote server.")
            return
        for item in self.crl_tree.get_children():
            self.crl_tree.delete(item)
        try:
            import requests
            resp = requests.get(f"{self._get_server_url()}/crl", timeout=5)
            crl = resp.json().get("crl", [])
            for entry in crl:
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry["revoked_at"]))
                self.crl_tree.insert("", tk.END, values=(entry["serial"], ts, entry.get("reason", "")))
            self._log(f"CRL fetched: {len(crl)} revoked certificates", "ok")
        except Exception as e:
            self._log(f"CRL fetch failed: {e}", "err")

    def _revoke_cert(self):
        serial = self.revoke_serial_var.get().strip()
        token = self.admin_token_var.get().strip()
        if not serial:
            messagebox.showerror("Error", "Serial number required.")
            return
        try:
            import requests
            resp = requests.post(f"{self._get_server_url()}/crl/revoke",
                json={"serial": serial, "reason": "Revoked via GUI"},
                headers={"X-Admin-Token": token}, timeout=5)
            if resp.status_code == 200:
                self._log(f"Certificate {serial[:20]}... revoked", "ok")
                messagebox.showinfo("Revoked", "Certificate revoked.")
                self._fetch_crl()
            else:
                self._log(f"Revoke failed: {resp.text}", "err")
                messagebox.showerror("Error", resp.json().get("error", resp.text))
        except Exception as e:
            self._log(f"Revoke error: {e}", "err")

    def _show_my_cert(self):
        client = self._get_active_client()
        if not client:
            return
        from common.crypto import get_cert_serial, get_cert_cn
        cert = client.certificate
        if hasattr(cert, 'not_valid_before_utc'):
            nvb = cert.not_valid_before_utc
            nva = cert.not_valid_after_utc
        else:
            nvb = cert.not_valid_before
            nva = cert.not_valid_after
        info = (
            f"Subject CN:  {get_cert_cn(cert)}\n"
            f"Serial:      {get_cert_serial(cert)}\n"
            f"Issuer:      {cert.issuer.rfc4514_string()}\n"
            f"Not Before:  {nvb}\n"
            f"Not After:   {nva}\n"
        )
        self.cert_info_text.config(state=tk.NORMAL)
        self.cert_info_text.delete("1.0", tk.END)
        self.cert_info_text.insert(tk.END, info)
        self.cert_info_text.config(state=tk.DISABLED)
        self._log(f"Showing cert for {self.active_user}", "info")

    def _show_ca_cert(self):
        client = self._get_active_client()
        if not client or not client.ca_cert:
            self._log("No CA cert loaded", "warn")
            return
        from common.crypto import get_cert_cn
        cert = client.ca_cert
        if hasattr(cert, 'not_valid_before_utc'):
            nvb = cert.not_valid_before_utc
            nva = cert.not_valid_after_utc
        else:
            nvb = cert.not_valid_before
            nva = cert.not_valid_after
        info = (
            f"CA Subject:  {get_cert_cn(cert)}\n"
            f"Serial:      {cert.serial_number}\n"
            f"Not Before:  {nvb}\n"
            f"Not After:   {nva}\n"
        )
        self.cert_info_text.config(state=tk.NORMAL)
        self.cert_info_text.delete("1.0", tk.END)
        self.cert_info_text.insert(tk.END, info)
        self.cert_info_text.config(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════════════════
    # RUN
    # ══════════════════════════════════════════════════════════════════════

    def run(self):
        self.root.mainloop()
        for c in self.clients.values():
            try:
                c.close()
            except Exception:
                pass


def main():
    app = ChatGUI()
    app.run()


if __name__ == "__main__":
    main()