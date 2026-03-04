"""
launcher.py — FS-PKI Chat Launcher.
Start the GUI (default), server-only, or CLI.
"""

import os
import sys
import argparse


def main():
    parser = argparse.ArgumentParser(description="FS-PKI Chat Launcher")
    sub = parser.add_subparsers(dest="mode")

    sub.add_parser("gui", help="Open the all-in-one GUI (default)")

    s = sub.add_parser("server", help="Start the server only (headless)")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--passphrase", default="ca-passphrase-change-me")
    s.add_argument("--admin-token", default="supersecretadmin")

    sub.add_parser("cli", help="Open CLI client (pass further args after 'cli')")

    c = sub.add_parser("init-ca", help="Initialize CA on running server")
    c.add_argument("--server", default="http://127.0.0.1:8000")
    c.add_argument("--passphrase", default="ca-passphrase-change-me")

    args, _ = parser.parse_known_args()

    # Default to GUI if no subcommand
    if args.mode is None or args.mode == "gui":
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from client.gui import main as gui_main
        gui_main()

    elif args.mode == "server":
        os.environ["FSPKI_CA_PASSPHRASE"] = args.passphrase
        os.environ["FSPKI_ADMIN_TOKEN"] = args.admin_token
        os.makedirs("data", exist_ok=True)
        print(f"Starting FS-PKI Chat Server on port {args.port}...")
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from server.app import create_app
        app = create_app()
        app.run(host="0.0.0.0", port=args.port, debug=True)

    elif args.mode == "cli":
        import subprocess
        subprocess.run([sys.executable, "-m", "client.cli"] + sys.argv[2:])

    elif args.mode == "init-ca":
        import requests
        resp = requests.post(f"{args.server}/ca/init", json={"passphrase": args.passphrase})
        print(resp.json())


if __name__ == "__main__":
    main()
