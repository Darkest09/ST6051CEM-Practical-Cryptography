"""
client/cli.py — CLI interface for FS-PKI Chat client.
Usage: python -m client.cli <command> [options]
"""

import argparse
import sys
import os
import json
import getpass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.core import ChatClient


def get_client(args) -> ChatClient:
    return ChatClient(data_dir=args.data_dir, server_url=args.server)


def cmd_init_user(args):
    client = get_client(args)
    password = args.password or getpass.getpass("Keystore password: ")
    result = client.init_user(args.username, password)
    print(json.dumps(result, indent=2))
    client.close()


def cmd_load_user(args):
    client = get_client(args)
    password = args.password or getpass.getpass("Keystore password: ")
    result = client.load_user(args.username, password)
    print(json.dumps(result, indent=2))
    client.close()


def cmd_register(args):
    client = get_client(args)
    password = args.password or getpass.getpass("Keystore password: ")
    client.load_user(args.username, password)
    result = client.register()
    print(json.dumps(result, indent=2))
    client.close()


def cmd_publish_prekey(args):
    client = get_client(args)
    password = args.password or getpass.getpass("Keystore password: ")
    client.load_user(args.username, password)
    result = client.publish_prekey()
    print(json.dumps(result, indent=2))
    client.close()


def cmd_fetch_cert(args):
    client = get_client(args)
    result = client.fetch_cert(args.target)
    print(json.dumps(result, indent=2))
    client.close()


def cmd_list_users(args):
    client = get_client(args)
    users = client.list_users()
    print("Registered users:", users)
    client.close()


def cmd_send(args):
    client = get_client(args)
    password = args.password or getpass.getpass("Keystore password: ")
    client.load_user(args.username, password)
    # Establish session
    result = client.establish_session(args.recipient)
    if "error" in result:
        print("Session error:", json.dumps(result, indent=2))
        client.close()
        return
    result = client.send_message(args.recipient, args.message)
    print(json.dumps(result, indent=2))
    client.close()


def cmd_inbox(args):
    client = get_client(args)
    password = args.password or getpass.getpass("Keystore password: ")
    client.load_user(args.username, password)
    # We need to establish sessions for each sender before we can decrypt
    # For simplicity, we try to establish sessions as needed
    messages = client.pull_inbox()
    for msg in messages:
        if "plaintext" in msg:
            print(f"[{msg['sender']}] (epoch {msg.get('epoch', 0)}): {msg['plaintext']}")
        else:
            print(f"[{msg.get('sender', '?')}] ERROR: {msg.get('error', 'unknown')}")
    if not messages:
        print("No messages.")
    client.close()


def cmd_rotate_keys(args):
    client = get_client(args)
    password = args.password or getpass.getpass("Keystore password: ")
    client.load_user(args.username, password)
    result = client.rotate_keys(args.peer)
    print(json.dumps(result, indent=2))
    client.close()


def cmd_fetch_crl(args):
    client = get_client(args)
    crl = client.fetch_crl()
    if crl:
        print("Revoked certificates:")
        for entry in crl:
            print(f"  Serial: {entry['serial']}, Revoked at: {entry['revoked_at']}, Reason: {entry.get('reason', '')}")
    else:
        print("CRL is empty (no revoked certificates).")
    client.close()


def main():
    parser = argparse.ArgumentParser(description="FS-PKI Chat Client CLI")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="Server URL")
    parser.add_argument("--data-dir", default="client_data", help="Client data directory")

    sub = parser.add_subparsers(dest="command", help="Command to run")

    # init-user
    p = sub.add_parser("init-user", help="Generate keys and get certificate from CA")
    p.add_argument("username")
    p.add_argument("--password", help="Keystore password (prompted if omitted)")

    # load-user
    p = sub.add_parser("load-user", help="Load existing user from keystore")
    p.add_argument("username")
    p.add_argument("--password")

    # register
    p = sub.add_parser("register", help="Register user with server")
    p.add_argument("username")
    p.add_argument("--password")

    # publish-prekey
    p = sub.add_parser("publish-prekey", help="Publish ephemeral prekey bundle")
    p.add_argument("username")
    p.add_argument("--password")

    # fetch-cert
    p = sub.add_parser("fetch-cert", help="Fetch another user's certificate")
    p.add_argument("target", help="Username to fetch cert for")

    # list-users
    sub.add_parser("list-users", help="List registered users")

    # send
    p = sub.add_parser("send", help="Send an encrypted message")
    p.add_argument("username", help="Your username")
    p.add_argument("recipient", help="Recipient username")
    p.add_argument("message", help="Message text")
    p.add_argument("--password")

    # inbox
    p = sub.add_parser("inbox", help="Fetch and decrypt inbox messages")
    p.add_argument("username")
    p.add_argument("--password")

    # rotate-keys
    p = sub.add_parser("rotate-keys", help="Rotate session keys with a peer")
    p.add_argument("username")
    p.add_argument("peer")
    p.add_argument("--password")

    # fetch-crl
    sub.add_parser("fetch-crl", help="Fetch the Certificate Revocation List")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    commands = {
        "init-user": cmd_init_user,
        "load-user": cmd_load_user,
        "register": cmd_register,
        "publish-prekey": cmd_publish_prekey,
        "fetch-cert": cmd_fetch_cert,
        "list-users": cmd_list_users,
        "send": cmd_send,
        "inbox": cmd_inbox,
        "rotate-keys": cmd_rotate_keys,
        "fetch-crl": cmd_fetch_crl,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
