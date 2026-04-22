"""
AIAuth Enterprise — SERVER_SECRET rotation helper (Piece 13)

Orchestrates a safe SERVER_SECRET rotation with dual-secret validation
so no user data is orphaned. See ENTERPRISE_ADMIN_GUIDE.md section 2.5.4
"SERVER_SECRET rotation" for the full runbook.

Typical flow:
  1. Stop the service.
  2. Update config.yaml:
       secrets.server_secret_previous: "<current>"
       secrets.server_secret: "<new>"
  3. Start the service. It accepts BOTH secrets for the rotation window.
  4. Run this script with --re-encrypt to migrate Fernet ciphertext and
     consent_log entries from old -> new secret.
  5. Prompt all users to re-authenticate (banner on /v1/account/me).
  6. When all active users have re-auth'd (or after the cutoff you pick),
     remove server_secret_previous, restart, run --prune-orphaned.

Usage:
  python rotate_server_secret.py --generate-new
  python rotate_server_secret.py --dry-run
  python rotate_server_secret.py --re-encrypt
  python rotate_server_secret.py --prune-orphaned
  python rotate_server_secret.py --status

All commands are idempotent.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
from pathlib import Path
from typing import Optional


def load_server_secrets():
    """Read SERVER_SECRET and SERVER_SECRET_PREVIOUS from env or config.yaml."""
    current = os.environ.get("SERVER_SECRET", "")
    previous = os.environ.get("SERVER_SECRET_PREVIOUS", "")
    config_path = Path(os.environ.get("AIAUTH_CONFIG", "/opt/aiauth/config.yaml"))
    if config_path.exists():
        try:
            import yaml
            with open(config_path) as f:
                cfg = yaml.safe_load(f) or {}
            secrets_cfg = cfg.get("secrets", {}) or {}
            current = current or secrets_cfg.get("server_secret", "")
            previous = previous or secrets_cfg.get("server_secret_previous", "")
        except Exception as exc:
            print(f"WARN: could not parse {config_path}: {exc}", file=sys.stderr)
    return current, previous


def derive_keys(server_secret: str):
    """Mirror of server.py's _derive_hardening_keys for the rotation helper."""
    if not server_secret:
        return None, None
    from cryptography.fernet import Fernet
    salt = hmac.new(server_secret.encode(), b"email-hash-v1", hashlib.sha256).digest()
    key = hmac.new(server_secret.encode(), b"db-encrypt-v1", hashlib.sha256).digest()
    return salt, Fernet(base64.urlsafe_b64encode(key))


def generate_new():
    new_secret = secrets.token_hex(32)
    print(new_secret)
    print(file=sys.stderr)
    print("Next steps:", file=sys.stderr)
    print("  1. systemctl stop aiauth", file=sys.stderr)
    print("  2. In config.yaml, set:", file=sys.stderr)
    print("       secrets.server_secret_previous: <YOUR CURRENT SERVER_SECRET>", file=sys.stderr)
    print(f"       secrets.server_secret: {new_secret}", file=sys.stderr)
    print("  3. systemctl start aiauth", file=sys.stderr)
    print("  4. python rotate_server_secret.py --re-encrypt", file=sys.stderr)
    return 0


def re_encrypt(db_path: str, dry_run: bool = False):
    current, previous = load_server_secrets()
    if not current:
        print("ERROR: SERVER_SECRET not set", file=sys.stderr)
        return 1
    if not previous:
        print("ERROR: SERVER_SECRET_PREVIOUS not set — nothing to rotate from", file=sys.stderr)
        return 1

    new_salt, new_fernet = derive_keys(current)
    old_salt, old_fernet = derive_keys(previous)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # --- consent_log.details_encrypted ---
    consent_rows = conn.execute(
        "SELECT id, details_encrypted FROM consent_log WHERE details_encrypted IS NOT NULL AND details_encrypted != ''"
    ).fetchall()
    consent_migrated = 0
    consent_failed = 0
    for r in consent_rows:
        ct = r["details_encrypted"]
        # Skip if already new-decryptable
        try:
            new_fernet.decrypt(ct.encode())
            continue  # already new-format
        except Exception:
            pass
        try:
            plain = old_fernet.decrypt(ct.encode())
            new_ct = new_fernet.encrypt(plain).decode()
            if not dry_run:
                conn.execute("UPDATE consent_log SET details_encrypted = ? WHERE id = ?", (new_ct, r["id"]))
            consent_migrated += 1
        except Exception:
            consent_failed += 1

    # --- enterprise_attestations.uid_encrypted ---
    att_rows = conn.execute(
        "SELECT id, uid_encrypted FROM enterprise_attestations WHERE uid_encrypted IS NOT NULL"
    ).fetchall()
    att_migrated = 0
    att_failed = 0
    for r in att_rows:
        ct = r["uid_encrypted"]
        try:
            new_fernet.decrypt(ct.encode())
            continue
        except Exception:
            pass
        try:
            plain = old_fernet.decrypt(ct.encode())
            new_ct = new_fernet.encrypt(plain).decode()
            if not dry_run:
                conn.execute("UPDATE enterprise_attestations SET uid_encrypted = ? WHERE id = ?", (new_ct, r["id"]))
            att_migrated += 1
        except Exception:
            att_failed += 1

    if not dry_run:
        conn.commit()

    print(f"consent_log        : migrated {consent_migrated}, failed {consent_failed}")
    print(f"enterprise_attest. : migrated {att_migrated}, failed {att_failed}")

    # --- email_hash migration ---
    # We can't re-derive email_hash without the plaintext email, so we
    # rely on the runtime `email_hash_candidates()` in server.py which
    # checks both salts during lookups. New magic-link verifications and
    # account creations will produce new-salt hashes. This command only
    # re-encrypts Fernet values.
    print("Note: email_hash rows remain old-salt. They will be re-hashed")
    print("      lazily as users re-authenticate (the server's dual-secret")
    print("      lookup handles the transition window). No manual action.")

    conn.close()
    return 0


def prune_orphaned(db_path: str, dry_run: bool = False):
    """After the rotation window closes (SERVER_SECRET_PREVIOUS removed),
    any rows whose ciphertext still can't be decrypted with the current
    key are orphaned. This prunes them."""
    current, _previous = load_server_secrets()
    if not current:
        print("ERROR: SERVER_SECRET not set", file=sys.stderr)
        return 1
    _salt, fernet = derive_keys(current)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    orphan_consent = []
    for r in conn.execute("SELECT id, details_encrypted FROM consent_log WHERE details_encrypted IS NOT NULL AND details_encrypted != ''"):
        try:
            fernet.decrypt(r["details_encrypted"].encode())
        except Exception:
            orphan_consent.append(r["id"])

    orphan_att = []
    for r in conn.execute("SELECT id, uid_encrypted FROM enterprise_attestations WHERE uid_encrypted IS NOT NULL"):
        try:
            fernet.decrypt(r["uid_encrypted"].encode())
        except Exception:
            orphan_att.append(r["id"])

    print(f"Orphan consent_log rows: {len(orphan_consent)}")
    print(f"Orphan enterprise_attestations rows: {len(orphan_att)}")

    if dry_run:
        return 0

    if orphan_consent:
        conn.executemany("DELETE FROM consent_log WHERE id = ?", [(i,) for i in orphan_consent])
    if orphan_att:
        conn.executemany("UPDATE enterprise_attestations SET uid_encrypted = NULL WHERE id = ?", [(i,) for i in orphan_att])
    conn.commit()
    conn.close()
    return 0


def status(db_path: str):
    current, previous = load_server_secrets()
    print(f"SERVER_SECRET set:          {'yes' if current else 'NO'}")
    print(f"SERVER_SECRET_PREVIOUS set: {'yes (rotation in progress)' if previous else 'no'}")
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        consent_total = conn.execute("SELECT COUNT(*) FROM consent_log WHERE details_encrypted IS NOT NULL").fetchone()[0]
        att_total = conn.execute("SELECT COUNT(*) FROM enterprise_attestations WHERE uid_encrypted IS NOT NULL").fetchone()[0]
        print(f"consent_log rows with ciphertext:        {consent_total}")
        print(f"enterprise_attestations rows with uid_enc: {att_total}")
        conn.close()
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--generate-new", action="store_true", help="Print a fresh SERVER_SECRET and next-step instructions")
    p.add_argument("--dry-run", action="store_true", help="Show what would change without modifying the DB")
    p.add_argument("--re-encrypt", action="store_true", help="Re-encrypt Fernet ciphertext from old -> new key")
    p.add_argument("--prune-orphaned", action="store_true", help="Remove rows whose ciphertext can't be decrypted by current key (use AFTER rotation window closes)")
    p.add_argument("--status", action="store_true", help="Show current rotation state")
    p.add_argument("--db", default=os.environ.get("AIAUTH_DB_PATH", "/opt/aiauth/aiauth.db"), help="Path to aiauth.db")
    args = p.parse_args()

    if args.generate_new:
        return generate_new()
    if args.status:
        return status(args.db)
    if args.re_encrypt:
        return re_encrypt(args.db, dry_run=args.dry_run)
    if args.prune_orphaned:
        return prune_orphaned(args.db, dry_run=args.dry_run)

    p.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
