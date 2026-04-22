"""
AIAuth Enterprise — self-hosted bootstrap (Phase C.1)

Reads config.yaml, validates the license, generates missing secrets
and signing keys, initializes both databases, and registers the
organization as described in the Admin Guide Section 1.3.

Idempotent: re-running on a configured deployment is safe and does
nothing destructive. Running on a fresh install completes the
handoff from customer IT to a working server in ~30 seconds.

Usage:
  python bootstrap.py --config /path/to/config.yaml
"""

import argparse
import base64
import json
import os
import secrets as _secrets
import sqlite3
import sys
from pathlib import Path
from typing import Any


def _load_yaml(path: Path) -> dict:
    try:
        import yaml
    except ImportError:
        print("ERROR: PyYAML not installed. Run `pip install PyYAML`.", file=sys.stderr)
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _save_yaml(path: Path, data: dict) -> None:
    import yaml
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


def _validate_license(license_key: str, server_module) -> dict:
    """Use server.py's validate_license to check the signature."""
    if not license_key or license_key.startswith("PASTE-"):
        print("ERROR: license_key not set in config.yaml.", file=sys.stderr)
        sys.exit(1)
    data = server_module.validate_license(license_key)
    if not data:
        print("ERROR: license validation failed. "
              "Either the key is corrupt, or the server's signing key has changed.",
              file=sys.stderr)
        sys.exit(1)
    return data


def _require_secrets(cfg: dict, cfg_path: Path) -> bool:
    """Generate server_secret + client_secret if empty. Returns True if
    we wrote back to config.yaml."""
    dirty = False
    sec = cfg.setdefault("secrets", {})
    if not sec.get("server_secret"):
        sec["server_secret"] = _secrets.token_hex(32)
        dirty = True
    if not sec.get("client_secret"):
        sec["client_secret"] = _secrets.token_hex(32)
        dirty = True
    if dirty:
        _save_yaml(cfg_path, cfg)
        # File contains secrets now — enforce 0600 on POSIX systems.
        try:
            os.chmod(cfg_path, 0o600)
        except Exception:
            pass
    return dirty


def _apply_env_from_config(cfg: dict, cfg_path: Path) -> None:
    """Populate os.environ so when server.py is imported it picks up
    our config. Must be called BEFORE the import."""
    sec = cfg.get("secrets", {}) or {}
    st = cfg.get("storage", {}) or {}
    hd = cfg.get("hardening", {}) or {}
    em = cfg.get("email", {}) or {}
    org = cfg.get("organization", {}) or {}

    # Resolve relative paths against the config file's directory
    base = cfg_path.parent.resolve()
    def rel(p: str) -> str:
        if not p: return ""
        pp = Path(p)
        return str(pp) if pp.is_absolute() else str((base / pp).resolve())

    env_map = {
        "SERVER_SECRET": sec.get("server_secret") or "",
        "CLIENT_SECRET": sec.get("client_secret") or "",
        "AIAUTH_LICENSE_KEY": cfg.get("license_key", ""),
        "AIAUTH_MODE": "enterprise",
        "AIAUTH_PUBLIC_URL": cfg.get("server_url", "") or "",
        "AIAUTH_KEY_DIR": rel(st.get("key_dir", "./keys")) or "./keys",
        "AIAUTH_DB_PATH": rel(st.get("app_db", "./aiauth.db")) or "./aiauth.db",
        "AIAUTH_REGISTRY_PATH": rel(st.get("registry_db", "./aiauth_registry.db")) or "./aiauth_registry.db",
        "AIAUTH_DEDUP_WINDOW": str(hd.get("dedup_window_seconds", 300)),
        "AIAUTH_LICENSE_GRACE_DAYS": str(hd.get("license_grace_days", 30)),
        "AIAUTH_LOG_MAGIC_LINKS": "true" if hd.get("log_magic_links") else "false",
        "AIAUTH_MASTER_KEY": cfg.get("master_key", "") or "bootstrap-no-admin",
    }
    if em.get("provider") == "resend" and em.get("api_key"):
        env_map["RESEND_API_KEY"] = em["api_key"]
        env_map["RESEND_FROM"] = em.get("from_address", "AIAuth <auth@aiauth.app>")

    for k, v in env_map.items():
        if v:
            os.environ[k] = v

    # Ensure storage dirs exist
    for key in ("key_dir",):
        p = Path(env_map["AIAUTH_KEY_DIR"])
        p.mkdir(parents=True, exist_ok=True)


def _ensure_org_row(server_module, cfg: dict) -> None:
    """Create the organizations row if it doesn't exist. Uses
    server_module.get_db() so the schema has already been initialized."""
    org = cfg.get("organization", {}) or {}
    name = (org.get("name") or "").strip()
    domains = [d.strip().lower() for d in (org.get("domains") or []) if d.strip()]
    if not name or not domains:
        print("ERROR: organization.name and organization.domains are required.", file=sys.stderr)
        sys.exit(1)
    conn = server_module.get_db()
    try:
        row = conn.execute(
            "SELECT org_id FROM organizations WHERE name = ? AND license_key = ? LIMIT 1",
            (name, cfg.get("license_key", "")),
        ).fetchone()
        if row:
            print(f"[bootstrap] Organization already registered: {row['org_id']}")
            return
        from datetime import datetime, timezone
        import uuid
        org_id = "ORG_" + uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).isoformat()
        license_data = server_module.validate_license(cfg["license_key"]) or {}
        tier = license_data.get("tier", "enterprise")
        conn.execute(
            "INSERT INTO organizations (org_id, name, domains, license_key, license_tier, created_at, active) "
            "VALUES (?,?,?,?,?,?,1)",
            (org_id, name, json.dumps(domains), cfg["license_key"], tier, now),
        )
        conn.commit()
        print(f"[bootstrap] Created organization {name!r} -> {org_id} (tier={tier}, domains={domains})")
    finally:
        conn.close()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", required=True, help="Path to config.yaml")
    p.add_argument("--dry-run", action="store_true", help="Validate + report, don't write anything")
    args = p.parse_args()

    cfg_path = Path(args.config).resolve()
    if not cfg_path.exists():
        print(f"ERROR: {cfg_path} does not exist. Copy config.yaml.example to this path and edit.",
              file=sys.stderr)
        sys.exit(1)

    cfg = _load_yaml(cfg_path)

    if not args.dry_run:
        dirty = _require_secrets(cfg, cfg_path)
        if dirty:
            print("[bootstrap] Generated missing secrets and wrote back to config.yaml")

    # Put everything into env BEFORE importing server.py
    _apply_env_from_config(cfg, cfg_path)

    # Import server.py lazily. It initializes keys + both databases as
    # a side-effect of import (via init_registry() + init_db()).
    here = Path(__file__).resolve().parent
    repo_root = here.parent.parent  # self-hosted/scripts/ -> self-hosted/ -> repo root
    sys.path.insert(0, str(repo_root))
    import importlib.util
    spec = importlib.util.spec_from_file_location("srv", repo_root / "server.py")
    srv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(srv)

    # License validation
    lic_data = _validate_license(cfg.get("license_key", ""), srv)
    print(f"[bootstrap] License valid: company={lic_data.get('company')!r} tier={lic_data.get('tier')!r}")
    if lic_data.get("expires"):
        status = "EXPIRED (grace period)" if lic_data.get("expired") else "valid"
        print(f"[bootstrap]   Expires: {lic_data['expires']} ({status})")

    # Confirm signing keys loaded
    print(f"[bootstrap] Signing keys loaded: {list(srv.KEY_REGISTRY.keys())}; current={srv.CURRENT_KEY_ID}")

    # Create organization row if missing
    if not args.dry_run:
        _ensure_org_row(srv, cfg)

    # Final summary
    print()
    print("=" * 60)
    print("AIAuth Enterprise bootstrap complete.")
    print("=" * 60)
    print(f"  Server URL:   {cfg.get('server_url')}")
    print(f"  Organization: {cfg.get('organization',{}).get('name')}")
    print(f"  Keys:         {os.environ.get('AIAUTH_KEY_DIR')}")
    print(f"  App DB:       {os.environ.get('AIAUTH_DB_PATH')}")
    print(f"  Registry DB:  {os.environ.get('AIAUTH_REGISTRY_PATH')}")
    print()
    print("Next step: start the server.")
    print("  Docker:  docker compose up -d")
    print("  Bare:    systemctl start aiauth")
    print("  Dev:     python -m uvicorn server:app --host 127.0.0.1 --port 8100")
    print()


if __name__ == "__main__":
    main()
