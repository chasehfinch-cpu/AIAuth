"""
AIAuth Server v4 — Chain-Aware Signing Authority

The server does three things:
  1. SIGN:   Hash in -> signed receipt out -> server forgets
  2. VERIFY: Receipt in -> yes/no out
  3. CHAIN:  Receipts in -> unbroken yes/no out

No database. No user data. No storage. Fully stateless.
The receipts themselves are the blockchain — each one references
the previous version's hash, creating a tamper-evident chain
of custody that follows content through its entire lifecycle.

Run:
  pip install fastapi uvicorn cryptography
  uvicorn server:app --host 0.0.0.0 --port 8100

Enterprise mode (adds storage, dashboard, review history):
  AIAUTH_MODE=enterprise uvicorn server:app --host 0.0.0.0 --port 8100
"""

import hashlib
import json
import os
import re
import uuid
import sqlite3
import base64
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel, Field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


# ===================================================================
# CONFIG
# ===================================================================

VERSION = "0.5.0"
SCHEMA_MIN = "0.4.0"   # server accepts receipts from any schema >= this
MODE = os.getenv("AIAUTH_MODE", "public")
KEY_DIR = Path(os.getenv("AIAUTH_KEY_DIR", "."))
DB_PATH = os.getenv("AIAUTH_DB_PATH", "aiauth.db")
LICENSE_KEY = os.getenv("AIAUTH_LICENSE_KEY", "")
MASTER_KEY = os.getenv("AIAUTH_MASTER_KEY", "")  # Admin key for license generation
SERVER_SECRET = os.getenv("SERVER_SECRET", "")   # HMAC secret for magic-link + session tokens (v0.5.0+)
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")   # HMAC secret for extension client_integrity (Piece 9)
PUBLIC_BASE_URL = os.getenv("AIAUTH_PUBLIC_URL", "https://aiauth.app")  # base URL for magic-link emails
DEDUP_WINDOW = int(os.getenv("AIAUTH_DEDUP_WINDOW", "300"))  # seconds; 0 disables dedup

# Regex for SHA-256 hex (lowercase or uppercase)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

app = FastAPI(title="AIAuth", version=VERSION)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ===================================================================
# RATE LIMITING (v0.5.0+)
# Per-IP sliding-window counters kept in memory. Per CLAUDE.md
# "Rate Limiting and Abuse Prevention" — these protect the free
# signing endpoint from DoS and enumeration attacks.
#
# Limits are per WORKER process (uvicorn --workers 2 doubles real
# throughput vs. spec, which is acceptable — spec limits are caps
# not exact). For stricter enforcement behind multiple workers,
# substitute a shared store (Redis/memcached) in the future.
# ===================================================================

import time
import threading as _rl_threading
from collections import deque

RATE_LIMITS: Dict[str, Dict[str, int]] = {
    "/v1/sign":           {"per_ip_per_min": 100},
    "/v1/sign/batch":     {"per_ip_per_min": 10},
    "/v1/account/create": {"per_ip_per_hour": 5},
    "/v1/account/auth":   {"per_ip_per_hour": 10},
    "/v1/discover":       {"per_ip_per_min": 60},
    "/v1/verify/prompt":  {"per_ip_per_min": 30},
}

# Ordered longest-prefix-first for path matching below
_RATE_PREFIXES = sorted(RATE_LIMITS.keys(), key=len, reverse=True)

_RATE_BUCKETS: Dict[tuple, deque] = {}
_RATE_LOCK = _rl_threading.Lock()


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _rate_check(key: tuple, window_seconds: int, limit: int) -> bool:
    """Sliding-window counter. Returns True if under limit (and records
    the hit), False if over. Thread-safe."""
    now = time.time()
    cutoff = now - window_seconds
    with _RATE_LOCK:
        dq = _RATE_BUCKETS.setdefault(key, deque())
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True


def _match_rate_endpoint(path: str) -> Optional[str]:
    for prefix in _RATE_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return prefix
    return None


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    endpoint_key = _match_rate_endpoint(request.url.path)
    if endpoint_key is None:
        return await call_next(request)

    cfg = RATE_LIMITS[endpoint_key]
    ip = _client_ip(request)

    def _reject(window: int, limit: int):
        return JSONResponse(
            status_code=429,
            content={"error": {
                "code": "RATE_LIMITED",
                "message": f"Rate limit exceeded for {endpoint_key}",
                "details": {"window_seconds": window, "limit": limit, "endpoint": endpoint_key},
            }},
        )

    if "per_ip_per_min" in cfg:
        limit = cfg["per_ip_per_min"]
        if not _rate_check((endpoint_key, "ip-min", ip), 60, limit):
            return _reject(60, limit)
    if "per_ip_per_hour" in cfg:
        limit = cfg["per_ip_per_hour"]
        if not _rate_check((endpoint_key, "ip-hr", ip), 3600, limit):
            return _reject(3600, limit)

    # X-AIAuth-Client header is advisory on /v1/sign* — we log absence but
    # do NOT reject (preserves backward compat with curl tests and older
    # clients). Enterprise tier may enforce in the future via policy engine.
    # (Intentional no-op here.)

    return await call_next(request)


# ===================================================================
# STANDARD ERROR RESPONSE FORMAT
# Matches the contract in CLAUDE.md "Error Handling" section.
# ===================================================================

class AIAuthError(Exception):
    def __init__(self, code: str, message: str, status: int = 400, details: Optional[dict] = None):
        self.code = code
        self.message = message
        self.status = status
        self.details = details or {}
        super().__init__(message)


@app.exception_handler(AIAuthError)
async def _aiauth_error_handler(request: Request, exc: AIAuthError):
    return JSONResponse(
        status_code=exc.status,
        content={"error": {"code": exc.code, "message": exc.message, "details": exc.details}},
    )


# ===================================================================
# ED25519 KEY MANAGEMENT (versioned, v0.5.0+)
# See CLAUDE.md "Key Management" section. Keys live under KEY_DIR/keys/
# with a key_manifest.json mapping key_ids to validity windows. The
# current signing key is identified by manifest.current_signing_key.
# Every signed receipt embeds the key_id used, so verification stays
# deterministic across key rotations.
#
# Migration: if a legacy KEY_DIR/aiauth_private.pem exists and no
# keys/ subdirectory exists yet, it is copied (not moved) to
# keys/key_000_active.pem on first startup. Historical receipts that
# lack a key_id field still verify because check_sig falls back to
# trying every known key.
# ===================================================================

import shutil  # used by legacy-key migration

KEYS_SUBDIR = KEY_DIR / "keys"
KEY_MANIFEST_PATH = KEYS_SUBDIR / "key_manifest.json"

# In-memory registry: key_id -> {"private", "public", "public_pem", "meta"}
KEY_REGISTRY: Dict[str, Dict[str, Any]] = {}
CURRENT_KEY_ID: str = ""


def _derive_public_pem(private_key) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _save_private_key(private_key, path: Path) -> None:
    with open(path, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def _save_public_key(private_key, path: Path) -> None:
    with open(path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


def _write_manifest(manifest: dict) -> None:
    KEYS_SUBDIR.mkdir(parents=True, exist_ok=True)
    with open(KEY_MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)


def _migrate_legacy_single_key() -> Optional[dict]:
    """If a pre-v0.5.0 KEY_DIR/aiauth_private.pem exists, convert it
    to key_000 under the versioned layout. Returns manifest or None."""
    legacy_priv = KEY_DIR / "aiauth_private.pem"
    if not legacy_priv.exists():
        return None
    KEYS_SUBDIR.mkdir(parents=True, exist_ok=True)
    dst_priv = KEYS_SUBDIR / "key_000_active.pem"
    if not dst_priv.exists():
        shutil.copy2(legacy_priv, dst_priv)  # copy, don't remove legacy file
        try:
            os.chmod(dst_priv, 0o600)
        except Exception:
            pass
    with open(dst_priv, "rb") as f:
        pk = serialization.load_pem_private_key(f.read(), password=None)
    _save_public_key(pk, KEYS_SUBDIR / "key_000_public.pem")
    manifest = {
        "keys": [{
            "key_id": "key_000",
            "algorithm": "Ed25519",
            # Retrospective window — covers all historical receipts.
            "valid_from": "2020-01-01T00:00:00Z",
            "valid_until": None,
            "status": "active",
            "public_key_pem": _derive_public_pem(pk),
        }],
        "current_signing_key": "key_000",
    }
    _write_manifest(manifest)
    print("[AIAuth] Migrated legacy aiauth_private.pem -> keys/key_000_active.pem")
    return manifest


def _load_or_init_manifest() -> dict:
    if KEY_MANIFEST_PATH.exists():
        with open(KEY_MANIFEST_PATH, "r") as f:
            return json.load(f)
    migrated = _migrate_legacy_single_key()
    if migrated:
        return migrated
    # Fresh install — generate key_001
    KEYS_SUBDIR.mkdir(parents=True, exist_ok=True)
    pk = Ed25519PrivateKey.generate()
    _save_private_key(pk, KEYS_SUBDIR / "key_001_active.pem")
    _save_public_key(pk, KEYS_SUBDIR / "key_001_public.pem")
    manifest = {
        "keys": [{
            "key_id": "key_001",
            "algorithm": "Ed25519",
            "valid_from": datetime.now(timezone.utc).isoformat(),
            "valid_until": None,
            "status": "active",
            "public_key_pem": _derive_public_pem(pk),
        }],
        "current_signing_key": "key_001",
    }
    _write_manifest(manifest)
    print("[AIAuth] Fresh install — generated keys/key_001_active.pem")
    return manifest


def _load_private_for(key_id: str):
    """Try active then retired variants on disk. Returns None if the
    private key is not available (e.g., historical key pruned from disk
    but still in the manifest for verification)."""
    for variant in ("active", "retired"):
        p = KEYS_SUBDIR / f"{key_id}_{variant}.pem"
        if p.exists():
            with open(p, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
    return None


def initialize_keys() -> None:
    global CURRENT_KEY_ID
    manifest = _load_or_init_manifest()
    CURRENT_KEY_ID = manifest.get("current_signing_key", "")
    KEY_REGISTRY.clear()
    for entry in manifest.get("keys", []):
        kid = entry["key_id"]
        priv = _load_private_for(kid)
        if priv is None:
            # Private pruned from disk — still loadable for verification
            # from the manifest's public_key_pem field.
            try:
                pub = serialization.load_pem_public_key(entry["public_key_pem"].encode())
            except Exception:
                continue
            KEY_REGISTRY[kid] = {
                "private": None,
                "public": pub,
                "public_pem": entry["public_key_pem"],
                "meta": entry,
            }
        else:
            KEY_REGISTRY[kid] = {
                "private": priv,
                "public": priv.public_key(),
                "public_pem": _derive_public_pem(priv),
                "meta": entry,
            }
    if not CURRENT_KEY_ID or CURRENT_KEY_ID not in KEY_REGISTRY:
        raise RuntimeError(f"Key manifest invalid: current_signing_key={CURRENT_KEY_ID} not in loaded set {list(KEY_REGISTRY.keys())}")
    print(f"[AIAuth] Loaded {len(KEY_REGISTRY)} key(s); current = {CURRENT_KEY_ID}")


initialize_keys()


# Backward-compatible globals: any external code still referencing
# PRIV_KEY / PUB_KEY / PUB_PEM resolves to the CURRENT signing key.
PRIV_KEY = KEY_REGISTRY[CURRENT_KEY_ID]["private"]
PUB_KEY = KEY_REGISTRY[CURRENT_KEY_ID]["public"]
PUB_PEM = KEY_REGISTRY[CURRENT_KEY_ID]["public_pem"]


def sign(data: dict) -> str:
    """Sign with the current signing key. The caller is responsible for
    embedding key_id in `data` before calling sign() — that way the
    key_id becomes part of the signed payload and cannot be forged."""
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
    priv = KEY_REGISTRY[CURRENT_KEY_ID]["private"]
    if priv is None:
        raise RuntimeError(f"Current signing key {CURRENT_KEY_ID} has no private key on disk")
    sig = priv.sign(payload.encode())
    return base64.urlsafe_b64encode(sig).decode()


def check_sig(data: dict, sig_b64: str) -> bool:
    """Verify signature. Uses key_id from `data` when present; otherwise
    tries every known public key (supports pre-v0.5.0 receipts that have
    no key_id field)."""
    payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    try:
        sig_bytes = base64.urlsafe_b64decode(sig_b64)
    except Exception:
        return False
    kid = data.get("key_id") if isinstance(data, dict) else None
    if kid and kid in KEY_REGISTRY:
        try:
            KEY_REGISTRY[kid]["public"].verify(sig_bytes, payload)
            return True
        except Exception:
            return False
    # Legacy fallback: try every loaded key
    for entry in KEY_REGISTRY.values():
        try:
            entry["public"].verify(sig_bytes, payload)
            return True
        except Exception:
            continue
    return False


def build_public_key_manifest(include_private_status: bool = False) -> dict:
    """Return the manifest as served to clients via /v1/public-key.
    Never includes private key material."""
    keys = []
    for kid, entry in KEY_REGISTRY.items():
        meta = entry["meta"]
        k = {
            "key_id": kid,
            "algorithm": meta.get("algorithm", "Ed25519"),
            "valid_from": meta.get("valid_from"),
            "valid_until": meta.get("valid_until"),
            "status": meta.get("status", "active"),
            "public_key_pem": entry["public_pem"],
        }
        if include_private_status:
            k["private_key_available"] = entry["private"] is not None
        keys.append(k)
    return {
        "algorithm": "Ed25519",
        "keys": keys,
        "current_signing_key": CURRENT_KEY_ID,
        "version": VERSION,
    }


# ===================================================================
# LICENSE KEY SYSTEM
# ===================================================================
# License keys are signed JSON tokens — same Ed25519 infrastructure.
# You generate them with /v1/admin/license/generate (requires master key).
# Customers set AIAUTH_LICENSE_KEY env var to activate enterprise mode.
# The server validates the signature on startup — no phone-home needed.

def generate_license(company: str, tier: str = "enterprise",
                     max_users: int = 0, expires: str = "") -> dict:
    """Generate a signed license key. Only you can create these."""
    license_data = {
        "type": "aiauth_license",
        "company": company,
        "tier": tier,
        "issued": datetime.now(timezone.utc).isoformat(),
    }
    if max_users > 0:
        license_data["max_users"] = max_users
    if expires:
        license_data["expires"] = expires

    signature = sign(license_data)

    # Pack as a single portable string: base64(json) + "." + signature
    data_b64 = base64.urlsafe_b64encode(
        json.dumps(license_data, sort_keys=True).encode()
    ).decode()
    return {
        "license_key": f"{data_b64}.{signature}",
        "license_data": license_data,
    }


def validate_license(license_key: str) -> dict:
    """Validate a license key. Returns license data if valid, None if not."""
    if not license_key:
        return None
    try:
        parts = license_key.strip().split(".")
        if len(parts) != 2:
            return None
        data_b64, sig = parts
        data_json = base64.urlsafe_b64decode(data_b64).decode()
        data = json.loads(data_json)

        if data.get("type") != "aiauth_license":
            return None

        # Verify signature using server's own key
        if not check_sig(data, sig):
            return None

        # Check expiry
        if data.get("expires"):
            exp = datetime.fromisoformat(data["expires"])
            if datetime.now(timezone.utc) > exp:
                return None

        return data
    except Exception:
        return None


# Validate enterprise license on startup
ENTERPRISE_LICENSE = None
if MODE == "enterprise":
    ENTERPRISE_LICENSE = validate_license(LICENSE_KEY)
    if ENTERPRISE_LICENSE:
        print(f"[AIAuth] Enterprise license valid: {ENTERPRISE_LICENSE.get('company')}")
        print(f"[AIAuth]   Tier: {ENTERPRISE_LICENSE.get('tier')}")
        exp = ENTERPRISE_LICENSE.get("expires", "never")
        print(f"[AIAuth]   Expires: {exp}")
    else:
        print("[AIAuth] WARNING: Enterprise mode requested but no valid license key found.")
        print("[AIAuth]   Set AIAUTH_LICENSE_KEY or run in public mode.")
        print("[AIAuth]   Enterprise features will be disabled.")
        MODE = "public"  # Fall back to public mode


def require_enterprise():
    """Gate for enterprise-only endpoints."""
    if MODE != "enterprise" or not ENTERPRISE_LICENSE:
        raise HTTPException(
            status_code=402,
            detail={
                "error": "enterprise_required",
                "message": "This feature requires an AIAuth Enterprise license.",
                "info": "Contact hello@aiauth.app for licensing.",
            }
        )


# ===================================================================
# HASH REGISTRY — public bulletin board (both modes)
# Maps content hashes to receipt IDs. No names, no details.
# Enables chain discovery: "does a parent/child receipt exist?"
# ===================================================================

REGISTRY_PATH = os.getenv("AIAUTH_REGISTRY_PATH", "aiauth_registry.db")

def get_registry():
    conn = sqlite3.connect(REGISTRY_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_registry():
    conn = get_registry()
    conn.execute("""CREATE TABLE IF NOT EXISTS hash_registry (
        content_hash  TEXT NOT NULL,
        receipt_id    TEXT NOT NULL,
        parent_hash   TEXT,
        registered_at TEXT NOT NULL
    )""")
    # v0.5.0 migration: add doc_id column if missing (idempotent, safe to re-run)
    existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(hash_registry)").fetchall()}
    if "doc_id" not in existing_cols:
        conn.execute("ALTER TABLE hash_registry ADD COLUMN doc_id TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reg_hash ON hash_registry(content_hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reg_parent ON hash_registry(parent_hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reg_receipt ON hash_registry(receipt_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reg_doc_id ON hash_registry(doc_id)")
    conn.commit()
    conn.close()

init_registry()

def register_hash(content_hash: str, receipt_id: str, parent_hash: str = None, doc_id: str = None):
    """Add an entry to the public registry. No user data stored.

    Five columns only (per Core Principle #3): content_hash, receipt_id,
    parent_hash, doc_id, registered_at. No uid, no model, no prompt_hash.
    """
    conn = get_registry()
    conn.execute(
        "INSERT INTO hash_registry (content_hash, receipt_id, parent_hash, doc_id, registered_at) VALUES (?,?,?,?,?)",
        (content_hash, receipt_id, parent_hash, doc_id, datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    conn.close()


def find_recent_duplicate(content_hash: str, window_seconds: int) -> Optional[dict]:
    """Return {receipt_id, registered_at} if this hash was registered within
    the dedup window, else None. Used by /v1/sign to avoid double-registration
    from accidental double-clicks or batched replay."""
    if window_seconds <= 0:
        return None
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    conn = get_registry()
    row = conn.execute(
        "SELECT receipt_id, registered_at FROM hash_registry "
        "WHERE content_hash = ? AND registered_at > ? "
        "ORDER BY registered_at DESC LIMIT 1",
        (content_hash, cutoff)
    ).fetchone()
    conn.close()
    return {"receipt_id": row["receipt_id"], "registered_at": row["registered_at"]} if row else None


# ===================================================================
# APPLICATION DB — accounts, orgs, tokens, consent, enterprise store
# (aiauth.db)
# Per CLAUDE.md "Database Architecture": two DBs total, not three.
# This single database holds everything that isn't the anonymous
# registry. Account/auth tables are always present (public account
# system is available in free tier). Enterprise tables are created
# regardless of MODE so that hosted enterprise ingest works without
# restart when a license is activated.
# ===================================================================

import hmac
import secrets


def get_db():
    """Connection to aiauth.db. Opened fresh per call — SQLite with WAL
    handles concurrency."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()

    # ---------------- Accounts (always, all modes) ----------------
    conn.execute("""CREATE TABLE IF NOT EXISTS accounts (
        account_id    TEXT PRIMARY KEY,
        primary_email TEXT NOT NULL,
        created_at    TEXT NOT NULL,
        updated_at    TEXT NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS account_emails (
        email         TEXT PRIMARY KEY,
        account_id    TEXT NOT NULL REFERENCES accounts(account_id),
        email_type    TEXT NOT NULL,
        org_id        TEXT,
        verified      INTEGER NOT NULL DEFAULT 0,
        added_at      TEXT NOT NULL,
        verified_at   TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ae_account ON account_emails(account_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ae_org ON account_emails(org_id)")

    # ---------------- Organizations + membership ----------------
    conn.execute("""CREATE TABLE IF NOT EXISTS organizations (
        org_id        TEXT PRIMARY KEY,
        name          TEXT NOT NULL,
        domains       TEXT NOT NULL,
        license_key   TEXT NOT NULL,
        license_tier  TEXT NOT NULL,
        created_at    TEXT NOT NULL,
        active        INTEGER NOT NULL DEFAULT 1
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS org_members (
        account_id    TEXT NOT NULL REFERENCES accounts(account_id),
        org_id        TEXT NOT NULL REFERENCES organizations(org_id),
        role          TEXT NOT NULL DEFAULT 'member',
        department    TEXT,
        joined_at     TEXT NOT NULL,
        left_at       TEXT,
        consent_personal_history INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (account_id, org_id)
    )""")

    # ---------------- Immutable consent audit log ----------------
    conn.execute("""CREATE TABLE IF NOT EXISTS consent_log (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id    TEXT NOT NULL,
        org_id        TEXT NOT NULL,
        action        TEXT NOT NULL,
        timestamp     TEXT NOT NULL,
        details       TEXT
    )""")

    # ---------------- Magic-link / session tokens ----------------
    conn.execute("""CREATE TABLE IF NOT EXISTS used_tokens (
        nonce         TEXT PRIMARY KEY,
        used_at       TEXT NOT NULL,
        purpose       TEXT NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS revoked_sessions (
        session_id    TEXT PRIMARY KEY,
        revoked_at    TEXT NOT NULL,
        reason        TEXT
    )""")

    # ---------------- Legacy v0.4.0 attestations (enterprise only) ----------------
    # Retained for backward compatibility. Piece 10 will introduce the
    # new enterprise_attestations table with the full v0.5.0 schema.
    if MODE == "enterprise":
        conn.execute("""CREATE TABLE IF NOT EXISTS attestations (
            id TEXT PRIMARY KEY, created_at TEXT, output_hash TEXT,
            user_id TEXT, model TEXT, provider TEXT, source TEXT,
            review_status TEXT DEFAULT 'pending', reviewer_id TEXT,
            reviewed_at TEXT, review_note TEXT,
            parent_hash TEXT, chain_root TEXT,
            signature TEXT, receipt TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS review_history (
            id TEXT PRIMARY KEY, attestation_id TEXT, reviewer_id TEXT,
            status TEXT, note TEXT, reviewed_at TEXT
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_chain ON attestations(chain_root)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_user ON attestations(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_hash ON attestations(output_hash)")

    conn.commit()
    conn.close()


init_db()


# ===================================================================
# MAGIC-LINK + SESSION TOKEN HELPERS (v0.5.0+)
# HMAC-signed JWT-style tokens: base64url(json).base64url(hmac).
# The server holds SERVER_SECRET; any tampering invalidates the MAC.
# ===================================================================

def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign_token(payload: dict) -> str:
    if not SERVER_SECRET:
        raise AIAuthError(
            "SERVER_MISCONFIGURED",
            "SERVER_SECRET env var is not set; magic-link auth is disabled",
            500,
        )
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    mac = hmac.new(SERVER_SECRET.encode(), canonical, hashlib.sha256).digest()
    return f"{_b64url_no_pad(canonical)}.{_b64url_no_pad(mac)}"


def _verify_token(token: str) -> Optional[dict]:
    if not SERVER_SECRET or not token or "." not in token:
        return None
    try:
        data_b64, sig_b64 = token.split(".", 1)
        canonical = _b64url_decode(data_b64)
        expected = hmac.new(SERVER_SECRET.encode(), canonical, hashlib.sha256).digest()
        actual = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected, actual):
            return None
        payload = json.loads(canonical)
        exp = payload.get("expires_at")
        if exp:
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            if exp_dt < datetime.now(timezone.utc):
                return None
        return payload
    except Exception:
        return None


def _make_magic_token(account_id: str, email: str, purpose: str, ttl_minutes: int = 15) -> tuple:
    now = datetime.now(timezone.utc)
    payload = {
        "account_id": account_id,
        "email": email,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=ttl_minutes)).isoformat(),
        "nonce": secrets.token_hex(16),
        "purpose": purpose,
    }
    return _sign_token(payload), payload


def _make_session_token(account_id: str, email: str, ttl_hours: int = 24) -> tuple:
    now = datetime.now(timezone.utc)
    payload = {
        "account_id": account_id,
        "email": email,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=ttl_hours)).isoformat(),
        "session_id": secrets.token_hex(16),
        "kind": "session",
    }
    return _sign_token(payload), payload


def _send_magic_link(email: str, token: str, purpose: str) -> None:
    """Email delivery is intentionally stubbed in v0.5.0. The link is
    logged to stdout and to KEY_DIR/magic_links.log so an admin can
    wire in a transactional email provider (Resend, Postmark, SES)
    without touching server code."""
    link = f"{PUBLIC_BASE_URL}/auth?token={token}&p={purpose}"
    msg = f"[AIAuth magic-link] to={email} purpose={purpose} link={link}"
    print(msg)
    try:
        log_path = KEY_DIR / "magic_links.log"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat()} {msg}\n")
    except Exception:
        pass


def _require_session(authorization: Optional[str]) -> dict:
    """Resolve a Bearer session token into its payload. Raises AIAuthError
    on missing/invalid/revoked sessions."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AIAuthError("UNAUTHENTICATED", "Missing Authorization: Bearer <session_token>", 401)
    token = authorization[7:].strip()
    payload = _verify_token(token)
    if payload is None or payload.get("kind") != "session":
        raise AIAuthError("SESSION_INVALID", "Session token is invalid or expired", 401)
    sid = payload.get("session_id")
    if sid:
        conn = get_db()
        row = conn.execute("SELECT session_id FROM revoked_sessions WHERE session_id = ?", (sid,)).fetchone()
        conn.close()
        if row:
            raise AIAuthError("SESSION_INVALID", "Session has been revoked", 401)
    return payload


def _find_account_by_email(email: str) -> Optional[sqlite3.Row]:
    conn = get_db()
    row = conn.execute(
        "SELECT ae.*, a.primary_email FROM account_emails ae "
        "JOIN accounts a ON ae.account_id = a.account_id "
        "WHERE ae.email = ?",
        (email,),
    ).fetchone()
    conn.close()
    return row


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _valid_email(email: str) -> bool:
    return bool(email) and bool(_EMAIL_RE.match(email.strip())) and len(email) <= 254


# ===================================================================
# 1. SIGN — create a signed receipt, store nothing
# ===================================================================

class SignRequest(BaseModel):
    # ----- Required (all schema versions) -----
    output_hash: str              # SHA-256 of the content (64 hex chars)
    user_id: str                  # Who is attesting (email or chosen uid)
    source: str = "unknown"       # Surface: chrome-extension / desktop-agent / litellm-callback

    # ----- v0.4.0 fields (retained) -----
    model: Optional[str] = None
    provider: Optional[str] = None
    review_status: Optional[str] = None  # approved / modified / rejected
    reviewer_id: Optional[str] = None
    note: Optional[str] = None
    parent_hash: Optional[str] = None    # previous version's content hash
    tags: Optional[list] = None
    register: bool = True                # add to public hash registry

    # ----- v0.5.0: free-tier additive fields -----
    prompt_hash: Optional[str] = None           # SHA-256 of prompt text (free tier, see CLAUDE.md Prompt Hashing)
    source_domain: Optional[str] = None         # e.g. "claude.ai"
    source_app: Optional[str] = None            # active window/app title (desktop)
    file_type: Optional[str] = None             # spreadsheet/document/pdf/code/image/prose/snippet/text/data
    content_length: Optional[int] = Field(default=None, alias="len")   # character/byte count, NOT content
    doc_id: Optional[str] = None                # persistent document identifier
    ai_markers: Optional[Dict[str, Any]] = None # {"source": "...", "verified": bool}
    client_integrity: Optional[str] = None      # "none" | "extension" | "os-verified"  (server may downgrade)

    # ----- v0.5.0: commercial-tier fields (free-tier clients omit) -----
    tta: Optional[int] = None                   # seconds between AI output and attestation
    sid: Optional[str] = None                   # session id grouping same AI conversation
    dest: Optional[str] = None                  # email / messaging / document-platform / code-repository
    dest_ext: Optional[bool] = None             # destination external to org?
    classification: Optional[str] = None        # financial / legal / client-facing / internal
    concurrent_ai_apps: Optional[List[str]] = None  # AI processes running at attest moment

    # Pydantic v2 config: allow "len" as alias; also tolerate extra fields for forward-compat
    model_config = {"populate_by_name": True, "extra": "ignore"}


def _validate_sign_request(req: SignRequest) -> None:
    """Apply v0.5.0 schema-level validation, raising AIAuthError on failure."""
    if not _SHA256_RE.match(req.output_hash or ""):
        raise AIAuthError("INVALID_HASH", "output_hash must be a 64-character SHA-256 hex string", 400)
    if req.prompt_hash is not None and not _SHA256_RE.match(req.prompt_hash):
        raise AIAuthError("INVALID_PROMPT_HASH", "prompt_hash must be a 64-character SHA-256 hex string", 400)
    if req.parent_hash is not None and not _SHA256_RE.match(req.parent_hash):
        raise AIAuthError("INVALID_HASH", "parent_hash must be a 64-character SHA-256 hex string", 400)
    if not (req.user_id or "").strip():
        raise AIAuthError("INVALID_RECEIPT", "user_id (uid) is required", 400)
    if req.client_integrity not in (None, "none", "extension", "os-verified"):
        raise AIAuthError("INVALID_RECEIPT", "client_integrity must be one of: none, extension, os-verified", 400)


@app.post("/v1/sign")
def sign_receipt(req: SignRequest):
    """
    Sign an attestation receipt and return it.

    If register=true (default), the content hash and receipt ID are
    added to the public hash registry. This enables chain discovery —
    others can find out that a receipt exists for a given content hash.
    The registry stores NO user data — only hash -> receipt_id mappings
    (five columns: content_hash, receipt_id, parent_hash, doc_id, registered_at).

    If register=false, the server signs and forgets entirely.

    v0.5.0 behavior:
      - Accepts all v0.5.0 schema fields (additive; missing fields default to null).
      - Applies a deduplication window (default 300s, configurable via AIAUTH_DEDUP_WINDOW):
        re-submitting the same content_hash within the window returns HTTP 409 with
        the original receipt_id, so the client can reuse its cached signature.
      - Rejects malformed hashes with standardized error response.
      - prompt_hash is signed into the receipt but NEVER added to the public registry
        (see Integrity Rule #12 in CLAUDE.md).
    """
    _validate_sign_request(req)

    # Deduplication: if the same content_hash was registered recently, return 409.
    # The public server does not store signatures, so we do not echo the prior signature —
    # the client's local receipt store already has it (see Offline-First Client Architecture).
    if req.register and DEDUP_WINDOW > 0:
        existing = find_recent_duplicate(req.output_hash, DEDUP_WINDOW)
        if existing:
            raise AIAuthError(
                code="RECEIPT_DUPLICATE",
                message="This content was already attested within the deduplication window",
                status=409,
                details={
                    "existing_receipt_id": existing["receipt_id"],
                    "registered_at": existing["registered_at"],
                    "window_seconds": DEDUP_WINDOW,
                },
            )

    receipt_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Build receipt: required fields first, then all populated optional fields.
    # Null/empty fields are OMITTED (keeps receipt compact and backward-compatible).
    # key_id is embedded so the signature covers it — cannot be forged after signing.
    receipt: Dict[str, Any] = {
        "v": VERSION,
        "id": receipt_id,
        "ts": now,
        "hash": req.output_hash,
        "uid": req.user_id,
        "src": req.source,
        "key_id": CURRENT_KEY_ID,
    }

    # v0.4.0-compat optional fields
    if req.model: receipt["model"] = req.model
    if req.provider: receipt["provider"] = req.provider
    if req.parent_hash: receipt["parent"] = req.parent_hash
    if req.tags: receipt["tags"] = req.tags

    # v0.5.0 free-tier additions
    if req.prompt_hash: receipt["prompt_hash"] = req.prompt_hash
    if req.source_domain: receipt["source_domain"] = req.source_domain
    if req.source_app: receipt["source_app"] = req.source_app
    if req.file_type: receipt["file_type"] = req.file_type
    if req.content_length is not None: receipt["len"] = req.content_length
    if req.doc_id: receipt["doc_id"] = req.doc_id
    if req.ai_markers: receipt["ai_markers"] = req.ai_markers
    # client_integrity: default to "none" if absent so downstream consumers always have a value
    receipt["client_integrity"] = req.client_integrity or "none"

    # v0.5.0 commercial-tier fields (server accepts whatever the client sends)
    if req.tta is not None: receipt["tta"] = req.tta
    if req.sid: receipt["sid"] = req.sid
    if req.dest: receipt["dest"] = req.dest
    if req.dest_ext is not None: receipt["dest_ext"] = req.dest_ext
    if req.classification: receipt["classification"] = req.classification
    if req.concurrent_ai_apps: receipt["concurrent_ai_apps"] = req.concurrent_ai_apps

    if req.review_status:
        receipt["review"] = {
            "status": req.review_status,
            "by": req.reviewer_id or req.user_id,
            "at": now,
        }
        if req.note: receipt["review"]["note"] = req.note

    signature = sign(receipt)

    # Public hash registry — stores hash->receipt_id mapping + doc_id only, no user data
    if req.register:
        register_hash(req.output_hash, receipt_id, req.parent_hash, req.doc_id)

    # Enterprise: also store full attestation
    if MODE == "enterprise":
        # Determine chain root
        chain_root = req.output_hash
        if req.parent_hash:
            conn = get_db()
            parent = conn.execute(
                "SELECT chain_root FROM attestations WHERE output_hash = ?",
                (req.parent_hash,)
            ).fetchone()
            if parent:
                chain_root = parent["chain_root"]
            conn.close()

        conn = get_db()
        conn.execute("""INSERT INTO attestations
            (id, created_at, output_hash, user_id, model, provider, source,
             review_status, reviewer_id, reviewed_at, review_note,
             parent_hash, chain_root, signature, receipt)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (receipt_id, now, req.output_hash, req.user_id,
             req.model, req.provider, req.source,
             req.review_status or "pending", req.reviewer_id,
             now if req.reviewer_id else None, req.note,
             req.parent_hash, chain_root, signature,
             json.dumps(receipt)))
        conn.commit(); conn.close()

    return {
        "receipt": receipt,
        "signature": signature,
        "short_id": receipt_id[:12],
        "receipt_code": f"[AIAuth:{receipt_id[:12]}]",
    }


# ===================================================================
# ACCOUNT SYSTEM — magic-link authentication (v0.5.0+)
# Endpoints: /v1/account/create, /auth, /verify, /confirm, /link,
#            /me, /consent, /export, /logout
# See CLAUDE.md "Authentication Model" for the full design. All
# enumeration-sensitive endpoints return 200 whether or not the email
# exists — callers can't tell.
# ===================================================================

class AccountCreateRequest(BaseModel):
    email: str


class AccountAuthRequest(BaseModel):
    email: str


class AccountVerifyRequest(BaseModel):
    token: str


class AccountLinkRequest(BaseModel):
    email: str
    email_type: str = "corporate"   # "personal" | "corporate"


class AccountConfirmRequest(BaseModel):
    token: str


class AccountConsentRequest(BaseModel):
    org_id: str
    consent_personal_history: bool


def _standard_enum_safe_ok():
    """Response returned by enumeration-sensitive endpoints regardless
    of whether the email exists. Keep wording identical to avoid side
    channels."""
    return {"message": "If the email is valid, a magic link has been sent. Link expires in 15 minutes."}


@app.post("/v1/account/create")
def account_create(body: AccountCreateRequest):
    """Create a new AIAuth account and send a magic link. Idempotent:
    if the email already maps to an account, behaves identically to
    /v1/account/auth (no enumeration signal)."""
    email = (body.email or "").strip().lower()
    if not _valid_email(email):
        raise AIAuthError("INVALID_EMAIL", "Email format is invalid", 400)

    existing = _find_account_by_email(email)
    now = datetime.now(timezone.utc).isoformat()
    if existing:
        account_id = existing["account_id"]
    else:
        account_id = "ACC_" + uuid.uuid4().hex[:12]
        conn = get_db()
        conn.execute(
            "INSERT INTO accounts (account_id, primary_email, created_at, updated_at) VALUES (?,?,?,?)",
            (account_id, email, now, now),
        )
        conn.execute(
            "INSERT INTO account_emails (email, account_id, email_type, verified, added_at) VALUES (?,?,?,?,?)",
            (email, account_id, "personal", 0, now),
        )
        conn.commit()
        conn.close()

    token, _ = _make_magic_token(account_id, email, "login")
    _send_magic_link(email, token, "login")
    return _standard_enum_safe_ok()


@app.post("/v1/account/auth")
def account_auth(body: AccountAuthRequest):
    """Request a magic link for an existing account. Does NOT reveal
    whether the email exists. Rate-limited by middleware
    (10/hour per IP)."""
    email = (body.email or "").strip().lower()
    if not _valid_email(email):
        # Silent success to avoid enumeration
        return _standard_enum_safe_ok()
    existing = _find_account_by_email(email)
    if existing:
        token, _ = _make_magic_token(existing["account_id"], email, "login")
        _send_magic_link(email, token, "login")
    # else: silently do nothing
    return _standard_enum_safe_ok()


@app.post("/v1/account/verify")
def account_verify(body: AccountVerifyRequest):
    """Validate a magic-link token and return a session token. Tokens
    are single-use: the nonce is recorded in used_tokens so replays
    fail with TOKEN_USED."""
    payload = _verify_token(body.token)
    if payload is None:
        raise AIAuthError("TOKEN_INVALID", "Magic link is invalid or expired", 400)
    if payload.get("purpose") not in ("login", "verify_email", "link_email"):
        raise AIAuthError("TOKEN_INVALID", "Token has unexpected purpose", 400)

    nonce = payload.get("nonce")
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO used_tokens (nonce, used_at, purpose) VALUES (?,?,?)",
            (nonce, now, payload.get("purpose", "")),
        )
    except sqlite3.IntegrityError:
        conn.close()
        raise AIAuthError("TOKEN_USED", "Magic link has already been used", 400)

    # Mark email as verified if this is a login/verify_email token
    conn.execute(
        "UPDATE account_emails SET verified = 1, verified_at = ? "
        "WHERE email = ? AND verified = 0",
        (now, payload["email"]),
    )
    conn.commit()
    conn.close()

    session_token, sess_payload = _make_session_token(payload["account_id"], payload["email"])
    return {
        "session_token": session_token,
        "expires_in": 86400,
        "expires_at": sess_payload["expires_at"],
        "account_id": payload["account_id"],
        "email": payload["email"],
    }


@app.get("/v1/account/me")
def account_me(authorization: Optional[str] = Header(default=None)):
    """Return the authenticated caller's account info: emails linked,
    verification status, org memberships."""
    session = _require_session(authorization)
    account_id = session["account_id"]
    conn = get_db()
    emails = [dict(r) for r in conn.execute(
        "SELECT email, email_type, org_id, verified, added_at, verified_at "
        "FROM account_emails WHERE account_id = ?",
        (account_id,),
    ).fetchall()]
    orgs = [dict(r) for r in conn.execute(
        "SELECT om.org_id, o.name, om.role, om.department, om.joined_at, "
        "       om.left_at, om.consent_personal_history "
        "FROM org_members om JOIN organizations o ON om.org_id = o.org_id "
        "WHERE om.account_id = ?",
        (account_id,),
    ).fetchall()]
    conn.close()
    return {
        "account_id": account_id,
        "current_email": session["email"],
        "emails": emails,
        "organizations": orgs,
    }


@app.post("/v1/account/link")
def account_link(body: AccountLinkRequest, authorization: Optional[str] = Header(default=None)):
    """Link an additional email to the authenticated account. Sends a
    magic link to the new email; completion happens via /v1/account/confirm."""
    session = _require_session(authorization)
    new_email = (body.email or "").strip().lower()
    if not _valid_email(new_email):
        raise AIAuthError("INVALID_EMAIL", "Email format is invalid", 400)
    if body.email_type not in ("personal", "corporate"):
        raise AIAuthError("INVALID_RECEIPT", "email_type must be personal or corporate", 400)

    # If email already belongs to a DIFFERENT account, reject (enumeration-
    # safe because the caller already has a session — no blind lookup).
    existing = _find_account_by_email(new_email)
    if existing and existing["account_id"] != session["account_id"]:
        raise AIAuthError(
            "EMAIL_ALREADY_LINKED",
            "This email is already linked to another account",
            409,
        )
    # The token carries target account_id; confirmation writes the link.
    # We pre-encode email_type in purpose to avoid needing a state row.
    token, _ = _make_magic_token(
        session["account_id"], new_email,
        purpose=f"link_email:{body.email_type}",
    )
    _send_magic_link(new_email, token, f"link_email:{body.email_type}")
    return {"message": f"Magic link sent to {new_email}. Click it to confirm the link."}


@app.post("/v1/account/confirm")
def account_confirm(body: AccountConfirmRequest):
    """Confirm an email-link token (sent via /v1/account/link). Adds
    the new email to account_emails. Does not require a session — the
    signed token is the proof of possession."""
    payload = _verify_token(body.token)
    if payload is None:
        raise AIAuthError("TOKEN_INVALID", "Link-confirmation token is invalid or expired", 400)
    purpose = payload.get("purpose", "")
    if not purpose.startswith("link_email"):
        raise AIAuthError("TOKEN_INVALID", "Token is not a link-email token", 400)

    nonce = payload.get("nonce")
    now = datetime.now(timezone.utc).isoformat()
    email_type = "corporate"
    if ":" in purpose:
        email_type = purpose.split(":", 1)[1] or "corporate"

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO used_tokens (nonce, used_at, purpose) VALUES (?,?,?)",
            (nonce, now, purpose),
        )
    except sqlite3.IntegrityError:
        conn.close()
        raise AIAuthError("TOKEN_USED", "Token has already been used", 400)

    # Insert or update the email
    try:
        conn.execute(
            "INSERT INTO account_emails (email, account_id, email_type, verified, added_at, verified_at) "
            "VALUES (?,?,?,1,?,?)",
            (payload["email"], payload["account_id"], email_type, now, now),
        )
    except sqlite3.IntegrityError:
        # Already linked to same account — just ensure verified
        conn.execute(
            "UPDATE account_emails SET verified = 1, verified_at = ? "
            "WHERE email = ? AND account_id = ?",
            (now, payload["email"], payload["account_id"]),
        )
    conn.commit()
    conn.close()
    return {"linked": True, "email": payload["email"], "email_type": email_type}


@app.post("/v1/account/consent")
def account_consent(body: AccountConsentRequest, authorization: Optional[str] = Header(default=None)):
    """Grant or revoke the authenticated account's consent for an
    organization to see their PERSONAL-email attestations. Corporate-
    email attestations are always visible to the org (that's the point
    of having a corporate email) — this flag only controls the
    personal-history sharing in the enterprise dashboard."""
    session = _require_session(authorization)
    account_id = session["account_id"]
    conn = get_db()
    # Must already be an org member
    member = conn.execute(
        "SELECT * FROM org_members WHERE account_id = ? AND org_id = ?",
        (account_id, body.org_id),
    ).fetchone()
    if member is None:
        conn.close()
        raise AIAuthError("NOT_MEMBER", "You are not a member of that organization", 403)
    new_val = 1 if body.consent_personal_history else 0
    conn.execute(
        "UPDATE org_members SET consent_personal_history = ? "
        "WHERE account_id = ? AND org_id = ?",
        (new_val, account_id, body.org_id),
    )
    now = datetime.now(timezone.utc).isoformat()
    action = "grant_personal" if new_val else "revoke_personal"
    conn.execute(
        "INSERT INTO consent_log (account_id, org_id, action, timestamp, details) VALUES (?,?,?,?,?)",
        (account_id, body.org_id, action, now, json.dumps({"email": session["email"]})),
    )
    conn.commit()
    conn.close()
    return {"account_id": account_id, "org_id": body.org_id,
            "consent_personal_history": bool(new_val)}


@app.post("/v1/account/export")
def account_export(authorization: Optional[str] = Header(default=None)):
    """Export the authenticated account's data bundle. In v0.5.0 this
    returns account metadata + org memberships + consent history.
    Attestation receipts live on the user's device (free tier) and
    under enterprise contract (enterprise tier) — we do not hold
    personal-tier receipts to export."""
    session = _require_session(authorization)
    account_id = session["account_id"]
    conn = get_db()
    account = dict(conn.execute(
        "SELECT * FROM accounts WHERE account_id = ?", (account_id,)
    ).fetchone() or {})
    emails = [dict(r) for r in conn.execute(
        "SELECT * FROM account_emails WHERE account_id = ?", (account_id,)
    ).fetchall()]
    orgs = [dict(r) for r in conn.execute(
        "SELECT * FROM org_members WHERE account_id = ?", (account_id,)
    ).fetchall()]
    consent = [dict(r) for r in conn.execute(
        "SELECT * FROM consent_log WHERE account_id = ? ORDER BY timestamp DESC",
        (account_id,),
    ).fetchall()]
    conn.close()
    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "account": account,
        "emails": emails,
        "organizations": orgs,
        "consent_history": consent,
        "note": "Free-tier attestation receipts are stored on your device, not on our server.",
    }


@app.post("/v1/account/logout")
def account_logout(authorization: Optional[str] = Header(default=None)):
    """Revoke the current session by adding its session_id to
    revoked_sessions. Rate-limited by middleware via the auth path."""
    session = _require_session(authorization)
    sid = session.get("session_id")
    if sid:
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO revoked_sessions (session_id, revoked_at, reason) VALUES (?,?,?)",
                (sid, datetime.now(timezone.utc).isoformat(), "logout"),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # already revoked
        conn.close()
    return {"logged_out": True}


# ===================================================================
# 2. VERIFY — check a receipt's signature (stateless Y/N)
# ===================================================================

class VerifyRequest(BaseModel):
    receipt: dict
    signature: str

@app.post("/v1/verify")
def verify(req: VerifyRequest):
    """
    Is this receipt authentic? Y/N. Pure cryptographic check.
    Also queries the hash registry for chain discovery —
    are there parent or child receipts linked to this content?
    """
    valid = check_sig(req.receipt, req.signature)

    # Chain discovery from registry
    content_hash = req.receipt.get("hash")
    parent_hash = req.receipt.get("parent")
    chain_info = {}

    if content_hash:
        conn = get_registry()

        # Look for child receipts (content that references THIS hash as parent)
        children = conn.execute(
            "SELECT receipt_id FROM hash_registry WHERE parent_hash = ?",
            (content_hash,)
        ).fetchall()
        if children:
            chain_info["children"] = [
                {"receipt_id": c["receipt_id"]} for c in children
            ]

        # Look for parent receipt (if this receipt has a parent_hash)
        if parent_hash:
            parents = conn.execute(
                "SELECT receipt_id FROM hash_registry WHERE content_hash = ?",
                (parent_hash,)
            ).fetchall()
            if parents:
                chain_info["parents"] = [
                    {"receipt_id": p["receipt_id"]} for p in parents
                ]
            else:
                chain_info["parents"] = []
                chain_info["parent_note"] = "Parent hash referenced but no matching receipt found in registry."

        conn.close()

    return {
        "valid": valid,
        "id": req.receipt.get("id"),
        "user": req.receipt.get("uid"),
        "timestamp": req.receipt.get("ts"),
        "hash": req.receipt.get("hash"),
        "model": req.receipt.get("model"),
        "review": req.receipt.get("review"),
        "has_parent": "parent" in req.receipt,
        "chain_discovery": chain_info if chain_info else None,
    }


class ContentVerifyRequest(BaseModel):
    content_hash: str
    receipt: dict
    signature: str

@app.post("/v1/verify/content")
def verify_content(req: ContentVerifyRequest):
    """Is this receipt authentic AND does the content match? Y/N.

    Caller supplies a content_hash. The server compares against the
    receipt's hash. Per CLAUDE.md Content Hashing Rules, browser text
    attestations (>= v0.5.0) hash the NORMALIZED text while files hash
    raw bytes. If the receipt predates v0.5.0 or was produced by a
    normalization-inconsistent client, the supplied hash may not match
    on the first try. The server currently accepts a single hash from
    the caller — clients that want to verify text content should try
    both raw and normalized hashing on their side and call this
    endpoint twice if the first call returns content_matches=false.
    """
    sig_ok = check_sig(req.receipt, req.signature)
    hash_ok = req.receipt.get("hash") == req.content_hash
    return {
        "authentic": sig_ok and hash_ok,
        "signature_valid": sig_ok,
        "content_matches": hash_ok,
        "note": "For text receipts, try both raw and normalized hashing on the client if the first call returns content_matches=false.",
    }


# ===================================================================
# TEXT NORMALIZATION + PROMPT VERIFICATION
# Per CLAUDE.md "Content Hashing Rules" — browser text selections and
# prompt text MUST be normalized identically on client and server so the
# same logical input produces the same hash regardless of where it is
# computed. Rules: collapse all whitespace runs to single spaces, trim,
# encode UTF-8, SHA-256. Files are NOT normalized (they hash raw bytes).
# ===================================================================

_WS_RE = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """Apply the canonical text-normalization rules used for prompt and
    browser-selection hashing. Returns a UTF-8-safe, whitespace-collapsed,
    trimmed string suitable for SHA-256."""
    if text is None:
        return ""
    return _WS_RE.sub(" ", text).strip()


def hash_normalized(text: str) -> str:
    """Normalize and SHA-256. Hex-encoded lowercase."""
    import hashlib
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


class PromptVerifyRequest(BaseModel):
    receipt: dict                       # full receipt JSON (must include prompt_hash)
    signature: str                      # server signature over receipt
    prompt_text: Optional[str] = None   # the prompt text to verify; normalized then hashed
    prompt_hash: Optional[str] = None   # OR a pre-computed hash (verifier already has it)


@app.post("/v1/verify/prompt")
def verify_prompt(req: PromptVerifyRequest):
    """
    Verify that a given prompt text (or pre-computed prompt hash) matches
    the `prompt_hash` field inside a signed AIAuth receipt.

    This is stateless: the server stores NO prompt text. The verifier
    supplies either the prompt text (which the server normalizes + hashes
    on the fly) OR a pre-computed prompt_hash (for verifiers that want to
    keep the text local). In either case the server does not persist the
    input.

    Use case: a downstream reviewer has the original prompt and the
    attested receipt. They call this endpoint to prove that the same
    prompt produced the attested output — without ever revealing the
    prompt content to AIAuth.

    Errors:
      400 INVALID_RECEIPT      — signature invalid (can't trust any field)
      400 MISSING_PROMPT_HASH  — receipt has no prompt_hash field
      400 INVALID_PROMPT_HASH  — supplied prompt_hash is not SHA-256 hex
      400 INVALID_RECEIPT      — neither prompt_text nor prompt_hash provided
    """
    # Signature must verify first — otherwise the receipt can't be trusted
    sig_ok = check_sig(req.receipt, req.signature)
    if not sig_ok:
        raise AIAuthError(
            "INVALID_RECEIPT",
            "Receipt signature is not valid — cannot verify fields inside it",
            400,
        )

    receipt_prompt_hash = req.receipt.get("prompt_hash")
    if not receipt_prompt_hash:
        raise AIAuthError(
            "MISSING_PROMPT_HASH",
            "This receipt was attested without a prompt_hash; nothing to compare against",
            400,
            details={"receipt_id": req.receipt.get("id")},
        )

    # Compute the comparison hash from whichever input the caller provided
    if req.prompt_hash is not None:
        if not _SHA256_RE.match(req.prompt_hash):
            raise AIAuthError(
                "INVALID_PROMPT_HASH",
                "Supplied prompt_hash must be a 64-character SHA-256 hex string",
                400,
            )
        computed = req.prompt_hash.lower()
    elif req.prompt_text is not None:
        computed = hash_normalized(req.prompt_text)
    else:
        raise AIAuthError(
            "INVALID_RECEIPT",
            "Must supply either prompt_text or prompt_hash for comparison",
            400,
        )

    matches = computed == receipt_prompt_hash.lower()

    return {
        "matches": matches,
        "receipt_id": req.receipt.get("id"),
        "signature_valid": sig_ok,
        "receipt_prompt_hash": receipt_prompt_hash,
        "note": "Prompt text was not stored. This verification is stateless.",
    }


# ===================================================================
# 3. CHAIN VERIFY — validate an entire provenance chain (stateless)
# ===================================================================

class ChainLink(BaseModel):
    receipt: dict
    signature: str

class ChainVerifyRequest(BaseModel):
    chain: List[ChainLink]

@app.post("/v1/verify/chain")
def verify_chain(req: ChainVerifyRequest):
    """
    Verify an entire provenance chain. The client sends all receipts
    in order (oldest first). The server checks:
      1. Every signature is valid
      2. Each receipt's parent_hash matches the previous receipt's hash
      3. The chain is unbroken from origin to final version

    Returns Y/N plus details on each link.

    This is the blockchain — but without a blockchain. The receipts
    ARE the ledger. The signatures ARE the consensus. The parent
    references ARE the chain. No mining, no tokens, no gas fees.
    """
    if not req.chain:
        return {"valid": False, "reason": "Empty chain"}

    links = []
    chain_valid = True

    for i, link in enumerate(req.chain):
        sig_ok = check_sig(link.receipt, link.signature)

        # First link should have no parent (it's the origin)
        if i == 0:
            parent_ok = "parent" not in link.receipt
            if not parent_ok:
                # First link has a parent we can't verify — still valid
                # but we note we can't see the full chain
                parent_ok = True  # allow partial chains
        else:
            # This receipt's parent should match the previous receipt's hash
            expected_parent = req.chain[i - 1].receipt.get("hash")
            actual_parent = link.receipt.get("parent")
            parent_ok = actual_parent == expected_parent

        link_valid = sig_ok and parent_ok
        if not link_valid:
            chain_valid = False

        links.append({
            "position": i,
            "id": link.receipt.get("id", "")[:12],
            "user": link.receipt.get("uid"),
            "model": link.receipt.get("model"),
            "timestamp": link.receipt.get("ts"),
            "review": link.receipt.get("review", {}).get("status"),
            "signature_valid": sig_ok,
            "parent_valid": parent_ok,
            "link_valid": link_valid,
        })

    return {
        "valid": chain_valid,
        "length": len(links),
        "origin": links[0]["user"] if links else None,
        "final": links[-1]["user"] if links else None,
        "links": links,
    }


# ===================================================================
# 4. CHAIN DISCOVERY — find related receipts via hash registry
# ===================================================================

@app.get("/v1/discover/{content_hash}")
def discover_chain(content_hash: str):
    """
    Given a content hash, discover related receipts in the registry.
    Returns receipt IDs only — no names, no details, no user data.

    Shows: does a receipt exist for this hash? Are there newer or
    older versions? How long is the chain?
    """
    conn = get_registry()

    exact = conn.execute(
        "SELECT receipt_id, registered_at FROM hash_registry WHERE content_hash = ?",
        (content_hash,)
    ).fetchall()

    children = conn.execute(
        "SELECT receipt_id FROM hash_registry WHERE parent_hash = ?",
        (content_hash,)
    ).fetchall()

    this_entry = conn.execute(
        "SELECT parent_hash FROM hash_registry WHERE content_hash = ? AND parent_hash IS NOT NULL LIMIT 1",
        (content_hash,)
    ).fetchone()

    parents = []
    if this_entry and this_entry["parent_hash"]:
        parent_receipts = conn.execute(
            "SELECT receipt_id FROM hash_registry WHERE content_hash = ?",
            (this_entry["parent_hash"],)
        ).fetchall()
        parents = [{"receipt_id": p["receipt_id"]} for p in parent_receipts]

    conn.close()

    return {
        "hash": content_hash,
        "found": len(exact) > 0,
        "receipts": [{"receipt_id": r["receipt_id"]} for r in exact],
        "chain": {
            "has_parent": len(parents) > 0,
            "parent_receipts": parents,
            "has_children": len(children) > 0,
            "child_receipts": [{"receipt_id": c["receipt_id"]} for c in children],
        },
        "note": "Receipt IDs shown only. To see who attested, request the full receipt from its owner.",
    }


# ===================================================================
# LOOKUP BY RECEIPT CODE (short id prefix)
# ===================================================================

@app.get("/v1/lookup/{code}")
def lookup_by_code(code: str):
    """
    Lightweight existence check by short receipt code (first 12 hex chars
    of receipt_id). Confirms the receipt is in the public registry and
    when it was registered. Does NOT verify the signature — signature
    verification requires the full receipt JSON (see /v1/verify).

    Returns no user identity or content.
    """
    # Accept either "[AIAuth:xxxx]" or a raw UUID-prefix (hyphens ok)
    import re
    m = re.search(r"[0-9a-f-]{8,}", code.lower())
    prefix = (m.group(0) if m else "")[:12]
    if len(prefix.replace("-", "")) < 8:
        return {"found": False, "reason": "Invalid code format."}

    conn = get_registry()
    rows = conn.execute(
        "SELECT receipt_id, registered_at FROM hash_registry WHERE receipt_id LIKE ? LIMIT 5",
        (prefix + "%",)
    ).fetchall()
    conn.close()

    if not rows:
        return {"found": False, "code": prefix}
    return {
        "found": True,
        "code": prefix,
        "matches": [
            {"receipt_id": r["receipt_id"], "registered_at": r["registered_at"]}
            for r in rows
        ],
        "note": "Existence confirmed from the public registry. To verify the signature and see attestation details, paste the full receipt JSON.",
    }


# ===================================================================
# PUBLIC KEY
# ===================================================================

@app.get("/v1/public-key")
def public_key(format: Optional[str] = Query(default=None, description="'legacy' returns v0.4.0 single-key shape; default is v0.5.0 manifest")):
    """Public key distribution.

    v0.5.0 default: returns the full key manifest with all known keys,
    their validity windows, and the current signing key.
    ?format=legacy: returns the v0.4.0 single-key JSON for
    backward compatibility with old verifiers.
    """
    if format == "legacy":
        return {"algorithm": "Ed25519", "public_key_pem": PUB_PEM, "version": VERSION}
    return build_public_key_manifest()


@app.get("/.well-known/aiauth-public-key")
def well_known_public_key():
    """Legacy well-known path. Returns the CURRENT public key as a
    single-key JSON for maximum compatibility with generic verifiers
    that don't understand the manifest shape. Use /v1/public-key for
    the full manifest."""
    return {"algorithm": "Ed25519", "public_key_pem": PUB_PEM, "version": VERSION}


# ===================================================================
# ENTERPRISE-ONLY ENDPOINTS (license-gated)
# ===================================================================

class ReviewRequest(BaseModel):
    reviewer_id: str
    status: str
    note: Optional[str] = None

@app.post("/v1/review/{attestation_id}")
def review(attestation_id: str, req: ReviewRequest):
    require_enterprise()
    if req.status not in ("approved", "modified", "rejected"):
        raise HTTPException(400, "Status must be: approved, modified, or rejected")
    conn = get_db()
    row = conn.execute("SELECT id FROM attestations WHERE id = ?", (attestation_id,)).fetchone()
    if not row: conn.close(); raise HTTPException(404, "Not found")
    now = datetime.now(timezone.utc).isoformat()
    rid = str(uuid.uuid4())
    conn.execute("INSERT INTO review_history (id,attestation_id,reviewer_id,status,note,reviewed_at) VALUES (?,?,?,?,?,?)",
                 (rid, attestation_id, req.reviewer_id, req.status, req.note, now))
    conn.execute("UPDATE attestations SET review_status=?,reviewer_id=?,reviewed_at=?,review_note=? WHERE id=?",
                 (req.status, req.reviewer_id, now, req.note, attestation_id))
    conn.commit(); conn.close()
    return {"review_id": rid, "status": req.status, "reviewed_at": now}

@app.get("/v1/chain/{chain_root}")
def get_stored_chain(chain_root: str):
    require_enterprise()
    conn = get_db()
    rows = conn.execute(
        "SELECT id, created_at, output_hash, user_id, model, review_status, reviewer_id, parent_hash FROM attestations WHERE chain_root = ? ORDER BY created_at ASC",
        (chain_root,)
    ).fetchall()
    conn.close()
    if not rows: raise HTTPException(404, "Chain not found")
    return {"chain_root": chain_root, "length": len(rows), "links": [dict(r) for r in rows]}

@app.get("/v1/attestations")
def list_attestations(user_id: Optional[str] = None, status: Optional[str] = None, limit: int = 50):
    require_enterprise()
    conn = get_db()
    q = "SELECT * FROM attestations WHERE 1=1"
    p = []
    if user_id: q += " AND user_id = ?"; p.append(user_id)
    if status: q += " AND review_status = ?"; p.append(status)
    q += " ORDER BY created_at DESC LIMIT ?"
    p.append(limit)
    rows = conn.execute(q, p).fetchall()
    conn.close()
    return {"attestations": [dict(r) for r in rows], "count": len(rows)}

@app.get("/v1/stats")
def stats():
    require_enterprise()
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) as c FROM attestations").fetchone()["c"]
    reviewed = conn.execute("SELECT COUNT(*) as c FROM attestations WHERE review_status != 'pending'").fetchone()["c"]
    by_model = conn.execute("SELECT model, COUNT(*) as c FROM attestations GROUP BY model ORDER BY c DESC LIMIT 10").fetchall()
    conn.close()
    return {
        "total": total,
        "review_rate": round(reviewed/total*100, 1) if total else 0,
        "models": [dict(r) for r in by_model],
    }


# ===================================================================
# ADMIN — License Key Generation (protected by master key)
# ===================================================================

class LicenseRequest(BaseModel):
    company: str
    tier: str = "enterprise"
    max_users: int = 0
    expires: Optional[str] = None  # ISO date string, e.g. "2027-04-21"
    master_key: str

@app.post("/v1/admin/license/generate")
def generate_license_endpoint(req: LicenseRequest):
    """
    Generate a license key for an enterprise customer.
    Protected by master key — only you can call this.

    The customer sets the returned license_key as their
    AIAUTH_LICENSE_KEY environment variable.
    """
    if not MASTER_KEY or req.master_key != MASTER_KEY:
        raise HTTPException(403, "Invalid master key")

    result = generate_license(
        company=req.company,
        tier=req.tier,
        max_users=req.max_users,
        expires=req.expires or "",
    )
    return result

@app.post("/v1/admin/license/validate")
def validate_license_endpoint(license_key: str = ""):
    """Check if a license key is valid. Public endpoint — anyone can verify."""
    data = validate_license(license_key)
    if data:
        return {"valid": True, "license": data}
    return {"valid": False}


# ===================================================================
# PUBLIC PAGES — verification and user guide
# ===================================================================

@app.get("/", response_class=HTMLResponse)
def homepage():
    """Public homepage: what AIAuth is, how it works, verify link, commercial licensing."""
    index_path = Path(__file__).parent / "index.html"
    if index_path.exists():
        return HTMLResponse(index_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>AIAuth</h1><p>Homepage not yet deployed.</p>")

@app.get("/logo.png")
def logo():
    logo_path = Path(__file__).parent / "logo.png"
    if logo_path.exists():
        return FileResponse(str(logo_path), media_type="image/png")
    return HTMLResponse("Not found", status_code=404)

@app.get("/favicon.ico")
def favicon():
    logo_path = Path(__file__).parent / "logo.png"
    if logo_path.exists():
        return FileResponse(str(logo_path), media_type="image/png")
    return HTMLResponse("", status_code=204)

@app.get("/check", response_class=HTMLResponse)
def verification_page():
    """The public verification page — anyone can paste a receipt and verify it."""
    verify_path = Path(__file__).parent / "verify.html"
    if verify_path.exists():
        return HTMLResponse(verify_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>AIAuth</h1><p>Verification page not found. Place verify.html alongside server.py.</p>")

def _page_shell(title: str, body_html: str, active: str = "") -> str:
    """Shared page chrome matching index.html."""
    def active_cls(key): return ' style="color:var(--text)"' if active == key else ""
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — AIAuth</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {{ --bg:#fff; --panel:#f7f8fa; --border:#e5e7eb; --text:#0b1220; --muted:#5b6573; --accent:#2563eb; --accent-soft:#eff4ff; --code-bg:#0b1220; --code-fg:#e6edf6; }}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:var(--bg); color:var(--text); font-family:'Inter',system-ui,sans-serif; -webkit-font-smoothing:antialiased; }}
a {{ color:var(--accent); text-decoration:none; }}
a:hover {{ text-decoration:underline; }}
.container {{ max-width:820px; margin:0 auto; padding:0 24px; }}
.container-wide {{ max-width:1080px; margin:0 auto; padding:0 24px; }}
.nav {{ position:sticky; top:0; z-index:10; background:rgba(255,255,255,0.85); backdrop-filter:saturate(140%) blur(10px); border-bottom:1px solid var(--border); }}
.nav-inner {{ display:flex; align-items:center; justify-content:space-between; padding:14px 0; }}
.brand {{ display:flex; align-items:center; gap:10px; font-weight:700; letter-spacing:-0.01em; }}
.brand img {{ width:32px; height:32px; border-radius:8px; display:block; }}
.brand span {{ font-size:17px; color:var(--text); }}
.nav-links {{ display:flex; gap:22px; align-items:center; font-size:14px; color:var(--muted); font-weight:500; }}
.nav-links a {{ color:var(--muted); }}
.nav-cta {{ background:var(--accent); color:#fff !important; padding:8px 14px; border-radius:8px; font-weight:600; }}
.nav-cta:hover {{ text-decoration:none; background:#1d4ed8; }}
.page {{ padding:64px 0 96px; }}
.eyebrow {{ display:inline-flex; padding:6px 12px; background:var(--accent-soft); color:var(--accent); border-radius:999px; font-size:12px; font-weight:600; letter-spacing:0.02em; text-transform:uppercase; }}
h1.page-title {{ font-size:clamp(30px,4vw,46px); line-height:1.1; font-weight:800; letter-spacing:-0.02em; margin-top:18px; }}
.lead {{ font-size:17px; color:var(--muted); margin-top:14px; line-height:1.6; }}
.prose {{ margin-top:40px; font-size:16px; line-height:1.75; color:var(--text); }}
.prose h1 {{ font-size:28px; font-weight:700; letter-spacing:-0.02em; margin:40px 0 14px; border-bottom:1px solid var(--border); padding-bottom:10px; }}
.prose h2 {{ font-size:22px; font-weight:700; letter-spacing:-0.01em; margin:36px 0 12px; }}
.prose h3 {{ font-size:17px; font-weight:700; margin:26px 0 8px; }}
.prose p {{ margin:12px 0; color:#1f2937; }}
.prose ul, .prose ol {{ margin:12px 0 12px 22px; }}
.prose li {{ margin:6px 0; color:#1f2937; }}
.prose code {{ background:var(--panel); border:1px solid var(--border); padding:1px 6px; border-radius:5px; font-family:'JetBrains Mono',monospace; font-size:13px; color:#0b1220; }}
.prose pre {{ background:var(--code-bg); color:var(--code-fg); padding:18px 20px; border-radius:10px; overflow-x:auto; font-family:'JetBrains Mono',monospace; font-size:13px; line-height:1.65; margin:16px 0; }}
.prose pre code {{ background:transparent; border:0; padding:0; color:inherit; font-size:inherit; }}
.prose blockquote {{ border-left:3px solid var(--accent); padding:6px 16px; color:var(--muted); background:var(--accent-soft); border-radius:0 6px 6px 0; margin:16px 0; }}
.prose table {{ border-collapse:collapse; width:100%; margin:16px 0; font-size:14px; }}
.prose th, .prose td {{ border:1px solid var(--border); padding:8px 12px; text-align:left; }}
.prose th {{ background:var(--panel); font-weight:600; }}
.prose a {{ color:var(--accent); }}
.card {{ background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:24px; margin-top:20px; }}
.key-block {{ background:var(--code-bg); color:var(--code-fg); padding:20px; border-radius:10px; font-family:'JetBrains Mono',monospace; font-size:12px; white-space:pre-wrap; word-break:break-all; line-height:1.6; }}
.copy-btn {{ display:inline-flex; align-items:center; gap:6px; padding:6px 10px; background:var(--accent-soft); color:var(--accent); border:0; border-radius:6px; font-size:12px; font-weight:600; cursor:pointer; margin-top:10px; font-family:inherit; }}
.copy-btn:hover {{ background:#e0eaff; }}
footer {{ padding:40px 0; color:var(--muted); font-size:13px; border-top:1px solid var(--border); }}
.foot-inner {{ display:flex; justify-content:space-between; flex-wrap:wrap; gap:16px; }}
.foot-inner a {{ color:var(--muted); margin-right:18px; }}
@media (max-width:760px) {{ .nav-links {{ display:none; }} }}
</style>
</head><body>
<nav class="nav"><div class="container-wide nav-inner">
  <a class="brand" href="/"><img src="/logo.png" alt="AIAuth"><span>AIAuth</span></a>
  <div class="nav-links">
    <a href="/#how"{active_cls('how')}>How it works</a>
    <a href="/#download"{active_cls('download')}>Download</a>
    <a href="/guide"{active_cls('guide')}>User guide</a>
    <a class="nav-cta" href="/check">Verify a receipt</a>
  </div>
</div></nav>
<main class="page"><div class="container">
{body_html}
</div></main>
<footer><div class="container-wide foot-inner">
  <div>&copy; 2026 Finch Business Services LLC · AIAuth</div>
  <div><a href="/check">Verify</a><a href="/guide">User guide</a><a href="/public-key">Public key</a></div>
</div></footer>
</body></html>"""


@app.get("/guide", response_class=HTMLResponse)
def user_guide():
    """Public user guide rendered from Markdown into the site theme."""
    guide_path = Path(__file__).parent / "docs" / "USER_GUIDE.md"
    if not guide_path.exists():
        return HTMLResponse(_page_shell("User guide", '<h1 class="page-title">User guide not found</h1><p class="lead">The guide has not been uploaded to the server yet.</p>', active="guide"))
    md_text = guide_path.read_text(encoding="utf-8")
    try:
        import markdown  # type: ignore
        body = markdown.markdown(md_text, extensions=["fenced_code", "tables", "toc"])
    except Exception:
        # Fallback if python-markdown not installed: render as preformatted text
        from html import escape
        body = f'<pre style="white-space:pre-wrap;font-family:inherit;background:none;color:inherit;padding:0">{escape(md_text)}</pre>'
    html = f"""<span class="eyebrow">User guide</span>
<h1 class="page-title">AIAuth — what it does and how to use it</h1>
<p class="lead">The plain-English guide to signing, sharing, and verifying AI-work receipts.</p>
<div class="prose">{body}</div>"""
    return HTMLResponse(_page_shell("User guide", html, active="guide"))


@app.get("/privacy", response_class=HTMLResponse)
def privacy_page():
    body = """<span class="eyebrow">Privacy policy</span>
<h1 class="page-title">AIAuth privacy policy</h1>
<p class="lead">Short version: your content never leaves your device. AIAuth only sees a one-way cryptographic fingerprint (SHA-256 hash) of what you attest, and that fingerprint cannot be reversed into your original content.</p>

<div class="prose">
<p style="color:var(--muted);font-size:13px">Last updated: April 21, 2026 · Operator: Finch Business Services LLC</p>

<h2>What AIAuth does</h2>
<p>AIAuth is a cryptographic attestation service. It lets you create tamper-evident receipts for AI-generated content that you produce or review. You interact with it through the AIAuth Chrome extension, a desktop app, or direct API calls.</p>

<h2>What data AIAuth processes</h2>
<h3>1. On your device (the Chrome extension)</h3>
<p>The extension stores, locally in Chrome's <code>chrome.storage.local</code>, only what you explicitly enter or create:</p>
<ul>
  <li>An identifier you enter (email address or name). Used inside your receipts so you can later prove you attested something. Never sent to AIAuth servers as a standalone record.</li>
  <li>The server URL you configure (default <code>https://aiauth.app</code>).</li>
  <li>Your receipts — the signed JSON for each attestation you create, kept so you can share or verify them later.</li>
</ul>
<p>This local data stays on your machine. Uninstalling the extension removes it.</p>

<h3>2. What the extension sends to the AIAuth server</h3>
<p>When you attest content, the extension computes a SHA-256 hash of that content <em>in your browser</em>, then sends the following to the server's <code>/v1/sign</code> endpoint over HTTPS:</p>
<ul>
  <li>The SHA-256 hash (a 64-character hex string).</li>
  <li>The identifier you entered (email or name).</li>
  <li>A source string (for example <code>chrome-extension</code> or <code>file:yourfile.xlsx</code>).</li>
  <li>For file attestations, an optional note containing filename, size, and MIME type so you can tell receipts apart in your own list.</li>
</ul>
<p><strong>The original content is never transmitted.</strong> A SHA-256 hash is a one-way fingerprint — it cannot be reversed to recover your content.</p>

<h3>3. What the AIAuth server stores</h3>
<p>In public mode (the default mode at <code>aiauth.app</code>), the server stores only:</p>
<ul>
  <li>A minimal <em>hash registry</em>: the content hash, the receipt ID, an optional parent hash, and a timestamp. No user identifier, no content, no IP address, no session data.</li>
</ul>
<p>The registry exists so that anyone holding the same content or a receipt code can confirm a receipt exists. It contains nothing that can identify a person.</p>
<p>The full signed receipt (which <em>does</em> contain your identifier) is returned to your device and never persisted on the server.</p>

<h2>What AIAuth does not do</h2>
<ul>
  <li>AIAuth does not read, store, or transmit the text or files you attest.</li>
  <li>AIAuth does not track you across sites, log your browsing, or profile your activity.</li>
  <li>AIAuth does not use analytics, cookies, trackers, or third-party SDKs in the extension.</li>
  <li>AIAuth does not sell, rent, or share your data with any third party.</li>
  <li>AIAuth does not use your data for advertising, credit scoring, or any purpose unrelated to producing and verifying the receipts you ask for.</li>
</ul>

<h2>Server logs</h2>
<p>The AIAuth web server (nginx + uvicorn) may write standard HTTP access logs containing request timestamps, paths, status codes, and IP addresses, for operational reliability and abuse prevention. These logs are rotated and are not used for marketing, analytics, or resale. They are not tied to any stored user profile because AIAuth does not maintain user profiles.</p>

<h2>Third-party services</h2>
<p>The AIAuth website loads fonts from Google Fonts for typography. When you visit a page on aiauth.app, your browser fetches these font files from Google's CDN; this is subject to Google's own privacy terms. No AIAuth data is transmitted to Google.</p>
<p>The AIAuth Chrome extension itself does not load any third-party resources.</p>

<h2>Enterprise / self-hosted deployments</h2>
<p>Organizations running AIAuth in <code>enterprise</code> mode on their own infrastructure may configure the server to store full attestation records, including content hashes, user identifiers, review status, and timestamps, inside their own database. In that case, the operating organization — not Finch Business Services LLC — is the data controller, and their own privacy policy governs that data.</p>

<h2>Your rights</h2>
<ul>
  <li>Your local data: you can delete it by clearing the extension's storage from <code>chrome://extensions</code> or by uninstalling the extension.</li>
  <li>Registered hashes: because the hash registry contains no identifying information, there is no personal data to access, correct, or delete. A hash cannot be traced to you.</li>
  <li>If you contact us with a specific request, we will respond within 30 days.</li>
</ul>

<h2>Children</h2>
<p>AIAuth is not directed to children under 13 and does not knowingly collect information from them.</p>

<h2>Changes to this policy</h2>
<p>Material changes will be announced on this page, and the "last updated" date above will change. The public-mode data practices described here (content never transmitted, no identifying data stored server-side) are core to the product and will not change without a new major version.</p>

<h2>Contact</h2>
<p>Questions, requests, or concerns: <a href="mailto:chase@finchbusinessserv.com">chase@finchbusinessserv.com</a>.</p>
</div>"""
    return HTMLResponse(_page_shell("Privacy", body, active=""))


@app.get("/public-key", response_class=HTMLResponse)
def public_key_page():
    """Human-readable public key page — developers can still hit /v1/public-key or /.well-known/aiauth-public-key."""
    body = f"""<span class="eyebrow">Verification key</span>
<h1 class="page-title">AIAuth public key</h1>
<p class="lead">This is the Ed25519 public key used to verify every AIAuth receipt. Anyone can use it to check that a receipt was signed by the AIAuth service and has not been altered.</p>

<h2 style="margin-top:32px;font-size:18px;font-weight:700">Algorithm</h2>
<p>Ed25519 — a modern elliptic-curve signature scheme (RFC 8032). Fast, small signatures, widely supported.</p>

<h2 style="margin-top:24px;font-size:18px;font-weight:700">Key (PEM format)</h2>
<div class="key-block" id="pem">{PUB_PEM.strip()}</div>
<button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('pem').innerText);this.textContent='Copied ✓'">Copy key</button>

<h2 style="margin-top:32px;font-size:18px;font-weight:700">Developer endpoints</h2>
<div class="card" style="margin-top:12px">
  <div style="font-family:'JetBrains Mono',monospace;font-size:13px">GET <a href="/v1/public-key">/v1/public-key</a></div>
  <p style="color:var(--muted);margin-top:6px;font-size:13px">Returns the same key as a JSON object. Use this from code.</p>
</div>
<div class="card" style="margin-top:12px">
  <div style="font-family:'JetBrains Mono',monospace;font-size:13px">GET <a href="/.well-known/aiauth-public-key">/.well-known/aiauth-public-key</a></div>
  <p style="color:var(--muted);margin-top:6px;font-size:13px">Standard well-known path for key discovery.</p>
</div>

<p class="lead" style="margin-top:32px">Version: <code style="background:var(--panel);padding:2px 8px;border-radius:5px;border:1px solid var(--border);font-family:'JetBrains Mono',monospace;font-size:13px">{VERSION}</code></p>"""
    return HTMLResponse(_page_shell("Public key", body, active=""))


# ===================================================================
# HEALTH
# ===================================================================

@app.get("/health")
def health():
    r = {"status": "ok", "service": "aiauth", "mode": MODE, "version": VERSION}
    if MODE == "enterprise" and ENTERPRISE_LICENSE:
        conn = get_db()
        r["attestations"] = conn.execute("SELECT COUNT(*) as c FROM attestations").fetchone()["c"]
        r["licensed_to"] = ENTERPRISE_LICENSE.get("company")
        r["tier"] = ENTERPRISE_LICENSE.get("tier")
        conn.close()
    return r
