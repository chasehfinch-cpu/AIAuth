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
LICENSE_GRACE_DAYS = int(os.getenv("AIAUTH_LICENSE_GRACE_DAYS", "30"))  # grace period after license expiry

# Dual-secret rotation support (Piece 13): when rotating SERVER_SECRET, set
# this to the PREVIOUS value for a transitional window. Email hashes and
# Fernet ciphertext encrypted with the old secret remain verifiable while
# new traffic uses the new secret.
SERVER_SECRET_PREVIOUS = os.getenv("SERVER_SECRET_PREVIOUS", "")

# Regex for SHA-256 hex (lowercase or uppercase)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


# ===================================================================
# ANTI-FORENSIC HARDENING (Piece 12, v0.5.1)
# The account system (Piece 7) stored emails in plaintext. If the
# server is compromised, an attacker should get HMAC hashes and
# ciphertext — not readable emails. See CLAUDE.md "Data Hardening".
#
# Keys are DERIVED from SERVER_SECRET at startup — nothing extra in
# .env to manage, nothing extra to rotate. If SERVER_SECRET itself
# leaks or rotates, see scripts/rotate_server_secret.py (Piece 13).
# ===================================================================

import hmac as _hmac_mod
import hashlib as _hashlib_mod

_EMAIL_HASH_SALT: bytes = b""         # populated at startup (if SERVER_SECRET set)
_EMAIL_HASH_SALT_PREV: bytes = b""    # populated at startup (if SERVER_SECRET_PREVIOUS set)
_DB_ENCRYPTION_KEY: bytes = b""       # populated at startup
_FERNET = None                        # populated at startup
_FERNET_MULTI = None                  # MultiFernet with [new, old] if SERVER_SECRET_PREVIOUS is set


def _derive_hardening_keys() -> None:
    """Derive email-hash salt and DB encryption key from SERVER_SECRET.
    If SERVER_SECRET_PREVIOUS is set, also derive PREV salt + a MultiFernet
    that reads old-encrypted values while encrypting new ones with the
    current key. Idempotent; safe to re-run."""
    global _EMAIL_HASH_SALT, _EMAIL_HASH_SALT_PREV
    global _DB_ENCRYPTION_KEY, _FERNET, _FERNET_MULTI
    if not SERVER_SECRET:
        return
    _EMAIL_HASH_SALT = _hmac_mod.new(
        SERVER_SECRET.encode(), b"email-hash-v1", _hashlib_mod.sha256
    ).digest()
    _DB_ENCRYPTION_KEY = _hmac_mod.new(
        SERVER_SECRET.encode(), b"db-encrypt-v1", _hashlib_mod.sha256
    ).digest()  # 32 bytes

    try:
        from cryptography.fernet import Fernet as _Fernet, MultiFernet as _MultiFernet
        _FERNET = _Fernet(base64.urlsafe_b64encode(_DB_ENCRYPTION_KEY))

        if SERVER_SECRET_PREVIOUS:
            _EMAIL_HASH_SALT_PREV = _hmac_mod.new(
                SERVER_SECRET_PREVIOUS.encode(), b"email-hash-v1", _hashlib_mod.sha256
            ).digest()
            prev_key = _hmac_mod.new(
                SERVER_SECRET_PREVIOUS.encode(), b"db-encrypt-v1", _hashlib_mod.sha256
            ).digest()
            _FERNET_MULTI = _MultiFernet([
                _FERNET,
                _Fernet(base64.urlsafe_b64encode(prev_key)),
            ])
        else:
            _FERNET_MULTI = None
    except Exception:
        _FERNET = None
        _FERNET_MULTI = None


def email_hash_candidates(email: str) -> List[str]:
    """Return the list of email_hash values to check during lookup when
    rotation is in progress: [new_hash, old_hash]. Callers use this to
    JOIN/IN-match during the rotation window so users linked under the
    old secret still resolve."""
    norm = (email or "").strip().lower()
    if not norm:
        return []
    out = [email_hash(norm)]
    if _EMAIL_HASH_SALT_PREV:
        out.append(_hmac_mod.new(
            _EMAIL_HASH_SALT_PREV, norm.encode("utf-8"), _hashlib_mod.sha256
        ).hexdigest())
    return out


def email_hash(email: str) -> str:
    """Return a deterministic, salt-HMAC hash suitable for use as a
    lookup index for an email address. Normalizes (lowercase + trim)
    before hashing. 64-char hex. If SERVER_SECRET is not configured,
    returns a SHA-256 of the normalized email (dev/test fallback — not
    for production)."""
    norm = (email or "").strip().lower()
    if not norm:
        return ""
    if _EMAIL_HASH_SALT:
        return _hmac_mod.new(_EMAIL_HASH_SALT, norm.encode("utf-8"), _hashlib_mod.sha256).hexdigest()
    return _hashlib_mod.sha256(norm.encode("utf-8")).hexdigest()


def encrypt_value(plaintext: str) -> str:
    """Fernet-encrypt a string. Returns base64 ciphertext (URL-safe).
    If Fernet is unavailable, returns the plaintext prefixed with
    `NOENC:` so it's obviously NOT ciphertext in a DB dump — but this
    is only for dev/test; production MUST have SERVER_SECRET set."""
    if not plaintext:
        return ""
    if _FERNET is not None:
        return _FERNET.encrypt(plaintext.encode("utf-8")).decode("ascii")
    return "NOENC:" + plaintext


def decrypt_value(ciphertext: str) -> str:
    """Inverse of encrypt_value. Returns empty string on decryption
    failure. During SERVER_SECRET rotation, tries the MultiFernet
    (new + previous) so values encrypted with the old key still decrypt."""
    if not ciphertext:
        return ""
    if ciphertext.startswith("NOENC:"):
        return ciphertext[6:]
    try:
        if _FERNET_MULTI is not None:
            return _FERNET_MULTI.decrypt(ciphertext.encode("ascii")).decode("utf-8")
        if _FERNET is not None:
            return _FERNET.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except Exception:
        pass
    return ""


# Derive now. If SERVER_SECRET is set later (e.g., env loaded after import),
# call _derive_hardening_keys() again manually.
_derive_hardening_keys()


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


def _apply_license_headers(response) -> None:
    """Inject license-expiry headers if the server is running on an
    expired-but-in-grace license. Called after every response."""
    if ENTERPRISE_LICENSE and ENTERPRISE_LICENSE.get("expired"):
        response.headers["X-AIAuth-License-Expired"] = "true"
        rem = ENTERPRISE_LICENSE.get("grace_remaining_days")
        if rem is not None:
            response.headers["X-AIAuth-License-Grace-Days"] = str(rem)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    endpoint_key = _match_rate_endpoint(request.url.path)
    if endpoint_key is None:
        # Still need to add license-expiry header to non-rate-limited routes.
        response = await call_next(request)
        _apply_license_headers(response)
        return response

    cfg = RATE_LIMITS[endpoint_key]
    ip = _client_ip(request)

    def _reject(window: int, limit: int):
        resp = JSONResponse(
            status_code=429,
            content={"error": {
                "code": "RATE_LIMITED",
                "message": f"Rate limit exceeded for {endpoint_key}",
                "details": {"window_seconds": window, "limit": limit, "endpoint": endpoint_key},
            }},
        )
        _apply_license_headers(resp)
        return resp

    if "per_ip_per_min" in cfg:
        limit = cfg["per_ip_per_min"]
        if not _rate_check((endpoint_key, "ip-min", ip), 60, limit):
            return _reject(60, limit)
    if "per_ip_per_hour" in cfg:
        limit = cfg["per_ip_per_hour"]
        if not _rate_check((endpoint_key, "ip-hr", ip), 3600, limit):
            return _reject(3600, limit)

    response = await call_next(request)
    _apply_license_headers(response)
    return response


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
    """Validate a license key. Returns license data if valid (including
    expired-but-in-grace), None if signature invalid, past grace period,
    or unparseable.

    Piece 13: soft-fail behavior. A billing lapse must never lock a
    customer out of their own historical data. We add a grace period
    (default 30 days, AIAUTH_LICENSE_GRACE_DAYS env override). Within
    grace, the license still validates but the returned dict has
    `expired: True` and `grace_remaining_days`. After grace, returns
    None — enterprise features gate off, but /v1/sign and all
    verification paths continue to work."""
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
        if not check_sig(data, sig):
            return None

        data["expired"] = False
        data["grace_remaining_days"] = None
        if data.get("expires"):
            exp = datetime.fromisoformat(data["expires"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if now > exp:
                grace_end = exp + timedelta(days=LICENSE_GRACE_DAYS)
                if now > grace_end:
                    return None  # past grace; hard-fail
                data["expired"] = True
                data["grace_remaining_days"] = (grace_end - now).days
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
        if ENTERPRISE_LICENSE.get("expired"):
            print(f"[AIAuth]   WARNING: license EXPIRED. Running in grace period "
                  f"({ENTERPRISE_LICENSE.get('grace_remaining_days')} days remaining). "
                  f"Contact sales@aiauth.app to renew.")
    else:
        print("[AIAuth] WARNING: Enterprise mode requested but no valid license key found "
              "(either invalid signature or past grace period).")
        print("[AIAuth]   Enterprise features will be disabled; attestation signing continues.")
        MODE = "public"


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
    # v0.5.0 migration: add doc_id column if missing (idempotent)
    # v0.5.1 migration: add content_hash_canonical column (6th col)
    existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(hash_registry)").fetchall()}
    if "doc_id" not in existing_cols:
        conn.execute("ALTER TABLE hash_registry ADD COLUMN doc_id TEXT")
    if "content_hash_canonical" not in existing_cols:
        conn.execute("ALTER TABLE hash_registry ADD COLUMN content_hash_canonical TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reg_hash ON hash_registry(content_hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reg_parent ON hash_registry(parent_hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reg_receipt ON hash_registry(receipt_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reg_doc_id ON hash_registry(doc_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reg_canonical ON hash_registry(content_hash_canonical)")
    conn.commit()
    conn.close()

init_registry()

def register_hash(content_hash: str, receipt_id: str, parent_hash: str = None,
                  doc_id: str = None, content_hash_canonical: str = None):
    """Add an entry to the public registry. No user data stored.

    Six columns (per Integrity Rule #3, post v0.5.1): content_hash,
    receipt_id, parent_hash, doc_id, content_hash_canonical, registered_at.
    All are hashes — still PII-free. The sixth column enables cross-format
    chain discovery (Piece 14): xlsx -> csv -> pdf of the same logical
    content share a content_hash_canonical, even though their byte
    hashes all differ.
    """
    conn = get_registry()
    conn.execute(
        "INSERT INTO hash_registry "
        "(content_hash, receipt_id, parent_hash, doc_id, content_hash_canonical, registered_at) "
        "VALUES (?,?,?,?,?,?)",
        (content_hash, receipt_id, parent_hash, doc_id, content_hash_canonical,
         datetime.now(timezone.utc).isoformat())
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
        account_id         TEXT PRIMARY KEY,
        primary_email_hash TEXT NOT NULL,
        created_at         TEXT NOT NULL,
        updated_at         TEXT NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS account_emails (
        email_hash    TEXT PRIMARY KEY,
        account_id    TEXT NOT NULL REFERENCES accounts(account_id),
        email_type    TEXT NOT NULL,
        org_id        TEXT,
        verified      INTEGER NOT NULL DEFAULT 0,
        added_at      TEXT NOT NULL,
        verified_at   TEXT,
        email_domain_plain TEXT  -- domain-only (e.g. "acme.com") for org-claim matching; never a full email
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ae_account ON account_emails(account_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ae_org ON account_emails(org_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ae_domain ON account_emails(email_domain_plain)")

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
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id          TEXT NOT NULL,
        org_id              TEXT NOT NULL,
        action              TEXT NOT NULL,
        timestamp           TEXT NOT NULL,
        subject_email_hash  TEXT,
        details_encrypted   TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cl_subject ON consent_log(subject_email_hash)")

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

    # Pilot-interest leads from /v1/pilot/interest (Phase B.5).
    # Admin emails are stored as hashes (Piece 12 hardening applies everywhere).
    conn.execute("""CREATE TABLE IF NOT EXISTS pilot_interest (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        submitted_at     TEXT NOT NULL,
        company          TEXT NOT NULL,
        admin_email_hash TEXT NOT NULL,
        admin_email_encrypted TEXT NOT NULL,
        admin_email_domain    TEXT,
        user_count       INTEGER,
        industry         TEXT,
        source_ip        TEXT,
        handled          INTEGER NOT NULL DEFAULT 0,
        handled_at       TEXT,
        handled_note     TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pi_submitted ON pilot_interest(submitted_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pi_handled ON pilot_interest(handled)")

    # Waitlist signups from the landing page (Stage 2a).
    # Same hashing discipline as pilot_interest: email stored only as
    # HMAC hash + Fernet ciphertext; plaintext lives only in the request
    # handler. No IP-to-email linkage is retained beyond rate-limit windows.
    conn.execute("""CREATE TABLE IF NOT EXISTS waitlist_signups (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        submitted_at    TEXT NOT NULL,
        email_hash      TEXT NOT NULL UNIQUE,
        email_encrypted TEXT NOT NULL,
        email_domain    TEXT,
        source_ip       TEXT,
        notified        INTEGER NOT NULL DEFAULT 0,
        notified_at     TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_wl_submitted ON waitlist_signups(submitted_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_wl_notified ON waitlist_signups(notified)")

    # Contact-sales inquiries from /contact (dedicated submission page for
    # the Pricing-section Team CTA). Same hardening pattern as
    # pilot_interest: email stored only as HMAC hash + Fernet ciphertext.
    conn.execute("""CREATE TABLE IF NOT EXISTS contact_inquiries (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        submitted_at     TEXT NOT NULL,
        company          TEXT NOT NULL,
        admin_email_hash TEXT NOT NULL,
        admin_email_encrypted TEXT NOT NULL,
        admin_email_domain    TEXT,
        plan             TEXT,
        user_count       INTEGER,
        message          TEXT,
        source_ip        TEXT,
        handled          INTEGER NOT NULL DEFAULT 0,
        handled_at       TEXT,
        handled_note     TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ci_submitted ON contact_inquiries(submitted_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ci_handled ON contact_inquiries(handled)")

    # ---------------- v0.5.0 enterprise attestation store ----------------
    # Full receipt metadata is stored here when enterprise clients POST
    # to /v1/enterprise/ingest. Created unconditionally so switching
    # modes doesn't require a migration. Populated only in enterprise
    # flows; free-tier /v1/sign NEVER writes here (see Dual-Path Arch).
    conn.execute("""CREATE TABLE IF NOT EXISTS enterprise_attestations (
        id              TEXT PRIMARY KEY,
        ts              TEXT NOT NULL,
        hash            TEXT NOT NULL,
        prompt_hash     TEXT,
        uid_hash        TEXT NOT NULL,
        uid_encrypted   TEXT,
        uid_pseudonym   TEXT,
        src             TEXT,
        model           TEXT,
        provider        TEXT,
        source_domain   TEXT,
        source_app      TEXT,
        concurrent_ai_apps TEXT,
        ai_markers      TEXT,
        doc_id          TEXT,
        parent          TEXT,
        file_type       TEXT,
        len             INTEGER,
        tta             INTEGER,
        sid             TEXT,
        dest            TEXT,
        dest_ext        INTEGER,
        classification  TEXT,
        review_status   TEXT,
        review_by       TEXT,
        review_at       TEXT,
        review_note     TEXT,
        tags            TEXT,
        schema_version  TEXT NOT NULL,
        org_id          TEXT NOT NULL REFERENCES organizations(org_id),
        client_integrity TEXT DEFAULT 'none',
        ingested_at     TEXT NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ea_uid_hash ON enterprise_attestations(uid_hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ea_ts ON enterprise_attestations(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ea_org ON enterprise_attestations(org_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ea_model ON enterprise_attestations(model)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ea_doc_id ON enterprise_attestations(doc_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ea_classification ON enterprise_attestations(classification)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ea_pseudonym ON enterprise_attestations(uid_pseudonym)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ea_prompt_hash ON enterprise_attestations(prompt_hash)")

    conn.execute("""CREATE TABLE IF NOT EXISTS policy_violations (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        attestation_id  TEXT NOT NULL REFERENCES enterprise_attestations(id),
        policy_id       TEXT NOT NULL,
        severity        TEXT NOT NULL,
        details         TEXT,
        detected_at     TEXT NOT NULL,
        resolved_at     TEXT,
        resolved_by     TEXT,
        resolution_note TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pv_severity ON policy_violations(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pv_detected ON policy_violations(detected_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pv_attest ON policy_violations(attestation_id)")

    # ---------------- Legacy v0.4.0 attestations (enterprise only) ----------------
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
        actual = _b64url_decode(sig_b64)
        # Try the current secret; if dual-secret rotation is active, fall back.
        expected = hmac.new(SERVER_SECRET.encode(), canonical, hashlib.sha256).digest()
        valid = hmac.compare_digest(expected, actual)
        if not valid and SERVER_SECRET_PREVIOUS:
            expected_prev = hmac.new(SERVER_SECRET_PREVIOUS.encode(), canonical, hashlib.sha256).digest()
            valid = hmac.compare_digest(expected_prev, actual)
        if not valid:
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
    """Email delivery path (v0.5.1+).

    Preferred: transactional email provider (Resend) when RESEND_API_KEY
    is set in the environment. Email is never persisted to disk.

    Fallback: stdout-only logging. A file-based log is available but
    DISABLED BY DEFAULT — operators must explicitly opt in via
    AIAUTH_LOG_MAGIC_LINKS=true (dev/test only; never production).

    The magic-link URL contains the token, which is HMAC-signed by
    SERVER_SECRET and expires in 15 minutes. The recipient email is
    in-memory for the duration of this call and never stored in our
    databases — see Integrity Rule #12 (Data Hardening)."""
    link = f"{PUBLIC_BASE_URL}/auth?token={token}&p={purpose}"

    # Track what was logged for return/test visibility (without leaking email)
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    if api_key:
        try:
            import resend
            resend.api_key = api_key
            resend.Emails.send({
                "from": os.getenv("RESEND_FROM", "AIAuth <auth@aiauth.app>"),
                "to": email,
                "subject": {
                    "login": "Your AIAuth login link",
                    "verify_email": "Verify your AIAuth email",
                }.get(purpose, "Your AIAuth link"),
                "text": (
                    f"Click to complete sign-in: {link}\n\n"
                    "This link expires in 15 minutes and can only be used once. "
                    "If you didn't request it, ignore this email."
                ),
            })
            print(f"[AIAuth magic-link] delivered via Resend; purpose={purpose}")
            return
        except Exception as exc:
            # Log the failure (not the email) and fall through to stdout
            print(f"[AIAuth magic-link] Resend delivery failed: {type(exc).__name__}; falling back to stdout log")

    # Stdout — operator can retrieve from systemd journal for testing
    print(f"[AIAuth magic-link] purpose={purpose} link={link}")

    # Opt-in file log (dev/test only)
    if os.getenv("AIAUTH_LOG_MAGIC_LINKS", "").strip().lower() == "true":
        try:
            log_path = KEY_DIR / "magic_links.log"
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(
                    f"{datetime.now(timezone.utc).isoformat()} "
                    f"purpose={purpose} link={link}\n"
                )
        except Exception:
            pass


def _notify_operator(subject: str, text: str) -> None:
    """Send a plaintext email to the operator address (AIAUTH_OPERATOR_EMAIL).

    Used for low-volume event notifications: new waitlist signups, new
    pilot-interest submissions, and similar. No-ops silently if either
    AIAUTH_OPERATOR_EMAIL or RESEND_API_KEY is missing — this keeps dev
    environments quiet and makes operator email a configuration opt-in
    rather than a hard dependency.

    Failures are caught and logged to stdout; they never propagate to the
    HTTP response of the event that triggered the notification. A signup
    that fails to notify the operator is still a successful signup from
    the user's perspective, and shows up in the database either way.
    """
    to_addr = os.getenv("AIAUTH_OPERATOR_EMAIL", "").strip()
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    if not to_addr or not api_key:
        return
    try:
        import resend
        resend.api_key = api_key
        resend.Emails.send({
            "from": os.getenv("RESEND_FROM", "AIAuth <auth@aiauth.app>"),
            "to": to_addr,
            "subject": subject,
            "text": text,
        })
        print(f"[AIAuth operator-notify] sent subject={subject!r} to_domain={to_addr.split('@')[-1]!r}")
    except Exception as exc:
        print(f"[AIAuth operator-notify] delivery failed: {type(exc).__name__}")


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
    """Look up an account_emails row by plaintext email. Hashes the
    email with the server-side salt and queries by email_hash. If a
    SERVER_SECRET rotation is in progress, also looks up by the old-salt
    hash. Returns None if not found."""
    candidates = email_hash_candidates(email)
    if not candidates:
        return None
    conn = get_db()
    placeholders = ",".join("?" * len(candidates))
    row = conn.execute(
        f"SELECT ae.*, a.account_id AS acct_id FROM account_emails ae "
        f"JOIN accounts a ON ae.account_id = a.account_id "
        f"WHERE ae.email_hash IN ({placeholders})",
        candidates,
    ).fetchone()
    conn.close()
    return row


def _email_domain(email: str) -> str:
    """Extract the lowercase domain part of an email address, or "" on malformed input."""
    norm = (email or "").strip().lower()
    if "@" not in norm:
        return ""
    return norm.split("@", 1)[1]


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

    # ----- v0.5.1: cross-format chain integrity (Piece 14) -----
    content_hash_canonical: Optional[str] = None  # SHA-256 of canonical text extraction (xlsx/csv/pdf chain)
    perceptual_hashes: Optional[Dict[str, Any]] = None  # {dhash, phash} for images
    canonical_extraction_failed: Optional[bool] = None  # set by client when format extractor was unavailable

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
    if req.content_hash_canonical is not None and not _SHA256_RE.match(req.content_hash_canonical):
        raise AIAuthError("INVALID_HASH", "content_hash_canonical must be a 64-character SHA-256 hex string", 400)


def _validate_client_integrity(request: Request, claimed: Optional[str], content_hash: str) -> str:
    """Return the ACTUAL client integrity level per CLAUDE.md "Metadata
    Integrity". Downgrades invalid claims to 'none' — never upgrades.

    Level 2 (extension): HMAC header X-AIAuth-Client-Hash over
    <version>:<timestamp>:<content_hash> using CLIENT_SECRET. Requires
    X-AIAuth-Extension-Version and X-AIAuth-Timestamp headers too.
    """
    if claimed != "extension" and claimed != "os-verified":
        return "none"

    if claimed == "extension":
        if not CLIENT_SECRET:
            return "none"  # server not configured for HMAC — cannot verify
        ver = request.headers.get("x-aiauth-extension-version", "")
        ts = request.headers.get("x-aiauth-timestamp", "")
        supplied = request.headers.get("x-aiauth-client-hash", "")
        if not ver or not ts or not supplied:
            return "none"
        # Timestamp freshness window: 5 minutes — prevents replay
        try:
            ts_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            drift = abs((datetime.now(timezone.utc) - ts_dt).total_seconds())
            if drift > 300:
                return "none"
        except Exception:
            return "none"
        expected = hmac.new(
            CLIENT_SECRET.encode(),
            f"{ver}:{ts}:{content_hash}".encode(),
            hashlib.sha256,
        ).hexdigest()
        if hmac.compare_digest(expected, supplied.lower()):
            return "extension"
        return "none"

    # "os-verified" would require per-agent cert verification; deferred.
    # Accept the claim only if the server has been configured to trust
    # the agent out of band (not implemented in v0.5.0 — downgrade).
    return "none"


@app.post("/v1/sign")
def sign_receipt(req: SignRequest, request: Request):
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
    # client_integrity: validate against HMAC header. Downgrades-only:
    # an invalid claim becomes "none"; never upgrades above what client requested.
    receipt["client_integrity"] = _validate_client_integrity(request, req.client_integrity, req.output_hash)

    # v0.5.0 commercial-tier fields (server accepts whatever the client sends)
    if req.tta is not None: receipt["tta"] = req.tta
    if req.sid: receipt["sid"] = req.sid
    if req.dest: receipt["dest"] = req.dest
    if req.dest_ext is not None: receipt["dest_ext"] = req.dest_ext
    if req.classification: receipt["classification"] = req.classification
    if req.concurrent_ai_apps: receipt["concurrent_ai_apps"] = req.concurrent_ai_apps

    # v0.5.1 cross-format chain fields (Piece 14)
    if req.content_hash_canonical:
        receipt["content_hash_canonical"] = req.content_hash_canonical
    if req.perceptual_hashes:
        receipt["perceptual_hashes"] = req.perceptual_hashes
    if req.canonical_extraction_failed is True:
        receipt["canonical_extraction_failed"] = True

    if req.review_status:
        receipt["review"] = {
            "status": req.review_status,
            "by": req.reviewer_id or req.user_id,
            "at": now,
        }
        if req.note: receipt["review"]["note"] = req.note

    signature = sign(receipt)

    # Public hash registry — 6 anonymous columns (still PII-free):
    # content_hash, receipt_id, parent_hash, doc_id, content_hash_canonical, registered_at
    if req.register:
        register_hash(req.output_hash, receipt_id, req.parent_hash, req.doc_id,
                      req.content_hash_canonical)

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
        eh = email_hash(email)
        domain = _email_domain(email)
        conn = get_db()
        conn.execute(
            "INSERT INTO accounts (account_id, primary_email_hash, created_at, updated_at) VALUES (?,?,?,?)",
            (account_id, eh, now, now),
        )
        conn.execute(
            "INSERT INTO account_emails "
            "(email_hash, account_id, email_type, verified, added_at, email_domain_plain) "
            "VALUES (?,?,?,?,?,?)",
            (eh, account_id, "personal", 0, now, domain),
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
        "WHERE email_hash = ? AND verified = 0",
        (now, email_hash(payload["email"])),
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
    """Return the authenticated caller's account info: linked emails
    (by hash + domain), verification status, org memberships.

    The server does NOT store plaintext emails — we return only the
    caller's CURRENT email (from their session token) plus metadata
    about OTHER linked emails: their domain, type, verification status.
    Full plaintext of additional linked emails is unavailable post-
    hardening; if you need to re-display the list, either the client
    caches it locally or the user re-verifies each (link flow)."""
    session = _require_session(authorization)
    account_id = session["account_id"]
    conn = get_db()
    raw_emails = [dict(r) for r in conn.execute(
        "SELECT email_hash, email_type, org_id, verified, added_at, verified_at, "
        "       email_domain_plain "
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

    # Only the CURRENT session's email can be returned in full (came in with the request).
    current_eh = email_hash(session.get("email", ""))
    emails_out = []
    for r in raw_emails:
        entry = {
            "email_hash": r["email_hash"],
            "email_type": r["email_type"],
            "org_id": r["org_id"],
            "verified": r["verified"],
            "added_at": r["added_at"],
            "verified_at": r["verified_at"],
            "domain": r["email_domain_plain"],
        }
        if r["email_hash"] == current_eh:
            entry["email"] = session["email"]  # current session's email is safe to echo
        emails_out.append(entry)

    return {
        "account_id": account_id,
        "current_email": session["email"],
        "emails": emails_out,
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

    # Insert or update the email (hashed)
    eh = email_hash(payload["email"])
    domain = _email_domain(payload["email"])
    try:
        conn.execute(
            "INSERT INTO account_emails "
            "(email_hash, account_id, email_type, verified, added_at, verified_at, email_domain_plain) "
            "VALUES (?,?,?,1,?,?,?)",
            (eh, payload["account_id"], email_type, now, now, domain),
        )
    except sqlite3.IntegrityError:
        # Already linked to same account — just ensure verified
        conn.execute(
            "UPDATE account_emails SET verified = 1, verified_at = ? "
            "WHERE email_hash = ? AND account_id = ?",
            (now, eh, payload["account_id"]),
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
        "INSERT INTO consent_log "
        "(account_id, org_id, action, timestamp, subject_email_hash, details_encrypted) "
        "VALUES (?,?,?,?,?,?)",
        (account_id, body.org_id, action, now,
         email_hash(session["email"]),
         encrypt_value(json.dumps({"email": session["email"]}))),
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
        "SELECT email_hash, email_type, org_id, verified, added_at, verified_at, email_domain_plain "
        "FROM account_emails WHERE account_id = ?", (account_id,)
    ).fetchall()]
    orgs = [dict(r) for r in conn.execute(
        "SELECT * FROM org_members WHERE account_id = ?", (account_id,)
    ).fetchall()]
    consent_raw = [dict(r) for r in conn.execute(
        "SELECT id, account_id, org_id, action, timestamp, details_encrypted "
        "FROM consent_log WHERE account_id = ? ORDER BY timestamp DESC",
        (account_id,),
    ).fetchall()]
    conn.close()
    # Decrypt consent details for the owner (they're authenticated)
    consent = []
    for r in consent_raw:
        dec = decrypt_value(r.pop("details_encrypted") or "")
        try:
            r["details"] = json.loads(dec) if dec else None
        except Exception:
            r["details"] = None
        consent.append(r)
    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "account": account,
        "current_email": session["email"],
        "emails": emails,
        "organizations": orgs,
        "consent_history": consent,
        "note": "Free-tier attestation receipts are stored on your device, not on our server. Stored emails are hashed; we return only hashes + domains for linked emails.",
    }


class PilotInterestRequest(BaseModel):
    company: str
    admin_email: str
    user_count: Optional[int] = None
    industry: Optional[str] = None


@app.post("/v1/pilot/interest")
def pilot_interest(body: PilotInterestRequest, request: Request):
    """Pilot-request form submission from /demo. Unauthenticated (anyone
    viewing the demo can submit). Rate-limit-adjacent via nginx IP throttle
    + a simple per-day cap enforced below.

    Stores a hashed admin email + company + user count + industry. Alerts
    the operator (via stdout + optional Resend notification) so follow-up
    happens within 24 hours.
    """
    company = (body.company or "").strip()
    email = (body.admin_email or "").strip().lower()
    if not company or not _valid_email(email):
        raise AIAuthError("INVALID_RECEIPT", "company and valid admin_email required", 400)
    # Rough rate guard: no more than 20 submissions per day per IP
    ip = _client_ip(request)
    conn = get_db()
    recent = conn.execute(
        "SELECT COUNT(*) AS n FROM pilot_interest WHERE source_ip = ? AND submitted_at > datetime('now', '-1 day')",
        (ip,),
    ).fetchone()
    if recent and recent["n"] >= 20:
        conn.close()
        raise AIAuthError("RATE_LIMITED", "Too many pilot requests from this IP today", 429)

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO pilot_interest "
        "(submitted_at, company, admin_email_hash, admin_email_encrypted, admin_email_domain, "
        " user_count, industry, source_ip) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (now, company, email_hash(email), encrypt_value(email),
         _email_domain(email), body.user_count, body.industry, ip),
    )
    conn.commit()
    conn.close()

    # Operator notification (stdout + Resend email when configured)
    print(f"[AIAuth pilot-interest] company={company!r} email_domain={_email_domain(email)!r} "
          f"users={body.user_count} industry={body.industry!r}")
    _notify_operator(
        subject=f"[AIAuth] New pilot request: {company}",
        text=(
            f"A new enterprise pilot request was submitted.\n\n"
            f"Company:    {company}\n"
            f"Admin:      {email}\n"
            f"Domain:     {_email_domain(email)}\n"
            f"User count: {body.user_count}\n"
            f"Industry:   {body.industry}\n"
            f"Source IP:  {ip}\n"
            f"Timestamp:  {now}\n\n"
            f"Follow up within 24 hours per the /demo form promise.\n"
        ),
    )

    return {"submitted": True, "message": "Thanks. We'll email you within 24 hours."}


class WaitlistRequest(BaseModel):
    email: str


@app.post("/v1/waitlist")
def waitlist_signup(body: WaitlistRequest, request: Request):
    """Capture a waitlist email from the landing-page hero form.

    Same data-hardening rules as pilot_interest: email is hashed (HMAC) as
    the unique index and Fernet-encrypted for later admin decryption when we
    send the "extension is live" broadcast. Plaintext email exists only for
    the duration of this request handler; it is not logged, not echoed back
    in responses, and not written to disk anywhere except the encrypted
    column. No confirmation email is sent in the waitlist flow — we spare
    the user the magic-link double-opt-in dance until they have a reason to
    authenticate (i.e., the extension is live).
    """
    email = (body.email or "").strip().lower()
    if not _valid_email(email):
        raise AIAuthError("INVALID_RECEIPT", "valid email required", 400)

    ip = _client_ip(request)
    conn = get_db()
    # Loose per-IP cap to deter mass-signup abuse.
    recent = conn.execute(
        "SELECT COUNT(*) AS n FROM waitlist_signups "
        "WHERE source_ip = ? AND submitted_at > datetime('now', '-1 day')",
        (ip,),
    ).fetchone()
    if recent and recent["n"] >= 10:
        conn.close()
        raise AIAuthError("RATE_LIMITED", "Too many waitlist signups from this IP today", 429)

    now = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            "INSERT INTO waitlist_signups "
            "(submitted_at, email_hash, email_encrypted, email_domain, source_ip) "
            "VALUES (?,?,?,?,?)",
            (now, email_hash(email), encrypt_value(email), _email_domain(email), ip),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # Email already on the waitlist — idempotent success, don't leak
        # enumeration signal to the caller.
        pass
    conn.close()

    print(f"[AIAuth waitlist] email_domain={_email_domain(email)!r}")
    _notify_operator(
        subject=f"[AIAuth] New waitlist signup: {email}",
        text=(
            f"A new user joined the AIAuth waitlist.\n\n"
            f"Email:      {email}\n"
            f"Domain:     {_email_domain(email)}\n"
            f"Source IP:  {ip}\n"
            f"Timestamp:  {now}\n\n"
            f"View full list:\n"
            f"  ssh root@<server> \"sqlite3 /opt/aiauth/aiauth.db "
            f"'SELECT COUNT(*) FROM waitlist_signups'\"\n"
        ),
    )
    return {"submitted": True, "message": "You're on the list. We'll email when the extension ships."}


class ContactRequest(BaseModel):
    company: str
    admin_email: str
    message: Optional[str] = None
    plan: Optional[str] = None
    user_count: Optional[int] = None


@app.post("/v1/contact")
def contact_sales(body: ContactRequest, request: Request):
    """Contact-sales submission from /contact (dedicated page for the
    Team pricing tier CTA). Mirrors the hardening discipline of
    pilot_interest and waitlist_signup: email hashed + encrypted, simple
    per-IP rate cap, operator notification fires on success.
    """
    company = (body.company or "").strip()
    email = (body.admin_email or "").strip().lower()
    if not company or not _valid_email(email):
        raise AIAuthError("INVALID_RECEIPT", "company and valid admin_email required", 400)

    ip = _client_ip(request)
    conn = get_db()
    recent = conn.execute(
        "SELECT COUNT(*) AS n FROM contact_inquiries "
        "WHERE source_ip = ? AND submitted_at > datetime('now', '-1 day')",
        (ip,),
    ).fetchone()
    if recent and recent["n"] >= 20:
        conn.close()
        raise AIAuthError("RATE_LIMITED", "Too many contact requests from this IP today", 429)

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO contact_inquiries "
        "(submitted_at, company, admin_email_hash, admin_email_encrypted, admin_email_domain, "
        " plan, user_count, message, source_ip) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (now, company, email_hash(email), encrypt_value(email),
         _email_domain(email), (body.plan or None), body.user_count,
         (body.message or None), ip),
    )
    conn.commit()
    conn.close()

    print(f"[AIAuth contact] company={company!r} plan={body.plan!r} "
          f"email_domain={_email_domain(email)!r}")
    _notify_operator(
        subject=f"[AIAuth] Contact sales: {company}",
        text=(
            f"A new Contact Sales inquiry was submitted.\n\n"
            f"Company:    {company}\n"
            f"Admin:      {email}\n"
            f"Domain:     {_email_domain(email)}\n"
            f"Plan:       {body.plan}\n"
            f"User count: {body.user_count}\n"
            f"Message:    {body.message}\n"
            f"Source IP:  {ip}\n"
            f"Timestamp:  {now}\n"
        ),
    )
    return {"submitted": True, "message": "Thanks. We'll email you within one business day."}


# ===================================================================
# INBOUND MAIL FORWARDER (Resend webhook → operator inbox)
#
# Resend's inbound feature accepts mail at any address on the verified
# domain (aiauth.app) and POSTs a webhook to the URL configured in the
# Resend dashboard. This endpoint receives that webhook, extracts the
# minimum fields needed to preserve the message, and forwards via
# Resend outbound to AIAUTH_OPERATOR_EMAIL.
#
# A shared-secret header (AIAUTH_INBOUND_SECRET) gates the endpoint so
# that only Resend — or someone with the secret — can trigger a forward.
# Without the gate, any attacker who discovers the URL could inject
# arbitrary mail into the operator's inbox.
#
# Intentionally simple: we do not parse attachments, do not persist
# inbound mail, and do not thread replies. The intent is to preserve
# the "security@aiauth.app" class of addresses as functioning mail
# drops, nothing more. If you need a real support inbox, swap this for
# a helpdesk product.
# ===================================================================


def _verify_svix_signature(secret: str, body: bytes, svix_id: str, svix_ts: str, svix_sig: str) -> bool:
    """Verify a Svix-style webhook signature (used by Resend).

    secret    — "whsec_<base64-key>" from the Resend webhook settings
    body      — raw request body bytes (signature is over raw bytes, not
                re-serialized JSON)
    svix_id   — value of the svix-id header
    svix_ts   — value of the svix-timestamp header (unix epoch seconds)
    svix_sig  — value of the svix-signature header; may contain multiple
                space-separated signatures, each formatted as "v1,<base64>"

    Returns True only if (a) the timestamp is within 5 minutes of now
    (replay guard) and (b) at least one of the presented signatures
    matches our recomputed HMAC-SHA256.
    """
    if not (secret and body and svix_id and svix_ts and svix_sig):
        return False
    if not secret.startswith("whsec_"):
        return False
    try:
        key = base64.b64decode(secret[len("whsec_"):])
    except Exception:
        return False
    try:
        ts = int(svix_ts)
    except ValueError:
        return False
    # Replay guard: reject older than 5 minutes in either direction.
    now = int(datetime.now(timezone.utc).timestamp())
    if abs(now - ts) > 300:
        return False
    to_sign = f"{svix_id}.{svix_ts}.".encode() + body
    expected = base64.b64encode(hmac.new(key, to_sign, hashlib.sha256).digest()).decode()
    for presented in svix_sig.split():
        if "," in presented:
            version, _, value = presented.partition(",")
            if version == "v1" and hmac.compare_digest(value, expected):
                return True
    return False


@app.post("/v1/inbound")
async def inbound_mail(request: Request):
    """Receive a Resend inbound-mail webhook and forward to the operator.

    The Resend webhook body varies by event type; we handle the
    `email.received` event and ignore everything else. The outbound
    forward preserves the original subject with a `[fwd]` prefix, the
    original From/To for context, and the body (HTML or text, whichever
    was present).

    Security:
      - Resend signs webhooks with Svix (svix-id, svix-timestamp,
        svix-signature headers). We verify using AIAUTH_INBOUND_SECRET,
        which should hold the "whsec_..." signing secret from the Resend
        webhook dashboard. If that env var is unset the endpoint returns
        503 (disabled).
      - Signature covers the raw request body + headers, with a 5-minute
        replay window.
      - We refuse to forward mail whose From address is already on
        aiauth.app. This prevents a trivial loop where the operator
        replies to a forwarded message and the reply comes back in.
      - We cap the forwarded body at 100 KB. Anything larger is
        truncated with a note.
    """
    secret = os.getenv("AIAUTH_INBOUND_SECRET", "").strip()
    if not secret:
        raise AIAuthError("DISABLED", "Inbound mail forwarding is not configured", 503)

    body_bytes = await request.body()
    svix_id = request.headers.get("svix-id") or request.headers.get("webhook-id") or ""
    svix_ts = request.headers.get("svix-timestamp") or request.headers.get("webhook-timestamp") or ""
    svix_sig = request.headers.get("svix-signature") or request.headers.get("webhook-signature") or ""

    if not _verify_svix_signature(secret, body_bytes, svix_id.strip(), svix_ts.strip(), svix_sig.strip()):
        raise AIAuthError("UNAUTHENTICATED", "Invalid or missing webhook signature", 401)

    operator = os.getenv("AIAUTH_OPERATOR_EMAIL", "").strip()
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    if not operator or not api_key:
        raise AIAuthError("DISABLED", "Operator email or Resend API key not configured", 503)

    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        raise AIAuthError("INVALID_RECEIPT", "Webhook body is not valid JSON", 400)

    event_type = (payload.get("type") or payload.get("event") or "").lower()
    if "email" in event_type and "received" not in event_type:
        # Ignore delivery events, opens, clicks, bounces that Resend may
        # emit to the same webhook. We only forward inbound-received.
        return {"forwarded": False, "reason": f"ignored event type: {event_type}"}

    data = payload.get("data") or payload

    def _first_addr(v) -> str:
        """Resend sends `to` as a list of strings (and may send `from` as
        a dict with an `email` field). Normalise any of those shapes to a
        single address string."""
        if not v:
            return ""
        if isinstance(v, str):
            return v.strip()
        if isinstance(v, list) and v:
            return _first_addr(v[0])
        if isinstance(v, dict):
            return str(v.get("email") or v.get("address") or "").strip()
        return ""

    sender = _first_addr(data.get("from") or data.get("From"))
    recipient = _first_addr(data.get("to") or data.get("To"))
    subject_raw = data.get("subject") or data.get("Subject") or "(no subject)"
    subject = str(subject_raw).strip() if subject_raw else "(no subject)"
    text_body = data.get("text") or data.get("Text") or ""
    html_body = data.get("html") or data.get("Html") or data.get("HTML") or ""
    # Log event shape once per request so future shape changes are debuggable.
    try:
        print(f"[AIAuth inbound] event={event_type!r} top_keys={list(payload.keys())} data_keys={list(data.keys()) if isinstance(data, dict) else type(data).__name__}")
    except Exception:
        pass

    # Resend's email.received webhook delivers metadata only — the body is
    # retrieved by calling GET /emails/{email_id} against the Resend API.
    # Fetch it only if the webhook payload didn't already include it
    # (future-proofing: if Resend adds body fields to the webhook, we'll
    # just use those and skip the API round-trip).
    if not text_body and not html_body:
        email_id = data.get("email_id") or data.get("id") or ""
        if email_id:
            try:
                import urllib.request, urllib.error
                req = urllib.request.Request(
                    f"https://api.resend.com/emails/{email_id}",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Accept": "application/json",
                    },
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body_json = json.loads(resp.read().decode("utf-8"))
                text_body = body_json.get("text") or ""
                html_body = body_json.get("html") or ""
                print(f"[AIAuth inbound] fetched body via API: email_id={email_id!r} "
                      f"text_len={len(text_body)} html_len={len(html_body)} "
                      f"keys={list(body_json.keys())}")
            except urllib.error.HTTPError as http_err:
                print(f"[AIAuth inbound] body fetch HTTP {http_err.code}: {http_err.reason} "
                      f"(email_id={email_id!r})")
            except Exception as fetch_err:
                print(f"[AIAuth inbound] body fetch failed: {type(fetch_err).__name__}: "
                      f"{str(fetch_err)[:200]}")
        else:
            print(f"[AIAuth inbound] no email_id in payload; body fetch skipped")

    # Loop guard: refuse to forward mail that claims to be from our own domain.
    if sender and "@aiauth.app" in sender.lower():
        print(f"[AIAuth inbound] refused loop: from={sender!r}")
        return {"forwarded": False, "reason": "loop prevention"}

    MAX = 100_000  # 100 KB
    truncated = False
    if len(text_body) > MAX:
        text_body = text_body[:MAX] + "\n\n[truncated — original exceeded 100 KB]"
        truncated = True
    if len(html_body) > MAX:
        html_body = html_body[:MAX] + "<p><em>[truncated — original exceeded 100 KB]</em></p>"
        truncated = True

    # Metadata we want to surface in the forwarded notification so the
    # operator can jump straight to the full message in the Resend
    # dashboard if they need the body. Resend's inbound storage is
    # dashboard-only today (GET /emails/{id} returns 403 for inbound),
    # so these IDs are the link between the Gmail notification and the
    # full original.
    email_id = str(data.get("email_id") or data.get("id") or "").strip()
    message_id = str(data.get("message_id") or "").strip()
    resend_url = f"https://resend.com/emails/{email_id}" if email_id else ""
    fallback_note = ""
    if not text_body and not html_body:
        fallback_note = (
            "\n[Body not included in this notification — open in Resend to read the full message.]"
        )
        html_fallback_note = (
            "<p style='font-size:13px;color:#64748b;margin:0 0 12px;'><em>"
            "Body not included in this notification — "
            f"<a href='{resend_url}'>open in Resend</a> to read the full message."
            "</em></p>"
        )
    else:
        html_fallback_note = ""

    prefix = (
        f"Forwarded from {recipient or 'unknown'} on aiauth.app.\n"
        f"Original From: {sender or '(unknown)'}\n"
        f"Original Subject: {subject}\n"
        f"Resend email ID: {email_id or '(unavailable)'}\n"
        f"Original Message-ID: {message_id or '(unavailable)'}\n"
        f"{'Full message: ' + resend_url if resend_url else ''}\n"
        f"{'— TRUNCATED — ' if truncated else ''}"
        f"────────────────────────────────────\n\n"
        f"{fallback_note}"
    )
    html_prefix = (
        f"<p style='font-family:system-ui,sans-serif;font-size:12px;color:#64748b;"
        f"background:#f1f5f9;padding:10px 14px;border-radius:6px;margin:0 0 16px;'>"
        f"Forwarded from <b>{recipient or 'unknown'}</b> on aiauth.app.<br>"
        f"Original From: <b>{sender or '(unknown)'}</b><br>"
        f"Original Subject: <b>{subject}</b><br>"
        f"Resend ID: <code style='font-size:11px;'>{email_id or '(unavailable)'}</code>"
        f"{'<br><a href=\"' + resend_url + '\">View full message in Resend →</a>' if resend_url else ''}"
        f"{'<br><b>TRUNCATED</b>' if truncated else ''}"
        f"</p>"
        f"{html_fallback_note}"
    )

    forward_subject = f"[fwd: {recipient or 'aiauth.app'}] {subject}"
    try:
        import resend
        resend.api_key = api_key
        fwd_args = {
            "from": os.getenv("RESEND_FROM", "AIAuth <auth@aiauth.app>"),
            "to": operator,
            "subject": forward_subject,
            "reply_to": sender if sender else None,
        }
        if html_body:
            fwd_args["html"] = html_prefix + html_body
        else:
            fwd_args["text"] = prefix + text_body
        # Remove None-valued fields that the SDK rejects.
        fwd_args = {k: v for k, v in fwd_args.items() if v is not None and v != ""}
        resend.Emails.send(fwd_args)
        print(f"[AIAuth inbound] forwarded to {operator.split('@')[-1]!r} from={sender!r} to={recipient!r} subject={subject!r}")
    except Exception as exc:
        print(f"[AIAuth inbound] forward failed: {type(exc).__name__}: {str(exc)[:200]}")
        raise AIAuthError("FORWARD_FAILED", "Forwarding via Resend failed", 502)

    return {"forwarded": True, "to_domain": operator.split("@")[-1]}


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
            pass
        conn.close()
    return {"logged_out": True}


# ===================================================================
# ENTERPRISE INGEST + POLICY ENGINE + ADMIN (v0.5.0+)
# See CLAUDE.md "Enterprise Offboarding" + "Policy Engine" + "DSAR".
# ===================================================================

# ------------- License + domain helpers -------------

def _require_license_header(request: Request) -> dict:
    """Resolve X-AIAuth-License -> org row. Raises 401 on failure."""
    lic = request.headers.get("x-aiauth-license", "").strip()
    if not lic:
        raise AIAuthError("LICENSE_MISSING", "X-AIAuth-License header required", 401)
    data = validate_license(lic)
    if data is None:
        raise AIAuthError("LICENSE_INVALID", "License key invalid or expired", 401)
    conn = get_db()
    org = conn.execute(
        "SELECT * FROM organizations WHERE license_key = ? AND active = 1", (lic,)
    ).fetchone()
    conn.close()
    if org is None:
        raise AIAuthError(
            "LICENSE_NOT_ACTIVATED",
            "License key is valid but not attached to an active organization. "
            "An admin must claim a domain first via /v1/admin/org/claim.",
            401,
        )
    return {"license_data": data, "org": dict(org)}


def _require_admin_session(authorization: Optional[str], org_id: Optional[str] = None) -> dict:
    """Return session payload if the caller is an admin of the given org
    (or any org, when org_id is None). Raises 403 otherwise."""
    session = _require_session(authorization)
    conn = get_db()
    if org_id:
        row = conn.execute(
            "SELECT * FROM org_members WHERE account_id = ? AND org_id = ? AND role = 'admin' AND left_at IS NULL",
            (session["account_id"], org_id),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM org_members WHERE account_id = ? AND role = 'admin' AND left_at IS NULL",
            (session["account_id"],),
        ).fetchone()
    conn.close()
    if row is None:
        raise AIAuthError("NOT_ADMIN", "Admin role required on the target organization", 403)
    session["org_membership"] = dict(row)
    return session


def _org_domains(org: dict) -> List[str]:
    try:
        return json.loads(org.get("domains") or "[]")
    except Exception:
        return []


def _uid_in_org_domain(uid: str, org: dict) -> bool:
    if "@" not in (uid or ""):
        return False
    domain = uid.split("@", 1)[1].lower()
    return domain in [d.lower() for d in _org_domains(org)]


# ------------- Policy engine -------------

DEFAULT_POLICIES = [
    {"id": "dual-review-financial",
     "severity": "high",
     "match": lambda r, ctx: r.get("classification") == "financial"
             and ctx.get("chain_unique_attesters", 1) < 2},
    {"id": "no-rubber-stamping",
     "severity": "medium",
     "match": lambda r, ctx: (r.get("tta") or 999) < 10 and (r.get("len") or 0) > 500},
    {"id": "external-must-attest",
     "severity": "critical",
     "match": lambda r, ctx: r.get("dest_ext") is True and not (r.get("review_status") or r.get("review", {}).get("status"))},
    {"id": "unverified-financial",
     "severity": "medium",
     "match": lambda r, ctx: r.get("client_integrity") == "none" and r.get("classification") == "financial"},
    {"id": "shadow-ai-detected",
     "severity": "low",
     "match": lambda r, ctx: _shadow_ai_hit(r)},
    {"id": "ungoverned-ai-content",
     "severity": "medium",
     "match": lambda r, ctx: (r.get("ai_markers") or {}).get("verified") is True and not r.get("parent")},
]


def _shadow_ai_hit(r: dict) -> bool:
    """Flag when concurrent_ai_apps includes a tool that is NOT the
    source_app / model of the attestation — i.e., an AI app was open
    but not the one that produced the attested content."""
    apps = r.get("concurrent_ai_apps") or []
    if not apps:
        return False
    src = (r.get("source_app") or r.get("source_domain") or "").lower()
    model = (r.get("model") or "").lower()
    for app in apps:
        nm = str(app).lower()
        if nm not in src and (not model or model not in nm):
            return True
    return False


def evaluate_policies(receipt: dict, ctx: Optional[dict] = None) -> List[dict]:
    """Evaluate DEFAULT_POLICIES against a receipt. Returns a list of
    {policy_id, severity, details} for each rule that matched. ctx
    carries cross-attestation signals (e.g. chain_unique_attesters)."""
    ctx = ctx or {}
    violations = []
    for pol in DEFAULT_POLICIES:
        try:
            if pol["match"](receipt, ctx):
                violations.append({
                    "policy_id": pol["id"],
                    "severity": pol["severity"],
                    "details": {
                        "classification": receipt.get("classification"),
                        "tta": receipt.get("tta"),
                        "len": receipt.get("len"),
                        "client_integrity": receipt.get("client_integrity"),
                        "dest_ext": receipt.get("dest_ext"),
                        "model": receipt.get("model"),
                    },
                })
        except Exception:
            continue
    return violations


# ------------- Enterprise ingest -------------

class EnterpriseIngestRequest(BaseModel):
    receipt: dict
    signature: str

    model_config = {"extra": "ignore"}


@app.post("/v1/enterprise/ingest")
def enterprise_ingest(body: EnterpriseIngestRequest, request: Request):
    """Receive a signed attestation from an enterprise client and store
    it in enterprise_attestations. Must include a valid license key
    (X-AIAuth-License header). The receipt's uid must end in one of
    the org's claimed domains.
    """
    ctx = _require_license_header(request)
    org = ctx["org"]

    receipt = body.receipt or {}
    # Verify the signature — anything unsigned is rejected outright.
    if not check_sig(receipt, body.signature):
        raise AIAuthError("INVALID_RECEIPT", "Receipt signature invalid", 400)

    uid = receipt.get("uid") or ""
    if not _uid_in_org_domain(uid, org):
        raise AIAuthError(
            "DOMAIN_MISMATCH",
            "Receipt uid domain is not in this org's claimed domains",
            403,
            details={"uid": uid, "org_domains": _org_domains(org)},
        )

    # Block offboarded users. Two signals, either one suffices:
    #   (a) org_members row with left_at set
    #   (b) consent_log row with action dsar_pseudonymize or dsar_delete
    #       for this (email_hash, org)
    uid_h = email_hash(uid)
    conn = get_db()
    left_member = conn.execute(
        "SELECT om.left_at FROM org_members om "
        "JOIN account_emails ae ON ae.account_id = om.account_id "
        "WHERE ae.email_hash = ? AND om.org_id = ? AND om.left_at IS NOT NULL",
        (uid_h, org["org_id"]),
    ).fetchone()
    dsar_out = conn.execute(
        "SELECT id FROM consent_log "
        "WHERE org_id = ? AND action IN ('dsar_pseudonymize','dsar_delete') "
        "AND subject_email_hash = ? LIMIT 1",
        (org["org_id"], uid_h),
    ).fetchone()
    if left_member is not None or dsar_out is not None:
        conn.close()
        raise AIAuthError("EMAIL_OFFBOARDED", "This uid has been offboarded from the organization", 403)

    # Idempotent: if already ingested, return existing row
    existing = conn.execute(
        "SELECT id FROM enterprise_attestations WHERE id = ?",
        (receipt.get("id"),),
    ).fetchone()
    if existing is not None:
        conn.close()
        return {"stored": True, "deduplicated": True, "attestation_id": receipt.get("id"), "violations": []}

    review = receipt.get("review") or {}
    row = (
        receipt.get("id"),
        receipt.get("ts"),
        receipt.get("hash"),
        receipt.get("prompt_hash"),
        uid_h,                          # uid_hash (HMAC-SHA256 of normalized uid)
        encrypt_value(uid),             # uid_encrypted (Fernet ciphertext)
        None,                           # uid_pseudonym
        receipt.get("src"),
        receipt.get("model"),
        receipt.get("provider"),
        receipt.get("source_domain"),
        receipt.get("source_app"),
        json.dumps(receipt.get("concurrent_ai_apps")) if receipt.get("concurrent_ai_apps") is not None else None,
        json.dumps(receipt.get("ai_markers")) if receipt.get("ai_markers") is not None else None,
        receipt.get("doc_id"),
        receipt.get("parent"),
        receipt.get("file_type"),
        receipt.get("len"),
        receipt.get("tta"),
        receipt.get("sid"),
        receipt.get("dest"),
        int(receipt["dest_ext"]) if isinstance(receipt.get("dest_ext"), bool) else None,
        receipt.get("classification"),
        review.get("status"),
        review.get("by"),
        review.get("at"),
        review.get("note"),
        json.dumps(receipt.get("tags")) if receipt.get("tags") is not None else None,
        receipt.get("v", VERSION),
        org["org_id"],
        receipt.get("client_integrity", "none"),
        datetime.now(timezone.utc).isoformat(),
    )
    conn.execute(
        "INSERT INTO enterprise_attestations ("
        "id, ts, hash, prompt_hash, uid_hash, uid_encrypted, uid_pseudonym, "
        "src, model, provider, source_domain, source_app, "
        "concurrent_ai_apps, ai_markers, doc_id, parent, "
        "file_type, len, tta, sid, dest, dest_ext, classification, "
        "review_status, review_by, review_at, review_note, tags, "
        "schema_version, org_id, client_integrity, ingested_at"
        ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        row,
    )

    # Policy evaluation
    violations = evaluate_policies(receipt)
    now = datetime.now(timezone.utc).isoformat()
    for v in violations:
        conn.execute(
            "INSERT INTO policy_violations (attestation_id, policy_id, severity, details, detected_at) "
            "VALUES (?,?,?,?,?)",
            (receipt.get("id"), v["policy_id"], v["severity"], json.dumps(v["details"]), now),
        )
    conn.commit()
    conn.close()
    return {
        "stored": True,
        "attestation_id": receipt.get("id"),
        "org_id": org["org_id"],
        "violations": violations,
    }


# ------------- Admin: org claim -------------

class OrgClaimRequest(BaseModel):
    name: str
    domains: List[str]
    license_key: str
    license_tier: str = "hosted"


@app.post("/v1/admin/org/claim")
def admin_org_claim(body: OrgClaimRequest, authorization: Optional[str] = Header(default=None)):
    """Claim one or more email domains for an organization and attach a
    license key. The authenticated user becomes the first admin member.

    Domains must match emails the calling account has VERIFIED — this
    proves the caller owns (or at least controls accounts on) the
    domain. Simplified proof — production deployments should require
    DNS TXT verification, which we can add via a follow-up piece.
    """
    session = _require_session(authorization)
    # Verify license first
    lic = validate_license(body.license_key)
    if lic is None:
        raise AIAuthError("LICENSE_INVALID", "License key is invalid or expired", 400)

    domains = [d.strip().lower() for d in body.domains if d.strip()]
    if not domains:
        raise AIAuthError("INVALID_RECEIPT", "At least one domain is required", 400)

    # Proof-of-control: the caller must have a verified email in each domain.
    # Post-Piece 12, emails are not stored plaintext — we use the separate
    # email_domain_plain column for domain matching.
    conn = get_db()
    verified = {row["email_domain_plain"]
                for row in conn.execute(
                    "SELECT email_domain_plain FROM account_emails "
                    "WHERE account_id = ? AND verified = 1 AND email_domain_plain IS NOT NULL",
                    (session["account_id"],),
                ).fetchall()}
    missing = [d for d in domains if d not in verified]
    if missing:
        conn.close()
        raise AIAuthError(
            "DOMAIN_NOT_VERIFIED",
            "You must have a verified email in each claimed domain",
            403,
            details={"missing_domains": missing},
        )

    org_id = "ORG_" + uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO organizations (org_id, name, domains, license_key, license_tier, created_at, active) "
        "VALUES (?,?,?,?,?,?,1)",
        (org_id, body.name, json.dumps(domains), body.license_key, body.license_tier, now),
    )
    conn.execute(
        "INSERT INTO org_members (account_id, org_id, role, joined_at) VALUES (?,?,?,?)",
        (session["account_id"], org_id, "admin", now),
    )
    # Also mark each of the caller's verified emails matching a claimed
    # domain as corporate emails under this org (match by domain column).
    for domain in domains:
        conn.execute(
            "UPDATE account_emails SET email_type = 'corporate', org_id = ? "
            "WHERE account_id = ? AND email_domain_plain = ? AND email_type != 'corporate'",
            (org_id, session["account_id"], domain),
        )
    conn.commit()
    conn.close()
    return {"org_id": org_id, "name": body.name, "domains": domains, "tier": body.license_tier,
            "note": "You are the first admin. Invite members via /v1/admin/org/invite (future)."}


# ------------- Admin: member list + DSAR + pseudonymize -------------

@app.get("/v1/admin/org/members")
def admin_org_members(org_id: str = Query(...), authorization: Optional[str] = Header(default=None)):
    """List members of an org (admin-authed). Shows link status:
    who has a personal email linked, who consented to personal-history
    sharing, who has left.

    Post-hardening: we return the primary-email HASH and the account's
    corporate-email DOMAIN (never the full plaintext email). Admins who
    need to contact a specific member go through the invite list kept
    in their own IT system."""
    session = _require_admin_session(authorization, org_id)
    conn = get_db()
    rows = conn.execute(
        "SELECT om.account_id, om.org_id, om.role, om.department, "
        "       om.joined_at, om.left_at, om.consent_personal_history, "
        "       a.primary_email_hash, "
        "       (SELECT email_domain_plain FROM account_emails ae "
        "        WHERE ae.account_id = om.account_id AND ae.org_id = om.org_id "
        "        LIMIT 1) AS corporate_domain, "
        "       (SELECT COUNT(*) FROM account_emails ae "
        "        WHERE ae.account_id = om.account_id AND ae.email_type = 'personal') AS has_personal "
        "FROM org_members om JOIN accounts a ON om.account_id = a.account_id "
        "WHERE om.org_id = ? ORDER BY om.joined_at DESC",
        (org_id,),
    ).fetchall()
    conn.close()
    return {"org_id": org_id, "members": [dict(r) for r in rows]}


class DSARRequest(BaseModel):
    email: str
    action: str              # "export" | "pseudonymize" | "delete"
    org_id: str


@app.post("/v1/admin/dsar")
def admin_dsar(body: DSARRequest, authorization: Optional[str] = Header(default=None)):
    """Process a Data Subject Access Request. Export returns all data
    tied to this email; pseudonymize replaces uid with a one-way hash
    while preserving audit rows; delete nukes personal data entirely
    (registry entries are NOT touched — they contain no PII).

    Actions are logged to consent_log (immutable)."""
    session = _require_admin_session(authorization, body.org_id)
    email = (body.email or "").strip().lower()
    if body.action not in ("export", "pseudonymize", "delete"):
        raise AIAuthError("INVALID_RECEIPT", "action must be export/pseudonymize/delete", 400)

    uid_h = email_hash(email)

    conn = get_db()
    member = conn.execute(
        "SELECT om.account_id FROM org_members om "
        "JOIN account_emails ae ON ae.account_id = om.account_id "
        "WHERE ae.email_hash = ? AND om.org_id = ?",
        (uid_h, body.org_id),
    ).fetchone()
    account_id = member["account_id"] if member else None

    now = datetime.now(timezone.utc).isoformat()
    if body.action == "export":
        # Pull attestations by uid_hash; decrypt uid_encrypted for the admin's view.
        raw = conn.execute(
            "SELECT * FROM enterprise_attestations WHERE uid_hash = ? AND org_id = ?",
            (uid_h, body.org_id),
        ).fetchall()
        attests = []
        for r in raw:
            d = dict(r)
            if d.get("uid_encrypted"):
                d["uid"] = decrypt_value(d["uid_encrypted"])   # admin view, in-memory only
            attests.append(d)
        emails = [dict(r) for r in conn.execute(
            "SELECT email_hash, email_type, org_id, verified, added_at, verified_at, email_domain_plain "
            "FROM account_emails WHERE email_hash = ?",
            (uid_h,),
        ).fetchall()]
        conn.execute(
            "INSERT INTO consent_log "
            "(account_id, org_id, action, timestamp, subject_email_hash, details_encrypted) "
            "VALUES (?,?,?,?,?,?)",
            (account_id or "unknown", body.org_id, "dsar_export", now, uid_h,
             encrypt_value(json.dumps({"email": email, "requested_by": session["email"]}))),
        )
        conn.commit()
        conn.close()
        return {"action": "export", "email": email, "attestations": attests, "emails": emails}

    if body.action == "pseudonymize":
        # One-way pseudonym derived from email + org salt. Deterministic so
        # re-running doesn't produce a new pseudonym each time.
        pseud = hashlib.sha256(f"{email}{body.org_id}pseudonymize".encode()).hexdigest()[:24]
        # Clear the uid_encrypted column and set the pseudonym; uid_hash
        # remains so offboarded-check queries keep working.
        conn.execute(
            "UPDATE enterprise_attestations "
            "SET uid_pseudonym = ?, uid_encrypted = NULL "
            "WHERE uid_hash = ? AND org_id = ?",
            (pseud, uid_h, body.org_id),
        )
        # Mark user as left (if they were linked as a member)
        if account_id:
            conn.execute(
                "UPDATE org_members SET left_at = ? WHERE account_id = ? AND org_id = ? AND left_at IS NULL",
                (now, account_id, body.org_id),
            )
        conn.execute(
            "INSERT INTO consent_log "
            "(account_id, org_id, action, timestamp, subject_email_hash, details_encrypted) "
            "VALUES (?,?,?,?,?,?)",
            (account_id or "unknown", body.org_id, "dsar_pseudonymize", now, uid_h,
             encrypt_value(json.dumps({"email": email, "pseudonym": pseud, "requested_by": session["email"]}))),
        )
        conn.commit()
        conn.close()
        return {"action": "pseudonymize", "email": email, "pseudonym": pseud}

    if body.action == "delete":
        deleted = conn.execute(
            "DELETE FROM enterprise_attestations WHERE uid_hash = ? AND org_id = ?",
            (uid_h, body.org_id),
        ).rowcount
        conn.execute(
            "INSERT INTO consent_log "
            "(account_id, org_id, action, timestamp, subject_email_hash, details_encrypted) "
            "VALUES (?,?,?,?,?,?)",
            (account_id or "unknown", body.org_id, "dsar_delete", now, uid_h,
             encrypt_value(json.dumps({"email": email, "deleted_rows": deleted, "requested_by": session["email"]}))),
        )
        conn.commit()
        conn.close()
        return {"action": "delete", "email": email, "deleted_rows": deleted,
                "warning": "Registry entries preserved (contain no PII). Chain integrity may be affected."}


class OffboardRequest(BaseModel):
    email: str
    org_id: str


@app.post("/v1/admin/pseudonymize")
def admin_offboard(body: OffboardRequest, authorization: Optional[str] = Header(default=None)):
    """Offboarding convenience wrapper around DSAR pseudonymize. Most
    common admin action when an employee leaves the company."""
    dsar = DSARRequest(email=body.email, action="pseudonymize", org_id=body.org_id)
    return admin_dsar(dsar, authorization=authorization)


# ------------- Admin: policy violations feed -------------

@app.get("/v1/violations")
def violations_feed(
    org_id: str = Query(...),
    severity: Optional[str] = Query(default=None, description="Filter: critical|high|medium|low"),
    limit: int = Query(default=100, le=500),
    authorization: Optional[str] = Header(default=None),
):
    """Recent policy violations for the org (admin-authed)."""
    _require_admin_session(authorization, org_id)
    conn = get_db()
    where = "ea.org_id = ?"
    params: list = [org_id]
    if severity:
        where += " AND pv.severity = ?"
        params.append(severity)
    rows = conn.execute(
        f"SELECT pv.*, ea.uid_hash, ea.uid_pseudonym, ea.ts AS attestation_ts "
        f"FROM policy_violations pv "
        f"JOIN enterprise_attestations ea ON pv.attestation_id = ea.id "
        f"WHERE {where} ORDER BY pv.detected_at DESC LIMIT ?",
        params + [limit],
    ).fetchall()
    conn.close()
    return {"org_id": org_id, "count": len(rows), "violations": [dict(r) for r in rows]}


# ===================================================================
# DASHBOARD DATA CONTRACT (v0.5.0+)
# GET /v1/admin/dashboard/data returns the exact schema documented in
# CLAUDE.md "Dashboard Data Contract". Aggregations use NULL-safe SQL
# per Schema Versioning Rule #3.
# ===================================================================

def _grade_for(review_rate: float, critical_violations: int) -> str:
    if critical_violations > 0 and review_rate < 0.95:
        return "F"
    if review_rate >= 0.95 and critical_violations == 0: return "A"
    if review_rate >= 0.85: return "B"
    if review_rate >= 0.70: return "C"
    if review_rate >= 0.50: return "D"
    return "F"


@app.get("/v1/admin/dashboard/data")
def dashboard_data(
    org_id: str = Query(...),
    from_: Optional[str] = Query(default=None, alias="from"),
    to: Optional[str] = Query(default=None),
    department: Optional[str] = Query(default=None),
    model: Optional[str] = Query(default=None),
    classification: Optional[str] = Query(default=None),
    authorization: Optional[str] = Header(default=None),
):
    """Aggregated enterprise dashboard data. See Dashboard Data Contract
    in CLAUDE.md for response schema. Every key in the shape appears in
    every response (null/0/[] when empty) — no consumer has to null-check."""
    _require_admin_session(authorization, org_id)

    conn = get_db()
    org_row = conn.execute("SELECT * FROM organizations WHERE org_id = ?", (org_id,)).fetchone()
    if org_row is None:
        conn.close()
        raise AIAuthError("ORG_NOT_FOUND", "Organization not found", 404)

    # Build WHERE clause + params shared by most queries
    where = "ea.org_id = :org"
    params: dict = {"org": org_id}
    if from_:
        where += " AND ea.ts >= :from_"; params["from_"] = from_
    if to:
        where += " AND ea.ts <= :to"; params["to"] = to
    if model:
        where += " AND ea.model = :model"; params["model"] = model
    if classification:
        where += " AND ea.classification = :cls"; params["cls"] = classification

    # Join to get department (NULL-safe via LEFT JOIN)
    join = (
        "LEFT JOIN account_emails ae ON ea.uid_hash = ae.email_hash "
        "LEFT JOIN org_members om ON ae.account_id = om.account_id AND om.org_id = ea.org_id "
    )

    dept_filter = ""
    if department:
        dept_filter = " AND IFNULL(om.department, 'Unmapped') = :dept"
        params["dept"] = department

    # Summary counts
    summary_row = conn.execute(
        f"SELECT COUNT(*) AS total, "
        f"       COUNT(DISTINCT ea.uid_hash) AS unique_users, "
        f"       COUNT(DISTINCT ea.sid) AS unique_sessions, "
        f"       AVG(ea.tta) AS avg_tta, "
        f"       SUM(CASE WHEN ea.review_status IS NOT NULL THEN 1 ELSE 0 END) AS reviewed, "
        f"       SUM(CASE WHEN COALESCE(ea.tta, 999) < 10 AND COALESCE(ea.len, 0) > 500 THEN 1 ELSE 0 END) AS rubber_stamps, "
        f"       SUM(CASE WHEN ea.dest_ext = 1 THEN 1 ELSE 0 END) AS external_exposure, "
        f"       SUM(CASE WHEN ea.ai_markers IS NOT NULL THEN 1 ELSE 0 END) AS ai_authored, "
        f"       SUM(CASE WHEN ea.prompt_hash IS NOT NULL THEN 1 ELSE 0 END) AS with_prompt_hash "
        f"FROM enterprise_attestations ea {join} WHERE {where} {dept_filter}",
        params,
    ).fetchone()
    total = summary_row["total"] or 0
    reviewed = summary_row["reviewed"] or 0
    review_rate = (reviewed / total) if total else 0.0
    rubber_stamp = summary_row["rubber_stamps"] or 0

    # Median TTA via quantile (SQLite has no native MEDIAN — approximate)
    median_tta = None
    tta_rows = [r["tta"] for r in conn.execute(
        f"SELECT ea.tta FROM enterprise_attestations ea {join} WHERE {where} {dept_filter} AND ea.tta IS NOT NULL ORDER BY ea.tta",
        params,
    ).fetchall() if r["tta"] is not None]
    if tta_rows:
        mid = len(tta_rows) // 2
        median_tta = tta_rows[mid]

    # Policy violations by severity
    violations_by_sev = {k: 0 for k in ("critical", "high", "medium", "low")}
    for sev_row in conn.execute(
        f"SELECT pv.severity, COUNT(*) AS n "
        f"FROM policy_violations pv JOIN enterprise_attestations ea ON pv.attestation_id = ea.id "
        f"{join} WHERE {where} {dept_filter} GROUP BY pv.severity",
        params,
    ).fetchall():
        if sev_row["severity"] in violations_by_sev:
            violations_by_sev[sev_row["severity"]] = sev_row["n"]

    # Chain-break detection: receipts with parent_hash that isn't in registry
    chain_breaks_rows = conn.execute(
        f"SELECT COUNT(DISTINCT ea.doc_id) AS total_chains, "
        f"       COUNT(DISTINCT CASE WHEN ea.parent IS NOT NULL "
        f"              AND NOT EXISTS (SELECT 1 FROM enterprise_attestations ea2 "
        f"              WHERE ea2.hash = ea.parent AND ea2.org_id = ea.org_id) "
        f"              THEN ea.doc_id END) AS broken "
        f"FROM enterprise_attestations ea {join} WHERE {where} {dept_filter} AND ea.doc_id IS NOT NULL",
        params,
    ).fetchone()
    total_chains = chain_breaks_rows["total_chains"] or 0
    broken_chains = chain_breaks_rows["broken"] or 0
    complete_chains = max(0, total_chains - broken_chains)

    # By department (NULL-safe: "Unmapped")
    by_department = []
    for dept_row in conn.execute(
        f"SELECT IFNULL(om.department, 'Unmapped') AS dept, "
        f"       COUNT(*) AS total, COUNT(DISTINCT ea.uid_hash) AS unique_users, "
        f"       AVG(ea.tta) AS avg_tta, "
        f"       SUM(CASE WHEN ea.review_status IS NOT NULL THEN 1 ELSE 0 END) AS reviewed, "
        f"       SUM(CASE WHEN COALESCE(ea.tta,999)<10 AND COALESCE(ea.len,0)>500 THEN 1 ELSE 0 END) AS rubber, "
        f"       SUM(CASE WHEN ea.dest_ext = 1 THEN 1 ELSE 0 END) AS ext_exposure "
        f"FROM enterprise_attestations ea {join} WHERE {where} {dept_filter} "
        f"GROUP BY dept ORDER BY total DESC",
        params,
    ).fetchall():
        t = dept_row["total"] or 0
        r_rate = (dept_row["reviewed"] / t) if t else 0.0
        # violation counts per dept
        v_per_dept = {k: 0 for k in ("critical", "high", "medium", "low")}
        vp_params = {**params, "dept_name": dept_row["dept"]}
        for sev in conn.execute(
            f"SELECT pv.severity, COUNT(*) AS n "
            f"FROM policy_violations pv JOIN enterprise_attestations ea ON pv.attestation_id = ea.id "
            f"{join} WHERE {where} AND IFNULL(om.department, 'Unmapped') = :dept_name "
            f"GROUP BY pv.severity",
            vp_params,
        ).fetchall():
            if sev["severity"] in v_per_dept:
                v_per_dept[sev["severity"]] = sev["n"]
        by_department.append({
            "department": dept_row["dept"],
            "total": t,
            "unique_users": dept_row["unique_users"] or 0,
            "review_rate": round(r_rate, 3),
            "rubber_stamp_rate": round((dept_row["rubber"] / t) if t else 0.0, 4),
            "avg_tta": round(dept_row["avg_tta"], 1) if dept_row["avg_tta"] else None,
            "external_exposure": dept_row["ext_exposure"] or 0,
            "violations": v_per_dept,
            "grade": _grade_for(r_rate, v_per_dept["critical"]),
        })

    # By model
    by_model = [
        {"model": r["model"], "provider": r["provider"], "count": r["n"],
         "avg_tta": round(r["avg_tta"], 1) if r["avg_tta"] else None}
        for r in conn.execute(
            f"SELECT ea.model, ea.provider, COUNT(*) AS n, AVG(ea.tta) AS avg_tta "
            f"FROM enterprise_attestations ea {join} WHERE {where} {dept_filter} "
            f"GROUP BY ea.model, ea.provider ORDER BY n DESC",
            params,
        ).fetchall()
    ]

    # TTA distribution
    def _bucket(tta):
        if tta is None: return None
        if tta < 10: return "0-10s"
        if tta < 30: return "10-30s"
        if tta < 60: return "30-60s"
        if tta < 300: return "1-5m"
        if tta < 900: return "5-15m"
        return "15m+"

    tta_buckets = {"0-10s": 0, "10-30s": 0, "30-60s": 0, "1-5m": 0, "5-15m": 0, "15m+": 0}
    for t in tta_rows:
        key = _bucket(t)
        if key: tta_buckets[key] = tta_buckets.get(key, 0) + 1

    tta_distribution = {
        "buckets": [
            {"range": k, "count": v, "flagged": k == "0-10s"}
            for k, v in tta_buckets.items()
        ],
        "rubber_stamps": {
            "count": rubber_stamp,
            "threshold": {"tta_under": 10, "len_over": 500},
            "top_offenders": [dict(r) for r in conn.execute(
                f"SELECT ea.uid_hash, ea.uid_pseudonym, COUNT(*) AS count, IFNULL(om.department, 'Unmapped') AS department "
                f"FROM enterprise_attestations ea {join} WHERE {where} {dept_filter} "
                f"AND COALESCE(ea.tta,999) < 10 AND COALESCE(ea.len,0) > 500 "
                f"GROUP BY ea.uid_hash ORDER BY count DESC LIMIT 5",
                params,
            ).fetchall()],
        },
    }

    # Shadow AI heatmap (commercial-tier field)
    shadow_by_app = []
    for r in conn.execute(
        f"SELECT json_each.value AS app, COUNT(*) AS times_open, "
        f"       SUM(CASE WHEN ea.source_app LIKE '%' || json_each.value || '%' THEN 1 ELSE 0 END) AS times_used "
        f"FROM enterprise_attestations ea, json_each(IFNULL(ea.concurrent_ai_apps, '[]')) "
        f"{join} WHERE {where} {dept_filter} "
        f"GROUP BY json_each.value ORDER BY (times_open - times_used) DESC LIMIT 10",
        params,
    ).fetchall():
        t_open = r["times_open"] or 0
        t_used = r["times_used"] or 0
        shadow_by_app.append({
            "app": r["app"],
            "times_open": t_open,
            "times_attested_from": t_used,
            "shadow_ratio": round((t_open - t_used) / t_open, 3) if t_open else 0.0,
            "interpretation": ("open but not attesting — potential ungoverned use"
                               if t_open > t_used else "aligned"),
        })

    # AI authorship detection
    ai_by_source = [
        {"source": r["source"], "count": r["n"]}
        for r in conn.execute(
            f"SELECT json_extract(ea.ai_markers, '$.source') AS source, COUNT(*) AS n "
            f"FROM enterprise_attestations ea {join} WHERE {where} {dept_filter} "
            f"AND ea.ai_markers IS NOT NULL "
            f"GROUP BY source ORDER BY n DESC",
            params,
        ).fetchall() if r["source"]
    ]
    ai_unattested = conn.execute(
        f"SELECT COUNT(*) AS n FROM enterprise_attestations ea {join} "
        f"WHERE {where} {dept_filter} "
        f"AND ea.ai_markers IS NOT NULL AND ea.parent IS NULL",
        params,
    ).fetchone()["n"] or 0

    # Recent violations feed (last 20)
    recent_vios = [
        {**dict(r), "details": json.loads(r["details"] or "{}")}
        for r in conn.execute(
            f"SELECT pv.id, pv.attestation_id, pv.policy_id, pv.severity, "
            f"       pv.details, pv.detected_at, pv.resolved_at "
            f"FROM policy_violations pv JOIN enterprise_attestations ea ON pv.attestation_id = ea.id "
            f"{join} WHERE {where} {dept_filter} "
            f"ORDER BY pv.detected_at DESC LIMIT 20",
            params,
        ).fetchall()
    ]

    file_type_rows = [
        {"type": r["file_type"] or "unknown", "count": r["n"]}
        for r in conn.execute(
            f"SELECT ea.file_type, COUNT(*) AS n FROM enterprise_attestations ea {join} "
            f"WHERE {where} {dept_filter} GROUP BY ea.file_type ORDER BY n DESC",
            params,
        ).fetchall()
    ]
    conn.close()

    # Prompt-hash coverage as a rate (useful "chain of AI custody" KPI)
    prompt_cov = (summary_row["with_prompt_hash"] / total) if total else 0.0

    return {
        "meta": {
            "org_id": org_id,
            "org_name": org_row["name"],
            "date_range": {"from": from_, "to": to},
            "filters_applied": {"department": department, "model": model, "classification": classification},
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "schema_version": VERSION,
        },
        "summary": {
            "total_attestations": total,
            "unique_users": summary_row["unique_users"] or 0,
            "unique_sessions": summary_row["unique_sessions"] or 0,
            "review_rate": round(review_rate, 3),
            "rubber_stamp_count": rubber_stamp,
            "rubber_stamp_rate": round((rubber_stamp / total) if total else 0.0, 4),
            "external_exposure_count": summary_row["external_exposure"] or 0,
            "chain_break_count": broken_chains,
            "policy_violations": violations_by_sev,
            "avg_tta_seconds": round(summary_row["avg_tta"], 1) if summary_row["avg_tta"] else None,
            "median_tta_seconds": median_tta,
            "prompt_hash_coverage": round(prompt_cov, 3),
            "ai_authored_detected": summary_row["ai_authored"] or 0,
            "shadow_ai_alerts": sum(1 for s in shadow_by_app if s["shadow_ratio"] > 0.2),
        },
        "by_department": by_department,
        "by_model": by_model,
        "by_time": {"bucket_size": "week", "buckets": []},  # simplified; full time-series in Piece 11b
        "tta_distribution": tta_distribution,
        "file_types": file_type_rows,
        "external_exposure": {
            "total": summary_row["external_exposure"] or 0,
            "by_destination": [],
            "by_classification": [],
        },
        "chain_integrity": {
            "total_chains": total_chains,
            "complete_chains": complete_chains,
            "broken_chains": broken_chains,
            "breaks": [],
        },
        "recent_violations": recent_vios,
        "shadow_ai_heatmap": {
            "total_unique_apps_detected": len(shadow_by_app),
            "by_app": shadow_by_app,
            "by_department": [],
        },
        "ai_authorship": {
            "total_with_markers": summary_row["ai_authored"] or 0,
            "by_source": ai_by_source,
            "unattested_with_markers": {
                "count": ai_unattested,
                "interpretation": "AI-authored content appearing in chain without attestation",
            },
        },
    }


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

class ContentDiscoveryRequest(BaseModel):
    """Body for POST /v1/discover/content."""
    content_hash_canonical: str


@app.post("/v1/discover/content")
def discover_by_canonical(req: ContentDiscoveryRequest):
    """Cross-format chain discovery (Piece 14).

    Given a canonical-text hash (same for xlsx -> csv -> pdf of the
    same logical content), return every registered receipt that shares
    it. Enables "find every receipt whose content is equivalent to
    this file, regardless of format".

    The public registry stores only the hash and the receipt_id — no
    file-type, no uid, no model. The response explicitly nulls
    any format-identifying field. Enterprise customers with access to
    their own enterprise_attestations table can JOIN on receipt_id to
    get file_type and user context within their data.
    """
    if not _SHA256_RE.match(req.content_hash_canonical or ""):
        raise AIAuthError(
            "INVALID_HASH",
            "content_hash_canonical must be a 64-character SHA-256 hex string",
            400,
        )
    conn = get_registry()
    rows = conn.execute(
        "SELECT receipt_id, content_hash, registered_at "
        "FROM hash_registry WHERE content_hash_canonical = ? "
        "ORDER BY registered_at ASC",
        (req.content_hash_canonical,),
    ).fetchall()
    conn.close()
    return {
        "canonical_hash": req.content_hash_canonical,
        "found": len(rows) > 0,
        "receipt_count": len(rows),
        "receipts": [
            {"receipt_id": r["receipt_id"],
             "content_hash": r["content_hash"],
             "registered_at": r["registered_at"],
             "file_type": None}  # explicit null — registry is anonymous
            for r in rows
        ],
        "note": (f"{len(rows)} receipts share this canonical content. "
                 "Different byte representations (likely format conversions) of "
                 "the same logical document."),
    }


class SimilarImageRequest(BaseModel):
    phash: Optional[str] = None
    dhash: Optional[str] = None
    distance: int = 5
    org_id: str


def _hamming_distance_hex(a: str, b: str) -> int:
    """Hamming distance between two hex strings of equal length. Used
    for perceptual-hash similarity scoring."""
    if not a or not b or len(a) != len(b):
        return 10**9
    try:
        ai = int(a, 16); bi = int(b, 16)
    except ValueError:
        return 10**9
    return bin(ai ^ bi).count("1")


@app.get("/v1/discover/similar-image")
def discover_similar_image(
    phash: Optional[str] = Query(default=None),
    dhash: Optional[str] = Query(default=None),
    distance: int = Query(default=5, ge=0, le=32),
    org_id: str = Query(...),
    authorization: Optional[str] = Header(default=None),
):
    """Enterprise-only perceptual-hash similarity search (Piece 14).

    Admin-authenticated against a specific org. Scans the org's
    enterprise_attestations for receipts whose ai_markers.perceptual_hashes
    are within Hamming distance `distance` of the supplied phash/dhash.

    Used for cases like 'find every receipt whose image is a resized
    or watermarked copy of this one'. Not exposed in the public
    anonymous registry — perceptual hashes CAN sometimes identify an
    image without revealing its content, which is a privacy concern
    for free-tier users; limiting to enterprise admins makes the
    consent context explicit.
    """
    if not (phash or dhash):
        raise AIAuthError("INVALID_RECEIPT", "Must supply phash and/or dhash", 400)
    _require_admin_session(authorization, org_id)

    conn = get_db()
    rows = conn.execute(
        "SELECT id, ts, hash, ai_markers, file_type, doc_id "
        "FROM enterprise_attestations "
        "WHERE org_id = ? AND ai_markers IS NOT NULL",
        (org_id,),
    ).fetchall()
    conn.close()

    matches = []
    for r in rows:
        try:
            markers = json.loads(r["ai_markers"] or "{}")
        except Exception:
            continue
        ph = markers.get("perceptual_hashes") or {}
        if not isinstance(ph, dict):
            continue
        best = 10**9
        if phash and ph.get("phash"):
            best = min(best, _hamming_distance_hex(phash, ph["phash"]))
        if dhash and ph.get("dhash"):
            best = min(best, _hamming_distance_hex(dhash, ph["dhash"]))
        if best <= distance:
            matches.append({
                "id": r["id"], "ts": r["ts"], "hash": r["hash"],
                "file_type": r["file_type"], "doc_id": r["doc_id"],
                "similarity_distance": best,
            })

    return {"org_id": org_id, "matches": sorted(matches, key=lambda x: x["similarity_distance"]),
            "distance_threshold": distance, "note": "Lower distance = more similar; 0 = identical."}


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
    """Public homepage — wraps the index.html body fragment in the
    shared site chrome (_site_shell) for consistency with every other
    page. Piece B.2."""
    index_path = Path(__file__).parent / "index.html"
    if index_path.exists():
        body = index_path.read_text(encoding="utf-8")
        # Legacy index.html files (before Phase B) were self-contained
        # HTML documents. Detect + fall back to serving raw if so.
        if body.lstrip().startswith("<!DOCTYPE"):
            return HTMLResponse(body)
        return HTMLResponse(_site_shell(
            "Chain of Custody for AI-Generated Work",
            body,
            active="home",
            wide=True,
        ))
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
    """Public verification page — wraps the verify.html body fragment in
    the shared site chrome (_site_shell) for consistency. Phase B.3."""
    verify_path = Path(__file__).parent / "verify.html"
    if verify_path.exists():
        body = verify_path.read_text(encoding="utf-8")
        # Legacy pre-Phase-B verify.html was self-contained; serve raw.
        if body.lstrip().startswith("<!DOCTYPE"):
            return HTMLResponse(body)
        return HTMLResponse(_site_shell(
            "Verify a Receipt", body, active="check",
        ))
    return HTMLResponse("<h1>AIAuth</h1><p>Verification page not found.</p>", status_code=404)


@app.get("/demo", response_class=HTMLResponse)
def demo_dashboard():
    """Interactive commercial demo using synthetic data. Prospects can
    add ?company=... to personalize. Template is standalone (not
    wrapped in _site_shell) so it exports cleanly as a self-contained
    HTML artifact for prospect handoff."""
    tpl = Path(__file__).parent / "templates" / "commercial" / "executive-summary.html"
    if tpl.exists():
        return HTMLResponse(tpl.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>AIAuth Demo</h1><p>Demo template not found.</p>", status_code=404)


# ===================================================================
# DEDICATED SUBMISSION PAGES
#
# Each Pricing-section CTA on the homepage routes to a standalone page
# with its own form. Free → /waitlist, Team → /contact, Enterprise →
# /pilot. /pricing is a canonical page for the pricing tiers so it can
# be linked from primary navigation.
# ===================================================================

# Shared CSS for the four submission pages. Pulled out so the page
# handlers stay small.
_SUBMIT_PAGE_STYLE = """
<style>
.submit-wrap { max-width: 560px; }
.submit-form { display: flex; flex-direction: column; gap: 14px; margin-top: 24px; }
.submit-form label { display: flex; flex-direction: column; gap: 6px; font-size: 13px; font-weight: 600; color: var(--text); }
.submit-form input, .submit-form textarea, .submit-form select {
  padding: 11px 14px; font-size: 15px; border: 1px solid var(--border); border-radius: 10px;
  font-family: inherit; color: var(--text); background: #fff;
}
.submit-form input:focus, .submit-form textarea:focus, .submit-form select:focus {
  outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft);
}
.submit-form textarea { min-height: 110px; resize: vertical; }
.submit-form .row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.submit-form button {
  padding: 12px 18px; font-size: 15px; font-weight: 600;
  background: var(--accent); color: #fff; border: 0; border-radius: 10px; cursor: pointer;
}
.submit-form button:hover { background: #1d4ed8; }
.submit-form button:disabled { opacity: 0.6; cursor: not-allowed; }
.submit-success {
  display: none; padding: 14px 18px; background: #ecfdf5; border: 1px solid #10b981;
  border-radius: 10px; color: #065f46; font-size: 14px; margin-top: 14px;
}
.submit-error {
  display: none; padding: 14px 18px; background: #fef2f2; border: 1px solid #ef4444;
  border-radius: 10px; color: #991b1b; font-size: 14px; margin-top: 14px;
}
.submit-note { font-size: 13px; color: var(--muted); margin-top: 10px; line-height: 1.5; }
</style>
"""


def _submit_page_script(form_id: str, endpoint: str, fields: list, success_msg: str) -> str:
    """Build the fetch-and-render JS for a submission form.

    fields: list of (input_name, json_key, type) tuples. type is "int" for
    numeric fields, anything else is treated as string.
    """
    import json as _json
    fields_json = _json.dumps(fields)
    return f"""
<script>
(function() {{
  var form = document.getElementById({form_id!r});
  var ok   = document.getElementById({form_id!r} + '-ok');
  var err  = document.getElementById({form_id!r} + '-err');
  if (!form) return;
  form.addEventListener('submit', function(e) {{
    e.preventDefault();
    ok.style.display = 'none';
    err.style.display = 'none';
    var btn = form.querySelector('button[type="submit"]');
    var origTxt = btn ? btn.textContent : '';
    if (btn) {{ btn.disabled = true; btn.textContent = 'Sending...'; }}
    var payload = {{}};
    var fields = {fields_json};
    for (var i = 0; i < fields.length; i++) {{
      var f = fields[i];
      var el = form.elements[f[0]];
      if (!el) continue;
      var val = el.value;
      if (f[2] === 'int') {{
        var n = parseInt(val, 10);
        payload[f[1]] = isNaN(n) ? null : n;
      }} else if (val !== undefined && val !== '') {{
        payload[f[1]] = val;
      }}
    }}
    fetch({endpoint!r}, {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(payload)
    }}).then(function(r) {{
      return r.json().then(function(j) {{ return {{ status: r.status, body: j }}; }});
    }}).then(function(res) {{
      if (btn) {{ btn.disabled = false; btn.textContent = origTxt; }}
      if (res.status >= 200 && res.status < 300 && res.body && res.body.submitted) {{
        ok.textContent = (res.body.message || {success_msg!r});
        ok.style.display = 'block';
        form.reset();
      }} else {{
        var msg = (res.body && (res.body.detail || res.body.message)) || 'Something went wrong.';
        if (typeof msg === 'object' && msg.message) msg = msg.message;
        err.textContent = String(msg);
        err.style.display = 'block';
      }}
    }}).catch(function() {{
      if (btn) {{ btn.disabled = false; btn.textContent = origTxt; }}
      err.textContent = 'Network error. Please try again.';
      err.style.display = 'block';
    }});
  }});
}})();
</script>
"""


@app.get("/pricing", response_class=HTMLResponse)
def pricing_page():
    """Standalone pricing page. Mirrors the Pricing section of the
    homepage but gives it a canonical URL so it can live in the primary
    nav (rather than as an in-page anchor)."""
    body = """
<span class="eyebrow">Pricing</span>
<h1 class="page-title">Simple pricing. Free for individuals.</h1>
<p class="lead">Start free — no account, no card. Upgrade when your team needs shared verification, compliance dashboards, or self-hosted deployment.</p>

<div style="display:grid; grid-template-columns:repeat(3,1fr); gap:20px; margin-top:36px;">
  <div style="background:#fff; border:1px solid var(--border); border-radius:14px; padding:28px; display:flex; flex-direction:column;">
    <div style="font-size:13px; font-weight:700; text-transform:uppercase; letter-spacing:0.07em; color:var(--muted);">Free</div>
    <div style="font-size:36px; font-weight:800; letter-spacing:-0.02em; margin-top:8px;">$0</div>
    <div style="font-size:13px; color:var(--muted); margin-top:4px;">Individuals &amp; open use</div>
    <ul style="list-style:none; padding:0; margin:20px 0; flex:1; font-size:14px; line-height:1.65;">
      <li>Unlimited attestations</li>
      <li>Local receipt storage</li>
      <li>Public-key verification</li>
      <li>Right-click from any site</li>
    </ul>
    <a href="/waitlist" style="display:block; text-align:center; padding:11px 16px; border-radius:10px; font-size:14px; font-weight:600; border:1px solid var(--border); color:var(--text); text-decoration:none;">Join the Waitlist</a>
  </div>
  <div style="background:#fff; border:2px solid var(--accent); border-radius:14px; padding:28px; display:flex; flex-direction:column; position:relative;">
    <span style="position:absolute; top:-11px; left:20px; background:var(--accent); color:#fff; font-size:11px; font-weight:700; letter-spacing:0.06em; text-transform:uppercase; padding:4px 10px; border-radius:999px;">Most Popular</span>
    <div style="font-size:13px; font-weight:700; text-transform:uppercase; letter-spacing:0.07em; color:var(--muted);">Team</div>
    <div style="font-size:36px; font-weight:800; letter-spacing:-0.02em; margin-top:8px;">Contact</div>
    <div style="font-size:13px; color:var(--muted); margin-top:4px;">5 &ndash; 25 seats</div>
    <ul style="list-style:none; padding:0; margin:20px 0; flex:1; font-size:14px; line-height:1.65;">
      <li>Shared team verification</li>
      <li>Attestation &amp; review-rate dashboard</li>
      <li>AI-tool breakdown</li>
      <li>Priority email support</li>
    </ul>
    <a href="/contact?plan=team" style="display:block; text-align:center; padding:11px 16px; border-radius:10px; font-size:14px; font-weight:600; background:var(--accent); color:#fff; border:1px solid var(--accent); text-decoration:none;">Contact Sales</a>
  </div>
  <div style="background:#fff; border:1px solid var(--border); border-radius:14px; padding:28px; display:flex; flex-direction:column;">
    <div style="font-size:13px; font-weight:700; text-transform:uppercase; letter-spacing:0.07em; color:var(--muted);">Enterprise</div>
    <div style="font-size:36px; font-weight:800; letter-spacing:-0.02em; margin-top:8px;">Custom</div>
    <div style="font-size:13px; color:var(--muted); margin-top:4px;">Self-hosted · unlimited seats</div>
    <ul style="list-style:none; padding:0; margin:20px 0; flex:1; font-size:14px; line-height:1.65;">
      <li>Self-hosted signing server</li>
      <li>Full compliance dashboard</li>
      <li>Policy engine &amp; DSAR tooling</li>
      <li>Rubber-stamp detection</li>
      <li>SSO/LDAP roadmap</li>
      <li>Dedicated onboarding</li>
    </ul>
    <a href="/pilot" style="display:block; text-align:center; padding:11px 16px; border-radius:10px; font-size:14px; font-weight:600; border:1px solid var(--border); color:var(--text); text-decoration:none;">Request a Pilot</a>
  </div>
</div>

<p class="submit-note" style="margin-top:32px; max-width:640px;">All tiers share the same zero-knowledge architecture: content never leaves your device. Upgrades add team-level visibility and self-hosted control, not content access.</p>
"""
    return HTMLResponse(_site_shell("Pricing", body, active="pricing"))


@app.get("/waitlist", response_class=HTMLResponse)
def waitlist_page():
    """Standalone waitlist signup page. Posts to POST /v1/waitlist."""
    body = _SUBMIT_PAGE_STYLE + """
<div class="submit-wrap">
  <span class="eyebrow">Free Tier</span>
  <h1 class="page-title">Join the Waitlist</h1>
  <p class="lead">We'll email you the moment the free extension ships. No account, no card, no follow-up sales.</p>

  <form id="wl-form" class="submit-form" novalidate>
    <label>
      Email
      <input name="email" type="email" required autocomplete="email" placeholder="you@example.com">
    </label>
    <button type="submit">Join the Waitlist</button>
  </form>
  <div id="wl-form-ok"  class="submit-success"></div>
  <div id="wl-form-err" class="submit-error"></div>
  <p class="submit-note">We store a one-way hash of your email and an encrypted copy used only to send the launch announcement. No list sales, no tracking pixels. See <a href="/privacy">Privacy</a>.</p>
</div>
""" + _submit_page_script("wl-form", "/v1/waitlist",
                          [["email", "email", "str"]],
                          "You're on the list. We'll email when the extension ships.")
    return HTMLResponse(_site_shell("Join the Waitlist", body, active="pricing"))


@app.get("/pilot", response_class=HTMLResponse)
def pilot_page():
    """Standalone pilot-request page for the Enterprise tier. Posts to
    POST /v1/pilot/interest (existing endpoint)."""
    body = _SUBMIT_PAGE_STYLE + """
<div class="submit-wrap">
  <span class="eyebrow">Enterprise</span>
  <h1 class="page-title">Request a 30-Day Pilot</h1>
  <p class="lead">Deploy AIAuth to one department, measure attestation adoption and review rate, decide whether a full rollout is warranted. No cost for the pilot window.</p>

  <form id="pi-form" class="submit-form" novalidate>
    <label>
      Company
      <input name="company" type="text" required placeholder="Acme Corp">
    </label>
    <label>
      Work email
      <input name="admin_email" type="email" required autocomplete="email" placeholder="you@company.com">
    </label>
    <div class="row">
      <label>
        Approximate users
        <input name="user_count" type="number" min="1" placeholder="25">
      </label>
      <label>
        Industry
        <input name="industry" type="text" placeholder="Healthcare, Legal, ...">
      </label>
    </div>
    <button type="submit">Request a Pilot</button>
  </form>
  <div id="pi-form-ok"  class="submit-success"></div>
  <div id="pi-form-err" class="submit-error"></div>
  <p class="submit-note">Submissions route to sales@aiauth.app. We reply within one business day with deployment notes and a pilot checklist.</p>
</div>
""" + _submit_page_script("pi-form", "/v1/pilot/interest",
                          [["company", "company", "str"],
                           ["admin_email", "admin_email", "str"],
                           ["user_count", "user_count", "int"],
                           ["industry", "industry", "str"]],
                          "Thanks. We'll email you within 24 hours.")
    return HTMLResponse(_site_shell("Request a Pilot", body, active="pricing"))


@app.get("/contact", response_class=HTMLResponse)
def contact_page(plan: Optional[str] = Query(default=None)):
    """Standalone Contact Sales page for the Team pricing tier. Posts to
    POST /v1/contact. The ?plan=... query param pre-fills a hidden input
    so the inbound lead is tagged with its source tier."""
    plan_value = plan or "team"
    body = _SUBMIT_PAGE_STYLE + f"""
<div class="submit-wrap">
  <span class="eyebrow">Team Plan</span>
  <h1 class="page-title">Contact Sales</h1>
  <p class="lead">Tell us about your team and we'll put together a quote with pricing, onboarding steps, and a pilot timeline. One business day reply.</p>

  <form id="ct-form" class="submit-form" novalidate>
    <input type="hidden" name="plan" value="{plan_value}">
    <label>
      Company
      <input name="company" type="text" required placeholder="Acme Corp">
    </label>
    <label>
      Work email
      <input name="admin_email" type="email" required autocomplete="email" placeholder="you@company.com">
    </label>
    <label>
      Approximate team size
      <input name="user_count" type="number" min="1" placeholder="12">
    </label>
    <label>
      What are you trying to solve?
      <textarea name="message" placeholder="We're evaluating AI governance tools because..."></textarea>
    </label>
    <button type="submit">Contact Sales</button>
  </form>
  <div id="ct-form-ok"  class="submit-success"></div>
  <div id="ct-form-err" class="submit-error"></div>
  <p class="submit-note">Goes to sales@aiauth.app. We never share your email or resell contact data.</p>
</div>
""" + _submit_page_script("ct-form", "/v1/contact",
                          [["company", "company", "str"],
                           ["admin_email", "admin_email", "str"],
                           ["plan", "plan", "str"],
                           ["user_count", "user_count", "int"],
                           ["message", "message", "str"]],
                          "Thanks. We'll email you within one business day.")
    return HTMLResponse(_site_shell("Contact Sales", body, active="pricing"))


@app.get("/standards", response_class=HTMLResponse)
def standards_page():
    """Standards-alignment page. Positions AIAuth as complementary to
    C2PA (Content Credentials) rather than competitive, and documents
    the receipt fields that carry C2PA interop data today."""
    body = """
<span class="eyebrow">Standards</span>
<h1 class="page-title">Built alongside C2PA, not against it.</h1>
<p class="lead">C2PA (Content Credentials) proves what tool created a piece of media. AIAuth proves that a human reviewed it. The two are complementary layers of the same provenance stack — and an AIAuth receipt can carry C2PA manifest data directly.</p>

<div class="prose">
  <h2>The provenance stack</h2>
  <p>Every piece of AI-assisted output leaves two kinds of evidence worth preserving:</p>
  <table>
    <thead><tr><th>Layer</th><th>Question it answers</th><th>Standard</th></tr></thead>
    <tbody>
      <tr><td>Tool provenance</td><td><em>What tool created this file?</em></td><td>C2PA / Content Credentials</td></tr>
      <tr><td>Human attestation</td><td><em>Did a person review it before I got it?</em></td><td>AIAuth</td></tr>
    </tbody>
  </table>
  <p>C2PA is strong on images, video, and audio — formats where a manifest can be embedded into the file itself. It says less about text, spreadsheets, documents, and knowledge-work artifacts where the "tool that made it" is often a chain of prompts rather than a single generator. AIAuth fills that last mile.</p>

  <h2>How AIAuth interoperates with C2PA today</h2>
  <ol>
    <li><b>Read path.</b> When a client attests a file that carries a C2PA manifest, it surfaces the manifest identity in the receipt under <code>ai_markers.c2pa</code> (<a href="/public-key">public signing keys</a> · <a href="https://github.com/chasehfinch-cpu/AIAuth/blob/main/docs/RECEIPT_SPEC.md#321-ai_markersc2pa--c2pa--content-credentials-interop">receipt spec §3.2.1</a>). The attester's verifier can then walk both chains: the C2PA manifest back to the generating tool, and the AIAuth receipt forward to the human who signed off.</li>
    <li><b>Signal consolidation.</b> AIAuth already aggregates AI-authorship signals from multiple sources in a single receipt — Office docProps, PDF XMP metadata, ChatGPT export markers, and (when present) C2PA manifests. A verifier reads one receipt instead of four out-of-band metadata stores.</li>
    <li><b>Offline verification.</b> Receipts verify against an Ed25519 public key published at <a href="/.well-known/aiauth-public-key">/.well-known/aiauth-public-key</a>. No AIAuth server is required to check a receipt, which matches the "verify anywhere" ethos of the C2PA Trust Framework.</li>
  </ol>

  <h2>Roadmap: a C2PA assertion type for human review</h2>
  <p>The C2PA spec permits custom assertion types under a URI namespace. We intend to publish one:</p>
  <pre><code>Assertion label: "aiauth.app/human-review/v1"
Fields:
  reviewer_identity_hash  - HMAC(reviewer email)
  tta_seconds             - seconds between content arrival and attestation
  review_confirmed        - bool
  receipt_id              - parent AIAuth receipt id
  chain_parent            - prior receipt in the doc_id chain</code></pre>
  <p>With the assertion type in place, an AIAuth receipt can be embedded directly inside a Content Credentials manifest — a single artifact that carries tool provenance and human attestation together. Target: Q4 2026, contingent on the C2PA Conformance Program timeline.</p>

  <h2>More than you'd expect from a three-line JSON receipt</h2>
  <p>A few capabilities that are live today and rarely surface in category comparisons:</p>
  <ul>
    <li><b>Cross-format chain integrity.</b> A canonical text hash (<code>content_hash_canonical</code>) is computed by the client from the extractable text of xlsx / pdf / docx / csv sources. When the file is exported to a different format, the canonical hash still matches — the receipt survives format conversion. Useful when a reviewer attests a draft in Word and the final deliverable ships as PDF.</li>
    <li><b>Automatic chain formation.</b> Receipts with a matching <code>doc_id</code> or <code>parent</code> hash auto-link into a chain on verification — no separate chain store to manage.</li>
    <li><b>Time-to-attest rubber-stamp detection.</b> Receipts carry <code>tta</code> (seconds between content arrival and attestation). A receipt with <code>tta &lt; 10</code> on &gt;500 characters is flagged on the verification page — the honest signal that "someone pressed a button" without implying "someone read it."</li>
    <li><b>AI authorship signal consolidation.</b> Office docProps, PDF metadata, ChatGPT / Claude export markers, and C2PA manifests all land in a single <code>ai_markers</code> block the verifier can read in one pass.</li>
    <li><b>Zero-knowledge by default.</b> Hashes and metadata travel to the signing server; the content itself never does — making AIAuth compatible with environments where the underlying file cannot be exfiltrated (healthcare, legal, classified).</li>
    <li><b>Key-rotation survivability.</b> The full <a href="/v1/public-key">key manifest</a> publishes every current and retired signing key with validity windows, so a receipt signed under an old key still verifies years later.</li>
  </ul>

  <h2>Regulatory fit</h2>
  <p>AIAuth aligns with the EU AI Act Article 50 deployer-disclosure provisions (enforcement begins August 2026) by providing a verifiable record that AI was involved and a human reviewed it. For media assets, we recommend pairing AIAuth with a C2PA implementation rather than substituting for one — AIAuth does not watermark images or embed metadata into media files. This mapping is informational; consult qualified counsel for compliance advice specific to your organization.</p>
</div>
"""
    return HTMLResponse(_site_shell("Standards — C2PA & AIAuth", body, active="standards"))


@app.get("/terms", response_class=HTMLResponse)
def terms_page():
    """Public Terms of Service page. Matches the honest-reality framing
    of the privacy policy: no SLA on the free tier, indefinite hash-
    registry retention, content rights stay with the user."""
    body = """
<span class="eyebrow">Terms of Service</span>
<h1 class="page-title">Terms of Service</h1>
<p class="lead">Last updated: 2026-04-24. These terms govern your use of the AIAuth free tier at aiauth.app. Enterprise self-hosted deployments are governed by the terms in their executed license agreement, which supersede these.</p>

<div class="prose">
  <h2>1. Service as-is</h2>
  <p>The free tier of AIAuth is provided without warranty of any kind. There is no service-level agreement (SLA), no uptime guarantee, and no promise that the signing server will remain available indefinitely. If the free service becomes unavailable, receipts already issued remain cryptographically verifiable offline against the public key published at <a href="/.well-known/aiauth-public-key">/.well-known/aiauth-public-key</a>.</p>

  <h2>2. Limitation of liability</h2>
  <p>To the maximum extent permitted by law, Finch Business Services LLC is not liable for any direct, indirect, incidental, consequential, or special damages arising from use of the free tier, including but not limited to loss of data, loss of business, or loss of reputation. The free tier is not a substitute for independent legal, compliance, or evidentiary counsel.</p>

  <h2>3. Data retention</h2>
  <p>Hash registry entries (content hash, receipt id, parent hash, doc id, registration timestamp) are retained indefinitely so that chain discovery continues to work for receipts issued at any time in the past. No content, no user identifiers, and no behavioral metadata are stored alongside those entries. If the free service is ever planned to be shut down, 90 days of notice will be posted on <a href="/">aiauth.app</a> and the last known public key and hash registry will be archived to a public location (GitHub release or IPFS) before takedown.</p>

  <h2>4. Intellectual property</h2>
  <p>You retain all rights to the content you attest with AIAuth. Finch Business Services LLC claims no rights to your content, your receipts, or any metadata on your receipts. The AIAuth source code, receipt format specification, and protocol are licensed under Apache 2.0 (core) and BUSL 1.1 (self-hosted deployment bundle); see the <a href="https://github.com/chasehfinch-cpu/AIAuth/blob/main/LICENSE">LICENSE</a> file.</p>

  <h2>5. Acceptable use</h2>
  <p>You agree not to:</p>
  <ul>
    <li>Use the signing server for mass automated attestation beyond the documented rate limits (100 requests/minute per IP, 1,000 requests/hour per IP on <code>/v1/sign</code>).</li>
    <li>Attempt to interfere with the signing server, its rate limits, or its availability for other users.</li>
    <li>Use AIAuth receipts to misrepresent human review — for example, attesting content without actually reviewing it, or attesting content authored by another person as your own review.</li>
    <li>Use AIAuth in a context where a qualified attorney has advised that receipts alone would not meet your evidentiary or regulatory requirements.</li>
  </ul>

  <h2>6. No PHI / no regulated content on the free tier</h2>
  <p>The free tier is intended for general-purpose use. Do not use the free tier to attest protected health information (PHI), classified government data, or any content subject to HIPAA, ITAR, or similar strict regulation. For regulated use, deploy the self-hosted enterprise build on infrastructure you control.</p>

  <h2>7. Modification of terms</h2>
  <p>Material changes to these terms will be announced on <a href="/">aiauth.app</a> with at least 30 days of notice. Continued use of the service after the notice period constitutes acceptance. These terms will be versioned with a dated header above — the <code>Last updated</code> line reflects the most recent effective date.</p>

  <h2>8. Governing law</h2>
  <p>These terms are governed by the laws of the Commonwealth of Virginia, United States, without regard to conflict-of-law rules. Any dispute that cannot be resolved informally will be brought in the state or federal courts of the Commonwealth of Virginia.</p>

  <h2>9. Contact</h2>
  <p>Questions about these terms: <a href="mailto:legal@aiauth.app">legal@aiauth.app</a>. Security reports: see <a href="https://github.com/chasehfinch-cpu/AIAuth/blob/main/SECURITY.md">SECURITY.md</a>. General contact: <a href="mailto:sales@aiauth.app">sales@aiauth.app</a>.</p>
</div>
"""
    return HTMLResponse(_site_shell("Terms of Service", body, active=""))


@app.get("/security", response_class=HTMLResponse)
def security_page():
    """Public Security & Trust page. Documents signing key custody,
    rotation, continuity, and bus-factor risk. Content lifts from the
    enterprise admin guide so free-tier users get the same transparency."""
    body = """
<span class="eyebrow">Security &amp; Trust</span>
<h1 class="page-title">Where the keys live and what happens if we disappear.</h1>
<p class="lead">An attestation receipt is only as trustworthy as the key that signed it. This page documents how AIAuth's signing keys are managed, rotated, backed up, and how the system continues to function if Finch Business Services LLC ever ceases to operate.</p>

<div class="prose">
  <h2>Signing key infrastructure</h2>
  <ul>
    <li><b>Algorithm.</b> Ed25519 (RFC 8032). Chosen because the public key (32 bytes) and signature (64 bytes) are small enough to embed in a receipt without hurting portability, verification is fast enough to run in a browser, and no side-channel attacks of concern are known against constant-time implementations.</li>
    <li><b>Generation.</b> Keys are generated on the signing server using <code>cryptography.hazmat.primitives.asymmetric.ed25519</code> — the Python <code>cryptography</code> package's bindings to <code>libsodium</code>.</li>
    <li><b>Storage.</b> The active private key lives in an encrypted volume attached to the signing host. The volume is unlocked at boot from a passphrase stored only in operator memory. The key file itself is <code>0600</code>, owned by a non-login service user.</li>
    <li><b>Backup.</b> The active private key is mirrored to an offline encrypted backup held by the operator. No cloud KMS or HSM is used for the free tier (enterprise self-hosted deployments can use their own HSM or cloud KMS).</li>
    <li><b>Public-key publication.</b> The current and all retired public keys are published at <a href="/v1/public-key"><code>/v1/public-key</code></a> and at the well-known discovery location <a href="/.well-known/aiauth-public-key"><code>/.well-known/aiauth-public-key</code></a>.</li>
  </ul>

  <h2>Key rotation</h2>
  <ul>
    <li>Scheduled annually (every 365 days) or immediately on any suspected compromise.</li>
    <li>The prior key is retired with <code>valid_until</code> set to the rotation timestamp; receipts signed under the retired key continue to verify indefinitely using that key's entry in the key manifest.</li>
    <li>The rotation event is documented in the key manifest's <code>updated_at</code> field, visible at <a href="/v1/public-key"><code>/v1/public-key</code></a>.</li>
    <li>The full rotation procedure is documented in <a href="https://github.com/chasehfinch-cpu/AIAuth/blob/main/docs/ENTERPRISE_ADMIN_GUIDE.md">docs/ENTERPRISE_ADMIN_GUIDE.md</a>. It is reproducible by any self-hosted customer on their own infrastructure.</li>
  </ul>

  <h2>Key manifest versioning</h2>
  <p>The public key endpoint returns a manifest containing every key AIAuth has ever used, each with a validity window:</p>
  <pre><code>{
  "keys": [
    { "key_id": "key_001", "algorithm": "Ed25519",
      "public_key_pem": "...", "status": "active",
      "valid_from": "2026-04-01T00:00:00Z",
      "valid_until": null, "current_signing_key": true },
    { "key_id": "key_000", "algorithm": "Ed25519",
      "public_key_pem": "...", "status": "retired",
      "valid_from": "2025-04-01T00:00:00Z",
      "valid_until": "2026-04-01T00:00:00Z",
      "current_signing_key": false }
  ],
  "manifest_version": 1,
  "updated_at": "2026-04-01T00:00:00Z"
}</code></pre>
  <p>When verifying a receipt, select the key whose <code>key_id</code> matches the receipt's <code>key_id</code> field. If the receipt has no <code>key_id</code> (legacy), fall back to trying each key in the manifest.</p>

  <h2>Continuity and bus-factor</h2>
  <p>AIAuth is intentionally designed so that the signing server is not a single point of failure for verification. If the signing server goes offline — permanently — receipts remain verifiable forever, provided the public key is available:</p>
  <ul>
    <li><b>Public key survivability.</b> The current and all retired public keys are published on GitHub alongside the source code. Any copy of the repo (including the Wayback Machine and any forks) preserves them.</li>
    <li><b>Stateless verification.</b> Receipt verification requires only the receipt, the public key matching the receipt's <code>key_id</code>, and an Ed25519 library. It does not require the AIAuth server to be reachable.</li>
    <li><b>Open-source client.</b> The Chrome extension and receipt format are open-source at <a href="https://github.com/chasehfinch-cpu/AIAuth">github.com/chasehfinch-cpu/AIAuth</a> under Apache 2.0. A fork can continue to build and publish the extension if we cannot.</li>
    <li><b>Self-hosted deployments are customer-owned.</b> Enterprise customers run AIAuth on their own infrastructure with their own keys. Nothing about an enterprise deployment depends on Finch Business Services LLC continuing to exist.</li>
    <li><b>90-day shutdown notice.</b> Per the <a href="/terms">Terms of Service</a>, any planned permanent shutdown of the free tier is announced at least 90 days in advance, and a final archive of the public key and hash registry is published before takedown.</li>
  </ul>

  <h2>Reporting a vulnerability</h2>
  <p>Responsible disclosure process, affected component categories, and contact addresses are documented in <a href="https://github.com/chasehfinch-cpu/AIAuth/blob/main/SECURITY.md">SECURITY.md</a>. We do not currently offer a bug bounty; we acknowledge reporters in the security advisory when a fix ships.</p>

  <h2>Where we aren't yet</h2>
  <p>Transparency about what we don't yet have:</p>
  <ul>
    <li>No formal SOC 2 audit report. A control-crosswalk document is on <a href="/compliance">/compliance</a> for reference.</li>
    <li>No third-party penetration test (a scoped engagement is on the roadmap).</li>
    <li>No bug bounty program (we treat vulnerability reports via the SECURITY.md channel seriously regardless).</li>
    <li>No HSM for the free-tier signing key (self-hosted enterprise customers can and do use HSMs for their own keys).</li>
  </ul>
</div>
"""
    return HTMLResponse(_site_shell("Security & Trust", body, active="security"))


@app.get("/compliance", response_class=HTMLResponse)
def compliance_page():
    """Public compliance / regulatory alignment page. Covers EU AI Act
    Article 50 (enforcement 2026-08-02) and a lightweight crosswalk to
    SOC 2, ISO 27001, and NIST AI RMF — informational, not legal advice."""
    body = """
<span class="eyebrow">Compliance</span>
<h1 class="page-title">Where AIAuth fits in your compliance stack.</h1>
<p class="lead">This page maps AIAuth's capabilities to the regulatory and control frameworks most often referenced in enterprise procurement — EU AI Act Article 50, SOC 2, ISO 27001, and the NIST AI Risk Management Framework. It is informational. Consult qualified counsel for advice specific to your organization.</p>

<div class="prose">
  <h2>EU AI Act — Article 50 (deployer disclosure)</h2>
  <p>Enforcement begins <b>2 August 2026</b>. Article 50 requires deployers of AI systems to disclose that content was generated or materially modified by an AI system and to mark such content in a machine-readable format.</p>
  <table>
    <thead><tr><th>Article 50 requirement</th><th>How AIAuth addresses it</th></tr></thead>
    <tbody>
      <tr>
        <td><b>50(2)</b> — Deployer discloses AI involvement to recipients.</td>
        <td>AIAuth receipts record that AI was involved (<code>model</code>, <code>provider</code>, <code>ai_markers</code>) and that a human reviewed the output. A receipt code attached to a deliverable serves as a verifiable disclosure mechanism.</td>
      </tr>
      <tr>
        <td><b>50(4)</b> — Machine-readable marking of AI-generated content.</td>
        <td>AIAuth receipts are JSON with stable field names; the <code>ai_markers</code> block identifies AI authorship signals in a parsable form. For media assets (image, video, audio) we recommend pairing AIAuth with a C2PA implementation — <a href="/standards">see the standards page</a>.</td>
      </tr>
      <tr>
        <td><b>50(5)</b> — Information provided in a clear and distinguishable manner, at latest at first interaction.</td>
        <td>Receipt codes can be attached to an email subject line, document footer, PR description, or message body. The verification page at <a href="/check">aiauth.app/check</a> is publicly accessible without an account.</td>
      </tr>
    </tbody>
  </table>

  <h3>What AIAuth does NOT address in Article 50</h3>
  <ul>
    <li>AIAuth does not perform watermarking of media files. For synthetic image/video/audio, use a C2PA-compatible tool and preserve the Content Credentials.</li>
    <li>AIAuth does not embed metadata inside media files — receipts live alongside the content as an external record.</li>
    <li>AIAuth does not perform AI-content detection. It is a voluntary attestation mechanism, not a forensic classifier.</li>
  </ul>

  <h2>SOC 2 Trust Service Criteria — control crosswalk</h2>
  <p>For enterprises evaluating AIAuth as part of a SOC 2-scoped environment, the self-hosted enterprise deployment supports the following controls:</p>
  <ul>
    <li><b>CC6.1 — Logical access.</b> Magic-link authentication with short-lived session tokens; admin endpoints gated behind a master key; managed-policy schema for Workspace/Intune provisioning.</li>
    <li><b>CC7.2 — System monitoring.</b> All attestation events are logged with attestation id, timestamp, and signing key id. The admin dashboard aggregates events; operator email alerts are available.</li>
    <li><b>CC8.1 — Change management.</b> Source is version-controlled on GitHub; releases are tagged and published; the signing key manifest versions every rotation.</li>
    <li><b>CC9.2 — Vendor / third-party.</b> Self-hosted enterprise runs on customer infrastructure; no third-party processor handles attested content.</li>
  </ul>

  <h2>ISO/IEC 27001 Annex A — control mapping</h2>
  <ul>
    <li><b>A.8.1 — Asset management.</b> Attested content is hashed, never stored. The hash registry is a single-purpose data asset with documented retention.</li>
    <li><b>A.12.4 — Logging and monitoring.</b> Per-attestation logs with cryptographic linkage via chain-of-custody parent hashes.</li>
    <li><b>A.14.1 — Security in development.</b> Apache 2.0 source; reproducible builds for the Chrome extension.</li>
    <li><b>A.18.1 — Compliance with legal / contractual requirements.</b> Data-handling terms codified in the <a href="/privacy">Privacy Policy</a> and <a href="/terms">Terms of Service</a>.</li>
  </ul>

  <h2>NIST AI Risk Management Framework</h2>
  <ul>
    <li><b>GOVERN-1.1</b> — AIAuth provides a verifiable record of human review, supporting organizational policies that require a human in the loop for AI-assisted output.</li>
    <li><b>MAP-1.1</b> — Receipts aggregate AI-authorship signals (<code>model</code>, <code>provider</code>, <code>source_domain</code>, <code>ai_markers</code>) for context identification.</li>
    <li><b>MEASURE-2.6</b> — Time-to-attest (<code>tta</code>) is a proxy metric for review quality; the enterprise dashboard surfaces rubber-stamp detection.</li>
    <li><b>MANAGE-2.3</b> — Chain of custody (<code>parent</code>, <code>doc_id</code>) supports incident review and rollback.</li>
  </ul>

  <h2>Scope of applicability</h2>
  <p>This mapping is informational and is not a substitute for a SOC 2 audit, ISO 27001 certification, or NIST AI RMF implementation. We are not yet SOC 2 audited; the crosswalk is provided so your compliance team can evaluate where AIAuth fits within your own control environment. For the self-hosted enterprise tier, we can provide architecture diagrams and control-evidence artifacts under NDA — contact <a href="mailto:sales@aiauth.app">sales@aiauth.app</a>.</p>

  <h2>References</h2>
  <ul>
    <li><a href="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1689" target="_blank" rel="noopener">EU AI Act (Regulation 2024/1689)</a></li>
    <li><a href="https://www.c2pa.org/specifications/specifications/2.1/index.html" target="_blank" rel="noopener">C2PA Specification 2.1</a></li>
    <li><a href="https://www.nist.gov/itl/ai-risk-management-framework" target="_blank" rel="noopener">NIST AI RMF 1.0</a></li>
    <li><a href="https://www.aicpa.org/resources/landing/soc-for-service-organizations" target="_blank" rel="noopener">AICPA SOC 2 Trust Services Criteria</a></li>
  </ul>
</div>
"""
    return HTMLResponse(_site_shell("Compliance", body, active="compliance"))


@app.get("/admin/license/issue", response_class=HTMLResponse)
def admin_license_issuer_page(master_key: Optional[str] = Query(default=None)):
    """License issuer admin page (Phase C.2).

    Gated behind AIAUTH_MASTER_KEY. This is the sales-side tool used
    to issue signed license keys to new enterprise customers. Not
    linked from any public nav; reached by explicit URL with master_key
    query param.
    """
    if not MASTER_KEY or master_key != MASTER_KEY:
        return HTMLResponse(_site_shell(
            "Not Found", "<h1 class='page-title'>Not Found</h1>"
            "<p class='lead'>This page requires administrative access.</p>",
            active=""), status_code=404)

    body = """<span class="eyebrow">Admin: License Issuer</span>
<h1 class="page-title">Issue Enterprise License</h1>
<p class="lead">Generate a signed license key for a new customer. Key is validated offline against this server's signing key; no phone-home required.</p>

<div class="card">
  <form id="issueForm" style="display:grid;gap:12px;">
    <label>
      <div style="font-size:12px;color:#64748b;margin-bottom:4px;">Company name</div>
      <input name="company" required style="width:100%;padding:10px;border:1px solid #e5e7eb;border-radius:8px;font:inherit;" placeholder="Acme Corp" />
    </label>
    <label>
      <div style="font-size:12px;color:#64748b;margin-bottom:4px;">Tier</div>
      <select name="tier" style="width:100%;padding:10px;border:1px solid #e5e7eb;border-radius:8px;font:inherit;">
        <option value="enterprise">enterprise (self-hosted)</option>
        <option value="compliance">compliance (self-hosted + policy engine + DSAR)</option>
      </select>
    </label>
    <label>
      <div style="font-size:12px;color:#64748b;margin-bottom:4px;">Max users (0 = unlimited)</div>
      <input type="number" name="max_users" value="0" min="0" style="width:100%;padding:10px;border:1px solid #e5e7eb;border-radius:8px;font:inherit;" />
    </label>
    <label>
      <div style="font-size:12px;color:#64748b;margin-bottom:4px;">Expires (ISO date, blank = never)</div>
      <input type="date" name="expires" style="width:100%;padding:10px;border:1px solid #e5e7eb;border-radius:8px;font:inherit;" />
    </label>
    <button type="submit" style="padding:12px;background:var(--accent);color:white;border:0;border-radius:8px;font:inherit;font-weight:600;cursor:pointer;">Generate License Key</button>
  </form>
  <pre id="result" style="display:none;margin-top:20px;padding:16px;background:#0b1220;color:#e6edf6;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;line-height:1.5;"></pre>
  <div id="copyRow" style="display:none;margin-top:10px;">
    <button id="copyBtn" class="copy-btn" type="button">Copy License Key</button>
  </div>
</div>

<script>
(function(){
  const urlKey = new URLSearchParams(location.search).get('master_key');
  document.getElementById('issueForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const payload = {
      company: fd.get('company'),
      tier: fd.get('tier'),
      max_users: Number(fd.get('max_users') || 0),
      expires: fd.get('expires') ? fd.get('expires') + 'T23:59:59+00:00' : '',
      master_key: urlKey,
    };
    const res = await fetch('/v1/admin/license/generate', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    const pre = document.getElementById('result');
    pre.style.display = 'block';
    if (res.ok) {
      pre.textContent = data.license_key;
      document.getElementById('copyRow').style.display = 'block';
      document.getElementById('copyBtn').onclick = () => navigator.clipboard.writeText(data.license_key);
    } else {
      pre.textContent = 'Error: ' + JSON.stringify(data, null, 2);
    }
  });
})();
</script>
"""
    return HTMLResponse(_site_shell("Issue License", body, active=""))


@app.get("/enterprise-guide", response_class=HTMLResponse)
def enterprise_guide():
    """Two-part enterprise documentation: Admin Guide | User Guide (Phase B.11).
    Tabbed navigation wrapped in _site_shell. Markdown rendered via `markdown` lib."""
    admin_path = Path(__file__).parent / "docs" / "ENTERPRISE_ADMIN_GUIDE.md"
    user_path  = Path(__file__).parent / "docs" / "ENTERPRISE_USER_GUIDE.md"

    try:
        import markdown as _md
    except ImportError:
        return HTMLResponse(_site_shell(
            "Enterprise Guide",
            "<h1 class='page-title'>Enterprise Guide</h1>"
            "<p class='lead'>The markdown renderer isn't installed on this server. "
            "Install the <code>markdown</code> package.</p>",
            active="enterprise"))

    def render_md(path: Path) -> str:
        if not path.exists():
            return "<p>Guide not deployed yet.</p>"
        txt = path.read_text(encoding="utf-8")
        return _md.markdown(
            txt,
            extensions=["fenced_code", "tables", "sane_lists", "toc"],
        )

    admin_html = render_md(admin_path)
    user_html  = render_md(user_path)

    body = f"""<span class="eyebrow">Enterprise Documentation</span>
<h1 class="page-title">Enterprise Guide</h1>
<p class="lead">Deployment, operation, and end-user documentation for AIAuth Enterprise (self-hosted).</p>

<div style="margin-top:24px; border-bottom:1px solid var(--border);">
  <button id="tab-admin" class="eg-tab eg-active" onclick="pickTab('admin')">Admin Guide</button>
  <button id="tab-user"  class="eg-tab" onclick="pickTab('user')">User Guide</button>
</div>

<style>
  .eg-tab {{ background: transparent; border: none; padding: 10px 18px; font-family: inherit; font-size: 14px;
             font-weight: 600; color: var(--muted); cursor: pointer; border-bottom: 2px solid transparent;
             margin-bottom: -1px; }}
  .eg-tab:hover {{ color: var(--text); }}
  .eg-active {{ color: var(--accent) !important; border-bottom-color: var(--accent) !important; }}
  .eg-pane {{ display: none; }}
  .eg-pane.eg-on {{ display: block; }}
</style>

<div id="pane-admin" class="prose eg-pane eg-on">{admin_html}</div>
<div id="pane-user"  class="prose eg-pane">{user_html}</div>

<script>
  function pickTab(which) {{
    document.getElementById('tab-admin').classList.toggle('eg-active', which === 'admin');
    document.getElementById('tab-user').classList.toggle('eg-active', which === 'user');
    document.getElementById('pane-admin').classList.toggle('eg-on', which === 'admin');
    document.getElementById('pane-user').classList.toggle('eg-on', which === 'user');
    if (history.replaceState) history.replaceState(null, '', '?' + which);
  }}
  // Deep link: /enterprise-guide?user or ?admin
  if (location.search.indexOf('user') !== -1) pickTab('user');
</script>
"""
    return HTMLResponse(_site_shell("Enterprise Guide", body, active="enterprise", wide=True))


@app.get("/samples/compliance-report", response_class=HTMLResponse)
def samples_compliance_report():
    """Audit-ready compliance report (Phase B.6). Standalone HTML with
    @media print styles for PDF export. Synthetic data by default;
    switches to live via ?source=live&org_id=...&session=..."""
    tpl = Path(__file__).parent / "templates" / "commercial" / "compliance-report.html"
    if tpl.exists():
        return HTMLResponse(tpl.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Compliance Report</h1><p>Template not deployed.</p>", status_code=404)


@app.get("/static/synthetic-data.js")
def static_synthetic_data_js():
    """Served alongside /demo so the template's <script src="synthetic-data.js"></script>
    resolves (the template references it relative to its own path)."""
    p = Path(__file__).parent / "templates" / "commercial" / "synthetic-data.js"
    if p.exists():
        return FileResponse(str(p), media_type="application/javascript")
    raise AIAuthError("NOT_FOUND", "synthetic-data.js not deployed", 404)


@app.get("/synthetic-data.js")
def synthetic_data_js_at_root():
    """Alias so the template's relative <script src="synthetic-data.js"> works
    when served via the HTMLResponse path (the request comes back to the
    server root, not to templates/commercial/)."""
    return static_synthetic_data_js()


@app.get("/v1/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard_html():
    """Enterprise compliance dashboard entry point. Renders the
    executive-summary template. Future versions will swap in a richer
    SPA; the data contract remains stable so the template works today."""
    tpl = Path(__file__).parent / "templates" / "commercial" / "executive-summary.html"
    if tpl.exists():
        return HTMLResponse(tpl.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Dashboard</h1><p>Template not deployed.</p>", status_code=404)

def _site_shell(title: str, body_html: str, active: str = "", wide: bool = False) -> str:
    """Shared site chrome — single source of nav + footer for every
    public page. Title Case throughout. Piece B.1.

    Args:
      title: inner <title> (gets " — AIAuth" suffix)
      body_html: page content (already-formed HTML)
      active: which nav item to highlight ("home" | "how" | "business" |
              "guide" | "check" | "enterprise" | "")
      wide: use wider content container (for dashboards, tables)
    """
    def active_cls(key): return ' style="color:var(--text)"' if active == key else ""
    inner_class = "container-wide" if wide else "container"
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
.nav-cta-outline {{ border:1px solid var(--border); color:var(--text) !important; padding:7px 12px; border-radius:8px; font-weight:600; }}
.nav-cta-outline:hover {{ text-decoration:none; border-color:var(--accent); color:var(--accent) !important; }}
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
@media (max-width:760px) {{ .nav-links a:not(.nav-cta):not(.brand) {{ display:none; }} }}
</style>
</head><body>
<nav class="nav"><div class="container-wide nav-inner">
  <a class="brand" href="/"><img src="/logo.png" alt="AIAuth"><span>AIAuth</span></a>
  <div class="nav-links">
    <a href="/#how-it-works"{active_cls('how')}>How It Works</a>
    <a href="/pricing"{active_cls('pricing')}>Pricing</a>
    <a href="/standards"{active_cls('standards')}>Standards</a>
    <a href="/#business"{active_cls('business')}>For Business</a>
    <a href="/guide"{active_cls('guide')}>User Guide</a>
    <a class="nav-cta-outline" href="/check"{active_cls('check')}>Verify a Receipt</a>
  </div>
</div></nav>
<main class="page"><div class="{inner_class}">
{body_html}
</div></main>
<footer><div class="container-wide foot-inner">
  <div>&copy; 2026 Finch Business Services LLC · AIAuth</div>
  <div>
    <a href="/privacy">Privacy</a>
    <a href="/terms">Terms</a>
    <a href="/security">Security</a>
    <a href="/compliance">Compliance</a>
    <a href="/public-key">Public Key</a>
    <a href="/enterprise-guide">Enterprise Guide</a>
    <a href="https://github.com/chasehfinch-cpu/AIAuth" target="_blank" rel="noopener">GitHub</a>
  </div>
</div></footer>
</body></html>"""


# Backward-compat alias so older route handlers continue to work while
# Phase B rewrites happen incrementally.
def _page_shell(title: str, body_html: str, active: str = "") -> str:
    return _site_shell(title, body_html, active=active)


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
    body = """<span class="eyebrow">Privacy Policy</span>
<h1 class="page-title">Privacy Policy</h1>
<p class="lead">Your content never leaves your device. We store hashes and ciphertext, not emails or files. If our server is compromised, an attacker should get nothing useful.</p>

<div class="prose">
<p style="color:var(--muted);font-size:13px">Last updated: April 22, 2026 · Operator: Finch Business Services LLC</p>

<h2>What AIAuth Does</h2>
<p>AIAuth creates tamper-proof receipts for AI-generated work. You interact with it through the Chrome extension, a desktop agent, or direct API calls. The free tier is anonymous by design; the Enterprise tier is self-hosted and runs on your own infrastructure.</p>

<h2>What We Store on the Free Tier</h2>

<h3>1. The anonymous hash registry</h3>
<p>Every attested content hash gets a row in a six-column registry:</p>
<ul>
  <li><code>content_hash</code> — SHA-256 of your content (one-way; cannot be reversed)</li>
  <li><code>receipt_id</code> — a random UUID</li>
  <li><code>parent_hash</code> — the previous version's hash, for chain discovery</li>
  <li><code>doc_id</code> — persistent document identifier</li>
  <li><code>content_hash_canonical</code> — SHA-256 of the canonical text (enables cross-format chain: xlsx → csv → pdf)</li>
  <li><code>registered_at</code> — timestamp</li>
</ul>
<p>No email. No name. No content. No IP address. Nothing here identifies a person.</p>

<h3>2. Email address and account_id — ONLY if you create an account</h3>
<p>Creating an account is optional. You can use AIAuth without one — the Chrome extension's "Start Attesting" button enables attestation immediately. An account is only needed if you want to link email addresses across devices, verify your identity for cross-person chain-of-custody use cases, or manage consent for enterprise deployments.</p>
<p>When you create an account, we store:</p>
<ul>
  <li>An HMAC hash of your email (never the plaintext)</li>
  <li>An account identifier</li>
  <li>Timestamps (created, updated, verified)</li>
  <li>A separate "domain" field (e.g. <code>acme.com</code>) for enterprise-domain matching</li>
</ul>
<p>We cannot enumerate who is registered — the hash is salted with a server secret. The only way your email is linked to your account in our database is through the one-way hash.</p>

<h3>3. Authentication ephemera</h3>
<p>For magic-link logins we store single-use nonces (to prevent token replay) and revoked session IDs (for logout). Both are auto-pruned. No long-lived identifiers.</p>

<h2>What We Never Store on the Free Tier</h2>
<ul>
  <li><strong>Your content.</strong> Only a SHA-256 hash is sent, and hashes are one-way.</li>
  <li><strong>Plaintext emails.</strong> We hash with HMAC-SHA256 before writing to disk. Our own database dumps show 64-character hashes, not email addresses.</li>
  <li><strong>Receipt contents.</strong> The full signed receipt is returned to your device; we sign and forget.</li>
  <li><strong>Behavioral metadata.</strong> Time-to-attest, destinations, classifications, concurrent AI apps — none of these are captured on the free tier. (Enterprise customers opt in to these for their own dashboards, on their own servers.)</li>
  <li><strong>Prompt text.</strong> If you attest AI output and we detect the prompt that produced it, only its one-way hash is recorded. We never see the prompt.</li>
</ul>

<h2>Data Hardening</h2>
<p>If someone breaks into our server, they should get as little as possible. Concretely:</p>
<ul>
  <li>Email addresses are stored as HMAC hashes, salted with a server secret.</li>
  <li>Enterprise-tier user identifiers (<code>uid</code>) are stored as AES-GCM ciphertext; only an authenticated admin of the owning organization can decrypt them, and only at response time — never written to a log.</li>
  <li>Consent-log details (who requested what access) are stored as AES-GCM ciphertext.</li>
  <li>Magic-link emails are delivered via a transactional email provider (Resend) and never written to our filesystem. Local file logging of magic links is off by default.</li>
  <li>The one residual risk is our private signing keys — losing them means receipts can't be verified, so we keep them on encrypted offline backups and rotate annually. A new signing key never invalidates historical receipts; the old public key stays in our key manifest for verification.</li>
</ul>

<h2>What Changes on the Enterprise Tier</h2>
<p>AIAuth Enterprise is <strong>self-hosted</strong>. You run the server on your own infrastructure, your IT team manages the keys, and your employees' attestation data stays on your network. We never see it. Finch Business Services LLC is a software vendor, not a data processor, for enterprise deployments. Your organization's own privacy policy governs the data your server processes.</p>

<h2>GDPR and Data Subject Rights</h2>
<p>Because the hash registry contains no personally identifiable information, registry rows are not subject to GDPR — a hash cannot be traced to you.</p>
<p>For accounts, you have the right to export, pseudonymize, or delete your data. Contact us at <a href="mailto:privacy@aiauth.app">privacy@aiauth.app</a> and we will respond within 30 days. In most cases, deleting your local data (by uninstalling the extension) and requesting account deletion is sufficient.</p>

<h2>What We Don't Do</h2>
<ul>
  <li>No tracking across sites. No analytics. No ad pixels.</li>
  <li>No third-party SDKs in the Chrome extension.</li>
  <li>No selling, renting, or sharing of your data.</li>
  <li>No scraping or retention of the content you attest.</li>
</ul>

<h2>Server Logs</h2>
<p>Our reverse proxy (nginx) logs standard HTTP access records — timestamps, paths, status codes, IP addresses — for operational reliability and abuse prevention. These are rotated weekly and not linked to any user profile (because we don't maintain user profiles in the traditional sense).</p>

<h2>Third-Party Services</h2>
<p>Our website loads typography fonts from Google Fonts. When you visit a page on aiauth.app, your browser fetches font files from Google's CDN — subject to Google's own privacy terms. The Chrome extension loads no third-party resources.</p>
<p>Our transactional email provider is <strong>Resend</strong>. They hold email-delivery metadata (recipient address, timestamp) for up to 30 days for deliverability diagnostics. We do not transmit anything else to them.</p>

<h2>Children</h2>
<p>AIAuth is not directed to children under 13 and does not knowingly collect information from them.</p>

<h2>Honest Reality</h2>
<p>AIAuth is built by a one-person business. We offer no SLAs, no 24/7 support line, and no formal data-protection officer. What we offer is software that tries to be small, honest, and correct. If you have questions or concerns, you'll get a direct reply from a human within a few days.</p>

<h2>Changes to This Policy</h2>
<p>Material changes are announced on this page and the "last updated" date changes. The core guarantees (content never transmitted; no plaintext emails stored; no selling data) will never change without a new major version and explicit notice to existing account holders.</p>

<h2>Contact</h2>
<p>Questions: <a href="mailto:privacy@aiauth.app">privacy@aiauth.app</a>. Security advisories: <a href="mailto:security@aiauth.app">security@aiauth.app</a>.</p>
</div>"""
    return HTMLResponse(_site_shell("Privacy", body, active=""))


@app.get("/auth", response_class=HTMLResponse)
def auth_landing(token: Optional[str] = None, p: Optional[str] = None):
    """Magic-link landing page.

    The email sent by `_send_magic_link` routes recipients here. The token
    itself is exchanged for a session via `POST /v1/account/verify` — this
    page drives that exchange client-side so the token never leaves the
    user's browser except to our own verify endpoint.

    Two user paths:
      1. Extension user: instructed to copy the current URL back into the
         AIAuth extension popup's "Paste link" field. The extension then
         handles the exchange and stores the session in chrome.storage.
      2. Browser-only user: clicks "Complete Sign-In Here" to exchange the
         token inline. The resulting session token is displayed and can be
         copied into the extension settings, or retained in sessionStorage
         for subsequent account-management calls from the website.

    The token is single-use. If the user already completed sign-in from
    the extension, clicking this page afterwards will show "already used."
    """
    purpose = (p or "").strip()
    purpose_label = {
        "login": "Sign in to AIAuth",
        "verify_email": "Verify your AIAuth email",
        "link_email": "Link this email to your AIAuth account",
    }.get(purpose, "Complete your AIAuth sign-in")

    has_token = bool(token and token.strip())
    body = f"""<span class="eyebrow">Magic link</span>
<h1 class="page-title">{purpose_label}</h1>
<p class="lead">Your single-use sign-in link is ready. Finish the sign-in where you started it.</p>

<div style="margin-top:28px;padding:20px;background:var(--panel);border:1px solid var(--border);border-radius:12px;">
  <h2 style="margin:0 0 8px;font-size:16px;font-weight:700;">Using the AIAuth extension?</h2>
  <p style="margin:0;font-size:14px;color:var(--muted);line-height:1.55;">Copy the entire URL from your browser's address bar, open the extension popup, and paste it into the <b>Paste link</b> field. Your extension will complete sign-in and you'll be ready to attest.</p>
</div>

<div style="margin-top:16px;padding:20px;background:#fff;border:1px solid var(--border);border-radius:12px;">
  <h2 style="margin:0 0 8px;font-size:16px;font-weight:700;">Signing in from the browser only?</h2>
  <p style="margin:0 0 14px;font-size:14px;color:var(--muted);line-height:1.55;">Click the button below to complete sign-in here. This stores a session token in this browser so you can manage your account at aiauth.app — you'll still need the extension to attest content.</p>
  <button id="complete-btn" class="btn btn-primary" style="padding:10px 18px;font-size:14px;font-weight:600;border-radius:10px;border:none;background:var(--accent);color:#fff;cursor:pointer;"{' disabled' if not has_token else ''}>Complete Sign-In Here</button>
  <div id="auth-result" style="margin-top:16px;font-size:14px;"></div>
</div>

<p style="margin-top:20px;font-size:13px;color:var(--muted);">Links expire 15 minutes after we send them, and each can be used only once. If your link has expired, request a fresh one from the extension popup or <a href="/">the home page</a>.</p>

<script>
  (function () {{
    var btn = document.getElementById("complete-btn");
    var out = document.getElementById("auth-result");
    if (!btn) return;
    var url = new URL(window.location.href);
    var token = url.searchParams.get("token");
    if (!token) {{
      out.innerHTML = '<span style="color:#991b1b;">No token found in URL. Please use the most recent email link we sent you.</span>';
      btn.disabled = true;
      return;
    }}
    btn.addEventListener("click", function () {{
      btn.disabled = true;
      btn.textContent = "Completing…";
      out.innerHTML = "";
      fetch("/v1/account/verify", {{
        method: "POST",
        headers: {{ "Content-Type": "application/json" }},
        body: JSON.stringify({{ token: token }})
      }}).then(function (r) {{
        return r.json().then(function (data) {{ return {{ ok: r.ok, data: data }}; }});
      }}).then(function (result) {{
        if (!result.ok) {{
          var msg = (result.data && result.data.error && result.data.error.message) ||
                    (result.data && result.data.detail) ||
                    "Sign-in failed. The link may be expired or already used.";
          out.innerHTML = '<div style="padding:12px 14px;background:#fef2f2;border:1px solid #ef4444;border-radius:8px;color:#991b1b;">' + msg + '</div>';
          btn.textContent = "Sign-In Failed";
          return;
        }}
        try {{ sessionStorage.setItem("aiauth_session", JSON.stringify(result.data)); }} catch (e) {{}}
        out.innerHTML =
          '<div style="padding:14px 16px;background:#ecfdf5;border:1px solid #10b981;border-radius:8px;color:#065f46;">' +
          '<b>✓ You\\'re signed in as ' + (result.data.email || "your account") + '.</b>' +
          '<div style="margin-top:8px;font-size:13px;">You can close this tab, or open the AIAuth extension — it will pick up the sign-in automatically if this is the same browser profile.</div>' +
          '</div>';
        btn.style.display = "none";
      }}).catch(function (err) {{
        out.innerHTML = '<div style="padding:12px 14px;background:#fef2f2;border:1px solid #ef4444;border-radius:8px;color:#991b1b;">Network error. Please try again.</div>';
        btn.disabled = false;
        btn.textContent = "Complete Sign-In Here";
      }});
    }});
  }})();
</script>"""
    return HTMLResponse(_site_shell("Sign In", body, active=""))


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
