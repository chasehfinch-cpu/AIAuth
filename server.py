"""
AIAuth Server v4 — Chain-Aware Signing Authority

The server does three things:
  1. SIGN:   Hash in → signed receipt out → server forgets
  2. VERIFY: Receipt in → yes/no out
  3. CHAIN:  Receipts in → unbroken yes/no out

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

import json
import os
import re
import uuid
import sqlite3
import base64
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
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
MASTER_KEY = os.getenv("AIAUTH_MASTER_KEY", "")  # Your admin key for issuing licenses
DEDUP_WINDOW = int(os.getenv("AIAUTH_DEDUP_WINDOW", "300"))  # seconds; 0 disables dedup

# Regex for SHA-256 hex (lowercase or uppercase)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

app = FastAPI(title="AIAuth", version=VERSION)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


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
# ED25519 KEYS
# ===================================================================

def load_or_create_keys():
    priv_path = KEY_DIR / "aiauth_private.pem"
    if priv_path.exists():
        with open(priv_path, "rb") as f:
            pk = serialization.load_pem_private_key(f.read(), password=None)
    else:
        pk = Ed25519PrivateKey.generate()
        with open(priv_path, "wb") as f:
            f.write(pk.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        os.chmod(priv_path, 0o600)
    pub = pk.public_key()
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return pk, pub, pub_pem

PRIV_KEY, PUB_KEY, PUB_PEM = load_or_create_keys()


def sign(data: dict) -> str:
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
    sig = PRIV_KEY.sign(payload.encode())
    return base64.urlsafe_b64encode(sig).decode()


def check_sig(data: dict, sig_b64: str) -> bool:
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
    try:
        PUB_KEY.verify(base64.urlsafe_b64decode(sig_b64), payload.encode())
        return True
    except:
        return False


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
# ENTERPRISE DB (optional)
# ===================================================================

def get_db():
    if MODE != "enterprise": return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    if MODE != "enterprise": return
    conn = get_db()
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
    conn.commit(); conn.close()

init_db()


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
    The registry stores NO user data — only hash → receipt_id mappings
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
    receipt: Dict[str, Any] = {
        "v": VERSION,
        "id": receipt_id,
        "ts": now,
        "hash": req.output_hash,
        "uid": req.user_id,
        "src": req.source,
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

    # Public hash registry — stores hash→receipt_id mapping + doc_id only, no user data
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
    """Is this receipt authentic AND does the content match? Y/N."""
    sig_ok = check_sig(req.receipt, req.signature)
    hash_ok = req.receipt.get("hash") == req.content_hash
    return {
        "authentic": sig_ok and hash_ok,
        "signature_valid": sig_ok,
        "content_matches": hash_ok,
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
@app.get("/.well-known/aiauth-public-key")
def public_key():
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
