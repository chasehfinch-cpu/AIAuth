"""
AI Attestation Layer — Extensible Schema & Engine
Built on LiteLLM + APP Protocol

Design principles:
  - Core fields are permanent and never change
  - Extensions are versioned and additive (never breaking)
  - Attestation chains link multi-model workflows
  - Metadata envelope allows arbitrary future fields
  - Every record is self-describing (carries its own schema version)
"""

import hashlib
import json
import uuid
import sqlite3
import os
from datetime import datetime, timezone
from typing import Optional, Any

from litellm.integrations.custom_logger import CustomLogger


# ---------------------------------------------------------------------------
# Schema version — increment when adding fields, never remove fields
# ---------------------------------------------------------------------------
SCHEMA_VERSION = "0.2.0"
APP_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Database — extensible from day one
# ---------------------------------------------------------------------------

DB_PATH = os.getenv("ATTESTATION_DB_PATH", "attestations.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")       # concurrent reads
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()

    # ------------------------------------------------------------------
    # Core attestation record — these fields are permanent
    # ------------------------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attestations (
            -- Identity
            id                TEXT PRIMARY KEY,
            schema_version    TEXT NOT NULL,
            created_at        TEXT NOT NULL,
            
            -- What AI produced it
            model             TEXT NOT NULL,
            provider          TEXT,
            
            -- Content fingerprints (never raw content)
            input_hash        TEXT NOT NULL,
            output_hash       TEXT NOT NULL,
            hash_algorithm    TEXT NOT NULL DEFAULT 'sha256',
            
            -- Who triggered it
            user_id           TEXT,
            api_key_alias     TEXT,
            
            -- Human review
            review_status     TEXT DEFAULT 'pending',
            reviewer_id       TEXT,
            reviewed_at       TEXT,
            review_note       TEXT,
            
            -- APP protocol
            app_version       TEXT DEFAULT '1.0.0',
            verification_uri  TEXT,
            
            -- Chain linking (multi-model workflows)
            parent_id         TEXT,
            chain_id          TEXT,
            chain_position    INTEGER DEFAULT 0,
            
            -- Extensible metadata (JSON blob for future fields)
            metadata          TEXT DEFAULT '{}',
            
            FOREIGN KEY (parent_id) REFERENCES attestations(id)
        )
    """)

    # ------------------------------------------------------------------
    # Extension registry — tracks what metadata fields exist
    # This lets the system self-describe its capabilities over time.
    # When a new field type appears (e.g., "risk_score" or 
    # "regulatory_jurisdiction"), it gets registered here so 
    # dashboards and APIs can discover it dynamically.
    # ------------------------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_extensions (
            field_name        TEXT PRIMARY KEY,
            field_type        TEXT NOT NULL,
            description       TEXT,
            added_in_version  TEXT NOT NULL,
            added_at          TEXT NOT NULL,
            deprecated        INTEGER DEFAULT 0
        )
    """)

    # ------------------------------------------------------------------
    # Review history — immutable log of every review action
    # A single attestation can be reviewed multiple times 
    # (escalation, secondary review, audit re-review).
    # The attestations table always reflects the LATEST review,
    # but the full history lives here.
    # ------------------------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS review_history (
            id                TEXT PRIMARY KEY,
            attestation_id    TEXT NOT NULL,
            reviewer_id       TEXT NOT NULL,
            status            TEXT NOT NULL,
            note              TEXT,
            reviewed_at       TEXT NOT NULL,
            review_metadata   TEXT DEFAULT '{}',
            FOREIGN KEY (attestation_id) REFERENCES attestations(id)
        )
    """)

    # ------------------------------------------------------------------
    # Indexes for the queries that matter
    # ------------------------------------------------------------------
    for idx in [
        "CREATE INDEX IF NOT EXISTS idx_att_user ON attestations(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_att_status ON attestations(review_status)",
        "CREATE INDEX IF NOT EXISTS idx_att_created ON attestations(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_att_chain ON attestations(chain_id)",
        "CREATE INDEX IF NOT EXISTS idx_att_parent ON attestations(parent_id)",
        "CREATE INDEX IF NOT EXISTS idx_att_model ON attestations(model)",
        "CREATE INDEX IF NOT EXISTS idx_review_att ON review_history(attestation_id)",
    ]:
        conn.execute(idx)

    # ------------------------------------------------------------------
    # Seed the extension registry with v0.2.0 metadata fields
    # ------------------------------------------------------------------
    seed_extensions = [
        ("tokens_in",       "integer", "Input token count",                SCHEMA_VERSION),
        ("tokens_out",      "integer", "Output token count",               SCHEMA_VERSION),
        ("cost_usd",        "float",   "Cost in USD",                      SCHEMA_VERSION),
        ("latency_ms",      "float",   "Response latency in milliseconds", SCHEMA_VERSION),
        ("request_type",    "string",  "completion|embedding|image|audio",  SCHEMA_VERSION),
        ("tags",            "array",   "User-defined classification tags",  SCHEMA_VERSION),
        ("risk_category",   "string",  "Risk classification for compliance",SCHEMA_VERSION),
        ("department",      "string",  "Organizational unit",              SCHEMA_VERSION),
        ("project",         "string",  "Project or engagement identifier", SCHEMA_VERSION),
        ("content_type",    "string",  "Type of output: text|code|data|image", SCHEMA_VERSION),
        ("tool_calls",      "array",   "Tools/functions the AI invoked",   SCHEMA_VERSION),
        ("agent_id",        "string",  "Autonomous agent identifier",      SCHEMA_VERSION),
        ("session_id",      "string",  "Conversation/session identifier",  SCHEMA_VERSION),
        ("parent_model",    "string",  "Upstream model in chain",          SCHEMA_VERSION),
    ]

    now = datetime.now(timezone.utc).isoformat()
    for name, ftype, desc, version in seed_extensions:
        conn.execute("""
            INSERT OR IGNORE INTO schema_extensions 
            (field_name, field_type, description, added_in_version, added_at)
            VALUES (?, ?, ?, ?, ?)
        """, (name, ftype, desc, version, now))

    conn.commit()
    conn.close()


init_db()


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def hash_content(content, algorithm="sha256") -> str:
    if isinstance(content, (dict, list)):
        content = json.dumps(content, sort_keys=True, default=str)
    h = hashlib.new(algorithm)
    h.update(str(content).encode("utf-8"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# The Callback
# ---------------------------------------------------------------------------

class AttestationHandler(CustomLogger):
    """
    LiteLLM callback — generates attestation records for every AI call.
    Runs post-response (zero added latency to the user).
    """

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        try:
            attestation_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc).isoformat()

            model = kwargs.get("model", "unknown")
            messages = kwargs.get("messages", [])
            user = kwargs.get("user", None)
            
            litellm_params = kwargs.get("litellm_params", {})
            metadata = litellm_params.get("metadata", {})
            api_key_alias = metadata.get("user_api_key_alias", None)

            provider = model.split("/")[0] if "/" in model else None

            # Response content for hashing
            response_content = ""
            if hasattr(response_obj, "choices") and response_obj.choices:
                choice = response_obj.choices[0]
                if hasattr(choice, "message") and choice.message:
                    response_content = choice.message.content or ""

            # Token usage
            usage = getattr(response_obj, "usage", None)
            tokens_in = getattr(usage, "prompt_tokens", None) if usage else None
            tokens_out = getattr(usage, "completion_tokens", None) if usage else None

            cost = kwargs.get("response_cost", None)
            latency_ms = (end_time - start_time).total_seconds() * 1000

            base_url = os.getenv("ATTESTATION_BASE_URL", "http://localhost:8100")
            verification_uri = f"{base_url}/v1/verify"

            # ---- Chain detection ----
            # If the caller passes chain metadata, link attestations
            chain_id = metadata.get("attestation_chain_id", None)
            parent_id = metadata.get("attestation_parent_id", None)
            chain_position = metadata.get("attestation_chain_position", 0)

            # ---- Tool call detection ----
            tool_calls = []
            if hasattr(response_obj, "choices") and response_obj.choices:
                choice = response_obj.choices[0]
                if hasattr(choice, "message") and choice.message:
                    tc = getattr(choice.message, "tool_calls", None)
                    if tc:
                        tool_calls = [
                            {"name": t.function.name, "id": t.id}
                            for t in tc if hasattr(t, "function")
                        ]

            # ---- Detect request type ----
            call_type = kwargs.get("call_type", "completion")

            # ---- Build extensible metadata ----
            ext_metadata = {
                "tokens_in": tokens_in,
                "tokens_out": tokens_out,
                "cost_usd": cost,
                "latency_ms": round(latency_ms, 2),
                "request_type": call_type,
                "content_type": "text",  # default; enhance later
                "tool_calls": tool_calls if tool_calls else None,
                "session_id": metadata.get("session_id", None),
                "agent_id": metadata.get("agent_id", None),
                "tags": metadata.get("attestation_tags", []),
                "risk_category": metadata.get("risk_category", None),
                "department": metadata.get("department", None),
                "project": metadata.get("project", None),
            }
            # Strip None values to keep storage lean
            ext_metadata = {k: v for k, v in ext_metadata.items() if v is not None}

            # ---- Write ----
            conn = get_db()
            conn.execute("""
                INSERT INTO attestations 
                (id, schema_version, created_at, model, provider,
                 input_hash, output_hash, hash_algorithm,
                 user_id, api_key_alias,
                 verification_uri,
                 parent_id, chain_id, chain_position,
                 metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                attestation_id, SCHEMA_VERSION, now,
                model, provider,
                hash_content(messages), hash_content(response_content), "sha256",
                user, api_key_alias,
                verification_uri,
                parent_id, chain_id, chain_position,
                json.dumps(ext_metadata),
            ))
            conn.commit()
            conn.close()

        except Exception as e:
            # Never break the user's request
            print(f"[Attestation] Error: {e}")

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(
                    self.async_log_success_event(kwargs, response_obj, start_time, end_time)
                )
            else:
                asyncio.run(
                    self.async_log_success_event(kwargs, response_obj, start_time, end_time)
                )
        except Exception as e:
            print(f"[Attestation] Sync error: {e}")


proxy_handler_instance = AttestationHandler()
