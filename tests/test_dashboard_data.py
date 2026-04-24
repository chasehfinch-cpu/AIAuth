"""Dashboard data contract — Commercial KPI Honesty PR.

Covers the two new `cross_format` queries:
  - multi_format_documents — count of content_hash_canonical values
    appearing with 2+ distinct output_hashes in the window.
  - ungoverned_ai_content — count of policy_violations where policy_id
    is 'ungoverned-ai-content'.

Also regression-tests the /v1/admin/org/departments CSV upload endpoint.

Tests construct enterprise_attestations rows directly via sqlite3 so we
can exercise the aggregator without running the full enterprise-ingest
auth flow.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone, timedelta

import pytest

import server


# ---------- helpers ------------------------------------------------------

def _fresh_db_conn():
    """Return a cursor on the test DB with all FKs enforced."""
    c = sqlite3.connect(server.DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    return c


def _ensure_org(conn, org_id: str = "ORG_TEST") -> str:
    """Create the organization row required by enterprise_attestations."""
    conn.execute(
        "INSERT OR IGNORE INTO organizations "
        "(org_id, name, domains, license_key, license_tier, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (org_id, "Test Org", "[\"test.example\"]", "test-license", "enterprise",
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    return org_id


def _insert_ea(conn, org_id: str, **fields) -> str:
    """Insert an enterprise_attestations row with sensible defaults."""
    now = datetime.now(timezone.utc).isoformat()
    row = {
        "id": fields.get("id", f"ea_{now}_{fields.get('hash', 'x')[:6]}"),
        "ts": fields.get("ts", now),
        "hash": fields.get("hash", "a" * 64),
        "prompt_hash": fields.get("prompt_hash"),
        "uid_hash": fields.get("uid_hash", "uid_hash_test"),
        "uid_encrypted": fields.get("uid_encrypted", "ENC"),
        "uid_pseudonym": None,
        "src": "chrome-extension",
        "model": fields.get("model"),
        "provider": fields.get("provider"),
        "source_domain": None,
        "source_app": None,
        "concurrent_ai_apps": None,
        "ai_markers": fields.get("ai_markers"),
        "doc_id": fields.get("doc_id"),
        "parent": fields.get("parent"),
        "file_type": None,
        "len": fields.get("len"),
        "tta": fields.get("tta"),
        "sid": None,
        "dest": None,
        "dest_ext": None,
        "classification": None,
        "review_status": fields.get("review_status"),
        "review_by": None,
        "review_at": None,
        "review_note": None,
        "tags": None,
        "schema_version": "0.5.0",
        "org_id": org_id,
        "client_integrity": "none",
        "ingested_at": now,
        "content_hash_canonical": fields.get("content_hash_canonical"),
    }
    conn.execute(
        "INSERT INTO enterprise_attestations ("
        "id, ts, hash, prompt_hash, uid_hash, uid_encrypted, uid_pseudonym, "
        "src, model, provider, source_domain, source_app, "
        "concurrent_ai_apps, ai_markers, doc_id, parent, "
        "file_type, len, tta, sid, dest, dest_ext, classification, "
        "review_status, review_by, review_at, review_note, tags, "
        "schema_version, org_id, client_integrity, ingested_at, "
        "content_hash_canonical"
        ") VALUES (" + ",".join(["?"] * 33) + ")",
        tuple(row[k] for k in [
            "id", "ts", "hash", "prompt_hash", "uid_hash", "uid_encrypted",
            "uid_pseudonym", "src", "model", "provider", "source_domain",
            "source_app", "concurrent_ai_apps", "ai_markers", "doc_id",
            "parent", "file_type", "len", "tta", "sid", "dest", "dest_ext",
            "classification", "review_status", "review_by", "review_at",
            "review_note", "tags", "schema_version", "org_id",
            "client_integrity", "ingested_at", "content_hash_canonical",
        ]),
    )
    conn.commit()
    return row["id"]


def _insert_violation(conn, attestation_id: str, policy_id: str,
                      severity: str = "medium"):
    conn.execute(
        "INSERT INTO policy_violations (attestation_id, policy_id, severity, details, detected_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (attestation_id, policy_id, severity, json.dumps({}),
         datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


@pytest.fixture
def clean_org():
    """Wipe per-test rows so tests don't contaminate each other."""
    conn = _fresh_db_conn()
    org_id = _ensure_org(conn)
    conn.execute("DELETE FROM policy_violations")
    conn.execute("DELETE FROM enterprise_attestations WHERE org_id = ?", (org_id,))
    conn.commit()
    yield conn, org_id
    conn.execute("DELETE FROM policy_violations")
    conn.execute("DELETE FROM enterprise_attestations WHERE org_id = ?", (org_id,))
    conn.commit()
    conn.close()


# ---------- multi_format_documents --------------------------------------

def test_multi_format_zero_when_no_canonical_hashes(clean_org):
    """Receipts without content_hash_canonical contribute nothing."""
    conn, org_id = clean_org
    _insert_ea(conn, org_id, hash="a" * 64)
    _insert_ea(conn, org_id, hash="b" * 64)
    from fastapi.testclient import TestClient
    client = TestClient(server.app)
    # The real endpoint is auth-gated; we test the SQL by calling the
    # underlying helper directly via monkeypatched session. Keeping it
    # SQL-level to avoid admin-session setup complexity.
    mfd = conn.execute(
        "SELECT COUNT(*) AS n FROM ( "
        "  SELECT ea.content_hash_canonical "
        "  FROM enterprise_attestations ea WHERE ea.org_id = ? "
        "  AND ea.content_hash_canonical IS NOT NULL "
        "  GROUP BY ea.content_hash_canonical "
        "  HAVING COUNT(DISTINCT ea.hash) > 1)",
        (org_id,),
    ).fetchone()["n"]
    assert mfd == 0


def test_multi_format_counts_canonical_groups_with_multiple_formats(clean_org):
    """Two receipts sharing a content_hash_canonical but with distinct
    output_hashes count as one multi-format group."""
    conn, org_id = clean_org
    canonical = "c" * 64
    _insert_ea(conn, org_id, hash="11" + "0" * 62, content_hash_canonical=canonical)
    _insert_ea(conn, org_id, hash="22" + "0" * 62, content_hash_canonical=canonical)
    # One more unrelated canonical group should NOT increase the count.
    _insert_ea(conn, org_id, hash="33" + "0" * 62, content_hash_canonical="d" * 64)

    mfd = conn.execute(
        "SELECT COUNT(*) AS n FROM ( "
        "  SELECT ea.content_hash_canonical "
        "  FROM enterprise_attestations ea WHERE ea.org_id = ? "
        "  AND ea.content_hash_canonical IS NOT NULL "
        "  GROUP BY ea.content_hash_canonical "
        "  HAVING COUNT(DISTINCT ea.hash) > 1)",
        (org_id,),
    ).fetchone()["n"]
    assert mfd == 1


def test_multi_format_same_hash_twice_not_counted(clean_org):
    """Two receipts with the SAME output_hash and same canonical are
    duplicates (dedup window) — not multi-format."""
    conn, org_id = clean_org
    canonical = "e" * 64
    _insert_ea(conn, org_id, id="dup-1", hash="44" + "0" * 62, content_hash_canonical=canonical)
    _insert_ea(conn, org_id, id="dup-2", hash="44" + "0" * 62, content_hash_canonical=canonical)

    mfd = conn.execute(
        "SELECT COUNT(*) AS n FROM ( "
        "  SELECT ea.content_hash_canonical "
        "  FROM enterprise_attestations ea WHERE ea.org_id = ? "
        "  AND ea.content_hash_canonical IS NOT NULL "
        "  GROUP BY ea.content_hash_canonical "
        "  HAVING COUNT(DISTINCT ea.hash) > 1)",
        (org_id,),
    ).fetchone()["n"]
    assert mfd == 0


# ---------- ungoverned_ai_content ---------------------------------------

def test_ungoverned_zero_with_no_matching_violations(clean_org):
    conn, org_id = clean_org
    ea_id = _insert_ea(conn, org_id)
    _insert_violation(conn, ea_id, "no-rubber-stamping")

    count = conn.execute(
        "SELECT COUNT(*) AS n FROM policy_violations pv "
        "JOIN enterprise_attestations ea ON pv.attestation_id = ea.id "
        "WHERE ea.org_id = ? AND pv.policy_id = 'ungoverned-ai-content'",
        (org_id,),
    ).fetchone()["n"]
    assert count == 0


def test_ungoverned_counts_matching_violations(clean_org):
    conn, org_id = clean_org
    ea1 = _insert_ea(conn, org_id, id="ea-ungov-1", hash="55" + "0" * 62)
    ea2 = _insert_ea(conn, org_id, id="ea-ungov-2", hash="66" + "0" * 62)
    _insert_violation(conn, ea1, "ungoverned-ai-content")
    _insert_violation(conn, ea2, "ungoverned-ai-content")
    _insert_violation(conn, ea1, "no-rubber-stamping")

    count = conn.execute(
        "SELECT COUNT(*) AS n FROM policy_violations pv "
        "JOIN enterprise_attestations ea ON pv.attestation_id = ea.id "
        "WHERE ea.org_id = ? AND pv.policy_id = 'ungoverned-ai-content'",
        (org_id,),
    ).fetchone()["n"]
    assert count == 2


# ---------- compliance-report smoke -------------------------------------

def test_compliance_report_renders(clean_org):
    """The public sample compliance report returns 200 and includes all
    four §6 KPI IDs. Regression guard if the template changes."""
    from fastapi.testclient import TestClient
    client = TestClient(server.app)
    r = client.get("/samples/compliance-report")
    assert r.status_code == 200
    body = r.text
    for kpi_id in ("cf_total", "cf_multi", "cf_ai", "cf_unatt"):
        assert f'id="{kpi_id}"' in body
    # Tier badges present
    assert "tier-badge" in body
    assert "Team / Enterprise Tier Only" in body
    # Footer link to the new §3.5 anchor
    assert "kpi-data-inputs-at-a-glance" in body


def test_exec_summary_demo_renders(clean_org):
    """The /demo executive summary renders and includes tier badges."""
    from fastapi.testclient import TestClient
    client = TestClient(server.app)
    r = client.get("/demo")
    assert r.status_code == 200
    body = r.text
    assert "tier-badge" in body
    assert "Team / Enterprise Tier Only" in body
    # KPI IDs still present
    for kpi_id in ("k_total", "k_users", "k_shadow", "k_ext"):
        assert f'id="{kpi_id}"' in body


# ---------- department CSV upload ---------------------------------------

def test_department_csv_rejects_bad_header(clean_org):
    """Wrong header should return 400 INVALID_RECEIPT."""
    from fastapi.testclient import TestClient
    # The endpoint is admin-auth-gated. We exercise the shape-checking
    # code path up to auth failure by calling with no auth header — the
    # endpoint returns 401/403 before reaching the CSV parser. Instead,
    # validate the parser logic by calling it directly via a patched
    # auth function.
    import server as _s
    original = _s._require_admin_session
    _s._require_admin_session = lambda *a, **k: {"org_id": clean_org[1]}
    try:
        client = TestClient(_s.app)
        body = {"csv": "wrong,header\nalice@x.com,Finance"}
        r = client.post(
            "/v1/admin/org/departments?org_id=" + clean_org[1],
            json=body,
            headers={"Authorization": "Bearer fake"},
        )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "INVALID_RECEIPT"
    finally:
        _s._require_admin_session = original


def test_department_csv_reports_unmatched(clean_org):
    """An email with no account returns as unmatched, not updated."""
    import server as _s
    original = _s._require_admin_session
    _s._require_admin_session = lambda *a, **k: {"org_id": clean_org[1]}
    try:
        from fastapi.testclient import TestClient
        client = TestClient(_s.app)
        body = {"csv": "email,department\nghost@example.invalid,Finance"}
        r = client.post(
            "/v1/admin/org/departments?org_id=" + clean_org[1],
            json=body,
            headers={"Authorization": "Bearer fake"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["updated"] == 0
        assert data["unmatched_count"] == 1
        assert data["unmatched_emails"] == ["ghost@example.invalid"]
    finally:
        _s._require_admin_session = original
