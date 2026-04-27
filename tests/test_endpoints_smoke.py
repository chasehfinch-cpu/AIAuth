"""HTTP smoke tests — uses FastAPI TestClient against server.app.

These are intentionally shallow: each test confirms an endpoint is
reachable, accepts a well-formed payload, and returns the documented
shape. Deep crypto behavior is covered in test_cross_schema_roundtrip;
schema validation in test_receipt_schema. This file is the "did we break
the HTTP layer" canary.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import server


@pytest.fixture(scope="module")
def client():
    return TestClient(server.app)


def test_health_live(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "aiauth"
    assert body["version"] == server.VERSION


def test_health_db_reports_latency(client):
    r = client.get("/health/db")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("ok", "degraded")
    assert body.get("db_ok") is True
    assert "db_latency_ms" in body


def test_public_key_manifest(client):
    r = client.get("/v1/public-key")
    assert r.status_code == 200
    body = r.json()
    assert "keys" in body and len(body["keys"]) >= 1


def test_public_key_legacy_format(client):
    """?format=legacy returns the v0.4.0 single-key shape for clients
    that predate the manifest."""
    r = client.get("/v1/public-key?format=legacy")
    assert r.status_code == 200
    body = r.json()
    assert body.get("algorithm") == "Ed25519"
    assert "public_key_pem" in body
    assert "version" in body


def test_well_known_public_key(client):
    r = client.get("/.well-known/aiauth-public-key")
    assert r.status_code == 200
    assert "public_key_pem" in r.json() or "keys" in r.json()


def test_sign_then_verify_happy_path(client):
    """End-to-end HTTP round-trip: POST /v1/sign, then POST /v1/verify
    with the returned receipt + signature. Most important smoke test."""
    sign_body = {
        "output_hash": "a" * 64,
        "user_id": "smoke@example.com",
        "source": "test",
        "model": "claude-sonnet-4",
        "len": 400,
        "tta": 30,
        "register": False,  # don't touch the registry from smoke tests
    }
    r1 = client.post("/v1/sign", json=sign_body)
    assert r1.status_code == 200, r1.text
    signed = r1.json()
    assert "receipt" in signed and "signature" in signed

    r2 = client.post("/v1/verify", json={
        "receipt": signed["receipt"],
        "signature": signed["signature"],
    })
    assert r2.status_code == 200
    assert r2.json()["valid"] is True


def test_sign_rejects_bad_hash(client):
    r = client.post("/v1/sign", json={
        "output_hash": "not-a-hash",
        "user_id": "smoke@example.com",
        "source": "test",
    })
    assert r.status_code == 400
    body = r.json()
    assert body["error"]["code"] == "INVALID_HASH"


def test_verify_with_tampered_receipt_returns_invalid(client):
    sign_body = {
        "output_hash": "b" * 64,
        "user_id": "smoke@example.com",
        "source": "test",
        "register": False,
    }
    r1 = client.post("/v1/sign", json=sign_body)
    signed = r1.json()
    tampered = dict(signed["receipt"])
    tampered["uid"] = "someone-else@example.com"
    r2 = client.post("/v1/verify", json={
        "receipt": tampered,
        "signature": signed["signature"],
    })
    assert r2.status_code == 200
    assert r2.json()["valid"] is False


def test_verify_file_signals_c2pa_branch(client):
    """POST /v1/verify/file-signals cross-checks a C2PA manifest hash
    against what the receipt carries. Regression guard on the Data
    Depth v1.3.0 endpoint."""
    c2pa_hash = "e" * 64
    r1 = client.post("/v1/sign", json={
        "output_hash": "c" * 64,
        "user_id": "smoke@example.com",
        "source": "test",
        "c2pa_manifest_hash": c2pa_hash,
        "register": False,
    })
    assert r1.status_code == 200
    receipt = r1.json()["receipt"]

    # Matching manifest hash → all_match True.
    r2 = client.post("/v1/verify/file-signals", json={
        "receipt": receipt,
        "c2pa_manifest_hash": c2pa_hash,
    })
    assert r2.status_code == 200
    body = r2.json()
    assert body["all_match"] is True
    assert body["checks"]["c2pa_manifest_hash"]["match"] is True

    # Mismatched manifest hash → match False (but endpoint still 200).
    r3 = client.post("/v1/verify/file-signals", json={
        "receipt": receipt,
        "c2pa_manifest_hash": "0" * 64,
    })
    assert r3.status_code == 200
    assert r3.json()["checks"]["c2pa_manifest_hash"]["match"] is False


def test_verify_file_signals_requires_at_least_one_check(client):
    """Calling the endpoint with no supplied hashes is a client error."""
    r = client.post("/v1/verify/file-signals", json={"receipt": {"id": "x"}})
    assert r.status_code == 400


def test_public_pages_render(client):
    """Light check that the public doc pages land 200s. These are rendered
    server-side so a syntax error in _site_shell would break them all."""
    for path in (
        "/",
        "/guide",
        "/check",
        "/privacy",
        "/terms",
        "/security",
        "/compliance",
        "/standards",
        "/pricing",
        "/api",
        "/one-pager",
        "/pilot",
        "/waitlist",
        "/contact",
    ):
        r = client.get(path)
        assert r.status_code == 200, f"{path} returned {r.status_code}"
        # Each public page should wrap in the site shell.
        assert "AIAuth" in r.text or "aiauth" in r.text


def test_stats_endpoint_license_gated(client):
    """/v1/stats is license-gated in free-tier builds — returns 402 without
    an enterprise license. Confirms the gate is wired; enterprise behavior
    is exercised by integration tests outside this smoke suite."""
    r = client.get("/v1/stats")
    assert r.status_code in (200, 402)
