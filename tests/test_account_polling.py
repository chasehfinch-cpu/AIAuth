"""Tests for cross-device magic-link login (pending_logins polling flow).

Exercises:
  - /v1/account/create with polling=true returns a pending_id
  - /v1/account/auth/status returns "pending" before claim
  - After /v1/account/verify with a token carrying the pending_id, the
    status endpoint returns "ready" with a session_token
  - Single-shot: a second status call after claim returns 404
  - Decoy pending_id for unknown emails returns 404 (enumeration safety)
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

import server


@pytest.fixture(scope="module")
def client():
    return TestClient(server.app)


def _extract_link_from_logs(capsys):
    """The dev path prints `[AIAuth magic-link] purpose=login link=...`
    to stdout. Pull the most recent link out of captured output."""
    captured = capsys.readouterr().out
    match = None
    for line in captured.splitlines():
        m = re.search(r"link=(\S+)", line)
        if m:
            match = m.group(1)
    return match


def test_polling_flow_end_to_end(client, capsys):
    create = client.post(
        "/v1/account/create",
        json={"email": "polltest@example.com", "polling": True},
    )
    assert create.status_code == 200, create.text
    body = create.json()
    pending_id = body.get("pending_id")
    assert pending_id and len(pending_id) >= 32
    assert body.get("poll_interval_ms") == 4000

    # Before the user clicks the link, status should be "pending".
    pending = client.get(f"/v1/account/auth/status?pending_id={pending_id}")
    assert pending.status_code == 200
    assert pending.json().get("status") == "pending"

    # Magic link is logged to stdout in dev. Extract the token from it.
    link = _extract_link_from_logs(capsys)
    assert link, "expected magic-link to be logged in dev mode"
    token_match = re.search(r"[?&]token=([^&]+)", link)
    assert token_match
    token = token_match.group(1)

    # Simulate the user clicking the link on another device.
    verified = client.post("/v1/account/verify", json={"token": token})
    assert verified.status_code == 200, verified.text
    assert verified.json().get("session_token")

    # Polling client picks up the session.
    ready = client.get(f"/v1/account/auth/status?pending_id={pending_id}")
    assert ready.status_code == 200
    rj = ready.json()
    assert rj.get("status") == "ready"
    assert rj.get("session_token")
    assert rj.get("expires_at")

    # Single-shot — replay returns 404 PENDING_NOT_FOUND.
    replay = client.get(f"/v1/account/auth/status?pending_id={pending_id}")
    assert replay.status_code == 404


def test_polling_unknown_pending_id_404(client):
    r = client.get("/v1/account/auth/status?pending_id=" + "a" * 64)
    assert r.status_code == 404


def test_polling_decoy_for_unknown_email_returns_pending_id(client):
    """Enumeration safety: /v1/account/auth with polling=true returns a
    pending_id for unknown emails too. The polling endpoint will then
    permanently 404 on that decoy (indistinguishable from a TTL-expired
    real row)."""
    r = client.post(
        "/v1/account/auth",
        json={"email": "definitely-does-not-exist@example.invalid", "polling": True},
    )
    assert r.status_code == 200
    body = r.json()
    assert body.get("pending_id") and len(body["pending_id"]) >= 32

    # Decoy pending_id was never inserted into the DB → status is 404.
    s = client.get(f"/v1/account/auth/status?pending_id={body['pending_id']}")
    assert s.status_code == 404
