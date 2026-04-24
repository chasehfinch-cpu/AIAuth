"""SignRequest pydantic schema validation.

These tests protect the data contract between the Chrome extension,
desktop agent, and server. A quiet breakage here would cause silent
client-side errors across every integration. They cover the three
schema eras: v0.4.0 (minimum required fields), v0.5.0 (additive fields),
v0.5.2 (c2pa_manifest_hash).
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

import server


_VALID_HASH = "a" * 64
_VALID_UID = "alice@example.com"


def _base_body(**overrides) -> dict:
    body = {
        "output_hash": _VALID_HASH,
        "user_id": _VALID_UID,
        "source": "chrome-extension",
    }
    body.update(overrides)
    return body


def test_minimum_required_fields_accepted():
    req = server.SignRequest(**_base_body())
    assert req.output_hash == _VALID_HASH
    assert req.user_id == _VALID_UID


def test_content_length_alias_len_works():
    """SignRequest.content_length aliases 'len' — keeps the on-the-wire
    field short. Breaking this alias would silently drop the field from
    every browser attestation."""
    req = server.SignRequest(**_base_body(len=1280))
    assert req.content_length == 1280

    # And the canonical name also works.
    req2 = server.SignRequest(**_base_body(content_length=500))
    assert req2.content_length == 500


def test_extra_fields_ignored_not_rejected():
    """forward-compat: a newer client can send fields a pre-v0.5.2 server
    doesn't understand without getting a 422."""
    req = server.SignRequest(**_base_body(some_future_field="hello"))
    assert req.output_hash == _VALID_HASH
    assert not hasattr(req, "some_future_field")


def test_every_v0_5_0_optional_field_accepted():
    """Exhaustive: populate every v0.5.0 field and confirm the schema
    accepts them. Catches typos or renames on the server side."""
    req = server.SignRequest(**_base_body(
        model="claude-sonnet-4",
        provider="anthropic",
        review_status="approved",
        reviewer_id="alice@example.com",
        note="test",
        parent_hash="b" * 64,
        tags=["q2-draft"],
        register=False,
        prompt_hash="c" * 64,
        source_domain="claude.ai",
        source_app="Google Chrome",
        file_type="prose",
        len=900,
        doc_id="doc-123",
        ai_markers={"source": "claude", "verified": True},
        client_integrity="extension",
        tta=42,
        sid="abc",
        dest="email",
        dest_ext=True,
        classification="client-facing",
        concurrent_ai_apps=["chatgpt-web"],
    ))
    assert req.model == "claude-sonnet-4"
    assert req.tta == 42
    assert req.register is False  # explicitly supports suppressing registry


def test_v0_5_2_c2pa_field_accepted():
    req = server.SignRequest(**_base_body(c2pa_manifest_hash="e" * 64))
    assert req.c2pa_manifest_hash == "e" * 64


# --- Validation rejections (via _validate_sign_request) -------------------

def _validate_body(body: dict):
    """Parse + run the server-side validator, raising AIAuthError on
    semantic failures (SHA-256 format, user_id presence, etc.)."""
    req = server.SignRequest(**body)
    server._validate_sign_request(req)
    return req


def test_invalid_output_hash_rejected():
    with pytest.raises(server.AIAuthError):
        _validate_body(_base_body(output_hash="not-a-hash"))


def test_short_output_hash_rejected():
    with pytest.raises(server.AIAuthError):
        _validate_body(_base_body(output_hash="a" * 63))


def test_invalid_prompt_hash_rejected():
    with pytest.raises(server.AIAuthError):
        _validate_body(_base_body(prompt_hash="xyz"))


def test_invalid_parent_hash_rejected():
    with pytest.raises(server.AIAuthError):
        _validate_body(_base_body(parent_hash="abc"))


def test_invalid_canonical_hash_rejected():
    with pytest.raises(server.AIAuthError):
        _validate_body(_base_body(content_hash_canonical="gg" * 32))


def test_invalid_c2pa_hash_rejected():
    with pytest.raises(server.AIAuthError):
        _validate_body(_base_body(c2pa_manifest_hash="not-a-hash"))


def test_empty_user_id_rejected():
    with pytest.raises(server.AIAuthError):
        _validate_body(_base_body(user_id=""))


def test_whitespace_only_user_id_rejected():
    with pytest.raises(server.AIAuthError):
        _validate_body(_base_body(user_id="   "))


def test_unknown_client_integrity_rejected():
    with pytest.raises(server.AIAuthError):
        _validate_body(_base_body(client_integrity="os-totally-verified"))


def test_known_client_integrity_values_accepted():
    """Explicit allowlist: none, extension, os-verified (CLAUDE.md
    "Metadata Integrity" levels). Any new level must update the
    validator AND this test."""
    for level in (None, "none", "extension", "os-verified"):
        _validate_body(_base_body(client_integrity=level))


def test_integer_user_id_rejected_by_pydantic():
    """user_id is declared str — pydantic rejects ints, not this hand-
    written validator. Confirms schema still guards types."""
    with pytest.raises(ValidationError):
        server.SignRequest(**_base_body(user_id=12345))
