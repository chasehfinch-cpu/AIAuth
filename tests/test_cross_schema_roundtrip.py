"""Ed25519 round-trip tests across the receipt schema envelope.

Addresses Promise Audit gap #16: the claim "Ed25519 round-trip works for
every shipping schema version" had no automated coverage. These tests
sign three receipts shaped like v0.4.0, v0.5.0, and v0.5.2 respectively,
then run each through check_sig() and assert the signature validates.

They also probe the failure surface — tampering with any signed field
must break verification — so the test suite catches accidental schema
regressions, not just the happy path.

The tests call server.sign() / server.check_sig() directly rather than
spinning up the full FastAPI app. That keeps this suite fast and
isolates crypto behavior from HTTP/DB layers.
"""
from __future__ import annotations

import copy

import pytest

# server module is import-once (has init-on-import side effects — DB
# creation, key generation). conftest.py has already pointed it at a
# temp directory.
import server  # noqa: E402


# --- v0.4.0 receipt -------------------------------------------------------
# No key_id field. Exercises the legacy-fallback branch of check_sig():
# "tries every loaded key" when the receipt predates key manifest
# versioning. (server.py:532-538)

def _v0_4_0_receipt() -> dict:
    return {
        "v": "0.4.0",
        "id": "11111111-2222-3333-4444-555555555555",
        "ts": "2025-06-01T10:00:00Z",
        "hash": "a" * 64,
        "uid": "alice@example.com",
        "model": "claude-3-opus",
        "provider": "anthropic",
        "review_status": "approved",
    }


# --- v0.5.0 receipt -------------------------------------------------------
# Adds key_id (primary verification path), prompt_hash, source_domain,
# and file_type.

def _v0_5_0_receipt() -> dict:
    return {
        "v": "0.5.0",
        "id": "22222222-3333-4444-5555-666666666666",
        "ts": "2026-02-14T08:30:00Z",
        "hash": "b" * 64,
        "uid": "bob@example.com",
        "key_id": server.CURRENT_KEY_ID,
        "model": "claude-sonnet-4",
        "provider": "anthropic",
        "prompt_hash": "c" * 64,
        "source_domain": "claude.ai",
        "file_type": "prose",
        "len": 1280,
        "tta": 42,
        "review_status": "approved",
    }


# --- v0.5.2 receipt -------------------------------------------------------
# Adds c2pa_manifest_hash folded into ai_markers.c2pa.manifest_hash per
# RECEIPT_SPEC §3.2.1. Exercises the v1.3.0 Data Depth schema addition.

def _v0_5_2_receipt() -> dict:
    return {
        "v": "0.5.2",
        "id": "33333333-4444-5555-6666-777777777777",
        "ts": "2026-04-24T15:00:00Z",
        "hash": "d" * 64,
        "uid": "carol@example.com",
        "key_id": server.CURRENT_KEY_ID,
        "model": "gemini",
        "provider": "google",
        "len": 900,
        "tta": 8,  # short tta — rubber-stamp rule would flag in the dashboard
        "ai_markers": {
            "source": "gemini",
            "provider": "google",
            "verified": True,
            "c2pa": {"manifest_hash": "e" * 64},
        },
        "content_hash_canonical": "f" * 64,
    }


# --- Round-trip tests -----------------------------------------------------

@pytest.mark.parametrize(
    "receipt_factory,label",
    [
        (_v0_4_0_receipt, "v0.4.0 (no key_id, legacy fallback)"),
        (_v0_5_0_receipt, "v0.5.0 (key_id primary path)"),
        (_v0_5_2_receipt, "v0.5.2 (Data Depth: ai_markers.c2pa)"),
    ],
)
def test_sign_verify_roundtrip(receipt_factory, label):
    """Sign each schema version with the current key and confirm check_sig()
    returns True. Fails loud if any schema field trips the canonical JSON
    serializer in server.sign()."""
    receipt = receipt_factory()
    signature = server.sign(receipt)
    assert server.check_sig(receipt, signature) is True, (
        f"check_sig returned False for {label}. "
        f"Either the signer or verifier rejected a field in the schema."
    )


@pytest.mark.parametrize(
    "receipt_factory",
    [_v0_4_0_receipt, _v0_5_0_receipt, _v0_5_2_receipt],
)
def test_tampered_hash_fails_verify(receipt_factory):
    """Changing the content hash after signing must invalidate the receipt.
    Guards against accidental changes to the canonical JSON encoder that
    would make the signature ignore fields."""
    receipt = receipt_factory()
    signature = server.sign(receipt)
    tampered = copy.deepcopy(receipt)
    tampered["hash"] = "0" * 64
    assert server.check_sig(tampered, signature) is False


def test_tampered_c2pa_fails_verify_v0_5_2():
    """The ai_markers.c2pa.manifest_hash sub-field must be covered by the
    signature, not just the top-level fields. If this ever starts passing
    with a tampered manifest_hash, the canonical serializer is excluding
    nested fields and the v0.5.2 addition silently leaked trust."""
    receipt = _v0_5_2_receipt()
    signature = server.sign(receipt)
    tampered = copy.deepcopy(receipt)
    tampered["ai_markers"]["c2pa"]["manifest_hash"] = "0" * 64
    assert server.check_sig(tampered, signature) is False


def test_garbage_signature_rejected():
    """check_sig must return False, not raise, on malformed base64 input.
    Prevents an attacker from crashing the verifier with adversarial input."""
    receipt = _v0_5_0_receipt()
    assert server.check_sig(receipt, "not-valid-base64!!!") is False
    assert server.check_sig(receipt, "") is False


def test_key_id_mismatch_legacy_fallback():
    """A receipt with a key_id pointing at an unknown key should still
    verify via the legacy-fallback branch (check_sig tries every loaded
    key). Guards the branch that keeps v0.4.0 receipts valid after key
    manifest versioning was introduced in v0.5.0."""
    receipt = _v0_5_0_receipt()
    signature = server.sign(receipt)
    # Rewrite key_id to a value the registry doesn't have. The signed
    # payload already committed the REAL key_id, so tampering with it
    # here changes the payload hash — signature should NOT verify.
    tampered = copy.deepcopy(receipt)
    tampered["key_id"] = "key_does_not_exist"
    assert server.check_sig(tampered, signature) is False

    # Dropping key_id altogether (simulating a legacy v0.4.0-shaped
    # receipt signed without committing to a key_id) mirrors the actual
    # legacy case and must verify via fallback.
    legacy = copy.deepcopy(receipt)
    del legacy["key_id"]
    legacy_sig = server.sign(legacy)
    assert server.check_sig(legacy, legacy_sig) is True
