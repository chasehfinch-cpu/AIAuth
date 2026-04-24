"""Key manifest shape — server.build_public_key_manifest().

The manifest is the source of truth clients use to pick the right
public key when verifying a historical receipt. Regressions here
silently break offline verification for rotated-key receipts."""
from __future__ import annotations

import server


def test_manifest_structure():
    m = server.build_public_key_manifest()
    assert isinstance(m, dict)
    assert "keys" in m and isinstance(m["keys"], list)
    assert len(m["keys"]) >= 1
    # Top-level metadata fields served alongside the keys list.
    assert "version" in m
    assert "algorithm" in m
    assert "current_signing_key" in m
    # The declared current_signing_key must appear in the keys list.
    kids = {k["key_id"] for k in m["keys"]}
    assert m["current_signing_key"] in kids


def test_every_key_has_required_fields():
    m = server.build_public_key_manifest()
    for k in m["keys"]:
        # The shape enterprise customers and the extension both rely on.
        for field in ("key_id", "algorithm", "status", "public_key_pem",
                      "valid_from", "valid_until"):
            assert field in k, f"missing {field} on {k.get('key_id')}"
        assert k["algorithm"] == "Ed25519"


def test_exactly_one_active_signing_key():
    """There may be many retired keys, but exactly one must be the
    current signing key. Breaking this invariant means new receipts
    would be signed under ambiguous authority."""
    m = server.build_public_key_manifest()
    active_count = sum(1 for k in m["keys"] if k.get("status") == "active")
    assert active_count == 1, (
        f"Expected exactly 1 active key, found {active_count} in {m['keys']}"
    )


def test_active_key_matches_current_key_id():
    m = server.build_public_key_manifest()
    active = next((k for k in m["keys"] if k.get("status") == "active"), None)
    assert active is not None
    assert active["key_id"] == server.CURRENT_KEY_ID


def test_private_status_not_leaked_by_default():
    """build_public_key_manifest() must never include private-key
    material or private-key-availability flags in its default output.
    That field is gated behind include_private_status=True (admin-only)."""
    m = server.build_public_key_manifest()
    for k in m["keys"]:
        assert "private_key_available" not in k
        assert "private_key_pem" not in k
        assert "private" not in k


def test_private_status_available_under_admin_flag():
    m = server.build_public_key_manifest(include_private_status=True)
    for k in m["keys"]:
        assert "private_key_available" in k
        assert isinstance(k["private_key_available"], bool)


def test_pem_parseable_as_ed25519_public_key():
    """Each published PEM must actually be a valid Ed25519 public key.
    Catches any subtle PEM-encoding regression in the manifest builder."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    m = server.build_public_key_manifest()
    for k in m["keys"]:
        pem = k["public_key_pem"].encode()
        pub = serialization.load_pem_public_key(pem)
        assert isinstance(pub, Ed25519PublicKey)
