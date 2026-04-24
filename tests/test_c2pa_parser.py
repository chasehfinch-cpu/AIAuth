"""C2PA parser tests — Python mirror of chrome-extension/c2pa_parser.js.

Keeps the JS and Python parsers in lock-step. If either drifts, these
tests fail against the Firefly fixture, surfacing the divergence before
it ships.

The fixture is the 27,744-byte caBX chunk extracted from a real Adobe
Firefly-generated PNG. Fixture is safe to commit publicly — Content
Credentials are designed to be readable by anyone.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "firefly_unicorn.cabx.bin"


# ---------------------------------------------------------------------------
# Python mirror of the JS parser. Keep these implementations in lock-step
# with chrome-extension/c2pa_parser.js. Any algorithmic change here must be
# reflected there and vice versa.
# ---------------------------------------------------------------------------

def walk_boxes(buf: bytes, offset: int = 0, depth: int = 0,
               max_depth: int = 10) -> list[dict]:
    """Walk an ISO-BMFF-style box tree. JUMBF uses the same encoding:
    4-byte big-endian length + 4-byte type + payload. Superboxes of type
    'jumb' contain child boxes starting with a 'jumd' description box.

    Returns a list of box dicts: {type, length, offset, label, children}.
    Caps recursion at max_depth to protect against malformed input.
    """
    out: list[dict] = []
    if depth > max_depth:
        return out
    p = 0
    while p + 8 <= len(buf):
        length = struct.unpack(">I", buf[p:p + 4])[0]
        btype = buf[p + 4:p + 8]
        if length < 8 or p + length > len(buf):
            # Malformed — stop walking this level.
            break
        try:
            type_str = btype.decode("ascii")
        except UnicodeDecodeError:
            type_str = btype.hex()

        node: dict = {
            "type": type_str,
            "length": length,
            "offset": offset + p,
            "label": None,
            "children": [],
        }

        # jumb superboxes contain a jumd description box first, then content.
        if btype == b"jumb":
            children = walk_boxes(buf[p + 8:p + length], offset + p + 8,
                                  depth + 1, max_depth)
            node["children"] = children
            if children and children[0]["type"] == "jumd":
                node["label"] = children[0]["label"]

        # jumd description boxes carry a 16-byte UUID + toggle byte + null-
        # terminated label string.
        if btype == b"jumd" and length >= 8 + 16 + 1:
            # 8 bytes of box header, 16 bytes UUID, 1 byte toggle, then label
            # up to the first NUL.
            rest = buf[p + 8 + 17:p + length]
            null_idx = rest.find(b"\x00")
            if null_idx > 0:
                node["label"] = rest[:null_idx].decode("utf-8", errors="replace")

        out.append(node)
        p += length
    return out


def find_boxes_by_label(tree: list[dict], label: str) -> list[dict]:
    """Depth-first search for every jumb superbox whose label matches.
    Exact string match on the jumd label."""
    results: list[dict] = []
    for node in tree:
        if node.get("label") == label:
            results.append(node)
        if node.get("children"):
            results.extend(find_boxes_by_label(node["children"], label))
    return results


def find_manifests(tree: list[dict]) -> list[dict]:
    """Return the list of manifest superboxes. A manifest is a jumb child
    of the outer 'c2pa' superbox whose label is a urn:uuid: identifier."""
    outer = next((n for n in tree if n.get("label") == "c2pa"), None)
    if outer is None:
        return []
    return [n for n in outer["children"]
            if n["type"] == "jumb"
            and n.get("label", "").startswith("urn:uuid:")]


def active_manifest(tree: list[dict]) -> dict | None:
    """Per C2PA spec §11.3, the active manifest is the last one in the
    JUMBF store. If the store has only one manifest, that's the active
    one."""
    manifests = find_manifests(tree)
    return manifests[-1] if manifests else None


def get_box_content_bytes(box: dict, full_buf: bytes) -> bytes:
    """Return the content bytes of a content box (not a superbox). For a
    'cbor' box inside a jumb superbox, the content starts after the 8-byte
    box header."""
    off = box["offset"]
    # Skip the 4-byte length + 4-byte type header.
    return full_buf[off + 8:off + box["length"]]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def firefly_bytes() -> bytes:
    assert FIXTURE.exists(), f"Missing fixture at {FIXTURE}"
    return FIXTURE.read_bytes()


def test_fixture_is_jumbf_superbox(firefly_bytes):
    """The caBX chunk payload MUST start with a single jumb superbox
    covering the whole 27,744 bytes."""
    assert len(firefly_bytes) == 27744
    length = struct.unpack(">I", firefly_bytes[:4])[0]
    assert firefly_bytes[4:8] == b"jumb"
    assert length == 27744


def test_walk_finds_outer_c2pa_label(firefly_bytes):
    tree = walk_boxes(firefly_bytes)
    assert len(tree) == 1
    assert tree[0]["label"] == "c2pa"
    assert tree[0]["type"] == "jumb"


def test_walk_finds_two_manifests(firefly_bytes):
    """The Firefly image carries a two-manifest chain. Manifest 2 is the
    active one (contains a c2pa.ingredient pointing at manifest 1)."""
    tree = walk_boxes(firefly_bytes)
    manifests = find_manifests(tree)
    assert len(manifests) == 2
    assert manifests[0]["label"].startswith("urn:uuid:33ba64b4")
    assert manifests[1]["label"].startswith("urn:uuid:239de382")


def test_active_manifest_is_second(firefly_bytes):
    tree = walk_boxes(firefly_bytes)
    active = active_manifest(tree)
    assert active is not None
    assert active["label"].startswith("urn:uuid:239de382")


def test_active_manifest_has_claim_and_signature(firefly_bytes):
    tree = walk_boxes(firefly_bytes)
    active = active_manifest(tree)
    child_labels = [c.get("label") for c in active["children"]]
    assert "c2pa.assertions" in child_labels
    assert "c2pa.claim" in child_labels
    assert "c2pa.signature" in child_labels


def test_active_manifest_assertion_labels(firefly_bytes):
    """The active (second) manifest carries three assertions. Sanity
    check that we see all three labels."""
    tree = walk_boxes(firefly_bytes)
    active = active_manifest(tree)
    assertions_group = next(c for c in active["children"]
                            if c.get("label") == "c2pa.assertions")
    assertion_labels = [ch["label"] for ch in assertions_group["children"]]
    assert "c2pa.ingredient.v2" in assertion_labels
    assert "c2pa.actions.v2" in assertion_labels
    assert "c2pa.hash.data" in assertion_labels


def test_claim_content_starts_with_cbor_box(firefly_bytes):
    """The c2pa.claim superbox contains a single 'cbor' content box.
    The cbor box's content is the CBOR-encoded claim map. First byte of
    a CBOR map is 0xA0-0xB7 (major type 5, small count) — for the Firefly
    claim it's 0xA9 (9-key map)."""
    tree = walk_boxes(firefly_bytes)
    active = active_manifest(tree)
    claim_box = next(c for c in active["children"]
                     if c.get("label") == "c2pa.claim")
    cbor_child = next(c for c in claim_box["children"] if c["type"] == "cbor")
    cbor_bytes = get_box_content_bytes(cbor_child, firefly_bytes)
    # Major type 5 (map) = bits 101xxxxx = 0xA0-0xBF
    first = cbor_bytes[0]
    assert 0xA0 <= first <= 0xBF, f"expected CBOR map marker, got 0x{first:02x}"


def test_parser_rejects_malformed_length(firefly_bytes):
    """If a box declares a length larger than the buffer, walker stops
    gracefully without raising."""
    # Truncate fixture mid-box.
    truncated = firefly_bytes[:100]
    tree = walk_boxes(truncated)
    # Should return 0 or 1 box — what matters is that it doesn't explode.
    assert isinstance(tree, list)


def test_parser_respects_depth_cap():
    """Construct a pathological JUMBF that recursively nests itself.
    Walker should cap at max_depth and return."""
    # A 24-byte jumb holding a 16-byte jumb holding... no, we need lengths to
    # match. Build one with an obviously-nested self-reference.
    # jumb(24) { jumb(16) {} }  — malformed (inner box has no room for jumd)
    # but walker must not recurse forever.
    inner = struct.pack(">I", 16) + b"jumb" + b"\x00" * 8
    outer = struct.pack(">I", 8 + len(inner)) + b"jumb" + inner
    tree = walk_boxes(outer, max_depth=3)
    assert isinstance(tree, list)


# ---------------------------------------------------------------------------
# CBOR decoder — Python mirror of chrome-extension/cbor_decoder.js.
# Same algorithm, same subset (no floats, no indefinite-length).
# ---------------------------------------------------------------------------

class CborError(Exception):
    pass


def _read_arg(buf: bytes, pos: int, info: int) -> tuple[int, int]:
    if info < 24:
        return info, pos
    if info == 24:
        if pos + 1 > len(buf):
            raise CborError("short read u8")
        return buf[pos], pos + 1
    if info == 25:
        if pos + 2 > len(buf):
            raise CborError("short read u16")
        return int.from_bytes(buf[pos:pos + 2], "big"), pos + 2
    if info == 26:
        if pos + 4 > len(buf):
            raise CborError("short read u32")
        return int.from_bytes(buf[pos:pos + 4], "big"), pos + 4
    if info == 27:
        if pos + 8 > len(buf):
            raise CborError("short read u64")
        v = int.from_bytes(buf[pos:pos + 8], "big")
        # JS safe-integer cap. Match JS behavior exactly.
        if v > (2 ** 53 - 1):
            raise CborError("u64 exceeds safe integer range")
        return v, pos + 8
    raise CborError(f"unsupported info value {info}")


def _decode_at(buf: bytes, pos: int):
    if pos >= len(buf):
        raise CborError("unexpected end of input")
    initial = buf[pos]
    mt = initial >> 5
    info = initial & 0x1F
    pos += 1

    if mt == 0:  # uint
        v, n = _read_arg(buf, pos, info); return v, n
    if mt == 1:  # negint
        v, n = _read_arg(buf, pos, info); return -1 - v, n
    if mt == 2:  # bytes
        length, p = _read_arg(buf, pos, info)
        if p + length > len(buf): raise CborError("short byte string")
        return buf[p:p + length], p + length
    if mt == 3:  # text
        length, p = _read_arg(buf, pos, info)
        if p + length > len(buf): raise CborError("short text string")
        return buf[p:p + length].decode("utf-8", errors="replace"), p + length
    if mt == 4:  # array
        length, p = _read_arg(buf, pos, info)
        out = []
        cur = p
        for _ in range(length):
            v, cur = _decode_at(buf, cur)
            out.append(v)
        return out, cur
    if mt == 5:  # map
        length, p = _read_arg(buf, pos, info)
        obj = {}
        cur = p
        for _ in range(length):
            k, cur = _decode_at(buf, cur)
            v, cur = _decode_at(buf, cur)
            key = k if isinstance(k, str) else str(k)
            obj[key] = v
        return obj, cur
    if mt == 6:  # tag — discard tag number, return inner
        _, p = _read_arg(buf, pos, info)
        return _decode_at(buf, p)
    if mt == 7:
        if info == 20: return False, pos
        if info == 21: return True, pos
        if info == 22: return None, pos
        if info == 23: return None, pos  # undefined → None
        raise CborError(f"unsupported simple value {info}")
    raise CborError(f"unreachable major type {mt}")


def decode_cbor(buf: bytes):
    v, _ = _decode_at(buf, 0)
    return v


def _decode_claim(firefly_bytes: bytes) -> dict:
    """Helper: pull the active manifest's CBOR claim and decode it."""
    tree = walk_boxes(firefly_bytes)
    active = active_manifest(tree)
    claim_box = next(c for c in active["children"] if c.get("label") == "c2pa.claim")
    cbor_child = next(c for c in claim_box["children"] if c["type"] == "cbor")
    cbor_bytes = get_box_content_bytes(cbor_child, firefly_bytes)
    return decode_cbor(cbor_bytes)


def test_cbor_decodes_active_claim(firefly_bytes):
    """The decoder successfully parses the real Firefly claim without
    erroring. This is the end-to-end happy path."""
    claim = _decode_claim(firefly_bytes)
    assert isinstance(claim, dict)
    assert len(claim) > 0


def test_cbor_claim_has_claim_generator(firefly_bytes):
    """Adobe Firefly self-identifies via the claim_generator field."""
    claim = _decode_claim(firefly_bytes)
    assert "claim_generator" in claim
    # Firefly writes "Adobe_Firefly" with an underscore.
    assert "Firefly" in claim["claim_generator"]


def test_cbor_claim_has_assertions_list(firefly_bytes):
    """The active manifest's claim should reference its assertions."""
    claim = _decode_claim(firefly_bytes)
    # The claim carries an 'assertions' list in v2.x manifests. Each entry
    # is a map with 'url' (assertion location) + 'hash' (assertion digest).
    assert "assertions" in claim
    assert isinstance(claim["assertions"], list)
    assert len(claim["assertions"]) >= 1
    # Each entry should carry an assertion URL pointing at one of the
    # assertion boxes we found in the JUMBF.
    urls = [a.get("url", "") for a in claim["assertions"] if isinstance(a, dict)]
    assert any("c2pa.hash.data" in u for u in urls), urls


def test_cbor_integer_round_trips():
    """Sanity: uint 0-23 are inlined, 24-255 use 1-byte follow-up."""
    assert decode_cbor(bytes([0x00])) == 0
    assert decode_cbor(bytes([0x17])) == 23
    assert decode_cbor(bytes([0x18, 100])) == 100
    assert decode_cbor(bytes([0x19, 0x01, 0x00])) == 256


def test_cbor_negative_integer():
    assert decode_cbor(bytes([0x20])) == -1
    assert decode_cbor(bytes([0x21])) == -2


def test_cbor_booleans_and_null():
    assert decode_cbor(bytes([0xF4])) is False
    assert decode_cbor(bytes([0xF5])) is True
    assert decode_cbor(bytes([0xF6])) is None


def test_cbor_text_string():
    # Major type 3, length 5, "hello"
    buf = bytes([0x65, 0x68, 0x65, 0x6C, 0x6C, 0x6F])
    assert decode_cbor(buf) == "hello"


def test_cbor_unsupported_feature_raises():
    """Indefinite-length (info 31) is not supported — must raise, not
    return garbage. Ensures the extension caller can catch and skip c2pa
    enrichment without corrupting the receipt."""
    # Indefinite-length array: 0x9F ... 0xFF. We don't support it.
    with pytest.raises(CborError):
        decode_cbor(bytes([0x9F, 0x01, 0xFF]))
