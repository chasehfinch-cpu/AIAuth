// AIAuth minimal CBOR decoder (RFC 8949 subset).
//
// Scope: decoding the claim CBOR that C2PA emits. C2PA claims use only
// a small, well-defined subset of CBOR — definite-length maps and
// arrays of integers, text strings, byte strings, booleans, null, and
// tagged values. That's what we implement here. No floats, no
// indefinite-length values, no big integers beyond what fits in a JS
// Number.
//
// If we ever encounter a manifest that uses features outside this
// subset, decode throws a descriptive error and the caller attests
// without c2pa data (graceful degradation — receipts still verify,
// they just lack the optional claim enrichment).
//
// Paired with chrome-extension/c2pa_parser.js. Tested against real
// Firefly claim bytes in tests/test_c2pa_parser.py.

/* global self */

const CBOR_MT_UINT = 0;
const CBOR_MT_NEGINT = 1;
const CBOR_MT_BYTES = 2;
const CBOR_MT_TEXT = 3;
const CBOR_MT_ARRAY = 4;
const CBOR_MT_MAP = 5;
const CBOR_MT_TAG = 6;
const CBOR_MT_SIMPLE = 7;

const SIMPLE_FALSE = 20;
const SIMPLE_TRUE = 21;
const SIMPLE_NULL = 22;
const SIMPLE_UNDEFINED = 23;

class CborError extends Error {
  constructor(msg) { super(msg); this.name = "CborError"; }
}

function readArg(buf, pos, info) {
  // Returns { value, next } where next is the offset past the argument.
  if (info < 24) return { value: info, next: pos };
  if (info === 24) {
    if (pos + 1 > buf.length) throw new CborError("short read u8");
    return { value: buf[pos], next: pos + 1 };
  }
  if (info === 25) {
    if (pos + 2 > buf.length) throw new CborError("short read u16");
    return { value: (buf[pos] << 8) + buf[pos + 1], next: pos + 2 };
  }
  if (info === 26) {
    if (pos + 4 > buf.length) throw new CborError("short read u32");
    // Use unsigned shift to keep the value non-negative.
    const v = (buf[pos] * 0x1000000)
            + (buf[pos + 1] << 16)
            + (buf[pos + 2] << 8)
            + buf[pos + 3];
    return { value: v, next: pos + 4 };
  }
  if (info === 27) {
    // 64-bit integer. JS Numbers are safe up to 2^53 — if we see a real
    // u64 bigger than that we throw rather than silently truncate.
    if (pos + 8 > buf.length) throw new CborError("short read u64");
    const hi = (buf[pos] * 0x1000000)
             + (buf[pos + 1] << 16)
             + (buf[pos + 2] << 8)
             + buf[pos + 3];
    const lo = (buf[pos + 4] * 0x1000000)
             + (buf[pos + 5] << 16)
             + (buf[pos + 6] << 8)
             + buf[pos + 7];
    const v = hi * 0x100000000 + lo;
    if (v > Number.MAX_SAFE_INTEGER) {
      throw new CborError("u64 exceeds safe integer range");
    }
    return { value: v, next: pos + 8 };
  }
  // info 28/29/30 are reserved; info 31 is indefinite-length which we
  // don't support.
  throw new CborError(`unsupported info value ${info}`);
}

function decodeAt(buf, pos) {
  if (pos >= buf.length) throw new CborError("unexpected end of input");
  const initial = buf[pos];
  const mt = initial >> 5;
  const info = initial & 0x1f;
  pos += 1;

  if (mt === CBOR_MT_UINT) {
    const { value, next } = readArg(buf, pos, info);
    return { value, next };
  }

  if (mt === CBOR_MT_NEGINT) {
    const { value, next } = readArg(buf, pos, info);
    return { value: -1 - value, next };
  }

  if (mt === CBOR_MT_BYTES) {
    const { value: len, next: p } = readArg(buf, pos, info);
    if (p + len > buf.length) throw new CborError("short byte string");
    return { value: buf.subarray(p, p + len), next: p + len };
  }

  if (mt === CBOR_MT_TEXT) {
    const { value: len, next: p } = readArg(buf, pos, info);
    if (p + len > buf.length) throw new CborError("short text string");
    const s = new TextDecoder("utf-8", { fatal: false }).decode(buf.subarray(p, p + len));
    return { value: s, next: p + len };
  }

  if (mt === CBOR_MT_ARRAY) {
    const { value: len, next: p } = readArg(buf, pos, info);
    const arr = new Array(len);
    let cur = p;
    for (let i = 0; i < len; i++) {
      const item = decodeAt(buf, cur);
      arr[i] = item.value;
      cur = item.next;
    }
    return { value: arr, next: cur };
  }

  if (mt === CBOR_MT_MAP) {
    const { value: len, next: p } = readArg(buf, pos, info);
    const obj = {};
    let cur = p;
    for (let i = 0; i < len; i++) {
      const k = decodeAt(buf, cur);
      const v = decodeAt(buf, k.next);
      // Coerce non-string map keys (integers) to strings. C2PA claims
      // use text-string keys exclusively, so this almost never fires,
      // but it's defensive for forward-compat.
      const key = typeof k.value === "string" ? k.value : String(k.value);
      obj[key] = v.value;
      cur = v.next;
    }
    return { value: obj, next: cur };
  }

  if (mt === CBOR_MT_TAG) {
    const { next: p } = readArg(buf, pos, info);
    // For our purposes, we don't interpret the tag number — we just
    // return the tagged value directly. (COSE_Sign1 is tag 18, which
    // we don't decode here; that's signature-parsing territory.)
    const inner = decodeAt(buf, p);
    return { value: inner.value, next: inner.next };
  }

  if (mt === CBOR_MT_SIMPLE) {
    if (info === SIMPLE_FALSE) return { value: false, next: pos };
    if (info === SIMPLE_TRUE) return { value: true, next: pos };
    if (info === SIMPLE_NULL) return { value: null, next: pos };
    if (info === SIMPLE_UNDEFINED) return { value: undefined, next: pos };
    // Floats (info 25/26/27 under major type 7) are not supported.
    throw new CborError(`unsupported simple value ${info}`);
  }

  throw new CborError(`unreachable major type ${mt}`);
}

/** Decode a CBOR byte array into a JS value. Throws CborError on any
 *  feature we don't support (floats, indefinite-length, etc.) — caller
 *  should catch and proceed without c2pa enrichment. */
function decodeCbor(buf) {
  if (!(buf instanceof Uint8Array)) {
    throw new CborError("decodeCbor expects a Uint8Array");
  }
  const { value } = decodeAt(buf, 0);
  return value;
}

self.AIAuthCBOR = { decodeCbor, CborError };
