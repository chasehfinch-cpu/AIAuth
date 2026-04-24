// AIAuth C2PA parser — finds and walks Content Credentials in PNG files.
//
// Two responsibilities:
//   1. extractJumbfFromPng(u8) — scan PNG chunks for the caBX chunk (the
//      Adobe PNG binding for JUMBF). Return its payload bytes or null.
//   2. parseJumbfBoxTree(jumbfBytes) — walk the ISO-BMFF-style box tree
//      and return a nested structure so callers can find the active
//      manifest, its claim box, and its signature box.
//
// NOTE: This file is the JS half of a paired implementation. The Python
// mirror lives at tests/test_c2pa_parser.py and the two MUST stay in
// lock-step on the box-walking algorithm. Tests in that file catch
// divergence against a real Firefly-generated fixture.
//
// Non-goals (Tier 3, deferred):
//   - CBOR decoding (see cbor_decoder.js)
//   - COSE_Sign1 parsing
//   - x509 certificate / signer_cn extraction
//   - C2PA trust-anchor validation

/* global self */

const PNG_SIGNATURE = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/** Return true if `u8` looks like a PNG file header. */
function isPng(u8) {
  if (!u8 || u8.length < 8) return false;
  for (let i = 0; i < 8; i++) {
    if (u8[i] !== PNG_SIGNATURE[i]) return false;
  }
  return true;
}

/** Read a big-endian 32-bit unsigned int from u8 at offset p. */
function readU32BE(u8, p) {
  return ((u8[p] << 24) >>> 0) + (u8[p + 1] << 16) + (u8[p + 2] << 8) + u8[p + 3];
}

/** Extract the caBX chunk payload from a PNG byte array. Returns the
 *  payload Uint8Array (without the chunk length/type/CRC), or null if
 *  the file isn't a PNG or has no caBX chunk. */
function extractJumbfFromPng(u8) {
  if (!isPng(u8)) return null;
  let p = 8; // skip PNG signature
  while (p + 12 <= u8.length) {
    const length = readU32BE(u8, p);
    const type = String.fromCharCode(u8[p + 4], u8[p + 5], u8[p + 6], u8[p + 7]);
    if (type === "caBX") {
      const start = p + 8;
      const end = start + length;
      if (end > u8.length) return null;
      return u8.subarray(start, end);
    }
    if (type === "IEND") break;
    p += 8 + length + 4; // 4 CRC bytes trailing
  }
  return null;
}

/** Walk an ISO-BMFF-style box tree. JUMBF uses the same encoding:
 *  4-byte big-endian length + 4-byte ASCII type + payload.
 *
 *  Superboxes of type "jumb" contain child boxes. The first child is
 *  always a "jumd" description box which carries a 16-byte UUID, a
 *  toggle byte, and a null-terminated UTF-8 label string.
 *
 *  Returns a list of { type, length, offset, label, children } nodes.
 *  Recursion capped at maxDepth (default 10) to guard against malformed
 *  input. Nodes whose length is invalid stop the walk at that level. */
function parseJumbfBoxTree(buf, offset = 0, depth = 0, maxDepth = 10) {
  const out = [];
  if (depth > maxDepth) return out;
  let p = 0;
  while (p + 8 <= buf.length) {
    const length = readU32BE(buf, p);
    if (length < 8 || p + length > buf.length) break;
    const typeBytes = [buf[p + 4], buf[p + 5], buf[p + 6], buf[p + 7]];
    const type = String.fromCharCode(typeBytes[0], typeBytes[1], typeBytes[2], typeBytes[3]);

    const node = {
      type,
      length,
      offset: offset + p,
      label: null,
      children: [],
    };

    if (type === "jumb") {
      const childBytes = buf.subarray(p + 8, p + length);
      node.children = parseJumbfBoxTree(childBytes, offset + p + 8, depth + 1, maxDepth);
      if (node.children.length > 0 && node.children[0].type === "jumd") {
        node.label = node.children[0].label;
      }
    }

    if (type === "jumd" && length >= 8 + 16 + 1) {
      // 8 bytes box header + 16 bytes UUID + 1 toggle byte, then label.
      const labelStart = p + 8 + 17;
      const labelEnd = p + length;
      // Find the first NUL byte to terminate the label.
      let nul = -1;
      for (let i = labelStart; i < labelEnd; i++) {
        if (buf[i] === 0) { nul = i; break; }
      }
      if (nul > labelStart) {
        node.label = new TextDecoder("utf-8", { fatal: false })
          .decode(buf.subarray(labelStart, nul));
      }
    }

    out.push(node);
    p += length;
  }
  return out;
}

/** Return every jumb superbox in the tree whose label matches `target`.
 *  Depth-first, exact string match. */
function findBoxesByLabel(tree, target) {
  const out = [];
  for (const node of tree) {
    if (node.label === target) out.push(node);
    if (node.children && node.children.length) {
      out.push(...findBoxesByLabel(node.children, target));
    }
  }
  return out;
}

/** Return the list of manifest superboxes: jumb children of the outer
 *  "c2pa" superbox whose label is a urn:uuid: identifier. */
function findManifests(tree) {
  const outer = tree.find(n => n.label === "c2pa");
  if (!outer) return [];
  return outer.children.filter(n =>
    n.type === "jumb" && n.label && n.label.startsWith("urn:uuid:")
  );
}

/** Per C2PA spec §11.3, the active manifest is the last one in the
 *  JUMBF store. Returns null if no manifest is present. */
function activeManifest(tree) {
  const manifests = findManifests(tree);
  return manifests.length ? manifests[manifests.length - 1] : null;
}

/** Given a content box (not a superbox), return the raw content bytes
 *  from the original JUMBF buffer. Callers use this to pull out the
 *  CBOR payload of a `cbor` box, for example. */
function getBoxContentBytes(box, fullBuf) {
  return fullBuf.subarray(box.offset + 8, box.offset + box.length);
}

/** SHA-256 of a Uint8Array, returned as lowercase hex. Uses Web Crypto. */
async function sha256Hex(u8) {
  const digest = await crypto.subtle.digest("SHA-256", u8);
  const bytes = new Uint8Array(digest);
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

// Export to the service worker's global scope (importScripts pattern).
self.AIAuthC2PA = {
  extractJumbfFromPng,
  parseJumbfBoxTree,
  findBoxesByLabel,
  findManifests,
  activeManifest,
  getBoxContentBytes,
  sha256Hex,
  isPng,
};
