# AIAuth Receipt Format — v0.5.0

**Status:** Stable
**License:** Apache 2.0 (you may implement this spec in any software, open or
proprietary, without restriction).
**Reference implementation:** [aiauth.app](https://www.aiauth.app) — source at
[github.com/chasehfinch-cpu/AIAuth](https://github.com/chasehfinch-cpu/AIAuth)
**Public signing keys:** [aiauth.app/v1/public-key](https://www.aiauth.app/v1/public-key)
· [/.well-known/aiauth-public-key](https://www.aiauth.app/.well-known/aiauth-public-key)

---

## 1. Purpose

An AIAuth receipt is a signed statement that a specific piece of content
existed at a specific time, was reviewed by a specific attester, and
optionally belongs to a chain of custody referencing prior versions. The
receipt is designed to be:

- **Verifiable offline** — given the receipt and the public signing key, any
  party can confirm the signature without contacting any server.
- **Privacy-preserving** — the receipt contains only a hash of the content,
  never the content itself.
- **Forward-compatible** — new optional fields may be added in minor
  versions; existing fields are never removed or renamed.

## 2. Receipt Structure

A receipt is a JSON object with the fields defined in §3 plus a detached
signature. The canonical serialization for signing is defined in §4.

### 2.1 Minimal example

```json
{
  "v": "0.5.0",
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "ts": "2026-04-21T20:15:30Z",
  "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "uid": "jane@example.com",
  "key_id": "key_001",
  "signature": "base64url-encoded-ed25519-signature"
}
```

### 2.2 Full example

```json
{
  "v": "0.5.0",
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "ts": "2026-04-21T20:15:30Z",
  "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "content_hash_canonical": "b7c3a91f2e4d8a6c5b9f1e2d7c8a4b6f3e5d9c1a7b2f8e4d6c5a9b3f7e1d2c8a",
  "prompt_hash": "c8a4b6f3e5d9c1a7b2f8e4d6c5a9b3f7e1d2c8ab7c3a91f2e4d8a6c5b9f1e2d7",
  "uid": "jane@company.com",
  "key_id": "key_001",
  "client_integrity": "extension",
  "src": "chrome-extension",
  "model": "claude-sonnet-4",
  "provider": "anthropic",
  "source_domain": "claude.ai",
  "source_app": "Google Chrome",
  "ai_markers": {"source": "docx-copilot", "verified": true},
  "doc_id": "DOC_7890abcd1234",
  "parent": "abc123def456...",
  "file_type": "spreadsheet",
  "len": 24500,
  "review": {
    "status": "approved",
    "by": "jane@company.com",
    "at": "2026-04-21T20:15:30Z",
    "note": "Verified margin assumptions against Q2 actuals"
  },
  "tags": ["q3-forecast"],
  "signature": "base64url-encoded-ed25519-signature"
}
```

## 3. Field Reference

### 3.1 Required fields (all tiers)

| Field | Type | Description |
|---|---|---|
| `v` | string | Schema version, e.g. `"0.5.0"`. Implementations MUST accept any version `>= 0.4.0` and ignore unknown fields. |
| `id` | string | Unique receipt ID. UUID v4 format recommended. |
| `ts` | string | Attestation timestamp. ISO 8601 with `Z` timezone suffix. |
| `hash` | string | SHA-256 hex digest of the content (see §5 for canonicalization rules). |
| `uid` | string | Attester identifier. Typically an email address; opaque to the signing server. |
| `key_id` | string | Identifier of the signing key used. MUST match an entry in the server's published `key_manifest`. |
| `signature` | string | Base64url-encoded Ed25519 signature over the canonical serialization of all other fields. |

### 3.2 Optional fields (both tiers)

| Field | Type | Description |
|---|---|---|
| `content_hash_canonical` | string | SHA-256 of format-normalized text (see §5.2). Enables cross-format chain discovery. |
| `prompt_hash` | string | SHA-256 of the prompt that produced this content, normalized per §5.1. Server MUST NOT persist in the public registry. |
| `client_integrity` | string | Client verification level: `"none"` \| `"extension"` \| `"os-verified"`. |
| `src` | string | Client surface: `"chrome-extension"` \| `"desktop-agent"` \| `"litellm-callback"` \| other. |
| `model` | string | AI model identifier (e.g. `"claude-sonnet-4"`). |
| `provider` | string | AI provider (e.g. `"anthropic"`). |
| `source_domain` | string | Browser hostname where AI interaction happened. |
| `source_app` | string | Active application name (desktop agent). |
| `ai_markers` | object | Detected AI authorship signals: `{source: string, verified: bool, c2pa?: object}`. See §3.2.1 for the C2PA sub-object. |
| `doc_id` | string | Persistent document identifier for file chain-of-custody. |
| `parent` | string | `hash` of the previous version in a `doc_id` chain. |
| `file_type` | string | Content category: `"prose"` \| `"code"` \| `"spreadsheet"` \| `"image"` \| `"pdf"` \| `"other"`. |
| `len` | integer | Content length in characters or bytes. |
| `review` | object | Human review: `{status, by, at, note?}`. |
| `tags` | array | User-supplied string labels. |

### 3.2.1 `ai_markers.c2pa` — C2PA / Content Credentials interop

When the attested content carries a C2PA manifest (Content Credentials — the
dominant open standard for media provenance), clients SHOULD surface the
manifest's identity to the receipt under `ai_markers.c2pa`. This lets a
verifier correlate an AIAuth human-review attestation with the upstream
tool-provenance chain without either system having to rewrite the other's
data.

Recommended sub-object shape:

```json
{
  "ai_markers": {
    "source": "dalle-3",
    "verified": true,
    "c2pa": {
      "manifest_hash": "sha256:3c5f...e1a2",
      "claim_generator": "Adobe Firefly 2026.1",
      "assertions": ["c2pa.actions", "c2pa.ingredient"],
      "signer_cn": "Adobe Inc.",
      "signed_at": "2026-04-18T10:22:00Z"
    }
  }
}
```

Field notes:

- `manifest_hash` — SHA-256 of the serialized C2PA manifest. Canonical
  interop primitive; required if `c2pa` is present.
- `claim_generator` — the C2PA `claim_generator` string, verbatim.
- `assertions` — list of assertion labels present in the manifest.
- `signer_cn` — Common Name of the manifest's signing certificate.
- `signed_at` — the C2PA signature time, distinct from AIAuth `ts`.

Forward-compatibility: a future AIAuth minor version may define a native
C2PA *assertion type* (`aiauth.app/human-review/v1`) that lets an AIAuth
receipt be embedded directly inside a Content Credentials manifest. Until
that assertion type ships, use the `ai_markers.c2pa` sub-object above.

### 3.3 Commercial-tier optional fields

These fields are populated only by enterprise-configured clients and are
always absent from free-tier receipts. Implementations MUST NOT treat their
presence on a receipt as proof of enterprise status — they are advisory.

| Field | Type | Description |
|---|---|---|
| `tta` | integer | Time-to-attest in seconds (interval from AI output to attestation). |
| `sid` | string | Session identifier grouping related attestations. |
| `dest` | string | Detected destination: `"email"` \| `"messaging"` \| `"document-platform"` \| `"code-repository"`. |
| `dest_ext` | boolean | Whether the destination is external to the attester's org. |
| `classification` | string | Suggested classification: `"financial"` \| `"legal"` \| `"client-facing"` \| `"internal"`. |
| `concurrent_ai_apps` | array | AI applications detected open at attestation time (allowlist-gated). |

## 4. Canonical Serialization and Signing

### 4.1 Canonicalization

Before signing, the receipt object (excluding the `signature` field) is
serialized to canonical JSON:

1. Remove the `signature` field if present.
2. Serialize to JSON with:
   - UTF-8 encoding
   - Keys sorted lexicographically at every nesting level
   - No insignificant whitespace
   - `null` values omitted (absent-is-null is equivalent to explicit-null)
3. The resulting byte string is the "signing input."

### 4.2 Signing

Signature algorithm: **Ed25519** (RFC 8032).

The 64-byte signature is base64url-encoded (no padding) and placed in the
`signature` field to produce the final receipt.

### 4.3 Verification

A verifier:
1. Retrieves the public key for `receipt.key_id` from the server's published
   key manifest (or a locally cached copy).
2. Confirms `receipt.ts` falls within the key's `valid_from` / `valid_until`
   window from the manifest.
3. Removes the `signature` field from the receipt.
4. Re-serializes per §4.1 to obtain the signing input.
5. Verifies the Ed25519 signature.

If any step fails, the receipt is invalid.

## 5. Content Hashing

### 5.1 Text content (required)

The `hash` field is the SHA-256 of the content after the following
normalization:

1. Collapse all runs of whitespace (spaces, tabs, newlines) into a single
   ASCII space.
2. Trim leading and trailing whitespace.
3. Encode the result as UTF-8.
4. Compute SHA-256 of the UTF-8 byte sequence.
5. Lowercase hex encoding.

For `prompt_hash`, apply the same normalization to the prompt text before
hashing. Normalization of prompts is optional but recommended — it lets
verifiers match prompts that differ only in whitespace or trailing newlines.

### 5.2 Canonical text content (optional, recommended)

`content_hash_canonical` enables chain discovery across format conversions
(e.g., Excel → CSV → PDF of the same table). To compute it:

1. Extract text content from the file using a format-specific extractor
   (see reference implementation in `self-hosted/aiauth_canonical.py`).
2. Lowercase the extracted text.
3. Collapse whitespace per §5.1 step 1–2.
4. UTF-8 encode.
5. SHA-256.

Extractors are best-effort; if extraction fails or produces fewer than 10
characters, `content_hash_canonical` SHOULD be omitted rather than set to a
meaningless value.

### 5.3 Raw file content (fallback)

For binary files with no useful text extraction (images without OCR,
archives, etc.), `hash` is the SHA-256 of the raw file bytes. No
normalization.

## 6. Chain Semantics

A chain of receipts represents version history for a logical document
identified by a shared `doc_id`. Each receipt after the first carries
`parent` = the `hash` of the previous version.

A verifier reconstructs the chain by:
1. Grouping receipts by `doc_id`.
2. Sorting by `ts`.
3. Confirming each receipt's `parent` equals the previous receipt's `hash`.

A chain is "intact" if every link is verified; "broken" otherwise. Broken
chains are meaningful — they indicate that a receipt in the sequence was
removed, tampered with, or not attested.

## 7. Privacy Invariants

Implementers MUST preserve the following properties:

1. **Content absence.** Receipts MUST NOT contain content; only its hash.
2. **Prompt absence.** Receipts MUST NOT contain prompt text; only its hash.
3. **Anonymous registry.** A public signing server MAY maintain a registry
   of `{hash, receipt_id, parent_hash, doc_id, registered_at,
   content_hash_canonical}`. It MUST NOT add `prompt_hash`, `uid`, `model`,
   `tta`, or any other potentially-identifying field to the public registry.
4. **Free-tier capture floor.** Free-tier clients MUST omit
   `tta`, `sid`, `dest`, `dest_ext`, `classification`, and
   `concurrent_ai_apps`. These fields MAY be captured only when the client
   is explicitly configured for enterprise operation.
5. **Local receipt storage.** Clients MUST store receipts on the user's
   device. Receipts MUST NOT be automatically uploaded to the signing server
   or any third party beyond the enterprise ingest endpoint when explicitly
   configured.

## 8. Versioning

- Minor versions (0.5 → 0.6) MAY add optional fields. Existing fields MUST
  NOT be renamed, retyped, or removed.
- Major versions (0.x → 1.0, 1.x → 2.0) MAY introduce breaking changes but
  MUST provide migration guidance and a compatibility window.
- Servers MUST accept any receipt with `v >= 0.4.0`. Unknown fields are
  ignored at the signing layer; the verifier may choose to surface unknown
  fields to the user as "vendor-specific data."

## 9. Public-Key Distribution

The signing server publishes a key manifest:

```json
{
  "keys": [
    {
      "key_id": "key_001",
      "algorithm": "Ed25519",
      "valid_from": "2026-06-01T00:00:00Z",
      "valid_until": null,
      "status": "active",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
    }
  ],
  "current_signing_key": "key_001"
}
```

Retrieved at `GET /v1/public-key` and `GET /.well-known/aiauth-public-key`.
The `.well-known` path is the recommended long-term discovery path; the
`/v1/` path is an alias for convenience.

Verifiers SHOULD cache the manifest and refresh periodically (daily is
sufficient). A receipt whose `key_id` is not in the manifest is invalid.

## 10. Changelog

### v0.5.0 (2026-04)
- Added: `key_id`, `client_integrity`, `model`, `provider`, `source_domain`,
  `source_app`, `file_type`, `len`, `tta`, `sid`, `dest`, `dest_ext`,
  `classification`, `tags`, `prompt_hash`, `ai_markers`,
  `concurrent_ai_apps`, `content_hash_canonical`.
- Clarified: free vs. commercial tier capture split.
- Formalized: canonical serialization for signing.

### v0.4.0 (2026-01)
- Initial published spec: `v`, `id`, `ts`, `hash`, `uid`, `src`, `doc_id`,
  `parent`, `review.*`.

---

Questions or proposals: open an issue at
[github.com/chasehfinch-cpu/AIAuth](https://github.com/chasehfinch-cpu/AIAuth)
with the `rfc` label.
