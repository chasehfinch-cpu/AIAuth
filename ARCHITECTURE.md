# AIAuth Architecture

This document describes the technical architecture of the AIAuth reference
implementation at [aiauth.app](https://www.aiauth.app). It is the canonical
source for external implementers, security reviewers, and enterprise
evaluators. For the wire format of receipts themselves, see
[`docs/RECEIPT_SPEC.md`](docs/RECEIPT_SPEC.md).

---

## 1. Core Principles

These are invariants, not aspirations. Every design decision defers to them.

1. **Content never leaves the user's machine.** Only a SHA-256 hash is sent
   to the signing server.
2. **The public server stores nothing about users' attestations.** Sign,
   forget, move on. Only an anonymous hash registry persists.
3. **Receipts are self-contained proof.** Verifiable offline with the
   published public key.
4. **The chain is the blockchain.** Each receipt references the previous
   version's hash.
5. **Attestation is voluntary.** The onus is on the individual.
6. **The hash registry stores only opaque identifiers.** No names, no
   models, no content, no prompts.
7. **Identity is portable.** A user's attestation history belongs to the
   user, not the employer.
8. **Enterprise visibility is consent-gated.** Corporate access to an
   employee's history requires the user to link their identity.
9. **Clients work offline.** Attestation must not depend on server
   availability.
10. **Data rights are absolute.** Any user can request pseudonymization or
    deletion of their PII.

---

## 2. Surfaces

```
USER SURFACES (auto-capture metadata — user presses one key or right-clicks)
├── Chrome Extension ─────── browser AI tools
├── Desktop Agent (Windows) ─ clipboard + file attestation
├── Desktop Agent (macOS) ─── planned v0.6.0
└── LiteLLM Callback ──────── API-level attestation for developers

         │ sends: hash + metadata (never content)
         │ free-tier clients omit commercial-only fields entirely
         │ (if server unreachable → queue locally, sync later)
         ▼

AIAUTH SERVER (aiauth.app — public; self-hosted for enterprise)
├── PUBLIC MODE (stateless, free, rate-limited)
│   ├── POST /v1/sign ─────────── sign receipt, register hash, forget
│   ├── POST /v1/sign/batch ────── sign queued receipts (offline sync)
│   ├── POST /v1/verify ────────── check signature Y/N + chain discovery
│   ├── POST /v1/verify/chain ──── validate full chain Y/N
│   ├── POST /v1/verify/content ── verify receipt + content hash match
│   ├── POST /v1/verify/prompt ─── verify prompt_hash matches a receipt
│   ├── POST /v1/discover/content  cross-format canonical-hash lookup
│   ├── GET  /v1/discover/{hash} ─ find related receipts in registry
│   ├── GET  /v1/discover/docid ── find all versions of a document
│   ├── GET  /v1/public-key ────── signing key list with validity windows
│   ├── POST /v1/account/* ─────── create / auth / verify / link (§5)
│   ├── POST /v1/waitlist ──────── landing-page signup
│   ├── GET  /check ────────────── public verification webpage
│   ├── GET  /auth ─────────────── magic-link landing page
│   ├── GET  /guide ────────────── user guide
│   └── GET  /health, /docs, /privacy, /public-key
│
└── ENTERPRISE MODE (license-gated, self-hosted)
    ├── All public endpoints, plus:
    ├── POST /v1/enterprise/ingest ─── store receipt metadata in org DB
    ├── POST /v1/enterprise/import ─── import user's exported history
    ├── POST /v1/review/{id} ──────── human review with audit trail
    ├── GET  /v1/attestations ─────── query stored attestations
    ├── GET  /v1/chain/{root} ─────── stored chain queries
    ├── GET  /v1/violations ───────── policy violation feed
    └── POST /v1/admin/* ──────────── org claim / DSAR / pseudonymize
```

---

## 3. Zero-Data Server Principle

Every design decision on the public/free tier defers to this property.

### What the public server persists on free tier

1. **`aiauth_registry.db`** — six anonymous columns: `content_hash`,
   `receipt_id`, `parent_hash`, `doc_id`, `registered_at`,
   `content_hash_canonical`. No PII, no content, no user identifiers.
2. **`aiauth.db` accounts + account_emails** — email-hash + account_id,
   created only when the user explicitly creates an account for
   magic-link authentication. Email addresses are never stored in
   plaintext; see §8.
3. **Auth ephemera** — single-use nonces (auto-pruned after 1 day),
   revoked session IDs.

### What the public server does NOT persist on free tier

- Receipt contents — fully signed and returned to the client, but the
  server discards the request body after signing.
- The content itself. Ever. Only a SHA-256 hash arrives, and hashes are
  one-way.
- Behavioral metadata: `tta`, session grouping, destinations,
  classification, concurrent AI apps.
- Prompt text. Only `prompt_hash` reaches the server, and it is NOT
  added to the public registry.

### What changes on enterprise (self-hosted) tier

Enterprise customers run their own AIAuth server on their own
infrastructure. Their employees' attestation metadata is stored in their
own `enterprise_attestations` table. The data belongs to the employer,
subject to DSAR protections for the individual. AIAuth the company
never sees any of it.

---

## 4. Databases

Two databases, by design.

### 4.1 `aiauth_registry.db` — Anonymous Hash Registry

```sql
CREATE TABLE hash_registry (
    content_hash            TEXT NOT NULL,
    receipt_id              TEXT NOT NULL,
    parent_hash             TEXT,
    doc_id                  TEXT,
    registered_at           TEXT NOT NULL,
    content_hash_canonical  TEXT        -- added in v0.5.0 for cross-format chains
);
CREATE INDEX idx_hr_content   ON hash_registry(content_hash);
CREATE INDEX idx_hr_doc_id    ON hash_registry(doc_id);
CREATE INDEX idx_hr_parent    ON hash_registry(parent_hash);
CREATE INDEX idx_hr_canonical ON hash_registry(content_hash_canonical);
```

Six columns. No names, no models, no content, no prompts. Anonymous.

`prompt_hash` is **deliberately excluded** from the registry — adding it
would create a correlation vector (an attacker with a guessed prompt
could confirm which content_hash matched). `prompt_hash` lives only in
the signed receipt and (on enterprise tier) in `enterprise_attestations`.

### 4.2 `aiauth.db` — Accounts, Orgs, Enterprise Data

Contains account identity, organization membership, consent audit log,
authentication tokens, enterprise attestation store (enterprise mode
only), and policy violations. Every table that references a user's email
stores it as an HMAC hash, not plaintext (see §8).

---

## 5. Authentication Model

### The problem

The account endpoints accept identity parameters but need a way to
verify the caller owns the identity claimed. Without auth, anyone who
guesses an `account_id` could modify consent grants or link malicious
emails.

### The solution — magic link + session tokens

No passwords. No OAuth dependency. The email itself is the
authentication factor.

```
1. User requests auth: POST /v1/account/auth {email}
2. Server generates   magic_token = HMAC(account_id + timestamp + nonce, SERVER_SECRET)
3. Server sends email: https://aiauth.app/auth?token=<magic_token>
4. User clicks link:   GET /auth — renders sign-in page
5. Client exchanges:   POST /v1/account/verify {token}
6. Server validates:   signature, expiration (15 min), single-use (nonce
                        recorded in used_tokens)
7. Server returns:     {session_token, expires_in: 86400, account_id, email}
8. Subsequent authed calls: Authorization: Bearer <session_token>
```

### Token shape

```python
magic_token  = {account_id, email, issued_at, expires_at, nonce, purpose}
session_token = {account_id, email, issued_at, expires_at, session_id, kind: "session"}
```

Both signed: HMAC-SHA256 over canonical JSON with `SERVER_SECRET`.
Nonce replay prevented via `used_tokens` table (auto-pruned after 1 day).
Session revocation via `revoked_sessions` (logout, security incident).

---

## 6. Dual-Path Architecture (Free + Enterprise)

Reconciles the zero-data-server principle with enterprise visibility.

```
PERSONAL USER (free tier):
  Client → POST /v1/sign (public) → signed, hash registered → done
  Receipt stored LOCALLY on the user's machine only
  Public server forgets everything except the anonymous registry entry

ENTERPRISE USER (after org onboarding):
  Client → POST /v1/sign (public)          → signed, hash registered
       └→ POST /v1/enterprise/ingest       → full metadata stored in enterprise DB

  Client makes TWO calls per attest: public sign + enterprise ingest.
  Enterprise ingest requires X-AIAuth-License header, validates that
  uid domain matches the org's claimed domains, evaluates policy engine
  rules, and stores the full receipt (commercial-only fields included)
  in enterprise_attestations.

SELF-HOSTED ENTERPRISE:
  Client → POST /v1/sign (their own server) → signs, registers, stores locally
  One endpoint, internal to their network. No data crosses boundaries.
```

---

## 7. Tier Gating

One receipt schema. The **client** decides which fields to populate
based on tier configuration. The server accepts both shapes without
distinguishing them at sign time — this preserves the property that the
public signing path identifies no one.

### Free tier (default)

Clients populate: `v`, `id`, `ts`, `hash`, `prompt_hash`, `uid`,
`key_id`, `client_integrity`, `src`, `model`, `provider`,
`source_domain`, `source_app`, `ai_markers`, `doc_id`, `parent`,
`file_type`, `len`, `review.*`, `tags`, `content_hash_canonical`.

Clients do NOT populate: `tta`, `sid`, `dest`, `dest_ext`,
`classification`, `concurrent_ai_apps`.

### Commercial tier (enterprise-linked clients)

All free-tier fields, plus the commercial-only fields listed above.

### How the client decides

Chrome extension: reads `chrome.storage.managed` (Google Workspace
managed config) or linked-org status. Desktop agent: reads
`config.yaml` or `/etc/aiauth/config.yaml`.

### Rationale

- **User trust on free tier:** behavioral data is never in the request
  body. The property is structural, not policy.
- **Server simplicity:** signing path is identical both tiers.
- **Audit transparency:** the client's local receipt store shows exactly
  what was sent.

---

## 8. Data Hardening

Threat model: attacker gains full read access to the server filesystem
(root or equivalent). What they see:

| Artifact                             | What they find                           |
|--------------------------------------|------------------------------------------|
| `accounts.primary_email_hash`        | HMAC hash only                           |
| `account_emails.email_hash` (PK)     | HMAC hash only                           |
| `enterprise_attestations.uid_hash`   | HMAC hash + Fernet ciphertext            |
| `consent_log.details_encrypted`      | Fernet ciphertext                        |
| `waitlist_signups.email_hash`        | HMAC hash + Fernet ciphertext            |
| `aiauth_registry.db`                 | 6 anonymous columns (unchanged)          |
| `magic_links.log`                    | Does not exist (disabled by default)     |

### Key derivation (deterministic, from `SERVER_SECRET`)

```python
EMAIL_HASH_SALT   = HMAC-SHA256(SERVER_SECRET, b"email-hash-v1").digest()
DB_ENCRYPTION_KEY = HMAC-SHA256(SERVER_SECRET, b"db-encrypt-v1").digest()[:32]
```

Both derived at startup. If `SERVER_SECRET` leaks, both are compromised
— but the attacker needs `.env` (chmod 600, never in backups), not just a
database dump.

Emails are HMAC-hashed (deterministic, lookup-friendly) AND Fernet-encrypted
(authenticated, decryptable only with the key). The hash is the index;
the ciphertext is what an admin session decrypts when legitimate access
to the plaintext is required (DSAR export, etc.).

### Residual risks (documented, not hidden)

- **Private signing keys in `/opt/aiauth/keys/`** are plaintext PEM. A
  root-level attacker can forge future receipts. Mitigations deferred:
  passphrase-wrapped keys, HSM integration, shorter validity windows.
- **`SERVER_SECRET` + `CLIENT_SECRET` in `.env`** are plaintext. If the
  attacker has both `.env` AND the database, email hashes can be
  brute-forced against known-email wordlists. Defense is `chmod 600`
  and never-in-backups.
- **In-memory plaintext** during request handling. Plaintext email
  lives in the request handler stack for the call's duration. Mitigable
  only via homomorphic encryption.
- **Resend retention.** Transactional-email delivery metadata retains
  recipient email for 30 days on their free tier. Acceptable for free
  tier; self-hosted SMTP is the option for regulated customers.

---

## 9. Key Management

### Versioned key list with validity windows

```
/opt/aiauth/keys/
├── key_manifest.json        ← {key_id → {valid_from, valid_until, status}}
├── key_001_active.pem       ← current signing key (Ed25519 private)
├── key_001_public.pem
├── key_000_retired.pem      ← previous signing key (verify only)
└── key_000_public.pem
```

**Signing:** server uses `current_signing_key`. `key_id` is embedded in
the signed receipt.

**Verification:** receipt's `key_id` → look up public key in manifest →
confirm `receipt.ts` falls in validity window → Ed25519 verify.

**Rotation:** add new key pair to manifest with `valid_from` = now +
overlap period → promote `current_signing_key` → set old key
`valid_until` = now + 30 days → after transition, mark old key
`status: retired`.

**Critical:** back up ALL key files. If a signing key is lost, every
receipt signed with it becomes permanently unverifiable. No recovery.

---

## 10. Rate Limiting

```python
RATE_LIMITS = {
    "/v1/sign":           {"per_ip": "100/minute", "burst": 20, "global": "10000/minute"},
    "/v1/sign/batch":     {"per_ip": "10/minute", "max_batch": 50},
    "/v1/account/create": {"per_ip": "5/hour"},
    "/v1/account/auth":   {"per_ip": "10/hour", "per_email": "3/hour"},
    "/v1/waitlist":       {"per_ip": "10/day"},
    "/v1/discover/*":     {"per_ip": "60/minute"},
    "/v1/verify/prompt":  {"per_ip": "30/minute"},
}
```

---

## 11. Schema Versioning Policy

1. **New fields are always additive.** Never rename or remove.
2. **The server accepts receipts from any schema version ≥ 0.4.0.**
   Unknown fields ignored (forward compat). Missing optional fields
   default to null (backward compat). Required fields enforced.
3. **The dashboard handles missing fields gracefully.** NULL-safe
   aggregation everywhere.
4. **Clients display a warning** if their schema version is more than
   one minor version behind the server. Warning, not block.

### Version history

- **v0.4.0** — `v, id, ts, hash, uid, src, doc_id, parent, review.*`
- **v0.5.0** — added: `key_id, client_integrity, model, provider,
  source_domain, source_app, file_type, len, tta, sid, dest, dest_ext,
  classification, tags, prompt_hash, ai_markers, concurrent_ai_apps,
  content_hash_canonical`. Tier-gated: `tta, sid, dest, dest_ext,
  classification, concurrent_ai_apps`.

---

## 12. Offline-First Client Behavior

1. User triggers attest — client computes SHA-256 locally.
2. Client detects AI context, computes optional fields (tier-gated).
3. Client generates receipt + stores in local receipt store (always
   succeeds).
4. Client attempts server signing:
   - Reachable → `POST /v1/sign` → signature appended → status
     `"signed"`.
   - Unreachable → status `"pending"`, queue for sync.
5. Background sync (every 5 min when online) → `POST /v1/sign/batch`
   with up to 50 pending receipts → mark signed.

Receipts once signed by the server are verifiable offline with the
public key. Pending receipts display a clear indicator until sync
completes.

---

## 13. Content Hashing Rules

| Surface           | Normalization                                           |
|-------------------|---------------------------------------------------------|
| Browser text      | collapse whitespace → UTF-8 → SHA-256                  |
| Clipboard text    | same                                                    |
| Raw file          | SHA-256 over raw bytes (no normalization)               |
| Canonical text    | format-specific extractor → lowercase → collapse → SHA-256 (see `self-hosted/aiauth_canonical.py`) |
| Prompt hash       | same normalization as text selection                    |

Canonical text extraction enables cross-format chains (Excel → CSV →
PDF of the same table). Extractors are best-effort; if extraction fails
or produces fewer than 10 characters, `content_hash_canonical` is
omitted rather than set to a meaningless value.

---

## 14. Integrity Rules (for implementers)

1. Receipt schema is the single source of truth for analytics.
2. The account layer is an index, not a data store — plaintext emails
   never reach storage.
3. The registry stays anonymous. Six columns only. **No `prompt_hash`,
   no `uid`, no `model` — ever.**
4. Department is a JOIN, not a receipt field.
5. Consent is auditable. Append-only `consent_log`.
6. Schema changes are additive only.
7. Two databases, not three.
8. PII is pseudonymizable.
9. Authentication is mandatory for identity operations.
10. Tier gating is client-side. The server does not distinguish tier at
    sign time.
11. Prompt hashes never enter the public registry.
12. Concurrent AI app enumeration uses an allowlist. Unknown processes
    are never recorded.
13. AI marker detection is read-only and local.

---

## 15. Data Rights and GDPR

### Architecture advantages

- The public registry stores no PII.
- Content never touches the server.
- The account system is the only PII store. Email addresses
  (`account_emails`) and uid (`enterprise_attestations`) are the only
  personal data. Both are pseudonymizable.

### DSAR flow

- **Export** — return all data associated with an email: account,
  linked emails, attestations with that uid, consent history, policy
  violations.
- **Pseudonymize** (recommended) — replace uid with
  `SHA-256(email + org_salt)`, clear `uid_encrypted`, retain audit
  records.
- **Delete** — full record removal; registry entries are NOT deleted
  (they contain no PII).
- All actions logged in `consent_log` (append-only).

---

## 16. Pointers to Source

- **Receipt format:** [`docs/RECEIPT_SPEC.md`](docs/RECEIPT_SPEC.md)
- **User guide:** [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md)
- **Enterprise admin guide:**
  [`docs/ENTERPRISE_ADMIN_GUIDE.md`](docs/ENTERPRISE_ADMIN_GUIDE.md)
- **Canonical text extraction:**
  [`self-hosted/aiauth_canonical.py`](self-hosted/aiauth_canonical.py)
- **Self-hosted deployment:** [`self-hosted/README.md`](self-hosted/README.md)
- **Signing server reference:** [`server.py`](server.py)
- **Chrome extension reference:** [`chrome-extension/`](chrome-extension/)
- **Desktop agent reference:** [`aiauth.py`](aiauth.py)

---

Questions, improvements, or implementations in other languages welcome —
open an issue at
[github.com/chasehfinch-cpu/AIAuth](https://github.com/chasehfinch-cpu/AIAuth).
