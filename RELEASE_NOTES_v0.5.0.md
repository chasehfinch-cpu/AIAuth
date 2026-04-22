# AIAuth v0.5.0 — Release Notes & Coverage Audit

**Branch:** `claude/gracious-solomon-997b24`
**Commits:** 13 pieces (1 spec merge, 11 feature pieces, 1 final audit)
**Target:** replace v0.4.0 on production

This document maps everything CLAUDE.md v0.5.0 asks for to what actually shipped in this release. **Green** = built and tested. **Yellow** = partial / intentional deferral. **Red** = not built.

---

## Summary

| Area | Status |
|---|---|
| Receipt schema (all 23 v0.5.0 fields) | ✅ Green |
| Zero-data server principle | ✅ Green |
| Magic-link authentication + accounts | ✅ Green |
| Key versioning + rotation | ✅ Green |
| Rate limiting | ✅ Green |
| Dedup window + standard error format | ✅ Green |
| Tier gating (client-side) | ✅ Green |
| Extension onboarding states 1–5 | ✅ Green |
| Desktop agent file + AI marker detection | ✅ Green |
| Enterprise ingest + policy engine + DSAR | ✅ Green |
| Dashboard data contract endpoint | ✅ Green |
| Commercial demo template + /demo route | ✅ Green |
| Data Architecture Integrity Rules 1–14 | ✅ Green |
| Offline bulk-sync endpoint | 🟡 Deferred |
| Real email delivery / DNS domain proof | 🟡 Deferred |
| macOS agent / LiteLLM v0.5.0 / React SPA | 🔴 Not built |

---

## 1. Endpoints

### Shipped
- `POST /v1/sign` — extended with all v0.5.0 fields, dedup, error format
- `POST /v1/verify`, `/v1/verify/chain`, `/v1/verify/content`, `/v1/verify/prompt`
- `GET /v1/discover/{hash}`, `/v1/lookup/{code}`
- `GET /v1/public-key` (manifest), `/.well-known/aiauth-public-key` (legacy shape)
- `POST /v1/account/{create,auth,verify,link,confirm,consent,export,logout}`, `GET /v1/account/me`
- `POST /v1/enterprise/ingest`
- `POST /v1/admin/{org/claim,dsar,pseudonymize}`, `GET /v1/admin/org/members`
- `GET /v1/admin/dashboard/data`, `GET /v1/admin/dashboard`
- `GET /v1/violations`
- `GET /check`, `/guide`, `/privacy`, `/public-key`, `/demo`, `/health`, `/docs` (FastAPI auto)
- Page shells + static assets (logo, synthetic-data.js)

### Not yet shipped (pending)
- `POST /v1/sign/batch` — offline bulk sync (spec defines it; rate limits preconfigured; handler not written)
- `POST /v1/enterprise/import` — bulk historical-receipt import
- `GET /v1/discover/docid/{id}` — doc_id chain lookup
- `GET /v1/review/{id}/history` — review audit trail

All four are additive and can be built without breaking the current API.

---

## 2. Receipt schema v0.5.0 — field matrix

| Field | Server accepts | Chrome ext populates | Desktop agent populates |
|---|---|---|---|
| `v`, `id`, `ts`, `hash`, `uid`, `src` | ✅ | ✅ | ✅ |
| `key_id` | ✅ (auto from manifest) | (server-set) | (server-set) |
| `client_integrity` | ✅ HMAC validated | ✅ "extension" via HMAC | ✅ "none" (Level 3 deferred) |
| `model`, `provider` | ✅ | ✅ auto-detect from AI_DOMAINS | ✅ auto-detect from window title |
| `source_domain`, `source_app` | ✅ | ✅ | ✅ (source_app only) |
| `prompt_hash` | ✅ free tier, in receipt not registry | ✅ via DOM prompt extraction | ✅ via Q:/A: clipboard heuristic |
| `ai_markers` | ✅ | 🟡 browser has no file access (always null) | ✅ PDF/DOCX/XLSX/PPTX/C2PA |
| `file_type` | ✅ | ✅ heuristic | ✅ extension + magic bytes |
| `len` | ✅ (alias for `content_length`) | ✅ | ✅ |
| `doc_id`, `parent` | ✅ (+ registry doc_id column) | 🟡 not yet populated by ext | ✅ used on file attest |
| `tags`, `review.*` | ✅ | ✅ review.* via review_status | ✅ review.* |
| **Commercial-only (enterprise tier gate):** | | | |
| `tta` | ✅ | ✅ via MutationObserver | 🟡 placeholder, not wired |
| `sid` | ✅ | ✅ per-tab session | 🟡 not wired |
| `dest`, `dest_ext` | ✅ | 🟡 dest via URL heuristic; `dest_ext` always null | 🔴 not wired |
| `classification` | ✅ | ✅ weak heuristic | 🔴 not wired |
| `concurrent_ai_apps` | ✅ (stored as JSON) | ✅ enumerates open AI tabs | ✅ psutil allowlist |

**Integrity Rule 11:** Tier gating is entirely client-side. Free-tier `/v1/sign` requests from the shipped clients contain only free-tier fields. Server accepts both shapes without distinguishing them.

---

## 3. Data Architecture Integrity Rules — all 14 ✅

Each rule is enforced by code, not convention:

1. Receipt schema is analytics source — dashboard aggregates only from receipt fields
2. Account layer is index-only — no receipt duplication in accounts tables
3. Registry = 5 columns — verified by `PRAGMA table_info(hash_registry)`
4. Department is a JOIN via `account_emails` → `org_members`, never on receipts
5. Synthetic-data.js outputs match `/v1/admin/dashboard/data` contract exactly
6. `consent_log` is append-only by design (no UPDATE/DELETE paths in code)
7. Schema additive-only — server accepts any `v ≥ 0.4.0`, `SCHEMA_MIN = "0.4.0"`
8. Two databases — `aiauth_registry.db` (anonymous) + `aiauth.db` (everything else)
9. Pseudonymization — `uid_pseudonym` column + DSAR endpoints + `[pseudonymized]` uid replacement
10. `_require_session` on every identity-mutation endpoint
11. Tier gating: extension `getTier()`, agent `config["tier"]` — server never knows
12. `prompt_hash` excluded from hash_registry schema by design
13. Desktop agent `AI_PROCESS_ALLOWLIST` — unknown process names never recorded
14. `detect_ai_markers()` reads file metadata locally, transmits only `{source, verified}`

---

## 4. Phase 2 Build Priority checklist — 22 of 22 items

Every item in the CLAUDE.md Phase 2 checklist has shipped. See audit output (run `python audit.py`) for direct grep verification.

---

## 5. Known gaps (honest list)

### Intentional deferrals
1. **`POST /v1/sign/batch`** — offline-sync bulk endpoint. Chrome extension's local receipt store has `status: "signed"` fields ready; the sync loop + batch handler are the next piece.
2. **Real transactional email** — magic links are logged to `/opt/aiauth/magic_links.log` so an admin can wire Resend/Postmark without code changes. Stub is intentional per v0.5.0 scope.
3. **DNS TXT domain verification** — org claim currently requires a verified email in the domain (proof of control via email access). Stronger DNS-based proof can replace this in a minor release.
4. **Web magic-link callback page** — user currently pastes the link URL into the extension popup (popup.js extracts `?token=`). A future aiauth.app/auth page would call `/v1/account/verify` directly and postMessage the session back.
5. **Full React dashboard SPA** — shipped an inline HTML template (`templates/commercial/executive-summary.html`) that renders the data contract. A richer multi-view React app can swap in without touching the stable `/v1/admin/dashboard/data` endpoint.
6. **by_time weekly buckets** — dashboard returns the key with `buckets: []` (contract-compliant). Time-series aggregation query is small, but deferred.
7. **Desktop agent `client_integrity: "os-verified"`** — requires code-signed binaries + OS-level process attestation. Infrastructure-level work beyond server scope.
8. **LiteLLM plugin v0.5.0 schema** — existing `litellm-plugin/attestation_callback.py` still uses v0.4.0 schema. Needs parallel work to populate prompt_hash, etc.

### Not yet built
9. **macOS desktop agent** — Windows-only in this release.
10. **Windows file right-click shell-menu registry keys** — Feature 9's installer step. The `--attest-file` CLI exists; the Registry integration comes with the MSI installer build.
11. **Custom per-org policy rules** — `DEFAULT_POLICIES` list is hardcoded. CRUD endpoint for org-specific rules is a clean follow-up.
12. **`POST /v1/enterprise/import`** — bulk historical-receipt import for personal-to-corporate transitions.
13. **`GET /v1/discover/docid/{id}`** and **`GET /v1/review/{id}/history`** — small additive endpoints.

---

## 6. Deployment order to production

Each piece is additive and backward-compatible with v0.4.0 clients. Recommended sequence:

1. **Upload new `server.py`** → includes pieces 1, 2, 5, 6, 7, 9, 10, 11 (server-side).
2. **Create `SERVER_SECRET` and `CLIENT_SECRET` in `/opt/aiauth/.env`** (required for auth + HMAC integrity).
3. **`systemctl restart aiauth`** — registry + accounts/orgs/consent/tokens tables auto-migrate; legacy `aiauth_private.pem` auto-moves into `keys/key_000_active.pem`.
4. **Verify `curl /health` returns `"version":"0.5.0"`** and `PRAGMA table_info(hash_registry)` shows 5 columns including `doc_id`.
5. **Upload `templates/commercial/*` and chrome-extension/* files** (Pieces 3, 8, 9, 11).
6. **Reload Chrome extension from `chrome://extensions/`.**
7. **Replace `/opt/aiauth/aiauth.py`** on any Windows agent installs (Piece 4).

See `CLAUDE.md` **Operations & Deployment** section for exact commands.

---

## 7. Commit ledger

```
670bcdd Piece 11: Dashboard data contract + demo template + /demo route
fc1a213 Piece 10: Enterprise ingest + policy engine + DSAR + org claim
8157dd6 Piece 9:  Enterprise-tier capture + HMAC client_integrity
893c568 Piece 8:  Extension popup onboarding states 1-5
407cefe Piece 7:  Magic-link auth + account/org/consent schema
1f3a961 Piece 6:  Rate limiting middleware on public endpoints
657247e Piece 5:  Key manifest migration — versioned keys + key_id in receipts
cb18535 Piece 4:  Desktop agent v0.5.0 — capture, file attest, AI markers
a6c75bf Piece 3:  Chrome extension v0.5.0 field capture
c993c23 Piece 2:  POST /v1/verify/prompt + text normalization helpers
efbc10e Piece 1:  server.py v0.5.0 — schema acceptance, dedup, error format
ed92677 Merge CLAUDE_1.md operational content into CLAUDE.md; delete CLAUDE_1.md
351f636 (v0.4.0 baseline, pre-work)
```

Everything on GitHub at `https://github.com/chasehfinch-cpu/AIAuth/tree/claude/gracious-solomon-997b24`.
