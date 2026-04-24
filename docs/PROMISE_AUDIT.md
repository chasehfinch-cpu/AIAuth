# Promise Audit — Public claims vs. shipped code

**Date:** 2026-04-24
**Scope:** every public-facing claim across `index.html`, `/standards`, `/security`, `/compliance`, `/pricing`, `/one-pager`, `/pilot-playbook`, `/api`, [README.md](../README.md), [docs/USER_GUIDE.md](USER_GUIDE.md), and the Chrome listing copy, checked against the actual code shipping on `main` (commit `ba81c4e`).
**Methodology:** static audit — file paths, line numbers, and data-flow traces. No live service calls; no production DB reads.

Verdict legend:
- **PASS** — claim is implemented as stated.
- **PARTIAL** — infrastructure exists but the full-strength claim isn't backed end-to-end.
- **UNVERIFIABLE** — claim is a policy or business commitment, not something code can prove.
- **FAIL** — claim is inaccurate or unimplemented. *(No rows fell into this category.)*

Severity guides triage: **High** = misleading to a sophisticated buyer; **Medium** = technically true but softer than marketing implies; **Low** = wording nit.

Per the post-launch plan, no fixes land in this PR. Each PARTIAL row below can be converted into its own follow-up PR after you review.

---

## Audit results

| # | Claim | Sources | Status | Evidence | Severity | Suggested fix effort |
|---|---|---|---|---|---|---|
| 1 | Content never leaves your device — only a SHA-256 fingerprint is sent. | README, index.html, /standards, /one-pager, CWS listing | **PASS** | [chrome-extension/background.js:68-72](../chrome-extension/background.js) hashes locally via `sha256Hex()`; [background.js:280-296](../chrome-extension/background.js) sends `output_hash` (not content) to `/v1/sign`. [server.py:1225,1339](../server.py) `SignRequest` schema requires `output_hash`, rejects raw content. | — | — |
| 2 | Ed25519 signatures, offline verification from the public key alone. | /security, /standards, /api | **PASS** | [server.py:38](../server.py) imports `Ed25519PrivateKey`; [server.py:504-513](../server.py) `sign()` uses `priv.sign()`; [server.py:516-539](../server.py) `check_sig()` verifies against `KEY_REGISTRY[kid]["public"]` with no DB lookup. Public key served at [/v1/public-key](../server.py) and [/.well-known/aiauth-public-key](../server.py) without auth. | — | — |
| 3 | Key manifest lists every key with validity windows so old receipts still verify. | /security, /standards, /api | **PASS** | [server.py:542-564](../server.py) `build_public_key_manifest()` emits `keys[]` with `key_id`, `status`, `valid_from`, `valid_until`, `current_signing_key`. `/v1/public-key` returns this manifest by default; `?format=legacy` returns the v0.4.0 single-key shape. | — | — |
| 4 | Cross-format chain integrity via canonical text hash (xlsx → csv → pdf). | /standards, /one-pager, /compliance | **PARTIAL** | Server accepts and indexes `content_hash_canonical` ([server.py:1258](../server.py), [server.py:3500-3537](../server.py) `/v1/discover/content`, [server.py:3443-3491](../server.py) `/v1/verify/file-signals`). Self-hosted helper exists at `self-hosted/aiauth_canonical.py`. **Gap:** the Chrome extension does not yet compute `content_hash_canonical` — browser-side xlsx/pdf/docx extraction is deferred. End-to-end "xlsx → csv → pdf" only works with the self-hosted desktop agent or a custom client populating the field. | High | ~1–2 weeks (extension Tier 3 work: bundle a canonical-text extractor or offload to the desktop agent) |
| 5 | Automatic chain formation via `parent_hash` matching. | /standards, /api | **PASS** | [server.py:1279-1280,1393](../server.py) accepts `parent_hash` on `/v1/sign`; [server.py:3177-3218](../server.py) `/v1/verify` queries the registry by parent/child hash and returns `chain_discovery`; [server.py:3366-3442](../server.py) `/v1/verify/chain` validates ordered chains end-to-end. | — | — |
| 6 | Time-to-attest rubber-stamp detection flagged when `tta < 10` and `len > 500`. | /standards, /one-pager, /pilot-playbook, /compliance | **PASS** | Policy rule at [server.py:2392-2394](../server.py); dashboard aggregate at [server.py:2902](../server.py); `/check` verify page surfaces the amber warning at [verify.html:196-200](../verify.html); extension popup shows it inline at [chrome-extension/popup.js:112-124](../chrome-extension/popup.js). | — | — |
| 7 | AI-authorship signal consolidation — Office docProps, PDF metadata, ChatGPT/Claude export markers, and C2PA manifests all in `ai_markers`. | /standards, /compliance | **PARTIAL** | Schema supports it ([server.py:1246](../server.py) `ai_markers: Dict[str, Any]`; [server.py:1403-1414](../server.py) folds `c2pa_manifest_hash` into `ai_markers.c2pa.manifest_hash`). **Gap:** the Chrome extension only populates `ai_markers` with domain-derived `{source, provider, verified}` ([chrome-extension/background.js:231-239](../chrome-extension/background.js)). No client-side code reads Office docProps, PDF XMP, or ChatGPT/Claude export markers. The claim "all in `ai_markers`" implies the extension does aggregation it doesn't yet perform. | High | ~1 week (extension Tier 2/3: bundle a lightweight DOCX/PDF parser or invoke the desktop agent) |
| 8 | Zero-knowledge free tier; enterprise tier captures work-metadata under contract on customer infrastructure. | /security, /one-pager, /compliance | **PASS** | `/v1/enterprise/ingest` at [server.py:2461-2515](../server.py) writes to the local `enterprise_attestations` table on the customer's own signing host (license-gated). Free-tier `buildSignBody()` at [chrome-extension/background.js:200-217](../chrome-extension/background.js) explicitly skips commercial-only fields (`tta`, `sid`, `dest`, `classification`, `concurrent_ai_apps`) — gated behind `tier === "enterprise"` at [background.js:243-270](../chrome-extension/background.js). | — | — |
| 9 | Chrome extension open-source on GitHub; a fork can maintain it. | /security | **PARTIAL** | Source is readable and unminified under [chrome-extension/](../chrome-extension/). Repo-level [LICENSE](../LICENSE) (Apache 2.0) covers the directory. **Gap:** no dedicated `chrome-extension/LICENSE` file. A fork reading just the extension subtree has to trace back up to the repo root to identify the license — not blocking, but friction. | Low | ~5 min (copy repo LICENSE into `chrome-extension/LICENSE`) |
| 10 | 90-day shutdown notice; hash registry archived to GitHub or IPFS before takedown. | /terms §3 | **UNVERIFIABLE** | This is a policy commitment documented in the Terms of Service. Nothing in code can enforce or disprove it. | — | — |
| 11 | `/v1/sign` rate-limited at 100/min per IP, 1000/hour per IP. Waitlist/pilot/contact at 10–20/day per IP. | /api, /terms §5 | **PASS** | `/v1/sign` limits enforced by [server.py:214-220](../server.py) `RATE_LIMITS` + middleware at [server.py:269-298](../server.py). Waitlist/pilot/contact caps enforced via in-handler DB counts: pilot at 20/day ([server.py:1872](../server.py)), waitlist at 10/day ([server.py:1938](../server.py)), contact at 20/day ([server.py:2001](../server.py)). All raise `RATE_LIMITED` 429s. | — | — |
| 12 | Waitlist / pilot / contact submissions route to `sales@aiauth.app`. | /pilot, /contact, /waitlist, /pricing | **PASS** (if env var is set in production) | `_notify_operator()` at [server.py:1133-1162](../server.py) reads `AIAUTH_OPERATOR_EMAIL` from the environment and sends via Resend. Called by all three handlers ([server.py:1891, 1958, 2020](../server.py)). The routing depends on the production env var being set to `sales@aiauth.app`. | — | **Verify prod env:** confirm `AIAUTH_OPERATOR_EMAIL=sales@aiauth.app` is live on the deployed server, and `RESEND_API_KEY` is set. This is ops work, not code. |
| 13 | `GET /v1/public-key` returns the full manifest. `GET /.well-known/aiauth-public-key` is a discovery endpoint. | /standards, /api, /security | **PASS** | Both at [server.py:3722-3742](../server.py). Neither requires auth. `/.well-known/` returns the single current key shape for compact discovery; `/v1/public-key` returns the full multi-key manifest. | — | — |
| 14 | `POST /v1/verify/file-signals` cross-checks file-hash / canonical-hash / c2pa_manifest_hash. | /api | **PASS** | [server.py:3443-3491](../server.py) implements all three check branches. Validates each hex input, compares against receipt fields, returns per-check `match: bool` + summary `all_match`. | — | — |
| 15 | Dashboard exposes `receipts_with_c2pa` counter. | v1.3.0 change notes | **PASS** | [server.py:2906](../server.py) adds the SQL counter; [server.py:3122](../server.py) exposes `receipts_with_c2pa` in the dashboard response. | — | — |
| 16 | Ed25519 round-trip works for every shipping schema version. | /security, inferred from RECEIPT_SPEC | **PARTIAL** | `SCHEMA_MIN = "0.4.0"` at [server.py:47](../server.py); `check_sig()` at [server.py:516-539](../server.py) tries the receipt's `key_id` first and falls back through legacy keys. **Gap:** no automated round-trip test suite validates this claim across the v0.4.0 → v0.5.2 schema envelope. Rolls up to the larger "no test suite" gap addressed in PR 7. | Medium | Resolved when PR 7 (test suite) adds a cross-schema-version round-trip test. |
| 17 | Self-hosted enterprise has no phone-home. | /standards, /one-pager, /security | **PASS** | No references to `aiauth.app` in `self-hosted/` Python. License validation is offline (signed token + bundled public key per [self-hosted/config.yaml.example:11](../self-hosted/config.yaml.example)). `self-hosted/aiauth_canonical.py` performs local extraction only. | — | — |
| 18 | `/samples/compliance-report` renders synthetic data. | /security, /enterprise-guide, /pricing | **PASS** | Template at [templates/commercial/compliance-report.html](../templates/commercial/compliance-report.html); route at [server.py:5046-5054](../server.py). Renders from a synthetic JSON blob, no live DB queries. | — | — |

---

## Overall score

- **PASS:** 13 of 18 claims (1, 2, 3, 5, 6, 8, 11, 12, 13, 14, 15, 17, 18).
- **PARTIAL:** 4 claims (4, 7, 9, 16).
- **UNVERIFIABLE (policy):** 1 claim (10).
- **FAIL:** 0.

The audit does not uncover any outright false claims. Every gap is either a promise the infrastructure supports but the client-side extraction doesn't yet populate (canonical text, richer `ai_markers` signals), a missing convenience artifact (extension `LICENSE` copy), or a validation gap covered by the planned test-suite PR.

---

## Suggested follow-up PRs (in priority order)

If you want each gap converted to its own PR per the plan's "per-gap PR" instruction:

1. **PR-fix-1 (Low, ~5 min):** copy [LICENSE](../LICENSE) into `chrome-extension/LICENSE` so the extension subtree is self-contained for forks. Addresses claim 9.
2. **PR-fix-2 (ops, no code):** confirm `AIAUTH_OPERATOR_EMAIL` and `RESEND_API_KEY` are set on the production server and that a test submission reaches `sales@aiauth.app`. Addresses verification note on claim 12.
3. **PR-fix-3 (Medium, bundled with PR 7 already planned):** add explicit cross-schema-version round-trip tests (v0.4.0 receipt, v0.5.0 receipt, v0.5.2 receipt with `c2pa_manifest_hash`) to the test suite. Addresses claim 16.
4. **PR-fix-4 (High, ~1 week, future extension tier):** have the Chrome extension compute `content_hash_canonical` for common document formats — bundle a lightweight DOCX/XLSX/PDF text extractor or delegate to the desktop agent. Addresses claim 4.
5. **PR-fix-5 (High, ~1 week, future extension tier):** have the Chrome extension read Office docProps, PDF XMP, and ChatGPT/Claude export markers into `ai_markers` on file attestations. Addresses claim 7.

Items 4 and 5 together are roughly the "Tier 2 / Tier 3" Data Depth work that was explicitly deferred from the v1.3.0 release. They're not urgent — the claim wording on `/standards` currently describes them as capabilities rather than uniform guarantees — but they'd close the highest-severity marketing-vs-reality gaps.

---

## Caveats on this audit

- **Static only.** No live traffic replay. Rate limits, email delivery, and production DNS were not exercised.
- **No cryptographic verification performed.** The audit confirms the code paths exist; it does not verify that a v0.4.0 receipt actually round-trips through the v0.5.2 server binary.
- **Marketing copy evolves.** New claims added to `/standards`, `/compliance`, or the CWS listing between this audit and any fix-PR merge would need a delta re-audit.
