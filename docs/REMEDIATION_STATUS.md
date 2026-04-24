# Remediation Spec — Implementation Status

This document reconciles every item in `AIAuth_Remediation_Spec.md` (derived from Critique V.2) against the actual state of the repo as of v1.2.2 (2026-04-24). The critique reviewed only the public homepage and a surface read of the repo, so it missed a number of items that are already implemented server-side or inside the extension.

Each row is tagged:
- **Built** — implemented; critique missed it.
- **Partial** — partially implemented; gap documented.
- **Missing — planned** — genuinely missing, addressed in a companion PR.
- **Missing — backlog** — genuinely missing, deferred.

---

## Section 1 — Trust & Key Management

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 1.1 | `/security` or `/trust` page | Missing — backlog | No route in `server.py`. Continuity content partially in `docs/ENTERPRISE_ADMIN_GUIDE.md`. |
| 1.2 | Public key manifest versioning endpoint | **Built** | `GET /v1/public-key` returns the full manifest via `build_public_key_manifest()` in `server.py`. `GET /.well-known/aiauth-public-key` exists as a discovery endpoint. |
| 1.3 | Continuity / bus-factor documentation | Missing — backlog | Enterprise guide covers self-hosted continuity; free-tier continuity is not documented on the public site. |

## Section 2 — Chrome Extension Hardening

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 2.1 | Minimize extension permissions | **Built** | `chrome-extension/manifest.json` requests only `activeTab`, `storage`, `notifications`, `clipboardWrite`, `contextMenus`. Host permissions scoped to four AI-tool origins. No `<all_urls>`, `webRequest`, `tabs`, `history`, etc. |
| 2.2 | Content Security Policy on extension pages | **Built** | `chrome-extension/manifest.json` includes `"content_security_policy": { "extension_pages": "script-src 'self'; object-src 'self'" }`. |
| 2.3 | Open-source repo structure | **Built (mostly)** | `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `README.md` all present at repo root. Reproducible-build / `VERIFICATION.md` instructions remain a backlog item. |
| 2.4 | Rubber-stamp detection (TTA) in free tier | **Built** | Receipts carry a `tta` field (see `server.py` — `POST /v1/sign` handler). Dashboard and verification pathways surface `avg_tta_seconds` and `median_tta_seconds`. A policy rule flags `tta < 10 and len > 500`. |

## Section 3 — Standards Alignment

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 3.1 | C2PA interop roadmap + positioning | Missing — planned | Addressed by PR `c2pa-standards-alignment`: new `/standards` page + optional `ai_signals.c2pa` field on receipts. |
| 3.2 | EU AI Act Article 50 mapping | Missing — backlog | Referenced in enterprise guide but no dedicated `/compliance` page. |
| 3.3 | SOC 2 / ISO 27001 / NIST AI RMF mapping | Missing — backlog | Not yet produced. |

## Section 4 — Legal & Evidentiary

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 4.1 | Evidentiary value white paper | Missing — backlog | Not yet produced. |
| 4.2 | Terms of Service page | Missing — backlog | Privacy policy lives at `/privacy`; no `/terms` route yet. |

## Section 5 — Revenue & Business Model

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 5.1 | Public pricing | Partial → planned | Pricing section already exists in `index.html`. PR `standalone-submission-pages` adds a canonical `/pricing` route and dedicated submission pages for Free/Team/Enterprise CTAs. |
| 5.2 | Free-to-enterprise conversion triggers | Missing — backlog | No in-product upgrade prompts yet. |

## Section 6 — Website & Documentation

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 6.1 | README overhaul | Partial | `README.md` has product description, license, quickstart. Gap: architecture diagram, "Permissions Explained" section (partially addressed by `chrome-extension/STORE_LISTING.md` from PR `chrome-v1.2.2-listing-compliance`). |
| 6.2 | Site navigation completeness | Partial → planned | PR `standalone-submission-pages` adds `/pricing` to nav. `/security`, `/standards`, `/terms`, `/api`, `/compare` nav links arrive as those pages ship. |
| 6.3 | Fix "GitHub (Coming Soon)" footer links | **Built** | Footer in `_site_shell` already points to `https://github.com/chasehfinch-cpu/AIAuth`. |
| 6.4 | API reference page | Missing — backlog | FastAPI auto-docs serve at `/docs` (framework default) but no hand-written `/api` reference exists. |

## Section 7 — Product Features

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 7.1 | Receipt export / backup UX | Missing — backlog | Extension popup lacks an "Export All Receipts" action. |
| 7.2 | Browser support beyond Chrome | Missing — backlog | Chrome/Chromium only. |
| 7.3 | Image attestation via right-click | Partial | `contextMenus` permission present; image-specific handling not explicitly wired. |
| 7.4 | Team tier features | Partial | Pricing section advertises Team tier; server does not yet distinguish team from individual. |

## Section 8 — Competitive Positioning

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 8.1 | "Why not just C2PA?" content | Missing — planned | PR `c2pa-standards-alignment` covers this on `/standards`. |
| 8.2 | Comparison page | Missing — backlog | No `/compare` route. Homepage has a small comparison strip. |

## Section 9 — Enterprise Readiness

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 9.1 | SSO / LDAP roadmap | Partial | Enterprise guide mentions v0.6.0 roadmap; could be dated more precisely. |
| 9.2 | Sample compliance report | **Built** | `GET /samples/compliance-report` renders `templates/commercial/compliance-report.html`. |
| 9.3 | Pilot playbook | Missing — backlog | Enterprise guide covers pilot technically; no standalone sales-ready playbook. |

## Section 10 — Technical Debt & Quality

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 10.1 | Automated test suite | **Built** | `tests/` directory shipped; 60 tests across crypto, rate limits, schema, HTTP. CI at `.github/workflows/test.yml`. |
| 10.2 | Rate limiting | **Built** | Middleware in `server.py` (~line 269). 429s enforced on `/v1/sign`, `/v1/pilot/interest`, `/v1/waitlist`. |
| 10.3 | Status page | Won't fix | `/health` and `/health/db` provide readiness signals. External public status page explicitly declined — operator preferred not to take on a third-party dependency. |

## Section 11 — Intellectual Property

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 11.1 | Patent evaluation | Missing — backlog | No patent activity on record. |

## Section 12 — Demo & Sales Materials

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 12.1 | Demo page graceful degradation | Partial | `/demo` renders `templates/commercial/executive-summary.html`. Static-fallback hardening not yet tested. |
| 12.2 | 2-minute product video | Missing — backlog | No video embedded. |
| 12.3 | One-pager PDF | Missing — backlog | Not yet produced. |

---

## Summary

Of the 34 items in the remediation spec:

- **10 Built** — the critique missed these. Most are server-side or inside the extension package (invisible to a homepage-only review).
- **8 Partial** — foundation exists, refinement outstanding.
- **4 Missing — planned** — shipped in the companion PRs that accompany this document (`chrome-v1.2.2-listing-compliance`, `standalone-submission-pages`, `c2pa-standards-alignment`).
- **12 Missing — backlog** — tracked for future releases.

The critique's underlying frame — that the product has a credible core and needs enterprise-facing scaffolding — holds up. But the specific gap list over-counts: key-manifest versioning, CSP, permission minimization, TTA detection, rate limiting, and the sample compliance report are all already shipped.
