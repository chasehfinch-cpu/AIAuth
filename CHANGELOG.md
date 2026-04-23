# Changelog

All notable changes to AIAuth are documented here. Versions follow
[Semantic Versioning](https://semver.org/). Schema-breaking changes to
the receipt format would bump the major version — we haven't needed
one yet.

## [v0.5.0] — 2026-04-23

Initial public release. Chain of custody for AI-generated work, with
zero server-side retention of content or behavioral data on the free
tier.

### Added
- Stateless Ed25519 signing server (`POST /v1/sign`) with anonymous
  six-column hash registry supporting cross-format chain discovery.
- Chrome extension, Windows desktop agent, and LiteLLM callback surfaces
  for attesting AI output.
- Self-hosted enterprise deployment bundle under `self-hosted/`
  (Docker + Python install routes, managed-config examples, policy
  engine, DSAR tooling).
- Magic-link authentication with single-use tokens and 24-hour
  sessions.
- Anti-forensic hardening: HMAC-hashed email indexes, Fernet-encrypted
  identifiers, magic-link file logs disabled by default.
- Inbound mail forwarder (`POST /v1/inbound`) backed by Resend webhook
  with Svix signature verification.
- Cross-format canonical-text hashing (Excel → CSV → PDF chain
  integrity), perceptual image hashing, sidecar `.aiauth` files for
  metadata-less formats.
- Landing page with waitlist signup, pricing (Free / Team / Enterprise),
  positioning content, and enterprise demo dashboard under `/demo`.
- Public receipt-format specification at `docs/RECEIPT_SPEC.md` under
  Apache 2.0.
- Architecture overview at `ARCHITECTURE.md`.
- Enterprise admin and user guides under `docs/`.

### Licensing
- Core server, Chrome extension, desktop agent, receipt spec licensed
  under **Apache 2.0** (`LICENSE`).
- Self-hosted deployment bundle licensed under **BUSL 1.1**
  (`self-hosted/LICENSE.BUSL`).

### Security
- Report vulnerabilities privately to `security@aiauth.app`.
  See [`SECURITY.md`](SECURITY.md).

---

## [Pre-v0.5.0]

Pre-release development history is preserved in the commit log but not
itemised here.
