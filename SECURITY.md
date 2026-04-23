# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately to **security@aiauth.app**.

Do **not** file public GitHub issues for security-relevant findings — even for
things that look minor. If you aren't sure whether a finding counts, email us
and we'll help you decide.

We aim to:
- Acknowledge your report within **72 hours**.
- Provide an initial assessment within **7 days**.
- Coordinate a fix and disclosure timeline with you before any public
  announcement.

We do not currently run a paid bug bounty program. We will credit reporters
publicly (with permission) in release notes for confirmed findings.

## Scope

In scope:
- The AIAuth signing server (`server.py`) and its HTTP endpoints.
- The Chrome extension (`chrome-extension/`).
- The desktop agent (`aiauth.py`).
- The self-hosted deployment bundle (`self-hosted/`).
- The public verification page and associated client-side cryptography.

Out of scope:
- Denial-of-service via unrealistic request volumes.
- Vulnerabilities in third-party services we use (Resend, DigitalOcean, etc.)
  — report those to the upstream vendor.
- Social engineering of AIAuth personnel.

## Trust Model Reminder

AIAuth's public server is intentionally stateless for receipt content. If a
vulnerability would compromise the content-stays-on-device guarantee or the
anonymous-registry invariants (see `docs/RECEIPT_SPEC.md` and `CLAUDE.md`),
treat it as high severity.

A root-level compromise of the production server would allow an attacker to
forge future receipts (signing-key access) but cannot retroactively reveal
user content — because we never have it.

## Keys and Rotation

The public signing-key list is published at:
- https://www.aiauth.app/v1/public-key
- https://www.aiauth.app/.well-known/aiauth-public-key

Key rotation procedures and validity windows are documented in `CLAUDE.md` →
"Key Management."
