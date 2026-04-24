# AIAuth

**Chain of Custody for AI-Generated Work.**

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Self-hosted: BUSL 1.1](https://img.shields.io/badge/self--hosted-BUSL--1.1-purple.svg)](self-hosted/LICENSE.BUSL)
[![Version: v0.5.0](https://img.shields.io/badge/version-v0.5.0-green.svg)](https://github.com/chasehfinch-cpu/AIAuth/releases/tag/v0.5.0)
[![Website: aiauth.app](https://img.shields.io/badge/website-aiauth.app-black.svg)](https://www.aiauth.app)
[![tests](https://github.com/chasehfinch-cpu/AIAuth/actions/workflows/test.yml/badge.svg)](https://github.com/chasehfinch-cpu/AIAuth/actions/workflows/test.yml)

AIAuth creates a tamper-proof receipt for AI-generated content you select,
proving what AI helped write it and that a human reviewed it. Your content
never leaves your machine — only a SHA-256 fingerprint is sent to the signing
server.

Live at **[aiauth.app](https://www.aiauth.app)**.

---

## What It Is

- A Chrome extension + optional Windows desktop agent that attests AI output
  with one keystroke.
- A stateless Ed25519 signing server that returns a signed receipt.
- A public anonymous registry that enables chain-of-custody verification
  without storing any content, behavioral metadata, or identifiable user data.
- A receipt format designed to be verifiable offline with the published
  public key.

## What It Isn't

- Not an AI-content *detector* (those guess; AIAuth is a voluntary,
  cryptographic answer).
- Not an AI *governance* platform (governance manages the model; AIAuth
  attests the output).
- Not a surveillance tool. The free tier captures zero behavioral metadata.
  Enterprise tier captures work-metadata under contract, on customer-owned
  infrastructure.

## How to Use

### Verify a receipt (no install needed)

Paste a receipt at **[aiauth.app/check](https://www.aiauth.app/check)**.
Verification runs client-side against the published public key.

### Attest content (closed beta)

The Chrome extension is in closed beta pending Chrome Web Store review. Join
the waitlist at [aiauth.app](https://www.aiauth.app) to be emailed when it
ships. In the meantime, the unpacked extension can be loaded from
`chrome-extension/` for developer testing.

### Self-host the server (enterprise)

See `self-hosted/README.md`. One `config.yaml`, two supported install routes
(Docker Compose or a Python `install.sh`). Your data stays on your
infrastructure — AIAuth the company cannot see it.

---

## Repository Layout

```
server.py                   Stateless signing server + enterprise endpoints
index.html / verify.html    Site fragments wrapped by server.py (_site_shell)
aiauth.py                   Windows desktop agent (clipboard + file attest)
chrome-extension/           Browser extension source
self-hosted/                Docker / Python deployment bundle for enterprises
docs/                       User guide, enterprise guides, receipt spec
templates/commercial/       Demo dashboard templates
litellm-plugin/             LiteLLM callback for API-level attestation
```

## Documentation

- **User Guide** — [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md)
- **Receipt Format Spec** — [`docs/RECEIPT_SPEC.md`](docs/RECEIPT_SPEC.md)
- **Enterprise Admin Guide** — [`docs/ENTERPRISE_ADMIN_GUIDE.md`](docs/ENTERPRISE_ADMIN_GUIDE.md)
- **Enterprise User Guide** — [`docs/ENTERPRISE_USER_GUIDE.md`](docs/ENTERPRISE_USER_GUIDE.md)
- **API Reference** — [aiauth.app/docs](https://www.aiauth.app/docs) (FastAPI auto-generated)

## Standards

AIAuth is complementary to the [C2PA Content Credentials](https://c2pa.org/)
standard, not a competitor to it. C2PA proves what tool created a file;
AIAuth proves a human reviewed it. Receipts carry C2PA manifest identity
under `ai_markers.c2pa` (see [`docs/RECEIPT_SPEC.md` §3.2.1](docs/RECEIPT_SPEC.md#321-ai_markersc2pa--c2pa--content-credentials-interop))
so the two chains can be walked from a single receipt.

Full positioning and roadmap (including a planned `aiauth.app/human-review/v1`
C2PA assertion type) lives at [aiauth.app/standards](https://www.aiauth.app/standards).

## Developer Quickstart

```bash
pip install -r requirements.txt
uvicorn server:app --host 127.0.0.1 --port 8100
curl http://127.0.0.1:8100/health
```

See the FastAPI docs at `http://127.0.0.1:8100/docs` for the full endpoint
surface.

## Testing

```bash
pip install -r requirements-dev.txt
pytest -v
```

60 tests covering canonical text normalization, rate limiting, receipt
schema validation, key manifest shape, sign/verify round-trips across
schema versions v0.4.0 through v0.5.2, and HTTP endpoint smoke over
every public page and sign/verify/file-signals flow. CI runs on every
push and pull request against Python 3.11 and 3.12 via
[`.github/workflows/test.yml`](.github/workflows/test.yml).

## Security

To report a vulnerability, see [`SECURITY.md`](SECURITY.md) — please do not
file public issues for security-relevant findings.

## License

Core server, Chrome extension, desktop agent, and receipt spec are licensed
under **Apache 2.0** (see [`LICENSE`](LICENSE)).

The `self-hosted/` deployment bundle is licensed under **Business Source
License 1.1** (see [`self-hosted/LICENSE.BUSL`](self-hosted/LICENSE.BUSL)) —
customers can run it for their own use; offering it as a managed service to
third parties requires a commercial license until the BUSL change date.

---

Operated by Finch Business Services LLC. `hello@aiauth.app`
