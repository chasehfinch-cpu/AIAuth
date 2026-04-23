# AIAuth

**Chain of Custody for AI-Generated Work.**

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

## Developer Quickstart

```bash
pip install -r requirements.txt
uvicorn server:app --host 127.0.0.1 --port 8100
curl http://127.0.0.1:8100/health
```

See the FastAPI docs at `http://127.0.0.1:8100/docs` for the full endpoint
surface.

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
