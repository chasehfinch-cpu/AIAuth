# AIAuth

**Notarize your AI work. Prove you reviewed it. Own your data.**

## For Everyone

AIAuth creates a tamper-proof receipt every time you take responsibility
for AI-generated content. Think of it like a digital notary stamp.

**Install and start in 30 seconds:**

- **Chrome users** → Install from the Chrome Web Store → press Ctrl+Shift+A on any AI text
- **Windows users** → Install from the Microsoft Store → press Ctrl+Shift+A anywhere

**What it does:** You copy AI output. You press Ctrl+Shift+A. AIAuth creates
a signed receipt and puts a code like `[AIAuth:a1b2c3d4]` in your clipboard.
Paste that code wherever you deliver the work.

**What it proves:** Anyone with that receipt can verify that you reviewed
this specific content, on this date, and (if applicable) which AI helped
create it.

**What it doesn't do:** AIAuth never sees your actual content. Only a
fingerprint is used. Your receipts are stored on YOUR computer, not on
any server.

**Full user guide:** Read docs/USER_GUIDE.md — written in plain English,
no technical knowledge required.

**Verify a receipt:** Go to aiauth.app/check — paste a receipt, see who
attested what and when.

---

## How Chains Work

Content gets passed around. AIAuth tracks the full history automatically.

```
  Sarah creates a draft with Claude → Receipt #1
       ↓
  Mike edits it → Receipt #2 (links to #1)
       ↓
  Consultant enhances with GPT-4o → Receipt #3 (links to #2)
       ↓
  CFO approves final version → Receipt #4 (links to #3)
```

Each receipt links to the previous one. The chain is tamper-evident —
change any link and the whole chain breaks. Verify a full chain at
aiauth.app/check by pasting all receipts as a JSON array.

---

## For Developers

AIAuth is a stateless Ed25519 signing authority. Three endpoints:

```
POST /v1/sign          → Hash in, signed receipt out, server forgets
POST /v1/verify        → Receipt in, valid Y/N out
POST /v1/verify/chain  → Receipts in, chain intact Y/N out
```

Verify receipts offline using the public key at
`/.well-known/aiauth-public-key`. No API call needed.

**Quick start:**
```bash
pip install fastapi uvicorn cryptography
uvicorn server:app --port 8100
```

**API docs:** aiauth.app/docs

---

## For Companies

Enterprise mode adds centralized storage, review history,
chain queries, and compliance dashboards. Self-host or let us
host it for you.

```bash
AIAUTH_MODE=enterprise AIAUTH_LICENSE_KEY=your-key uvicorn server:app --port 8100
```

Contact hello@aiauth.app for enterprise licensing.

---

## Project Files

```
server.py              Server (signing authority + enterprise)
verify.html            Public verification page (aiauth.app/check)
desktop-agent/         Windows system tray app
chrome-extension/      Chrome Web Store extension
docs/USER_GUIDE.md     Plain-English user guide
```

---

Apache 2.0 — Finch Business Services LLC — aiauth.app
