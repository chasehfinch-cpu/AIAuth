# Chrome Web Store — Listing Copy

Paste these fields into the Chrome Developer Console (Item → Store listing).

---

## Name (max 75 chars)

```
AIAuth — Chain of Custody for AI Work
```

## Short description (max 132 chars)

```
One-click tamper-proof receipts for AI-generated work. Content never leaves your device. Free forever.
```

## Detailed description (max 16,000 chars)

```
AIAuth is chain-of-custody for AI-generated work. Press Ctrl+Shift+A on any AI output and you get a tamper-proof receipt proving what AI produced it and that you reviewed it — in one keystroke.

Your content never leaves your device. Only a one-way SHA-256 hash is sent to AIAuth's signing server. No content surveillance, no keystroke logging, no screen capture.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WHAT IT DOES

→ One-press attestation: select AI output, press Ctrl+Shift+A, get a tamper-proof receipt.
→ Auto-detects which AI tool produced the content (Claude, ChatGPT, Copilot, Gemini, Cursor, Perplexity, Poe).
→ Creates a short shareable code like [AIAuth:a1b2c3d4] that pastes into email, Slack, documents, anywhere you need proof.
→ Works offline. Receipts sync when your connection is restored.
→ File attestation: right-click any file to create a receipt. Works on Excel, PDF, Word, images, code.
→ AI authorship detection: recognizes Copilot docProps, ChatGPT PDF exports, C2PA image manifests.
→ Cross-format chain integrity: an Excel file → CSV export → PDF share-version all share a single canonical-text hash, so your chain of custody survives format conversions.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WHY CHAIN OF CUSTODY

If you use AI to help produce work that other people rely on — reports, code, briefs, analyses, communications — there's value in being able to prove which parts were AI-assisted and that a human reviewed the output. AIAuth is the lightest-weight way to build that proof, without any of the privacy costs of content-surveillance products.

Compliance teams use it as audit-ready documentation. Team leads use it to see which AI tools their team uses. Individuals use it to keep a verifiable record of their own work.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

HOW YOUR DATA IS HANDLED

→ Your content is hashed in your browser (SHA-256). Only the hash is sent to the server.
→ The server signs the hash with an Ed25519 key and returns the signed receipt. The server stores the hash only, never your content.
→ Email is OPTIONAL. The extension works without an account; you can start attesting immediately. Verifying your email (via a one-time link) enables cross-person chain-of-custody but is never required.
→ Stored emails are HMAC-hashed. The server never holds plaintext email addresses.
→ Prompt text (if detected) is hashed locally and only the hash is transmitted.
→ No analytics. No cookies. No third-party trackers.

Full privacy policy: https://www.aiauth.app/privacy

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ENTERPRISE DEPLOYMENT

Companies can deploy AIAuth Enterprise on their own infrastructure — self-hosted only. Your data never touches AIAuth's servers. Your IT team runs the server; your employees point the extension at it. AIAuth (the vendor) has zero access to your deployment's data.

See: https://www.aiauth.app/enterprise-guide

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TRUST

→ Zero-knowledge architecture
→ Content never leaves your device
→ GDPR-ready by design
→ Verifiable offline with the public key
→ Open verification standard (any AIAuth-compatible verifier works)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SUPPORTED AI SITES

Claude (claude.ai), ChatGPT (chatgpt.com), Gemini (gemini.google.com), Microsoft Copilot (copilot.microsoft.com), GitHub Copilot, Perplexity, Poe, Cursor. Any other site works too — receipts are still created, just without automatic model detection.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

AIAuth is built by Finch Business Services LLC. Open source. Contact: chase@finchbusinessservices.com.
```

## Category

```
Productivity
```

## Language

```
English (United States)
```

## Tags / Keywords (internal, not user-visible)

```
ai, attestation, chain of custody, provenance, compliance, receipts, audit, tamper-proof, chatgpt, claude, copilot, gemini
```

---

## Version notes (for the "What's new" field on updates)

```
v1.2.0 — Chain-of-custody rebranding, shared site theme on /check, unverified onboarding path (Start Attesting immediately, verify your email later), enterprise managed-config support for Workspace admins.
```
