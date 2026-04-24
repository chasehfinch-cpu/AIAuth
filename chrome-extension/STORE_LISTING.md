# Chrome Web Store Listing Copy — v1.2.2

**Purpose:** Exact text to paste into the Chrome Web Store Developer Dashboard for the AIAuth extension listing. Replaces the v1.2.2 draft that was rejected on 2026-04-24 (reference: Yellow Argon) for "excessive keywords in the item's description."

**Rejection root cause:** The previous detailed description enumerated seven brand names in a single line (`Claude, ChatGPT, Copilot, Gemini, Cursor, Perplexity, Poe`). Chrome Web Store treats brand-list enumerations as keyword stuffing under the Spam and Placement in the Store policy. This rewrite removes the enumeration entirely and describes compatibility generically.

**Scope of this file:** The in-repo [manifest.json](manifest.json) description is already compliant and does not change. This file is the source of truth for the dashboard fields only.

---

## Short description (≤132 characters)

> Tamper-proof chain-of-custody receipts for AI-generated work. Right-click to attest. Content never leaves your device.

(Matches the manifest `description` field.)

---

## Detailed description (dashboard field)

```
AIAuth turns AI-generated work into a verifiable record of human review.

Select the content you want to stand behind, right-click, and choose
"Attest selection with AIAuth". The extension computes a cryptographic
fingerprint of the selection on your device, sends only that fingerprint
to the AIAuth signing server, and returns a signed receipt you can share
or store. The original text is never transmitted.

Each receipt records:
  - A SHA-256 fingerprint of the content you reviewed
  - The time you reviewed it
  - The time-to-attest (how long you had the content on screen before signing)
  - An Ed25519 signature from the AIAuth signing key

Anyone with the receipt and the AIAuth public key can verify that the
content you shared matches the content you attested, without ever seeing
the original text.

Why this matters
  - Publishers, compliance teams, and counterparties increasingly need
    to know whether AI-assisted output has been human-reviewed.
  - AIAuth provides that evidence without logging the content itself.
  - Receipts form a chain: edit the reviewed content and the chain
    surfaces the change.

What AIAuth does NOT do
  - It does not read, store, or transmit the content of the pages you visit.
  - It does not run on sites other than the AI tools you choose to attest from.
  - It does not send content to any server — only the one-way SHA-256 hash.

Works alongside any AI tool you already use. The extension is only active
when you invoke it by right-click; it has no background page-monitoring.

Free for individual use. Enterprise tier available for organizations that
need self-hosted signing, compliance dashboards, and policy controls at
aiauth.app.

Open source at https://github.com/chasehfinch-cpu/AIAuth
Privacy policy at https://aiauth.app/privacy
```

---

## Permissions explained (for the dashboard "Privacy practices" section and the listing body)

| Permission | Why AIAuth needs it |
|---|---|
| `activeTab` | To read the user's current selection at the moment they invoke the right-click attestation. Used only in response to an explicit user action; no persistent page access. |
| `storage` | To store receipts locally in the extension's own storage area. Receipts never leave the device unless the user shares them. |
| `notifications` | To show a small confirmation when an attestation completes (e.g., "Receipt created"). |
| `clipboardWrite` | To copy the resulting receipt code to the clipboard when the user chooses. |
| `contextMenus` | To register the "Attest selection with AIAuth" right-click entry. |
| Host permissions (`chatgpt.com`, `claude.ai`, `gemini.google.com`, `copilot.microsoft.com`) | Scoped so the content-script registration only runs on the AI tool surfaces the user explicitly wants to attest from. No access to other sites. |

AIAuth does **not** request: `<all_urls>`, `tabs`, `webRequest`, `webNavigation`, `history`, `bookmarks`, `cookies`, `downloads`, or any broad content-script injection.

---

## Single-purpose justification

AIAuth has one purpose: to let a user cryptographically attest that they have reviewed a selection of AI-generated content, and to produce a verifiable receipt of that attestation. All requested permissions serve that single purpose.

---

## Data-handling disclosures

- **Personally identifiable information:** Not collected by the extension.
- **Health information:** Not collected.
- **Financial and payment information:** Not collected.
- **Authentication information:** Not collected.
- **Personal communications:** Not collected (the content the user attests is hashed on-device; only the hash is transmitted).
- **Location:** Not collected.
- **Web history:** Not collected.
- **User activity:** Attestation timestamps and time-to-attest are stored in the receipt, at the user's explicit invocation. Nothing else about the user's activity is recorded.
- **Website content:** Not collected. Only a SHA-256 hash of content the user explicitly selects is transmitted to the AIAuth signing server.

Data usage certification:
- I do not sell or transfer user data to third parties outside of approved use cases.
- I do not use user data for purposes unrelated to the item's single purpose.
- I do not use user data to determine creditworthiness or for lending purposes.

---

## Resubmission checklist

Before clicking "Submit for review":

- [ ] Detailed description field matches the text in this file exactly.
- [ ] Single-purpose description matches.
- [ ] Permissions justifications above are pasted into the dashboard.
- [ ] Privacy practices certifications are re-confirmed.
- [ ] Package version matches `manifest.json` (`1.2.2`).
- [ ] No keyword lists of brand names anywhere in the listing copy.
