# Microsoft Edge Add-ons Listing Copy — v1.5.0

**Purpose:** Exact text to paste into the Microsoft Partner Center developer dashboard for the AIAuth Edge extension listing. Companion to [STORE_LISTING.md](STORE_LISTING.md) (Chrome Web Store).

**Same package, different store:** Edge runs Chromium and accepts Chrome MV3 extensions as-is. The same `dist/aiauth-extension-v1.5.0.zip` you upload to Chrome Web Store can be uploaded to Edge Add-ons unchanged.

**Field-by-field differences from the Chrome listing** are called out below where they matter. Where Edge fields don't exist in CWS (or vice versa), a note explains.

---

## Properties

| Field | Value |
|---|---|
| Category | Productivity |
| Supported languages | English (en-US) |
| Age rating | Everyone (no objectionable content) |
| Country/region availability | All available |

---

## Store listing — Display name

```
AIAuth — Chain of Custody for AI Work
```

(Matches the manifest `name` field.)

---

## Store listing — Short description (≤200 characters)

```
Tamper-proof chain-of-custody receipts for AI-generated work. Right-click to attest. Content never leaves your device.
```

(Same as the Chrome short description; Edge allows up to 200 chars vs Chrome's 132 — current copy fits both.)

---

## Store listing — Description (long; up to 10,000 characters)

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

## Store listing — Search terms

(Edge allows up to 7 search terms, ~30 chars each. Avoid the brand-name keyword stuffing that got the Chrome v1.2.2 listing rejected as Yellow Argon.)

```
AI attestation
chain of custody
content authenticity
provenance
review receipt
SHA-256 signing
human in the loop
```

---

## Store listing — Screenshots

(Same screenshots as the Chrome submission. Edge requires at least 1, recommends 4–10. Min 1280×800. As of 2026-04-27, no screenshots are uploaded; this is non-blocking but boosts conversion. Screenshots are a separate task — see backlog.)

---

## Privacy — Privacy policy URL

```
https://aiauth.app/privacy
```

---

## Privacy — Data collection disclosures

For each data type, mark **No** unless otherwise specified:

| Data type | Collected? | Notes |
|---|---|---|
| Personal identifying information | No | |
| Health information | No | |
| Financial information | No | |
| Authentication information | No | |
| Personal communications | No | Content the user attests is hashed on-device; only the hash is transmitted. |
| Location | No | |
| Web history | No | |
| User activity | **Yes (limited)** | Attestation timestamps and time-to-attest are stored in the receipt, at the user's explicit invocation. Nothing else. |
| Website content | No | Only a SHA-256 hash of content the user explicitly selects is transmitted. |

**Disclose user-data certifications** (check all):
- [x] I do not sell or transfer user data to third parties outside of approved use cases.
- [x] I do not use user data for purposes unrelated to the item's single purpose.
- [x] I do not use user data to determine creditworthiness or for lending purposes.

---

## Notes for certification (Edge-specific reviewer field)

This is Edge's free-form field for the human reviewer. Use it to preempt the questions a reviewer will have. Paste the following:

```
This extension is also published on the Chrome Web Store (same Manifest V3
package). It is open source at https://github.com/chasehfinch-cpu/AIAuth.

Single purpose:
The extension lets a user cryptographically attest that they have reviewed
a selection of AI-generated content, and produces a verifiable receipt of
that attestation. All requested permissions serve this single purpose.

Permissions justifications:
- activeTab — read the user's current selection at the moment they invoke
  the right-click attestation. Used only in response to an explicit user
  action; no persistent page access.
- storage — store receipts locally in the extension's own storage area.
  Receipts never leave the device unless the user shares them.
- notifications — show a small confirmation when an attestation completes
  ("Receipt created").
- clipboardWrite — copy the resulting receipt code to the clipboard when
  the user chooses.
- contextMenus — register the "Attest selection with AIAuth" right-click entry.
- Host permissions (chatgpt.com, claude.ai, gemini.google.com,
  copilot.microsoft.com) — scoped so the content-script registration only
  runs on the AI tool surfaces the user explicitly wants to attest from.
  No access to any other sites.

The extension does NOT request: <all_urls>, tabs, webRequest, webNavigation,
history, bookmarks, cookies, downloads, or any broad content-script injection.

Network behavior:
The extension makes outbound HTTPS requests only to https://aiauth.app
(the AIAuth signing server). All other API endpoints are configurable to
self-hosted servers via the managed_schema.json policy file for enterprise
deployments.

Source code:
https://github.com/chasehfinch-cpu/AIAuth (public)
Privacy policy:
https://aiauth.app/privacy
```

---

## Submission checklist

Before clicking "Submit for review":

- [ ] Package uploaded matches `manifest.json` version (`1.5.0`).
- [ ] Display name, short description, long description match this file.
- [ ] Search terms entered (no brand-name enumeration).
- [ ] Privacy policy URL set to `https://aiauth.app/privacy`.
- [ ] Data collection disclosures filled out per the table above.
- [ ] Certification checkboxes ticked.
- [ ] Notes for certification field pasted.
- [ ] At least one screenshot uploaded if the dashboard requires it (it may not for first submission, but the listing is much stronger with them).

---

## After approval

- The Edge Add-ons URL becomes `https://microsoftedge.microsoft.com/addons/detail/<addon-id>` once published.
- Add that URL to the AIAuth homepage browser-install matrix alongside the Chrome Web Store URL.
- Update `chrome-extension/STORE_LISTING.md` line 119 — currently still says version `1.2.2` for the Chrome resubmission checklist; should be `1.5.0`.
