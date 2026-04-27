# Firefox Add-ons (AMO) Listing Copy — v1.5.1

**Purpose:** Exact text to paste into the Mozilla Add-on Developer Hub (`addons.mozilla.org/developers/`) for the AIAuth Firefox listing. Companion to [STORE_LISTING.md](STORE_LISTING.md) (Chrome) and [STORE_LISTING_EDGE.md](STORE_LISTING_EDGE.md) (Edge).

**Same source, Firefox-specific build:** the Firefox zip is built from the same `chrome-extension/` source via `python scripts/build-extension-zip.py --firefox`. The build script injects a `browser_specific_settings.gecko` block (id `aiauth@aiauth.app`, strict_min_version 121.0) into the manifest at zip time. The JS is shared verbatim — Firefox 109+ supports the `chrome.*` namespace as an alias for `browser.*`, and Firefox 121+ supports MV3 service-worker backgrounds.

**Upload artifact:** `dist/aiauth-extension-firefox-v1.5.1.zip` (52 KB).

---

## Properties

| Field | Value |
|---|---|
| Add-on name | AIAuth — Chain of Custody for AI Work |
| Add-on URL slug | `aiauth` (or `aiauth-chain-of-custody` if `aiauth` is taken) |
| Categories | Productivity, Privacy & Security |
| Tags | (Firefox doesn't use search-keyword fields the way Chrome/Edge do.) |
| Default language | English (US) |

---

## Summary (≤250 characters)

```
Tamper-proof chain-of-custody receipts for AI-generated work. Right-click to attest. Content never leaves your device.
```

---

## Description (long; pasted into the dashboard)

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

## License

```
Apache License 2.0
```

The `LICENSE` file is included in the zip (`LICENSE`, 11,130 bytes).

---

## Privacy policy URL

```
https://aiauth.app/privacy
```

---

## Source code URL (required when uploading minified or built code)

The AIAuth extension ships unminified, so technically a source URL is not required. Provide it anyway for transparency:

```
https://github.com/chasehfinch-cpu/AIAuth/tree/main/chrome-extension
```

If the AMO reviewer asks for build instructions, the answer is:

> The Firefox zip is produced by `python scripts/build-extension-zip.py --firefox` from the repository root. This copies the files in `chrome-extension/` verbatim and injects a `browser_specific_settings.gecko` block into the manifest. No transpilation, bundling, or minification is performed.

---

## Notes for reviewers (Mozilla "Notes for review" field)

```
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
  No access to any other sites. Firefox treats these as opt-in by default;
  the user grants them via the Add-ons panel after install.

The extension does NOT request: <all_urls>, tabs, webRequest, webNavigation,
history, bookmarks, cookies, downloads, or any broad content-script injection.

Network behavior:
The extension makes outbound HTTPS requests only to https://aiauth.app
(the AIAuth signing server). All other API endpoints are configurable to
self-hosted servers via the managed_schema.json policy file for enterprise
deployments.

Cross-browser parity:
This extension is also published on the Chrome Web Store and the
Microsoft Edge Add-ons store. The Firefox zip is built from the same
source files; only browser_specific_settings.gecko differs in the manifest.

Source code:
https://github.com/chasehfinch-cpu/AIAuth (public, Apache 2.0)
Privacy policy:
https://aiauth.app/privacy
```

---

## Submission checklist

Before clicking "Submit version":

- [ ] Add-on package: `dist/aiauth-extension-firefox-v1.5.1.zip` (rebuild fresh with `python scripts/build-extension-zip.py --firefox` if there's any doubt).
- [ ] Add-on name, summary, description, categories match this file.
- [ ] License set to Apache 2.0.
- [ ] Privacy policy URL set to `https://aiauth.app/privacy`.
- [ ] Source code URL set to the GitHub `chrome-extension/` tree path.
- [ ] Notes for reviewers field pasted.
- [ ] Verify locally first: in Firefox, go to `about:debugging#/runtime/this-firefox` → "Load Temporary Add-on" → select the zip's `manifest.json` (or extract the zip and select the manifest from the extracted folder). Confirm popup opens, magic-link flow works, right-click attestation succeeds on chatgpt.com.

---

## Post-approval

- The AMO listing URL becomes `https://addons.mozilla.org/firefox/addon/<slug>/` once published.
- Add that URL to the AIAuth homepage browser-install matrix alongside Chrome and Edge.
- Any future v1.x.0 releases: rebuild with `--firefox` and upload the new zip — no listing-copy edits needed unless the description changes.
