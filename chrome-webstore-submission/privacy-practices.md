# Chrome Web Store — Privacy Practices Answers

The Developer Console's Privacy Practices tab asks you to declare how your extension handles user data. Paste these into the corresponding fields.

---

## Single Purpose Description

```
Create one-click tamper-proof receipts (cryptographic attestations) for AI-generated content, proving what AI produced it and that a human reviewed it, without sending the content itself to any server.
```

---

## Permission Justifications

### `activeTab`

```
Required to read the user's text selection on AI sites (e.g., claude.ai, chatgpt.com) so it can be hashed locally and attested when the user presses Ctrl+Shift+A.
```

### `storage`

```
Used to store the user's local receipt history, server URL preference, email identifier, and session state in chrome.storage.local. All data stays on the user's device. Optional managed config (chrome.storage.managed) lets enterprise Workspace admins pre-configure the extension.
```

### `notifications`

```
Used to confirm that a receipt was successfully created (or failed) with a small system notification showing the receipt code.
```

### `clipboardWrite`

```
Used to automatically copy the short receipt code (e.g., [AIAuth:a1b2c3d4]) to the user's clipboard after a successful attestation, so they can paste it where they need proof.
```

### `contextMenus`

```
Adds a right-click menu option 'Attest selection with AIAuth' so users can attest selected text without using the keyboard shortcut.
```

### Host permissions (`https://chatgpt.com/*`, `https://claude.ai/*`, `https://gemini.google.com/*`, `https://copilot.microsoft.com/*`)

```
Content script runs only on these AI chat sites to detect the user's text selection and identify the AI model / provider automatically. The content script does not transmit page content to any server.
```

---

## Data Usage Disclosures

The Chrome Web Store Privacy Practices tab asks: "Does your extension collect or transfer any of the following?"

Answer with the following selections:

### Personally identifiable information (name, email, ID)

```
YES — collects and transfers to AIAuth's server for purposes of producing signed attestation receipts. Specifically: the user's self-provided email/identifier is sent along with each attestation request. Stored on the server as an HMAC hash, never in plaintext.
```

### Authentication information (passwords, credentials, security questions)

```
YES — collects and transfers session tokens used for account management endpoints (magic-link sign-in). Password-less authentication: the extension never sees the user's password; session tokens are issued by the server after the user clicks a magic link delivered to their email.
```

### Personal communications (emails, texts, chat messages)

```
NO.
```

### Location (region, IP address, GPS)

```
NO — other than the inherent IP-address logging any web server does for rate limiting and abuse prevention, disclosed in our privacy policy.
```

### Web history

```
NO.
```

### User activity (clicks, mouse position, scroll)

```
YES — the extension records time-to-attest metadata (seconds elapsed between the AI producing output and the user creating the attestation). This is used by enterprise tier customers to detect rubber-stamping and is NEVER populated on the free tier. Detailed disclosure in our privacy policy.
```

### Website content (text, images, sounds, videos, hyperlinks)

```
NO — the extension NEVER transmits page content, text selections, or other on-page data to any server. Content is hashed locally (SHA-256) in the user's browser; only the hash is sent to our server.
```

### Financial and payment information

```
NO.
```

### Health information

```
NO.
```

---

## Certifications

Check the three certification boxes:

```
☑  I do not sell or transfer user data to third parties, outside of the approved use cases.
☑  I do not use or transfer user data for purposes that are unrelated to my item's single purpose.
☑  I do not use or transfer user data to determine creditworthiness or for lending purposes.
```

---

## Privacy Policy URL

```
https://www.aiauth.app/privacy
```
