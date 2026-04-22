# AIAuth Enterprise — User Guide

This guide is for employees whose company has deployed AIAuth Enterprise. Short version: almost nothing changes about how you work. Keep reading for the details.

---

## 1. What's Changing for You

Your company now uses AIAuth to create a chain of custody for AI-assisted work. When you use ChatGPT, Claude, Copilot, or any other AI tool to help produce work output, you press **Ctrl+Shift+A** to create a tamper-proof receipt proving:

- What AI was used
- When it was used
- That you reviewed the output before using it

That's it. Your workflow doesn't change beyond one keystroke.

**What your employer can see through AIAuth:**
- Which AI tools you use for work (ChatGPT, Claude, Copilot, etc.)
- How long you spend reviewing AI output before attesting (time-to-attest)
- Whether you approved, modified, or rejected the output
- The metadata category of what you produced (spreadsheet, code, document, etc.)
- Whether the content appears to flow to external destinations

**What your employer cannot see, by design:**
- The actual text of your AI prompts
- The actual content of what you write
- Your browsing history outside of AI sites
- Screenshots, keystrokes, or any content capture
- Prompts and content you haven't attested

AIAuth is a chain-of-custody tool, not a surveillance tool. Your employer sees metadata about the shape of your AI-assisted work; they do not see the substance.

---

## 2. Getting Set Up

### 2.1 If the Chrome Extension Was Pre-Installed

Look for the AIAuth icon in your browser toolbar (a small blue "A"). Click it:
1. The Server URL should be pre-filled with your company's AIAuth server (e.g., `aiauth.yourco.com`).
2. Enter your **corporate** email address (e.g., `you@yourco.com`).
3. Click **Verify My Email (Recommended)**.
4. Open your corporate inbox — there's a one-time link waiting. Click it (or copy-paste it into the extension's verification box).
5. You're ready. Press Ctrl+Shift+A on any AI site to attest.

### 2.2 If You Need to Install It Yourself

Your IT department will point you at the Chrome Web Store listing. Install the extension, then follow 2.1 above.

### 2.3 If You Already Had a Personal AIAuth Account

You can link your corporate email to your existing account so your attestation history carries over:
1. Log into your personal AIAuth account in the extension.
2. Go to Settings → Link Additional Email.
3. Enter your corporate email.
4. Verify via the one-time link.

Your prior personal attestations **remain private by default**. You can optionally opt in to share them with your employer's dashboard via Settings → Consent. Your employer sees only what you explicitly consent to.

---

## 3. Daily Workflow

### 3.1 Attesting AI-Assisted Work

After you've reviewed AI output and decided it's ready to use:

1. Select the output text on the AI site.
2. Press **Ctrl+Shift+A** (or Cmd+Shift+A on Mac).
3. A receipt is created. You'll see a toast notification with a short code like `[AIAuth:a1b2c3d4]`.
4. That code is copied to your clipboard. Paste it wherever you want proof of provenance — alongside the content in an email, in a Slack message, in a document comment, etc.

### 3.2 Reviewing Before You Attest

The extension records how long you spent looking at the AI output before pressing Ctrl+Shift+A. This is the "time-to-attest" metric. Under 10 seconds on long content triggers a "rubber-stamp" alert.

If you're genuinely skimming something short, no alert fires. The threshold is calibrated for "long content reviewed too quickly to have actually been read."

### 3.3 File Attestation

Right-click any file → **AIAuth: Attest this file**. The agent hashes the file locally, reads AI-authorship markers, and creates a receipt. The file is never uploaded anywhere.

### 3.4 When You're Offline

Press Ctrl+Shift+A anyway. The receipt is created locally with a "Pending" badge. When you're back online, the extension syncs pending receipts automatically.

---

## 4. Your Receipts

### 4.1 Where They're Stored

- **On your device:** always. Open the popup to see your recent receipts.
- **On your company's AIAuth server:** for corporate attestations (once your corporate email is verified and linked to the org). Your employer's dashboard shows these.
- **On your personal AIAuth account:** for attestations made with your personal email. Your employer does NOT see these unless you opt in.

### 4.2 Verifying a Receipt

Anyone with the short code or the full receipt JSON can verify it at `aiauth.yourco.com/check` (or `aiauth.app/check` for personal-tier receipts). Verification is cryptographic — no account required.

### 4.3 Sharing a Receipt

In the extension popup, click **Share** next to a receipt. The full signed JSON is copied to your clipboard. Paste it anywhere that needs proof of chain of custody.

---

## 5. Leaving the Company

When you leave:

- Your **personal** attestation history stays with you. Your personal AIAuth account is unaffected.
- Your **corporate** attestations stay with the company. Your name is pseudonymized in the audit record so you're no longer personally identifiable, but the audit-record integrity is preserved.

Your employer cannot retroactively extract your personal attestation data. AIAuth's pseudonymization is one-way.

---

## 6. FAQ

**Can my employer see what I type into ChatGPT?**
No. Only a one-way hash of the prompt is recorded, and only when you create an attestation. Your employer sees the hash — not the prompt text. The hash cannot be reversed into the original prompt.

**Can my employer see what AI apps I have open on my computer?**
On the enterprise version, yes — but only AI applications we recognize (ChatGPT Desktop, Claude Desktop, Cursor, Copilot, Perplexity, Poe), only at the exact moment you press Ctrl+Shift+A, and never the contents of those apps. This is called the Shadow AI Heatmap. On the free version, this is never collected.

This is disclosed here because your employer is a consent-required data controller for this data, and consent requires that you know what's captured.

**Do I have to use this?**
Your company's policy determines this. AIAuth is technically optional — if you don't press Ctrl+Shift+A, no receipt is created. But if your company's policy says "all AI-assisted client deliverables must carry an AIAuth receipt," not attesting means your work isn't shippable.

**What if I forget to attest?**
Nothing breaks. Attestation is additive — your work still happens, just without the audit trail. Your manager might ask you to attest retroactively; you can do this by pasting the text into the extension popup's "Attest pasted text" box.

**Can I use AIAuth for personal projects?**
Yes. Install the extension at home with your personal email. Your personal attestations live on your personal account and never touch your employer's systems.

**What if my time-to-attest is flagged as rubber-stamping but I really did read the content?**
The threshold is `<10 seconds on content >500 characters`. If you consistently read fast, talk to your manager — the threshold can be tuned per-organization. If you were skimming because you'd already reviewed the content in an earlier attestation, you're not doing anything wrong; the metric captures "how long between the AI producing this and you attesting," not "how long you reviewed it."

**What happens if my company's AIAuth server goes down?**
Attestation works offline. Your extension queues pending receipts and syncs them when the server is back. You'll see a "Pending" badge on unsynced receipts.

**Can AIAuth the company (Finch Business Services LLC) see my data?**
No. Your company runs AIAuth on their own infrastructure. Finch Business Services LLC (the software vendor) has no access to the data — they ship the software, your IT team operates the server.
