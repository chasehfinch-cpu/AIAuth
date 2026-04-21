# AIAuth — User Guide

## What is AIAuth?

AIAuth is a stamp for AI-generated work. When you use ChatGPT, Claude, 
Copilot, or any AI tool, AIAuth lets you create a permanent, tamper-proof 
record that says:

**"I used AI to help create this, and I personally reviewed it."**

That record is called a **receipt**. You keep it. Nobody else stores it. 
Anyone you share it with can verify it's real.

---

## Getting Started

### Install (pick one or both)

**If you use AI in a web browser** (ChatGPT, Claude, Gemini):
→ Install the AIAuth Chrome extension from the Chrome Web Store

**If you use AI anywhere on your computer** (VS Code, terminal, any app):
→ Install AIAuth Desktop from the Microsoft Store

### First-time setup

When you first open AIAuth, it asks for two things:

1. **Your identity** — your email address or name. This is what appears 
   on your receipts. Use your work email for work stuff.

2. **Server** — leave this as the default unless your company runs its 
   own AIAuth server.

That's it. You're ready.

---

## How to Use AIAuth

### Step 1: Use AI like you normally do

Write an email with ChatGPT. Draft a report with Claude. Generate code 
with Copilot. Nothing changes about your workflow.

### Step 2: Copy the AI output

Select the text the AI generated and copy it to your clipboard 
(Ctrl+C or right-click → Copy).

### Step 3: Press Ctrl+Shift+A

That's the AIAuth shortcut. You can also right-click the AIAuth icon 
in your system tray or browser toolbar.

### Step 4: What happens behind the scenes

- AIAuth creates a unique fingerprint of the text (like a digital 
  thumbprint — it can identify the text but can't recreate it)
- The fingerprint — NOT your text — is sent to the AIAuth server
- The server signs it with a tamper-proof digital seal and immediately 
  forgets it
- A signed receipt is saved on YOUR computer
- A receipt code like `[AIAuth:a1b2c3d4ab12]` replaces your clipboard

### Step 5: Paste the receipt code in your work

Put the receipt code wherever you deliver the work:

- At the bottom of an email
- In a document footer
- In a code comment
- In a Slack message
- Anywhere the recipient will see it

That receipt code is proof. Anyone who sees it can verify that you 
reviewed this AI-generated content on that date.

---

## What is a Receipt?

A receipt is a small file saved on your computer that contains:

| What | Example | Why |
|------|---------|-----|
| Your identity | jane@company.com | Who reviewed it |
| Timestamp | April 21, 2026 3:47 PM | When you reviewed it |
| Content fingerprint | a1b2c3... | Proves which content was reviewed |
| AI model (if known) | Claude Sonnet 4 | What AI helped create it |
| Digital signature | (cryptographic seal) | Proves the receipt is real |

The receipt does NOT contain the actual text you wrote. Nobody can 
read your work from the receipt — it only proves the work existed 
and you reviewed it.

---

## What is a Chain?

Sometimes content doesn't just get created once. It gets passed around, 
modified, run through AI again, and reviewed by multiple people. AIAuth 
tracks this automatically.

### Example: A financial report

```
  Monday 9:00 AM
  ┌─────────────────────────────────────────────┐
  │  Sarah drafts a forecast using Claude        │
  │  She reviews it and presses Ctrl+Shift+A     │
  │  → Receipt #1: Sarah created this with AI    │
  └──────────────────┬──────────────────────────┘
                     │
  Monday 2:00 PM     ▼
  ┌─────────────────────────────────────────────┐
  │  Mike receives it, changes the numbers       │
  │  He reviews his version, Ctrl+Shift+A        │
  │  → Receipt #2: Mike modified Sarah's work    │
  └──────────────────┬──────────────────────────┘
                     │
  Tuesday 10:00 AM   ▼
  ┌─────────────────────────────────────────────┐
  │  A consultant runs it through GPT-4o         │
  │  for additional analysis, Ctrl+Shift+A       │
  │  → Receipt #3: AI-enhanced by consultant     │
  └──────────────────┬──────────────────────────┘
                     │
  Tuesday 4:00 PM    ▼
  ┌─────────────────────────────────────────────┐
  │  The CFO reviews the final version           │
  │  She approves it, Ctrl+Shift+A               │
  │  → Receipt #4: CFO approved the final        │
  └─────────────────────────────────────────────┘
```

Each receipt automatically links to the one before it. This creates 
a **chain** — a complete history of who touched the content, what AI 
was involved, and who approved each version.

### How chains form automatically

When you attest content that was previously attested by someone else, 
AIAuth detects that the content has changed and links the new receipt 
to the old one. You don't do anything special — just use Ctrl+Shift+A 
as usual. The chain builds itself.

---

## How to Verify a Receipt

### If someone sends you a receipt code

You receive an email or document with something like 
`[AIAuth:a1b2c3d4ab12]` at the bottom. You want to know: is this real?

**Option 1: Use the verification page**

Go to **https://aiauth.app/check** (or whatever your company's AIAuth 
address is). Paste the receipt file contents. Click "Verify." You'll see:

- ✅ **Valid** — the receipt is authentic and hasn't been tampered with
- The name of who reviewed it
- When they reviewed it
- What AI model was involved (if applicable)

**Option 2: Ask the sender for the full receipt**

The receipt code is just a short reference. The actual receipt is a 
small file on the sender's computer (in their AIAuth receipts folder). 
Ask them to send you the `.json` file. You can upload it to the 
verification page for full details.

### If you want to verify a chain

If you received content that passed through multiple people, ask each 
person in the chain for their receipt. Upload all of them to the 
verification page. AIAuth will show you:

- Whether every link in the chain is authentic
- The complete history from creation to final approval
- Whether any link is broken (meaning someone tampered with a receipt)

---

## Where Are My Receipts?

Your receipts are saved on YOUR computer. AIAuth's server does not 
keep copies.

**Windows:** `C:\Users\YOUR_NAME\AppData\Roaming\AIAuth\receipts\`

**To find them:** Right-click the AIAuth icon in your system tray → 
"Open Receipt Store"

Each receipt is a small `.json` file named by its ID. You can:
- Back them up to a USB drive or cloud storage
- Email them to someone who asks for verification
- Keep them as long as you want (they never expire)
- Delete them if you no longer need them (but they can't be recreated)

---

## Common Questions

**Do I have to use this for everything?**
No. Only attest content you want to have a record for. Some people 
attest everything; others only attest important deliverables.

**Does my company see my attestations?**
Not unless your company runs its own AIAuth server in enterprise mode. 
With the free version, receipts exist only on your computer.

**Can I use this on my phone?**
Not yet. Desktop and browser only for now.

**What if I lose my receipts?**
They can't be recreated — the AIAuth server doesn't keep copies. 
Back up your receipts folder regularly, just like you would any 
important files.

**Does this work with every AI tool?**
Yes. AIAuth doesn't need to connect to the AI tool. You just copy 
the output and press Ctrl+Shift+A. It works with any AI — ChatGPT, 
Claude, Gemini, Copilot, Midjourney, Stable Diffusion, or anything 
else that produces output you can copy.

**What if I modify the AI output before attesting?**
That's expected and encouraged. Edit the AI's output, make it yours, 
then attest your final version. The receipt covers whatever was in 
your clipboard when you pressed Ctrl+Shift+A — which is your 
reviewed, edited version.

**Is this legally binding?**
AIAuth provides a cryptographically verifiable record of who reviewed 
what and when. Whether it's "legally binding" depends on your 
jurisdiction and context. It's comparable to a digital signature or 
a notarized timestamp — strong evidence, but consult a lawyer for 
specific legal questions.

**What does "chain broken" mean during verification?**
It means one of the receipts in the chain doesn't properly link to 
the previous one. This could mean someone modified a receipt after 
creating it (tampering), or the content was changed without creating 
a new attestation. Either way, the chain can't be trusted from that 
point forward.

---

## For Your IT Department

If your company wants centralized tracking of all AI attestations, 
AIAuth offers an enterprise mode with:

- Dashboard showing attestation volume by team
- Review rates and compliance metrics
- Chain visualization across the organization
- Audit export for regulators

Contact hello@aiauth.app for enterprise licensing.
