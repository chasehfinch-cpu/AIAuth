# CLAUDE.md — AIAuth Complete Build Specification

## Project Identity

- **Product:** AIAuth — cryptographic attestation for AI-generated work
- **Entity:** Finch Business Services LLC
- **Domain:** www.aiauth.app
- **Server:** DigitalOcean droplet at 167.172.250.174 (Ubuntu 24.04)
- **Repository:** https://github.com/chasehfinch-cpu/AIAuth
- **SSH:** Owner has access to the production server
- **Master key:** Located on the server at `/opt/aiauth/.env` as `AIAUTH_MASTER_KEY`
- **Signing keys:** `/opt/aiauth/keys/` directory (see Key Management section)
- **Current version:** 0.4.0
- **Target version:** 0.5.0

-----

## Core Principles (Never Violate)

1. Content never leaves the user's machine. Only a SHA-256 hash is sent to the server.
2. The public server stores nothing about users' attestations. Sign, forget, move on.
3. Receipts are self-contained proof. Verifiable offline with the public key.
4. The chain is the blockchain. Each receipt references the previous version's hash.
5. Attestation is voluntary. The onus is on the individual.
6. The hash registry stores only opaque identifiers. No names, no models, no content.
7. Identity is portable. A user's attestation history belongs to the user, not the employer.
8. Enterprise visibility is consent-gated. Corporate access to an employee's attestation history requires the user to link their identity.
9. Clients work offline. Attestation must not depend on server availability.
10. Data rights are absolute. Any user can request pseudonymization or deletion of their PII from any AIAuth system.

-----

## Zero-Data Server Principle (Free Tier)

This principle governs every design decision on the public/free tier. It is the promise in our marketing copy and the reason the architecture exists.

### What the public server persists on free tier

Only three things:

1. **`aiauth_registry.db`** — the five-column anonymous hash registry: `content_hash`, `receipt_id`, `parent_hash`, `doc_id`, `registered_at`. Contains no PII, no content, no user identifiers. This is the minimum data needed for chain discovery to work.
2. **`aiauth.db accounts + account_emails`** — email address and account_id, created only when the user explicitly creates an account for magic-link authentication. Required so the user can log in from multiple devices and manage their receipts. This is the only user-identifiable data we store.
3. **Auth ephemera** — `used_tokens` (nonces, auto-pruned after 1 day), `revoked_sessions` (session IDs for logout). Operational state, not user data.

### What the public server does NOT persist on free tier

- **Receipt contents.** The full receipt — including `prompt_hash`, `ai_markers`, `model`, `provider`, `tta`, `len`, `uid`, `review.*`, and every other field — is signed by the server and **returned to the client without being stored.** The client keeps the receipt on the user's device. The server keeps only the 5-column registry entry.
- **Content itself.** Ever. Only a SHA-256 hash is sent, and hashes are one-way.
- **Behavioral metadata.** TTA, session grouping, destinations, classification — all live on the user's machine only.
- **Concurrent AI app lists, prompt text, viewport data, edit patterns** — free-tier clients do not collect these fields at all (see Tier Gating). They are never transmitted, so they cannot be stored.

### What changes on enterprise tier

Enterprise hosted customers opt in, by contract (DPA), to having their employees' attestation metadata stored server-side in `enterprise_attestations`. This is the product they are paying for: visibility into their own workforce's AI usage. The data belongs to the employer, subject to GDPR/DSAR protections for the individual. Self-hosted enterprise runs the full AIAuth server on the customer's infrastructure — no data ever leaves their network.

### How this affects the three new v0.5.0 fields

- `prompt_hash` (free tier): Included in the receipt the server signs. Not persisted server-side on free tier. Persisted in `enterprise_attestations` on enterprise tier.
- `ai_markers` (free tier): Same pattern. Signed by server, not stored on free tier, stored in enterprise DB on enterprise tier.
- `concurrent_ai_apps` (commercial tier only): Never populated by free-tier clients. Free-tier server never receives this field. Only stored in enterprise DB when enterprise clients send it.

### Auditability

The user's own client can verify what was sent: every request to `/v1/sign` is logged client-side in the extension's / agent's local store, showing exactly which fields were transmitted. The server's response includes only the signature — no echo of persisted state that could reveal hidden storage.

-----

## Public-Facing Content and Messaging

### Messaging Hierarchy

AIAuth's public language must use terms enterprise buyers already understand. The messaging hierarchy, from most prominent to least:

1. **Chain of custody** — the primary frame. "Unbroken chain of custody for AI-generated work."
2. **Provenance** — who created it, when, with what tools. "AI content provenance without surveillance."
3. **Attestation** — the mechanism. "One-click attestation that proves your work was reviewed."
4. **Compliance** — the outcome. "AI compliance that doesn't require new workflows."

**Never lead with "cryptographic" in customer-facing copy.** It's technically accurate but alienates non-technical buyers. Use "tamper-proof" or "verifiable" instead.

### Landing Page (aiauth.app — root route)

```
STRUCTURE:

HERO SECTION:
  Headline: "Chain of Custody for AI-Generated Work"
  Subheadline: "Prove what AI helped create. Prove a human reviewed it.
               One click. No content leaves your machine."
  CTA Primary: "Install Free Extension" → Chrome Web Store
  CTA Secondary: "See Enterprise Demo" → /demo

HOW IT WORKS (3 steps, with animation or icons):
  1. "AI helps you write" — shows Claude/ChatGPT/Copilot logos
  2. "You press one key" — shows Ctrl+Shift+A keystroke
  3. "Tamper-proof receipt created" — shows receipt with checkmark
  "Your content never leaves your machine. Only a fingerprint is sent."

WHO IT'S FOR (3 columns):
  Individual: "Build a verifiable record of your AI-assisted work. Free forever."
  Team Lead:  "See which AI tools your team uses and whether output is reviewed."
  Compliance: "Audit-ready chain of custody. No content surveillance required."

ENTERPRISE VALUE PROP:
  Headline: "See Everything. Store Nothing."
  Body: "AIAuth gives you complete visibility into AI usage across your
         organization — which tools, which departments, whether output is
         reviewed — without ever seeing, storing, or transmitting the
         content itself."
  Key metrics shown: AI tools detected, review rate, rubber-stamp alerts,
                     external exposure, chain integrity
  CTA: "Start a 30-Day Free Pilot" → /demo with enterprise contact form

TRUST BAR:
  "Zero-knowledge architecture • Content never leaves your device •
   GDPR-ready by design • Verifiable offline • Open verification standard"

FOOTER:
  Links: /check (Verify a Receipt), /guide (User Guide), /docs (API),
         /demo (Enterprise Demo), GitHub repo
  "Built by Finch Business Services LLC"
```

### Verification Page (/check)

```
PURPOSE: Public verification of any AIAuth receipt. Anyone with a receipt
file can verify it here — no account needed.

STRUCTURE:
  Headline: "Verify a Receipt"
  Subheadline: "Drop an AIAuth receipt to verify its chain of custody"

  Upload area: drag-and-drop or file picker for .json receipt file
  OR: paste receipt JSON directly

  Results display:
  ✓ "Signature valid" — receipt was signed by AIAuth, not tampered with
  ✓ "Hash registered" — content fingerprint found in registry
  ✓ "Chain intact" — all parent versions verified (if doc_id chain)
  ✗ "Chain broken at version 3" — with gap details

  Show receipt metadata (non-sensitive fields):
  - When attested (ts)
  - Schema version (v)
  - Document ID (doc_id, if present)
  - Chain length (number of versions)

  DO NOT show: uid, model, provider, classification, prompt_hash,
               concurrent_ai_apps, ai_markers details
  (these are the attester's data, not the verifier's)
```

### User Guide (/guide)

```
STATUS: LIVE — excellent quality. DO NOT rewrite.
Extend incrementally as features ship.

The existing guide covers: what AIAuth is, installation, first-time setup,
Ctrl+Shift+A workflow, receipt explanation, chain concept (with the
Sarah → Mike → Consultant → CFO financial report example — keep this),
verification, receipt storage, and FAQ.

EXTEND IN PHASE 2 (when features are built):
  - Magic link authentication flow
  - Extension popup states and status indicators
  - Offline attestation and sync
  - AI model auto-detection explanation
  - Prompt hashing (what it is, why it's useful)
  - AI authorship markers (C2PA, Copilot docProps)

EXTEND IN PHASE 3:
  - File attestation right-click workflow
  - Account linking (personal → corporate)
  - Destination detection explanation

FILE: guide content is currently embedded in server.py or served as
static HTML. Migrate to /opt/aiauth/docs/USER_GUIDE.md when convenient,
but do not disrupt the live page.
```

### Enterprise Demo (/demo)

```
PURPOSE: Interactive demo showing dashboard value with synthetic data.
         Prospect can enter their company name for branded experience.

STRUCTURE:
  Headline: "See What AIAuth Reveals — Without Seeing Any Content"
  Company name input: "Enter your company name to personalize the demo"

  Loads executive-summary template with synthetic data (Feature 14)
  Tabs or navigation to: Executive Summary, Department Scorecard,
                          Tool Adoption, Compliance Report, Shadow AI Heatmap

  Each view has a "What this means" callout explaining the insight

  Bottom CTA: "Start a 30-Day Free Pilot"
  Contact form: company name, admin email, estimated user count, industry

  Pilot signup → creates org, sends admin magic link, provides
  Chrome extension install instructions for pilot department
```

### Enterprise Guide (/enterprise-guide)

```
PURPOSE: Two-part guide for corporate customers — one for admins, one for
end users. Served as rendered markdown.

FILES:
  /opt/aiauth/docs/ENTERPRISE_ADMIN_GUIDE.md
  /opt/aiauth/docs/ENTERPRISE_USER_GUIDE.md

ROUTE: /enterprise-guide renders both with tab navigation
```

-----

## Documentation Specifications

### Enterprise Admin Guide (ENTERPRISE_ADMIN_GUIDE.md)

```
TABLE OF CONTENTS:

1. GETTING STARTED
   1.1 What AIAuth Does for Your Organization
       - Chain of custody, not content surveillance
       - What you can see vs. what you cannot see
       - The zero-knowledge architecture in plain language
   1.2 Activating Your Enterprise Account
       - Domain claiming and verification
       - License key activation
       - Choosing hosted vs. self-hosted
   1.3 Your First 30 Minutes
       - Quick-start checklist for admins

2. DEPLOYING TO YOUR ORGANIZATION
   2.1 Chrome Extension Deployment
       - Google Workspace Admin Console force-install
       - Pre-configuring the extension for your org
       - Enabling enterprise-tier capture (concurrent AI apps, etc.)
   2.2 Desktop Agent Deployment
       - GPO / Intune / Winget / Jamf
       - Config file pre-population
   2.3 Pilot Deployment (Recommended)
       - Deploying to one department first
       - What to look for in the first 30 days

3. MANAGING USERS
   3.1 Inviting Users
       - Bulk invite via CSV
       - LDAP/Azure AD sync (when available)
   3.2 User Account Linking
       - What happens when an employee has a personal AIAuth account
       - Consent: what you can and cannot see
       - How to check linking status
   3.3 Offboarding an Employee
       - Step-by-step offboarding process
       - What happens to their attestations
       - Pseudonymization explained
       - DSAR handling
   3.4 Department Mapping
       - Uploading department CSV
       - Updating departments
       - What happens to unmapped users

4. READING THE DASHBOARD
   4.1 Dashboard Overview
       - What each view shows and why it matters
   4.2 AI Usage Heatmap
       - Reading the matrix: departments × tools
       - Identifying unapproved tool usage
   4.3 Shadow AI Heatmap
       - What concurrent_ai_apps reveals
       - Identifying tools open but not used for attested work
   4.4 Review Rate Scorecard
       - Letter grades explained (A–F)
       - What a low review rate means operationally
   4.5 Time-to-Attest Distribution
       - The rubber-stamp zone: what to do about it
       - Healthy vs. concerning TTA patterns
   4.6 Chain Integrity Monitor
       - What a broken chain means
       - Common causes and how to fix them
   4.7 Policy Violations
       - Default policies explained
       - Customizing policies for your organization
       - Resolving violations
   4.8 External Exposure Report
       - Understanding external content flow
       - Setting up external attestation requirements
   4.9 AI Authorship Detection
       - What ai_markers reveals (C2PA, Copilot, etc.)
       - Using it to identify ungoverned AI content

5. RUNNING REPORTS
   5.1 Pilot Report (30-day)
       - Generating the report
       - Interpreting results for leadership
   5.2 Compliance Report (quarterly)
       - Audit-ready output
       - What auditors look for
   5.3 Custom Exports
       - CSV/PDF export
       - Date range and filter options

6. DATA, PRIVACY, AND COMPLIANCE
   6.1 What AIAuth Stores (and Doesn't Store)
   6.2 Tier Gating: What Enterprise Clients Collect vs. Free Clients
   6.3 GDPR and DSAR Handling
   6.4 SOC 2 Readiness
   6.5 Data Retention Policies
   6.6 Self-Hosted Data Sovereignty
```

### Enterprise User Guide (ENTERPRISE_USER_GUIDE.md)

```
TABLE OF CONTENTS:

1. WHAT'S CHANGING FOR YOU
   - Your company now uses AIAuth for AI chain of custody
   - What this means for your daily workflow (almost nothing)
   - What AIAuth can and cannot see (it cannot see your content)
   - What the enterprise version captures that the free version does not

2. GETTING SET UP
   2.1 If the Chrome Extension Was Pre-Installed
       - Look for the AIAuth icon in your toolbar
       - Click it → enter your work email → verify
   2.2 If You Need to Install It Yourself
       - Chrome Web Store installation
       - Desktop agent installation (if applicable)
   2.3 If You Already Had a Personal AIAuth Account
       - Linking your personal and work emails
       - What your employer can see (only work attestations by default)
       - Choosing whether to share your personal history

3. DAILY WORKFLOW
   3.1 Attesting AI-Assisted Work
       - Select text → Ctrl+Shift+A (or Cmd+Shift+A on Mac)
       - What happens when you press the key
       - The status indicators: ✓ Signed, ◐ Pending, ✗ Failed
   3.2 Reviewing Before You Attest
       - Why review time matters (and what rubber-stamping is)
       - The review prompt: approved / modified / rejected
   3.3 File Attestation
       - Right-click any file → "AIAuth: Attest this file"
       - Document lifecycle and version tracking
   3.4 When You're Offline
       - Attestation works offline — receipts sync when you reconnect
       - What the "Pending" badge means

4. YOUR RECEIPTS
   4.1 Where Your Receipts Are Stored
       - Locally on your machine (always)
       - In your company's enterprise system (after org linking)
   4.2 Verifying a Receipt
       - Using the /check page
       - Sharing a receipt with someone for verification

5. LEAVING THE COMPANY
   - Your personal attestation history stays with you
   - Work attestations stay with the company
   - Your personal account is unaffected

6. FAQ
   - "Can my employer see what I type?" → No. Only metadata.
   - "Can my employer see what AI apps I have open?"
     → On the enterprise version, yes — but only the AI applications
       we recognize, only at the moment you press Ctrl+Shift+A,
       and never the contents of those apps. This is called the
       Shadow AI Heatmap and is disclosed to you here. On the free
       version, this data is never collected.
   - "Can my employer see the prompts I type into ChatGPT?"
     → No. We record a one-way hash of the prompt so we can prove
       that the same prompt produced the output you attested.
       The prompt text itself never leaves your machine. Your
       employer sees only the hash — they cannot read the prompt.
   - "Do I have to use this?" → Your company's policy determines this.
   - "What if I forget to attest?" → Nothing breaks. Attestation is additive.
   - "Can I use this for personal projects?" → Yes, with your personal email.
```

-----

## Architecture

```
USER SURFACES (all auto-capture metadata — user presses one key)
├── Chrome Extension ──────── browser AI tools
├── Desktop Agent (Windows) ─ any Windows application, any file
├── Desktop Agent (macOS) ─── any macOS application [TO BUILD]
└── LiteLLM Callback ──────── API-level attestation for developers

         │ sends: hash + metadata (never content)
         │ free-tier clients omit commercial-only fields entirely
         │ (if server unreachable → queue locally, sync later)
         ▼

AIAUTH SERVER (aiauth.app)
├── PUBLIC MODE (stateless, free, rate-limited)
│   ├── POST /v1/sign ──────────── sign receipt, register hash, forget
│   ├── POST /v1/sign/batch ─────── sign queued receipts (offline sync)
│   ├── POST /v1/verify ─────────── check signature Y/N + chain discovery
│   ├── POST /v1/verify/chain ───── validate full chain Y/N
│   ├── POST /v1/verify/content ─── verify receipt + content hash match
│   ├── POST /v1/verify/prompt ──── verify prompt_hash matches a receipt
│   ├── GET  /v1/discover/{hash} ── find related receipts in registry
│   ├── GET  /v1/discover/docid/{id} ── find all versions of a document
│   ├── GET  /v1/public-key ─────── signing key list with validity windows
│   ├── GET  /check ─────────────── public verification webpage (LIVE)
│   ├── GET  /guide ─────────────── user guide (LIVE — preserve, extend per phase)
│   ├── GET  /health ────────────── server status
│   ├── GET  /docs ──────────────── FastAPI auto-generated API docs (LIVE)
│   ├── GET  /demo ──────────────── interactive commercial demo dashboard
│   ├── GET  /privacy ───────────── privacy policy (LIVE)
│   ├── GET  /public-key ────────── Ed25519 public key page (LIVE)
│   └── GET  /.well-known/aiauth-public-key ── key discovery (LIVE)
│
├── ACCOUNT SYSTEM (authenticated — see Authentication section)
│   ├── POST /v1/account/create ──── create account, send magic link
│   ├── POST /v1/account/auth ────── request magic link for login
│   ├── POST /v1/account/verify ──── validate magic link token → session
│   ├── POST /v1/account/link ────── link additional email (authed)
│   ├── POST /v1/account/confirm ─── confirm email link (token-based)
│   ├── GET  /v1/account/me ──────── current account info (authed)
│   ├── POST /v1/account/consent ─── grant/revoke org visibility (authed)
│   └── POST /v1/account/export ──── export personal receipts for org import
│
├── ENTERPRISE MODE (license-gated, see Enterprise Data Flow)
│   ├── All public endpoints PLUS:
│   ├── POST /v1/enterprise/ingest ── receive attestations from enterprise clients
│   ├── POST /v1/enterprise/import ── import user's exported personal history
│   ├── POST /v1/review/{id} ────── human review with immutable history
│   ├── GET  /v1/review/{id}/history ── full review audit trail
│   ├── GET  /v1/attestations ───── query stored attestations with filters
│   ├── GET  /v1/stats ─────────── usage analytics
│   ├── GET  /v1/chain/{root} ──── stored chain queries
│   ├── GET  /v1/violations ────── policy violation feed
│   ├── POST /v1/admin/license/generate ── create enterprise license keys
│   ├── POST /v1/admin/org/claim ──── claim email domain for org
│   ├── GET  /v1/admin/org/members ── list org members + link status
│   ├── GET  /v1/admin/dashboard/data ── aggregated dashboard data endpoint
│   ├── GET  /v1/admin/dashboard ───── enterprise compliance dashboard (React)
│   ├── POST /v1/admin/dsar ─────── process data subject access request
│   └── POST /v1/admin/pseudonymize ── pseudonymize departed user's uid
│
└── STORED DATA
    ├── keys/
    │   ├── key_001_active.pem ──── current signing key
    │   ├── key_001_public.pem ──── current public key
    │   ├── key_000_retired.pem ─── previous signing key (for verification only)
    │   ├── key_000_public.pem ──── previous public key
    │   └── key_manifest.json ──── key ID → validity window mapping
    ├── aiauth_registry.db ──── hash registry (anonymous — 5 columns only)
    ├── aiauth.db ───────────── accounts, orgs, enterprise attestations, consent
    └── templates/
        └── commercial/ ─────── dashboard demo templates with synthetic data
```

-----

## Authentication Model

### The Problem

The account system endpoints (`/v1/account/me`, `/v1/account/consent`, `/v1/account/link`) accept identity parameters but have no mechanism to verify the caller owns that identity. Without authentication, anyone who guesses an `account_id` can query linked emails, modify consent grants, or link malicious emails to someone else's account. Since consent controls what the enterprise dashboard can see, this is a security-critical gap.

### The Solution: Magic Link Authentication

No passwords to store, no OAuth complexity, no third-party dependency. The email itself is the authentication factor.

```
AUTHENTICATION FLOW:

1. User requests auth:  POST /v1/account/auth {email: "jane@gmail.com"}
2. Server generates:    token = HMAC-SHA256(account_id + timestamp + nonce, SERVER_SECRET)
3. Server sends email:  "Click to log in: https://aiauth.app/auth?token=abc123"
4. User clicks link:    POST /v1/account/verify {token: "abc123"}
5. Server validates:    token signature, expiration (15 min), single-use
6. Server returns:      {session_token: "eyJ...", expires_in: 86400}
7. Client stores:       session_token in chrome.storage.local or config file
8. All authed requests: Authorization: Bearer <session_token>
```

### Token Specification

```python
# Magic link token (email → click → session)
magic_token = {
    "account_id": "ACC_a1b2c3d4",
    "email": "jane@gmail.com",
    "issued_at": "2026-04-21T20:00:00Z",
    "expires_at": "2026-04-21T20:15:00Z",  # 15-minute window
    "nonce": "random_32_bytes_hex",
    "purpose": "login"  # or "verify_email" or "link_email"
}
# Signed: HMAC-SHA256(json_canonical(magic_token), SERVER_SECRET)
# Single-use: nonce stored in used_tokens table, checked before acceptance

# Session token (returned after magic link validation)
session_token = {
    "account_id": "ACC_a1b2c3d4",
    "email": "jane@gmail.com",
    "issued_at": "2026-04-21T20:15:30Z",
    "expires_at": "2026-04-22T20:15:30Z",  # 24-hour session
    "session_id": "random_32_bytes_hex"
}
# Signed: HMAC-SHA256(json_canonical(session_token), SERVER_SECRET)
# Validated on every authenticated request
# Can be revoked by adding session_id to revoked_sessions table
```

### Token Database Tables (in aiauth.db)

```sql
-- Prevent token replay
CREATE TABLE used_tokens (
    nonce         TEXT PRIMARY KEY,
    used_at       TEXT NOT NULL,
    purpose       TEXT NOT NULL
);
-- Auto-prune: DELETE FROM used_tokens WHERE used_at < datetime('now', '-1 day')

-- Session revocation (logout, security incident)
CREATE TABLE revoked_sessions (
    session_id    TEXT PRIMARY KEY,
    revoked_at    TEXT NOT NULL,
    reason        TEXT  -- "logout" | "security" | "password_change"
);
```

### Authentication Requirements by Endpoint

```
UNAUTHENTICATED (public):
  POST /v1/sign              ← rate-limited by IP, no auth needed
  POST /v1/sign/batch        ← rate-limited by IP, no auth needed
  POST /v1/verify            ← public verification
  POST /v1/verify/chain      ← public verification
  POST /v1/verify/content    ← public verification
  POST /v1/verify/prompt     ← public prompt-hash verification
  GET  /v1/discover/*        ← public discovery
  GET  /v1/public-key        ← public key distribution
  GET  /check, /guide, /health, /docs, /demo

  POST /v1/account/create    ← creates account, sends magic link
  POST /v1/account/auth      ← requests magic link (no auth to request)
  POST /v1/account/verify    ← validates magic link → issues session
  POST /v1/account/confirm   ← validates email link token

AUTHENTICATED (session token required):
  POST /v1/account/link      ← must prove you own the source account
  GET  /v1/account/me        ← returns your own account data only
  POST /v1/account/consent   ← consent changes require identity proof
  POST /v1/account/export    ← export your own data

ENTERPRISE-AUTHENTICATED (license key + admin session):
  POST /v1/enterprise/ingest ← license key in header
  POST /v1/enterprise/import ← license key + user consent verification
  All /v1/admin/* endpoints  ← license key + admin-role session token
  All /v1/review/* endpoints ← license key + member-role session token
  GET  /v1/attestations      ← license key + member-role session token
  GET  /v1/stats, /violations, /chain ← license key + admin session
```

### Client-Side Token Management

```javascript
// Chrome extension — token storage and refresh
chrome.storage.local.get("aiauth_session", ({aiauth_session}) => {
  if (!aiauth_session || new Date(aiauth_session.expires_at) < new Date()) {
    // Session expired or missing — prompt for re-auth
    // Show badge on extension icon: "Login required"
    // User clicks → opens magic link flow in new tab
    return;
  }
  // Session valid — include in authenticated requests
  headers["Authorization"] = `Bearer ${aiauth_session.token}`;
});

// Desktop agent — token in config file
// ~/.aiauth/session.json (chmod 600)
// Same expiration check, same magic link flow via default browser
```

-----

## User Onboarding Flow

### The Problem

The spec says "install, set uid, attest" but doesn't define the actual first-run experience. Without explicit onboarding states, the builder will make UX decisions ad hoc, leading to inconsistencies between the Chrome extension and desktop agent, and undefined behavior when the user skips steps.

### Extension Popup States

```
STATE 1: NOT CONFIGURED (first install)
┌─────────────────────────────────────┐
│  AIAuth                             │
│                                     │
│  Chain of custody for AI work.      │
│  Enter your email to get started.   │
│                                     │
│  [  your@email.com  ]               │
│  [ Get Started ]                    │
│                                     │
│  Free forever. No content leaves    │
│  your machine.                      │
└─────────────────────────────────────┘
- Ctrl+Shift+A is DISABLED in this state
- Attempting to attest shows: "Set up AIAuth first → click the extension icon"
- "Get Started" → POST /v1/account/create → sends magic link → State 2

STATE 2: AWAITING VERIFICATION
┌─────────────────────────────────────┐
│  AIAuth                             │
│                                     │
│  ✉ Check your email                │
│  We sent a link to your@email.com   │
│                                     │
│  [ Resend Link ]  [ Change Email ]  │
│                                     │
│  Link expires in 15 minutes.        │
└─────────────────────────────────────┘
- Ctrl+Shift+A is DISABLED in this state
- Resend Link: rate-limited to 3/hour per email
- Change Email: returns to State 1
- User clicks magic link in email → State 3

STATE 3: VERIFIED — READY
┌─────────────────────────────────────┐
│  AIAuth  ✓ your@email.com           │
│                                     │
│  Select text, then press            │
│  Ctrl+Shift+A to attest.           │
│                                     │
│  Attestations today: 3              │
│  ✓ 2 signed  ◐ 1 pending           │
│                                     │
│  [ View Receipts ]  [ Settings ]    │
└─────────────────────────────────────┘
- Ctrl+Shift+A is ENABLED
- Badge shows attestation count for the day
- Settings: change email, link enterprise account, export receipts

STATE 4: ENTERPRISE LINKED
┌─────────────────────────────────────┐
│  AIAuth  ✓ your@company.com         │
│  🏢 Company Inc.                    │
│                                     │
│  Select text, then press            │
│  Ctrl+Shift+A to attest.           │
│                                     │
│  Attestations today: 7              │
│  ✓ 6 signed  ◐ 1 pending           │
│                                     │
│  [ View Receipts ]  [ Settings ]    │
└─────────────────────────────────────┘
- Shows org name and corporate email
- Attestations route to both public + enterprise endpoints
- Enterprise-tier fields (concurrent_ai_apps, etc.) now populated

STATE 5: SESSION EXPIRED
┌─────────────────────────────────────┐
│  AIAuth                             │
│                                     │
│  ⚠ Session expired                  │
│  Log in again to manage your        │
│  account. Attestation still works.  │
│                                     │
│  [ Send Login Link ]                │
└─────────────────────────────────────┘
- IMPORTANT: Attestation (Ctrl+Shift+A) STILL WORKS without auth
  because signing is unauthenticated. Only account management
  requires a session. This avoids blocking the user's workflow.
```

### Desktop Agent First-Run

```
1. Agent launches on first login after installation
2. System tray notification: "AIAuth is ready. Click to configure."
3. Click opens configuration window:
   - Email input field
   - "Get Started" button → magic link flow
   - If enterprise-deployed: email pre-populated from config file,
     only verification needed
4. After verification: tray icon changes to active state
5. Ctrl+Shift+A enabled globally
```

### Edge Cases

```
USER ENTERS INVALID EMAIL:
  Client-side: basic format validation (contains @ and .)
  Server-side: if format is valid but domain doesn't exist, still create
  account — email delivery will fail, user won't verify, stays in State 2.
  DO NOT reveal whether an email exists in the system (enumeration attack).

USER CLOSES MAGIC LINK EMAIL:
  Magic link expires in 15 minutes. User can request new link from State 2.
  If they never verify: account exists but is unverified, no attestations
  are possible. They can restart anytime from the extension popup.

USER CHANGES EMAIL AFTER VERIFYING:
  Settings → "Change email" → triggers new magic link to new email.
  Old email remains linked to account (can be removed in settings).
  uid changes to new email for future attestations.
  Previous attestations keep the old uid (immutable receipts).

ENTERPRISE EXTENSION PRE-INSTALL:
  When deployed via Google Workspace Admin Console, the extension config
  can include: {"enterprise_server": "https://aiauth.app", "org_domain": "company.com",
                "tier": "enterprise"}
  On first launch, the extension detects the pre-config and adjusts State 1:
  "Your company uses AIAuth. Enter your @company.com email to get started."
  The "tier: enterprise" flag activates commercial-only field capture
  (concurrent_ai_apps, tta, sid, dest, classification, etc.) —
  see Tier Gating section.
```

-----

## Enterprise Offboarding (Operational Detail)

### The Problem

Core Principle #2 says "the public server stores nothing about users — sign, forget, move on." But the enterprise dashboard needs to query attestations by uid, department, model, etc. These are contradictory unless the enterprise data path is explicitly separated from the public signing path.

### The Solution: Dual-Path Architecture

```
PERSONAL USER (free tier):
  Client → POST /v1/sign (public) → receipt signed → hash registered → done
  Receipt stored locally on user's machine only
  Public server forgets everything except the 5-column registry entry

ENTERPRISE USER (after org onboarding):
  Client → POST /v1/sign (public) → receipt signed → hash registered
       └→ POST /v1/enterprise/ingest → receipt metadata stored in enterprise DB

  The client makes TWO calls:
  1. Public sign (same as personal — maintains public registry)
  2. Enterprise ingest (sends receipt metadata to enterprise attestation store)

  The enterprise ingest endpoint:
  - Requires license key in X-AIAuth-License header
  - Validates that uid domain matches org's claimed domains
  - Stores full receipt metadata (all fields, including commercial-only
    fields like concurrent_ai_apps) in enterprise attestation table
  - Evaluates policy engine rules
  - Returns: {stored: true, violations: [...]}

SELF-HOSTED ENTERPRISE:
  Client → POST /v1/sign (enterprise server) → does both in one call
  Self-hosted deployments run the full AIAuth server internally
  The single /v1/sign endpoint signs, registers, AND stores
  No data leaves the corporate network
```

### Transition Flow (Personal → Enterprise)

```
BEFORE ENTERPRISE ONBOARDING:
  Jane's client points at: https://aiauth.app/v1/sign (public only)
  Jane's client is in free-tier capture mode (no concurrent_ai_apps, etc.)
  Receipts stored: locally + public registry

ENTERPRISE ACTIVATES:
  1. Admin claims company.com domain
  2. Admin sends invite to jane@company.com
  3. Jane links her corporate email to her account
  4. Jane's client detects org membership → switches to enterprise capture mode
     (starts populating tta, sid, dest, classification, concurrent_ai_apps)
  5. Client now sends to BOTH:
     - https://aiauth.app/v1/sign (public registry — unchanged)
     - https://aiauth.app/v1/enterprise/ingest (enterprise store — new)
  6. If Jane consents to share personal history:
     - Client calls POST /v1/account/export → gets signed receipt bundle
     - Admin calls POST /v1/enterprise/import with the bundle
     - Enterprise DB now has her historical attestations too
     - NOTE: Historical receipts made in free-tier mode will have NULL
       for commercial-only fields — this is expected, not an error.

SELF-HOSTED TRANSITION:
  1. Client reconfigured to point at https://aiauth.company.com/v1/sign
  2. Single endpoint handles everything internally
  3. Optional: org can also register hashes to public registry for
     cross-org chain verification (configurable)
```

### Enterprise Attestation Store Schema (in aiauth.db)

```sql
-- Enterprise attestation store (full receipt metadata)
CREATE TABLE enterprise_attestations (
    id              TEXT PRIMARY KEY,  -- receipt ID
    ts              TEXT NOT NULL,
    hash            TEXT NOT NULL,
    prompt_hash     TEXT,              -- SHA-256 of prompt text, if captured
    uid             TEXT NOT NULL,
    uid_pseudonym   TEXT,              -- set on DSAR/offboarding, original uid cleared
    src             TEXT,
    model           TEXT,
    provider        TEXT,
    source_domain   TEXT,
    source_app      TEXT,
    concurrent_ai_apps TEXT,           -- JSON array of detected AI processes
    ai_markers      TEXT,              -- JSON: {source, verified}
    doc_id          TEXT,
    parent          TEXT,
    file_type       TEXT,
    len             INTEGER,
    tta             INTEGER,
    sid             TEXT,
    dest            TEXT,
    dest_ext        INTEGER,           -- SQLite boolean
    classification  TEXT,
    review_status   TEXT,
    review_by       TEXT,
    review_at       TEXT,
    review_note     TEXT,
    tags            TEXT,              -- JSON array
    schema_version  TEXT NOT NULL,     -- "0.5.0"
    org_id          TEXT NOT NULL,
    client_integrity TEXT,             -- "none" | "extension" | "os-verified"
    ingested_at     TEXT NOT NULL,
    FOREIGN KEY (org_id) REFERENCES organizations(org_id)
);
CREATE INDEX idx_ea_uid ON enterprise_attestations(uid);
CREATE INDEX idx_ea_ts ON enterprise_attestations(ts);
CREATE INDEX idx_ea_org ON enterprise_attestations(org_id);
CREATE INDEX idx_ea_model ON enterprise_attestations(model);
CREATE INDEX idx_ea_doc_id ON enterprise_attestations(doc_id);
CREATE INDEX idx_ea_classification ON enterprise_attestations(classification);
CREATE INDEX idx_ea_pseudonym ON enterprise_attestations(uid_pseudonym);
CREATE INDEX idx_ea_prompt_hash ON enterprise_attestations(prompt_hash);
CREATE INDEX idx_ea_ai_markers ON enterprise_attestations(ai_markers);

-- Policy violation log
CREATE TABLE policy_violations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    attestation_id  TEXT NOT NULL REFERENCES enterprise_attestations(id),
    policy_id       TEXT NOT NULL,
    severity        TEXT NOT NULL,     -- "low" | "medium" | "high" | "critical"
    details         TEXT,              -- JSON: what triggered the violation
    detected_at     TEXT NOT NULL,
    resolved_at     TEXT,
    resolved_by     TEXT,
    resolution_note TEXT
);
CREATE INDEX idx_pv_severity ON policy_violations(severity);
CREATE INDEX idx_pv_detected ON policy_violations(detected_at);
```

-----

## Identity Model (Critical Design Decision)

### The Problem

A user starts with a personal email (`jane@gmail.com`). She builds an attestation history. Her employer buys AIAuth Enterprise. Now she needs to attest under `jane@company.com`. Without an identity model, these are two unrelated strangers. Her history is lost. The employer gets no onboarding value.

### The Solution: Account-Layer Identity

Identity linkage lives ABOVE the receipt layer. Receipts are never modified.

```
┌─────────────────────────────────────────────────────┐
│  ACCOUNT LAYER (aiauth.db — accounts table)         │
│                                                     │
│  account_id: "ACC_a1b2c3d4"                         │
│  emails: [                                          │
│    {email: "jane@gmail.com",    type: "personal",   │
│     verified: true, added: "2026-01-15"},           │
│    {email: "jane@company.com",  type: "corporate",  │
│     verified: true, added: "2026-04-01",            │
│     org_id: "ORG_xyz"}                              │
│  ]                                                  │
│  created_at: "2026-01-15T10:00:00Z"                 │
│  primary_email: "jane@gmail.com"                    │
│                                                     │
│  CONSENT GRANTS:                                    │
│  org_id: "ORG_xyz"                                  │
│    → can_see: corporate attestations (always)       │
│    → can_see: personal attestations (if consented)  │
│    → can_see: linked history (if consented)         │
└─────────────────────────────────────────────────────┘
         │
         │ uid on receipts = email used at time of attestation
         │ (immutable, audit-accurate, never rewritten)
         ▼
┌─────────────────────────────────────────────────────┐
│  RECEIPT LAYER (unchanged)                          │
│                                                     │
│  Receipt 1: uid="jane@gmail.com"    (personal)      │
│  Receipt 2: uid="jane@gmail.com"    (personal)      │
│  Receipt 3: uid="jane@company.com"  (corporate)     │
│  Receipt 4: uid="jane@company.com"  (corporate)     │
│                                                     │
│  All four receipts are linked via account_id in     │
│  the account layer, but the receipts themselves     │
│  are immutable and store only the uid.              │
└─────────────────────────────────────────────────────┘
```

### User Lifecycle

```
PERSONAL USER JOURNEY:
1. Install Chrome extension or desktop agent
2. Set uid = personal email (jane@gmail.com)
3. First attestation triggers: POST /v1/account/create
   → magic link sent → account created on confirmation
4. Attest freely — receipts signed, hash registered, stored locally
   Free-tier capture mode: only free-tier fields populated (see Tier Gating)
5. account_id stored locally for account management only

ENTERPRISE ONBOARDING:
1. Employer buys AIAuth Enterprise, provides domain(s): company.com
2. Admin sends invite to jane@company.com (or bulk invite via CSV/LDAP)
3. Jane receives email: "Company X uses AIAuth. Link your account?"
4. Jane clicks link → confirms she owns jane@company.com
5. Server checks: does an account already exist with a verified email
   that matches this person? (email prefix matching is a hint, not proof)
6. If existing account found:
   a. Jane is prompted: "Link jane@company.com to your existing account?"
   b. Jane confirms → corporate email added to her account
   c. Client detects org membership → switches to enterprise-tier capture
      (starts populating concurrent_ai_apps, tta, dest, etc.)
   d. Client starts sending to enterprise ingest endpoint in parallel
   e. Jane is asked: "Allow Company X to see your prior attestation history?"
      - If YES: Jane exports personal receipts → admin imports to enterprise DB
      - If NO: employer sees only attestations made with @company.com going forward
7. If no existing account: new account created with corporate email

OFFBOARDING:
1. Employee leaves company
2. Admin triggers offboarding: POST /v1/admin/pseudonymize
3. Attestations made WITH @company.com:
   - uid field replaced with uid_pseudonym (SHA-256 of uid + org salt)
   - Attestation records retained for audit (corporate records)
   - Original uid no longer queryable
4. Attestations made WITH @gmail.com revert to personal-only
   (consent grant revoked automatically on offboarding)
5. Jane's account persists — she keeps her personal email + history
6. She can link a new employer's email later → repeat the cycle
7. Consent change logged in consent_log (immutable)
8. Client reverts to free-tier capture mode (stops collecting commercial fields)
```

### Why This Design

- **Receipts stay immutable.** `uid` is the email at time of attestation. Period.
- **No PII in the registry.** The anonymous hash registry is untouched.
- **Consent is explicit.** Employers see corporate attestations by default (work product), personal history only with user opt-in.
- **Portability is real.** A user's attestation reputation follows them across jobs.
- **Enterprise gets value immediately.** Even before users link accounts, all `@company.com` attestations are visible to the org dashboard.
- **The transition is seamless.** The Chrome extension / desktop agent detects the corporate email and prompts the user to link — one click, not a re-registration.
- **GDPR/DSAR compliant.** Pseudonymization preserves audit value while eliminating PII.

-----

## Database Architecture

### Consolidation Rationale

Two databases, not three. The anonymous registry has fundamentally different access patterns, backup requirements, and privacy guarantees — it stays separate. Everything else (accounts, organizations, consent, enterprise attestations, tokens, policy violations) shares a single database for efficient JOINs and simplified operations.

### Database 1: aiauth_registry.db (Anonymous Hash Registry)

```sql
-- This is the ONLY table in the registry database
-- Five columns. No names, no models, no content. Anonymous.
CREATE TABLE hash_registry (
    content_hash   TEXT NOT NULL,
    receipt_id     TEXT NOT NULL,
    parent_hash    TEXT,
    doc_id         TEXT,
    registered_at  TEXT NOT NULL
);
CREATE INDEX idx_hr_content ON hash_registry(content_hash);
CREATE INDEX idx_hr_doc_id ON hash_registry(doc_id);
CREATE INDEX idx_hr_parent ON hash_registry(parent_hash);
```

**IMPORTANT:** The registry does NOT store `prompt_hash`. Prompt hashes live only in the signed receipt (client-side) and, on enterprise tier, in `enterprise_attestations`. Putting prompt_hash in the public registry would create a correlation vector: an attacker could match a known prompt to its content_hash. Keep these unlinked on the public server.

**Maintenance:** Registry entries unreferenced by any chain verification within 180 days MAY be pruned (configurable, default: no pruning). This prevents unbounded growth from spam/abuse while preserving all entries with demonstrated value.

### Database 2: aiauth.db (Everything Else)

```sql
-- ============================================================
-- ACCOUNT SYSTEM
-- ============================================================

-- Core identity table
CREATE TABLE accounts (
    account_id    TEXT PRIMARY KEY,  -- "ACC_" + uuid4 hex[:12]
    primary_email TEXT NOT NULL,
    created_at    TEXT NOT NULL,     -- ISO 8601
    updated_at    TEXT NOT NULL
);

-- Email linkage (one account → many emails)
CREATE TABLE account_emails (
    email         TEXT PRIMARY KEY,
    account_id    TEXT NOT NULL REFERENCES accounts(account_id),
    email_type    TEXT NOT NULL,     -- "personal" | "corporate"
    org_id        TEXT,              -- NULL for personal, org ID for corporate
    verified      INTEGER NOT NULL DEFAULT 0,
    added_at      TEXT NOT NULL,
    verified_at   TEXT
);
CREATE INDEX idx_ae_account ON account_emails(account_id);
CREATE INDEX idx_ae_org ON account_emails(org_id);

-- ============================================================
-- ENTERPRISE ORGANIZATIONS
-- ============================================================

CREATE TABLE organizations (
    org_id        TEXT PRIMARY KEY,  -- "ORG_" + uuid4 hex[:12]
    name          TEXT NOT NULL,
    domains       TEXT NOT NULL,     -- JSON array: ["company.com", "subsidiary.com"]
    license_key   TEXT NOT NULL,
    license_tier  TEXT NOT NULL,     -- "self-hosted" | "hosted" | "compliance"
    created_at    TEXT NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1
);

-- Org membership
CREATE TABLE org_members (
    account_id    TEXT NOT NULL REFERENCES accounts(account_id),
    org_id        TEXT NOT NULL REFERENCES organizations(org_id),
    role          TEXT NOT NULL DEFAULT 'member',  -- "admin" | "member"
    department    TEXT,             -- from department mapping (Feature 11)
    joined_at     TEXT NOT NULL,
    left_at       TEXT,            -- NULL = active member
    consent_personal_history INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, org_id)
);

-- ============================================================
-- CONSENT AUDIT LOG (immutable — never delete or modify rows)
-- ============================================================

CREATE TABLE consent_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id    TEXT NOT NULL,
    org_id        TEXT NOT NULL,
    action        TEXT NOT NULL,    -- "grant_personal" | "revoke_personal" | "offboard"
                                   -- | "dsar_pseudonymize" | "dsar_export" | "dsar_delete"
    timestamp     TEXT NOT NULL,
    details       TEXT              -- JSON: additional context for audit
);

-- ============================================================
-- AUTHENTICATION TOKENS
-- ============================================================

CREATE TABLE used_tokens (
    nonce         TEXT PRIMARY KEY,
    used_at       TEXT NOT NULL,
    purpose       TEXT NOT NULL     -- "login" | "verify_email" | "link_email"
);

CREATE TABLE revoked_sessions (
    session_id    TEXT PRIMARY KEY,
    revoked_at    TEXT NOT NULL,
    reason        TEXT              -- "logout" | "security" | "offboard"
);

-- ============================================================
-- ENTERPRISE ATTESTATION STORE
-- (Only populated in enterprise/hosted mode)
-- ============================================================

CREATE TABLE enterprise_attestations (
    id              TEXT PRIMARY KEY,
    ts              TEXT NOT NULL,
    hash            TEXT NOT NULL,
    prompt_hash     TEXT,
    uid             TEXT NOT NULL,
    uid_pseudonym   TEXT,
    src             TEXT,
    model           TEXT,
    provider        TEXT,
    source_domain   TEXT,
    source_app      TEXT,
    concurrent_ai_apps TEXT,           -- JSON array
    ai_markers      TEXT,              -- JSON: {source, verified}
    doc_id          TEXT,
    parent          TEXT,
    file_type       TEXT,
    len             INTEGER,
    tta             INTEGER,
    sid             TEXT,
    dest            TEXT,
    dest_ext        INTEGER,
    classification  TEXT,
    review_status   TEXT,
    review_by       TEXT,
    review_at       TEXT,
    review_note     TEXT,
    tags            TEXT,              -- JSON array
    schema_version  TEXT NOT NULL,
    org_id          TEXT NOT NULL REFERENCES organizations(org_id),
    client_integrity TEXT DEFAULT 'none',
    ingested_at     TEXT NOT NULL
);
CREATE INDEX idx_ea_uid ON enterprise_attestations(uid);
CREATE INDEX idx_ea_ts ON enterprise_attestations(ts);
CREATE INDEX idx_ea_org ON enterprise_attestations(org_id);
CREATE INDEX idx_ea_model ON enterprise_attestations(model);
CREATE INDEX idx_ea_doc_id ON enterprise_attestations(doc_id);
CREATE INDEX idx_ea_classification ON enterprise_attestations(classification);
CREATE INDEX idx_ea_pseudonym ON enterprise_attestations(uid_pseudonym);
CREATE INDEX idx_ea_prompt_hash ON enterprise_attestations(prompt_hash);

-- ============================================================
-- POLICY VIOLATIONS
-- ============================================================

CREATE TABLE policy_violations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    attestation_id  TEXT NOT NULL REFERENCES enterprise_attestations(id),
    policy_id       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    details         TEXT,
    detected_at     TEXT NOT NULL,
    resolved_at     TEXT,
    resolved_by     TEXT,
    resolution_note TEXT
);
CREATE INDEX idx_pv_severity ON policy_violations(severity);
CREATE INDEX idx_pv_detected ON policy_violations(detected_at);
```

### Key Queries the Database Enables

```sql
-- "Show me all attestations for this org" (enterprise dashboard)
SELECT ea.*, om.department
FROM enterprise_attestations ea
LEFT JOIN account_emails ae ON ea.uid = ae.email
LEFT JOIN org_members om ON ae.account_id = om.account_id AND om.org_id = ea.org_id
WHERE ea.org_id = ?
  AND ea.ts BETWEEN ? AND ?
ORDER BY ea.ts DESC;

-- "Shadow AI Heatmap": which AI tools are open but NOT being used for attestation
SELECT json_each.value AS open_app,
       COUNT(*) AS times_detected,
       SUM(CASE WHEN ea.source_app LIKE '%' || json_each.value || '%'
                THEN 1 ELSE 0 END) AS times_used_for_attest
FROM enterprise_attestations ea, json_each(ea.concurrent_ai_apps)
WHERE ea.org_id = ? AND ea.ts BETWEEN ? AND ?
GROUP BY json_each.value
ORDER BY (times_detected - times_used_for_attest) DESC;

-- "AI authorship detection": attested artifacts that were AI-authored
SELECT ea.uid, ea.ts, json_extract(ea.ai_markers, '$.source') AS marker_source
FROM enterprise_attestations ea
WHERE ea.org_id = ?
  AND ea.ai_markers IS NOT NULL
  AND json_extract(ea.ai_markers, '$.verified') = 1
ORDER BY ea.ts DESC;

-- "Show me Jane's full history" (only if consent_personal_history = 1)
SELECT ea.* FROM enterprise_attestations ea
JOIN account_emails ae ON ea.uid = ae.email
JOIN org_members om ON ae.account_id = om.account_id
WHERE ae.account_id = ?
  AND (ae.email_type = 'corporate' OR om.consent_personal_history = 1)
ORDER BY ea.ts DESC;
```

-----

## Key Management

### The Problem

A single Ed25519 signing key with no rotation plan means: if the key is compromised, every future receipt is untrustworthy AND there's no migration path. If the key is lost, all historical receipts become unverifiable forever.

### The Solution: Versioned Key List with Validity Windows

```
/opt/aiauth/keys/
├── key_manifest.json          ← maps key IDs to validity windows
├── key_001_active.pem         ← current signing key (Ed25519 private)
├── key_001_public.pem         ← current public key
├── key_000_retired.pem        ← previous signing key (verify only)
└── key_000_public.pem         ← previous public key
```

### Key Manifest

```json
{
  "keys": [
    {
      "key_id": "key_000",
      "algorithm": "Ed25519",
      "valid_from": "2026-01-01T00:00:00Z",
      "valid_until": "2026-06-30T23:59:59Z",
      "status": "retired",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
    },
    {
      "key_id": "key_001",
      "algorithm": "Ed25519",
      "valid_from": "2026-06-01T00:00:00Z",
      "valid_until": null,
      "status": "active",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
    }
  ],
  "current_signing_key": "key_001"
}
```

### How It Works

**Signing:** Server always signs with the `current_signing_key`. The `key_id` is embedded in the signed receipt.

**Verification:** Receipt includes `key_id`. Verifier looks up the key in the manifest, checks that the receipt's `ts` falls within the key's validity window, and verifies the signature with the corresponding public key.

**Rotation:** Generate new key pair → add to manifest with `valid_from` = now and overlap period → update `current_signing_key` → set old key `valid_until` = now + 30 days → after transition period, set old key `status: retired`.

**CRITICAL:** Back up ALL key files. If a signing key is lost, all receipts signed with that key become unverifiable forever. Key backup is as critical as database backup.

-----

## Metadata Integrity

### The Problem

The server signs whatever metadata the client sends. A user could fabricate `tta: 847` (pretending they reviewed carefully) when they actually attested in 2 seconds. For personal use this is harmless — lying to yourself is your problem. For enterprise compliance, the entire value proposition depends on metadata trustworthiness.

### The Solution: Layered Integrity Verification

Full client-side verification is impossible without violating the "content never leaves the machine" principle. Instead, we make spoofing progressively harder and always detectable:

**Level 1: None** (`client_integrity: "none"`)
- Direct API calls, LiteLLM callbacks, unknown clients
- Metadata is self-reported, no verification
- Enterprise dashboard flags these as "unverified source"

**Level 2: Extension-Attested** (`client_integrity: "extension"`)
- Chrome extension includes a client attestation hash in each request
- Hash = HMAC-SHA256(extension_version + timestamp + receipt_hash, CLIENT_SECRET)
- CLIENT_SECRET is embedded in the extension, rotated with each extension update
- Server validates the hash, confirming the request originated from a legitimate AIAuth extension
- Not tamper-proof (determined user can extract CLIENT_SECRET) but raises the bar significantly

**Level 3: OS-Verified** (`client_integrity: "os-verified"`)
- Desktop agent uses OS-level APIs to verify the active application:
  - Windows: ETW (Event Tracing for Windows) for process/window verification
  - macOS: Endpoint Security Framework for application identity
- Agent signs the metadata with its own key pair (installed during deployment)
- Enterprise IT can verify the agent hasn't been tampered with via code signing
- Enterprise dashboard shows these as "OS-verified" — highest confidence

Enterprise policy engine can use this field: e.g., `"condition": "client_integrity == 'none' AND classification == 'financial'"` → flag unverified financial attestations.

-----

## Rate Limiting and Abuse Prevention

```python
# Rate limiting configuration
RATE_LIMITS = {
    "/v1/sign": {
        "per_ip": "100/minute",
        "per_ip_burst": 20,
        "global": "10000/minute",
    },
    "/v1/sign/batch": {
        "per_ip": "10/minute",
        "max_batch_size": 50,
    },
    "/v1/account/create": {
        "per_ip": "5/hour",
    },
    "/v1/account/auth": {
        "per_ip": "10/hour",
        "per_email": "3/hour",
    },
    "/v1/discover/*": {
        "per_ip": "60/minute",
    },
    "/v1/verify/prompt": {
        "per_ip": "30/minute",
    },
}

REQUIRED_HEADERS = {
    "/v1/sign": ["X-AIAuth-Client"],
    "/v1/sign/batch": ["X-AIAuth-Client"],
}
```

### Registry Hygiene

```python
def prune_registry():
    """
    Remove registry entries that:
    1. Were registered more than 180 days ago AND
    2. Have never been referenced in a verification request AND
    3. Are not part of any chain (no other entry references them as parent)

    Default: DISABLED. Enable via AIAUTH_REGISTRY_PRUNE=true in .env
    """
    pass

def check_registry_health():
    """
    Alert if registry exceeds thresholds:
    - Warning: > 1M entries
    - Critical: > 10M entries
    - Alert: growth rate > 100K/day (likely abuse)
    """
    pass
```

-----

## Offline-First Client Architecture

### Client Attestation Flow

```
1. User presses Ctrl+Shift+A (or right-clicks file)
2. Client computes SHA-256 hash of content locally
3. If prompt text is available and free-or-enterprise tier: compute prompt_hash
4. If enterprise tier: capture concurrent_ai_apps, tta, dest, etc.
5. Detect ai_markers (C2PA, Copilot docProps) — both tiers
6. Client generates receipt locally with all applicable metadata fields
7. Client stores receipt in LOCAL RECEIPT STORE (always succeeds)
8. Client attempts server signing:
   a. If server reachable:
      - POST /v1/sign → receipt signed → signature appended to local receipt
      - Hash registered in registry (prompt_hash NOT in registry)
      - Receipt status: "signed"
   b. If server unreachable:
      - Receipt stored locally WITHOUT server signature
      - Receipt status: "pending"
      - Queue for sync
9. Background sync (runs every 5 minutes when online):
   - Find all "pending" receipts
   - POST /v1/sign/batch with up to 50 receipts
   - Server signs each, registers hashes, returns signatures
   - Client updates local receipts: status → "signed"
```

### Local Receipt Store

```javascript
// Chrome extension — IndexedDB via chrome.storage.local
{
  "receipts": {
    "receipt_id_1": {
      "receipt": { /* full receipt object, including all captured fields */ },
      "status": "signed",
      "signature": "base64...",
      "created_at": "2026-04-21T20:15:30Z",
      "signed_at": "2026-04-21T20:15:31Z",
      "sync_attempts": 0,
      "last_sync_error": null
    }
  },
  "sync_queue": ["receipt_id_3", "receipt_id_4"],
  "last_sync": "2026-04-21T20:10:00Z"
}

// Desktop agent — SQLite at ~/.aiauth/receipts.db
// Same schema, table-based
```

### Offline Verification

Receipts signed by the server can always be verified offline. Pending (unsigned) receipts have a clear visual indicator:

```
✓ Signed     — server-verified, in registry, full confidence
◐ Pending    — locally attested, awaiting server signature
✗ Failed     — sync failed 3+ times, manual intervention needed
```

-----

## Schema Versioning Policy

### The Rules (Non-Negotiable)

1. **New fields are always additive.** Never rename or remove. Deprecated fields remain in the schema.
2. **The server must accept receipts from any schema version ≥ 0.4.0.** Unknown fields ignored (forward compat). Missing optional fields default to `null` (backward compat). Required fields (`v`, `id`, `ts`, `hash`, `uid`) enforced across all versions.
3. **The dashboard handles missing fields gracefully.** NULL-safe aggregation everywhere.
4. **Clients display a warning if their schema version is more than one minor version behind the server.** Warning, not block — attestation still works.
5. **Schema version changelog maintained here.**

### Version History

```
v0.4.0 (current production)
  Fields: v, id, ts, hash, uid, src, doc_id, parent, review.*

v0.5.0 (target)
  Added: key_id, client_integrity, model, provider, source_domain,
         source_app, file_type, len, tta, sid, dest, dest_ext,
         classification, tags, prompt_hash, ai_markers, concurrent_ai_apps
  Changed: none
  Deprecated: none
  Tier-gated fields (commercial clients only):
    tta, sid, dest, dest_ext, classification, concurrent_ai_apps
  Free-tier fields (all clients):
    All others, including prompt_hash and ai_markers
```

-----

## Data Rights and GDPR Compliance

### The Architecture's Built-In Advantages

1. **The public registry stores no PII.** Five anonymous columns.
2. **Content never touches the server.**
3. **The account system is the only PII store.** Email addresses in `account_emails` and `uid` in `enterprise_attestations` are the only personal data. Both are designed for pseudonymization.

### DSAR (Data Subject Access Request) Flow

```python
@app.post("/v1/admin/dsar")
def process_dsar(email: str, action: str, org_id: str):
    """
    Actions:
    - "export": Return all data associated with this email
    - "pseudonymize": Replace uid with pseudonym, retain records
    - "delete": Remove all traces (nuclear option)

    All actions are logged in consent_log.
    """

    if action == "export":
        # Return: account info, linked emails, all attestations with this uid,
        # consent history, policy violations involving this uid
        pass

    if action == "pseudonymize":
        # 1. Generate pseudonym: SHA-256(email + org_salt + "pseudonymize")
        # 2. UPDATE enterprise_attestations SET uid_pseudonym = ?, uid = '[pseudonymized]'
        #    WHERE uid = ? AND org_id = ?
        # 3. Log action in consent_log
        pass

    if action == "delete":
        # 1. DELETE FROM enterprise_attestations WHERE uid = ? AND org_id = ?
        # 2. DELETE FROM account_emails WHERE email = ?
        # 3. If no remaining emails, DELETE FROM accounts WHERE account_id = ?
        # 4. Registry entries are NOT deleted (they contain no PII)
        # 5. Log action in consent_log
        pass
```

### What to Tell Enterprise Legal

```
Q: "What personal data does AIAuth store?"
A: Email addresses in the account system and attestation records.
   The hash registry stores no personal data.
   Content never touches our servers.
   Prompts never touch our servers — only hashes.

Q: "What happens when an employee leaves?"
A: Admin triggers offboarding. Email addresses in attestation records
   are replaced with a one-way pseudonym. Audit records are preserved
   (required for compliance) but the individual is no longer identifiable.

Q: "Can an employee request deletion under GDPR Article 17?"
A: Yes. We support full deletion, but we recommend pseudonymization
   instead — it satisfies GDPR while preserving audit integrity.

Q: "Does AIAuth monitor what applications employees have open?"
A: On the enterprise tier, yes — but only AI applications we recognize
   (ChatGPT Desktop, Claude Desktop, Cursor, etc.), only at the exact
   moment an attestation is created, and never the contents of those
   applications. This is disclosed to employees in the Enterprise User Guide.
   On the free tier, this data is never collected.

Q: "Where is data stored?"
A: Hosted tier: DigitalOcean infrastructure, US region (configurable).
   Self-hosted tier: Your infrastructure, your jurisdiction, your control.

Q: "Is AIAuth a data processor or data controller?"
A: For hosted enterprise: Data processor under DPA with the customer.
   For self-hosted: Not applicable — we never see the data.
   For free individual tier: Data controller for account data only.
   The hash registry is anonymous and not subject to GDPR.
```

-----

## Dashboard Data Contract

### Response Schema

```json
// GET /v1/admin/dashboard/data?from=2026-01-01&to=2026-03-31&org_id=ORG_xyz
// Optional filters: &department=finance&model=claude&classification=financial

{
  "meta": {
    "org_id": "ORG_xyz",
    "org_name": "Acme Financial Services",
    "date_range": {
      "from": "2026-01-01T00:00:00Z",
      "to": "2026-03-31T23:59:59Z"
    },
    "filters_applied": {
      "department": null,
      "model": null,
      "classification": null
    },
    "generated_at": "2026-04-01T10:00:00Z",
    "schema_version": "0.5.0"
  },

  "summary": {
    "total_attestations": 12847,
    "unique_users": 143,
    "unique_sessions": 8921,
    "review_rate": 0.87,
    "rubber_stamp_count": 234,
    "rubber_stamp_rate": 0.018,
    "external_exposure_count": 891,
    "chain_break_count": 12,
    "policy_violations": {
      "critical": 3,
      "high": 17,
      "medium": 89,
      "low": 234
    },
    "avg_tta_seconds": 127,
    "median_tta_seconds": 84,
    "prompt_hash_coverage": 0.92,
    "ai_authored_detected": 421,
    "shadow_ai_alerts": 18
  },

  "by_department": [ /* unchanged */ ],
  "by_model": [ /* unchanged */ ],
  "by_time": { /* unchanged */ },
  "tta_distribution": { /* unchanged */ },
  "file_types": [ /* unchanged */ ],
  "external_exposure": { /* unchanged */ },
  "chain_integrity": { /* unchanged */ },
  "recent_violations": [ /* unchanged */ ],

  "shadow_ai_heatmap": {
    "total_unique_apps_detected": 12,
    "by_app": [
      {
        "app": "chatgpt-desktop",
        "times_open": 3402,
        "times_attested_from": 2180,
        "shadow_ratio": 0.36,
        "interpretation": "open but not attesting — potential ungoverned use"
      }
    ],
    "by_department": [
      {
        "department": "Marketing",
        "top_shadow_apps": ["poe-desktop", "perplexity-desktop"],
        "shadow_ratio": 0.42
      }
    ]
  },

  "ai_authorship": {
    "total_with_markers": 421,
    "by_source": [
      {"source": "docx-copilot", "count": 234},
      {"source": "pdf-chatgpt", "count": 112},
      {"source": "c2pa", "count": 75}
    ],
    "unattested_with_markers": {
      "count": 18,
      "interpretation": "AI-authored content appearing in chain without attestation"
    }
  }
}
```

### Contract Rules

1. **This schema is the contract.** The dashboard, `synthetic-data.js`, and pilot report template all consume this exact shape.
2. **Fields may be `null` but never absent.** Every key appears in every response.
3. **The `meta.schema_version` field** allows consumers to detect contract changes.
4. **Departments without mapping default to `"Unmapped"`.**
5. **The `grade` field** in `by_department` is computed server-side: A (≥95% reviewed, 0 critical violations), B (≥85%), C (≥70%), D (≥50%), F (<50%).
6. **Shadow AI and AI authorship sections are enterprise-only.** Free-tier data cannot populate these (fields never captured). On free-only datasets, these sections return zeros with `"interpretation": "enterprise-tier capture required"`.

-----

## Receipt Schema v0.5.0

Every field except `uid`, `hash`, `ts`, and `review.status` is auto-populated. User presses one key.

```json
{
  "v": "0.5.0",
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "ts": "2026-04-21T20:15:30Z",
  "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "prompt_hash": "b7c3a91f2e4d8a6c5b9f1e2d7c8a4b6f3e5d9c1a7b2f8e4d6c5a9b3f7e1d2c8a",
  "uid": "jane@company.com",
  "key_id": "key_001",
  "client_integrity": "extension",
  "src": "chrome-extension",
  "model": "claude-sonnet-4",
  "provider": "anthropic",
  "source_domain": "claude.ai",
  "source_app": "Google Chrome",
  "concurrent_ai_apps": ["chatgpt-desktop", "cursor"],
  "ai_markers": {"source": "docx-copilot", "verified": true},
  "doc_id": "DOC_7890",
  "parent": "abc123def456...",
  "file_type": "spreadsheet",
  "len": 24500,
  "tta": 847,
  "sid": "f7a3b2c1d9e8",
  "dest": "email",
  "dest_ext": false,
  "classification": "financial",
  "review": {
    "status": "approved",
    "by": "jane@company.com",
    "at": "2026-04-21T20:15:30Z",
    "note": "Verified margin assumptions against Q2 actuals"
  },
  "tags": ["q3-forecast"]
}
```

### Field Reference

|Field               |Type   |Tier   |Auto?          |Purpose                                                  |Dashboard Aggregation Use                        |
|--------------------|-------|-------|---------------|---------------------------------------------------------|-------------------------------------------------|
|v                   |string |both   |Yes            |Schema version                                           |Compatibility tracking                           |
|id                  |string |both   |Yes            |Unique receipt identifier                                |Primary key for drill-down                       |
|ts                  |string |both   |Yes            |When attestation occurred                                |Time-series: trends, heatmaps, velocity          |
|hash                |string |both   |Yes            |SHA-256 of content (computed locally)                    |Chain integrity, dedup detection                 |
|prompt_hash         |string |both   |Yes (if avail) |SHA-256 of prompt text (normalized, not persisted on free server)|Prompt-to-output verification; enterprise: prompt-chain analytics|
|uid                 |string |both   |Setup once     |Who is attesting                                         |GROUP BY for per-user metrics                    |
|key_id              |string |both   |Yes (server)   |Which signing key was used                               |Key rotation tracking                            |
|client_integrity    |string |both   |Yes (server)   |Verification level of client metadata                    |Trust-level filtering                            |
|src                 |string |both   |Yes            |chrome-extension / desktop-agent / litellm-callback      |Adoption by surface type                         |
|model               |string |both   |Yes            |Which AI model (auto-detected)                           |Tool usage heatmap                               |
|provider            |string |both   |Yes            |Which AI company                                         |Vendor concentration                             |
|source_domain       |string |both   |Yes            |Website hostname where AI interaction happened           |Shadow AI detection via domain                   |
|source_app          |string |both   |Yes            |Active window title (desktop agent)                      |Application-level usage tracking                 |
|concurrent_ai_apps  |array  |commercial|Yes (agent) |List of AI applications running at attest moment (process names)|Shadow AI Heatmap — open but not attesting|
|ai_markers          |object |both   |Yes            |Detected AI-authorship signals in the artifact: {source: "docx-copilot"\|"c2pa"\|"pdf-chatgpt"\|"xlsx-copilot"\|null, verified: bool}|AI Authorship Detection view|
|doc_id              |string |both   |Yes (files)    |Persistent document ID                                   |Document lifecycle view                          |
|parent              |string |both   |Yes (if doc_id)|Previous version's content hash                          |Chain integrity                                  |
|file_type           |string |both   |Yes            |File category                                            |Content categorization                           |
|len                 |integer|both   |Yes            |Character/byte count                                     |Scale proxy                                      |
|tta                 |integer|commercial|Yes (browser)|Seconds between AI output and attestation               |Review quality proxy, rubber-stamp detection     |
|sid                 |string |commercial|Yes (browser)|Groups attestations from same AI conversation           |AI dependency ratio                              |
|dest                |string |commercial|Yes (partial)|email/messaging/document-platform/code-repository       |Content flow analysis                            |
|dest_ext            |boolean|commercial|Yes (partial)|Whether destination appears external to org             |External exposure risk scoring                   |
|classification      |string |commercial|Auto-suggested|financial/legal/client-facing/internal                 |Risk bucketing                                   |
|review.status       |string |both   |User choice    |approved/modified/rejected                               |Confidence patterns, compliance rate             |
|review.by           |string |both   |Yes            |Who reviewed                                             |Dual-review compliance                           |
|review.at           |string |both   |Yes            |When reviewed                                            |Review latency metrics                           |
|review.note         |string |both   |Optional       |Review notes                                             |Audit trail                                      |
|tags                |array  |both   |Optional       |Custom labels                                            |Custom grouping                                  |

### Schema ↔ Dashboard Traceability Matrix

|Dashboard View                    |Primary Fields                          |Tier Required    |Aggregation Method                   |
|----------------------------------|----------------------------------------|-----------------|-------------------------------------|
|AI Usage Heatmap                  |uid, model, provider, ts               |both             |COUNT GROUP BY department × model    |
|Shadow AI Heatmap                 |concurrent_ai_apps, source_app, uid    |commercial       |json_each expansion + join           |
|AI Authorship Detection           |ai_markers, uid, ts                    |both             |COUNT WHERE ai_markers.verified = true|
|Prompt-to-Output Chain            |prompt_hash, hash, uid                 |both             |JOIN receipts on prompt_hash         |
|Review Rate Scorecard             |uid, review.status, ts                 |both             |approved/total ratio per department  |
|Chain Integrity Monitor           |doc_id, parent, hash                   |both             |Chain traversal, gap detection       |
|Time-to-Attest Distribution       |tta, len, uid                          |commercial       |Histogram, flag tta<10 AND len>500   |
|Tool Adoption Timeline            |model, provider, ts                    |both             |Stacked area, COUNT per time bucket  |
|Policy Violation Feed             |All policy-relevant fields              |commercial       |Real-time rule evaluation            |
|Document Lifecycle View           |doc_id, parent, hash, uid, ts          |both             |Chain reconstruction per doc_id      |
|External Exposure Report          |dest, dest_ext, classification, uid    |commercial       |COUNT WHERE dest_ext=true            |
|Client Trust Report               |client_integrity, src, uid             |both             |Distribution of verification levels  |
|Audit Export                      |All fields                              |commercial       |Flat dump, filtered by date range    |

### Registry Entry (what the public server stores per attestation)

```
content_hash, receipt_id, parent_hash, doc_id, registered_at
```

Five columns. No names, models, file types, departments. **No prompt_hash.** Anonymous.

-----

## Tier Gating

### Principle

One receipt schema. The **client** decides which fields to populate based on tier. The server accepts both shapes — it does not enforce tier at the signing layer (this would require identifying the user, which we don't want to do on the public sign path).

### Free Tier (default — personal users, no enterprise link)

**Clients populate:** `v`, `id`, `ts`, `hash`, `prompt_hash`, `uid`, `key_id`, `client_integrity`, `src`, `model`, `provider`, `source_domain`, `source_app`, `ai_markers`, `doc_id`, `parent`, `file_type`, `len`, `review.*`, `tags`.

**Clients do NOT populate:** `tta`, `sid`, `dest`, `dest_ext`, `classification`, `concurrent_ai_apps`.

**Server persists:** 5-column registry entry only. No PII. No metadata.

### Commercial Tier (enterprise-linked clients)

**Clients populate:** All free-tier fields, plus `tta`, `sid`, `dest`, `dest_ext`, `classification`, `concurrent_ai_apps`.

**Server persists:** Full receipt in `enterprise_attestations` (enterprise DB), plus standard 5-column registry entry (unchanged).

### How the Client Decides

```javascript
// Chrome extension
const tier = await getTier(); // reads from chrome.storage.local
// tier = "free" | "enterprise"
// Determined by:
// 1. Pre-configured via Google Workspace Admin Console (enterprise deployment), OR
// 2. User has linked a corporate email belonging to an active org, OR
// 3. Default: "free"

function buildReceipt(content, promptText, source) {
  const receipt = {
    v: "0.5.0",
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
    hash: sha256(normalize(content)),
    prompt_hash: promptText ? sha256(normalize(promptText)) : null,
    uid: getUid(),
    src: "chrome-extension",
    model: detectModel(),
    provider: detectProvider(),
    source_domain: source.hostname,
    source_app: "Google Chrome",
    ai_markers: detectAIMarkers(content, source),
    file_type: detectFileType(content, source),
    len: content.length,
    review: getReviewState(),
    tags: [],
  };

  if (tier === "enterprise") {
    receipt.tta = getTTA();
    receipt.sid = getSessionId();
    receipt.dest = detectDestination();
    receipt.dest_ext = isExternalDestination();
    receipt.classification = suggestClassification();
    receipt.concurrent_ai_apps = []; // browser can't enumerate — desktop agent fills this
  }

  return receipt;
}
```

```python
# Desktop agent
tier = config.get("tier", "free")

def build_receipt(content, prompt_text=None):
    receipt = {
        "v": "0.5.0",
        "id": str(uuid.uuid4()),
        "ts": datetime.utcnow().isoformat() + "Z",
        "hash": sha256_normalized(content),
        "prompt_hash": sha256_normalized(prompt_text) if prompt_text else None,
        "uid": config["uid"],
        "src": "desktop-agent",
        "model": detect_model_from_window(),
        "provider": detect_provider_from_window(),
        "source_app": get_active_window_title(),
        "ai_markers": detect_ai_markers(content),
        "file_type": detect_file_type(content),
        "len": len(content),
        "review": get_review_state(),
        "tags": [],
    }

    if tier == "enterprise":
        receipt["tta"] = get_tta()
        receipt["sid"] = get_session_id()
        receipt["dest"] = detect_destination()
        receipt["dest_ext"] = is_external_destination()
        receipt["classification"] = suggest_classification()
        receipt["concurrent_ai_apps"] = enumerate_concurrent_ai_processes()

    return receipt
```

### Rationale

- **User trust on free tier:** a free-tier client never sends behavioral data. Full stop. Not even "the server could store it if it wanted to" — the data is never in the request body.
- **Server simplicity:** signing path is identical for both tiers. No conditional logic based on license status at sign time.
- **Enterprise deployability:** flipping tier on an enterprise-deployed extension is a config flag, not a code change.
- **Audit transparency:** the client's local receipt store shows exactly what was sent. An enterprise user can verify their client is sending the commercial fields; a personal user can verify theirs is not.

### Disclosure Requirement

Enterprise deployment MUST surface tier status in the extension popup (State 4) and via a dedicated `chrome://extensions` detail pane explaining which fields are being captured. The Enterprise User Guide FAQ documents this in plain language. Failing to disclose commercial-tier capture to end users violates the consent principle (Core Principle 8).

-----

## Content Hashing Rules

### Browser Text Selection (Chrome extension)

```
1. Get selection: window.getSelection().toString()
2. Normalize: text.replace(/\s+/g, ' ').trim()
3. Encode: new TextEncoder().encode(normalized_text)
4. Hash: SHA-256 of the UTF-8 bytes
```

### Clipboard Text (desktop agent)

```
1. Get clipboard: pyperclip.paste()
2. Normalize: re.sub(r'\s+', ' ', text).strip()
3. Encode: text.encode('utf-8')
4. Hash: SHA-256 of the UTF-8 bytes
```

### File Attestation (desktop agent)

```
1. Read: open(filepath, 'rb').read()
2. Hash: SHA-256 of raw bytes (no normalization — files hash as stored)
```

### Prompt Hashing (new in v0.5.0)

```
PURPOSE: Provide cryptographic proof that a specific prompt produced the
attested output. Enables "chain of AI custody" — link the question to
the answer without revealing either to the server.

WHERE CAPTURED:
  Chrome extension: when the user selects AI output, the extension
  traverses the DOM to find the most recent user prompt in the same
  conversation thread (heuristic per AI platform — Claude uses
  role="human" markers, ChatGPT uses user-turn containers, etc.).
  If no prompt is detectable, prompt_hash = null.

  Desktop agent: if the clipboard contains both prompt and output
  (multi-line with a "Q:/A:" or "--- prompt ---" separator), the agent
  can hash the prompt portion. If not detectable, prompt_hash = null.

  LiteLLM callback: has direct access to prompt and response — always
  populates prompt_hash.

HASHING RULES:
  Same normalization as text selection:
  1. Trim + collapse whitespace
  2. UTF-8 encode
  3. SHA-256

VERIFICATION (new endpoint):
  POST /v1/verify/prompt
  Body: {receipt: {...}, prompt_text: "..."}
  Returns: {matches: true/false}

  The verifier normalizes and hashes the supplied prompt, compares to
  receipt.prompt_hash, and returns whether they match. The prompt text
  is not stored — verification is stateless.

PRIVACY NOTE:
  The server never sees prompt text. It sees only prompt_hash in the
  receipt body at sign time, and on free tier this hash is not persisted.
  On enterprise tier, prompt_hash is stored alongside content hash in
  enterprise_attestations — enabling queries like "show me all content
  attested from this prompt" without the prompt ever leaving the user's
  device. The employer sees the hash and can verify it matches a prompt
  they also have access to, but cannot reverse-engineer the prompt text.

REGISTRY EXCLUSION:
  prompt_hash is NOT added to aiauth_registry.db. Adding it would create
  a correlation vector: an attacker with a guess about the prompt could
  confirm which content_hash was attested from it. Keeping prompt_hash
  only in the enterprise DB (where access is already restricted to the
  org) preserves the zero-data-on-public-server promise.
```

### AI Marker Detection (new in v0.5.0)

```
PURPOSE: Detect when attested content was AI-authored, regardless of
whether the user remembers or declares it.

SOURCES DETECTED:

1. Office documents (docx, xlsx, pptx) via docProps/custom.xml:
   - Read with openpyxl (xlsx) or python-docx (docx) or python-pptx (pptx)
   - Look for custom properties named: "Copilot.GUID", "AI.Model",
     "AIContent.Source", etc.
   - If found: ai_markers = {"source": "docx-copilot" (or xlsx/pptx), "verified": true}

2. PDFs via /Producer and /Creator metadata:
   - Read with pikepdf or pypdf
   - Look for strings matching: "ChatGPT", "Claude", "Gemini", "Copilot",
     "DALL-E", "Stable Diffusion"
   - If found: ai_markers = {"source": "pdf-chatgpt" (or claude/gemini/etc.), "verified": true}

3. Images via C2PA manifest:
   - Use c2pa-python or similar library
   - If manifest is present AND cryptographically valid: verified: true
   - If manifest is present but invalid: verified: false (still record the claim)
   - ai_markers = {"source": "c2pa", "verified": true/false}

4. Text/code: NO markers detected (heuristic indicators too unreliable).
   ai_markers = null.

WHEN TO RUN:
  File attestation: always (both tiers — this is artifact metadata, not
  user behavior).
  Browser text attestation: skip (no file to read).

STORAGE:
  On free tier: present in local receipt only, not persisted server-side.
  On enterprise tier: stored in enterprise_attestations.ai_markers as JSON.

VERIFICATION:
  The receipt's ai_markers field is signed by the server. A third-party
  verifier can see that AIAuth recorded the presence of a marker at
  attest time, but cannot independently re-verify without the source
  file. For C2PA specifically, the file itself contains the verifiable
  manifest — so verification can be performed offline with the file.
```

-----

## Error Handling

### Standard Error Response Format

```json
{
  "error": {
    "code": "RECEIPT_DUPLICATE",
    "message": "This content was already attested within the deduplication window",
    "details": {
      "existing_receipt_id": "a1b2c3d4...",
      "window_seconds": 300
    }
  }
}
```

### Error Conditions by Endpoint

```
POST /v1/sign
  400 INVALID_RECEIPT       Missing required field (v, id, ts, hash, uid)
  400 INVALID_HASH          Hash is not a valid SHA-256 hex string
  400 INVALID_PROMPT_HASH   prompt_hash present but not valid SHA-256 hex
  400 INVALID_SCHEMA        Schema version < 0.4.0
  409 RECEIPT_DUPLICATE     Same content_hash + uid within dedup window
  429 RATE_LIMITED          IP exceeded 100 requests/minute
  500 SIGNING_ERROR         Key file unreadable or corrupt

POST /v1/verify/prompt
  400 MISSING_PROMPT_HASH   Receipt has no prompt_hash field
  400 INVALID_RECEIPT       Receipt signature invalid
  429 RATE_LIMITED          IP exceeded 30 requests/minute

(other endpoints: see original spec — unchanged)
```

-----

## Duplicate Attestation Handling

```python
DEDUP_WINDOW = 300  # 5 minutes (configurable via AIAUTH_DEDUP_WINDOW in .env)

@app.post("/v1/sign")
def sign(receipt: dict):
    existing = db.execute("""
        SELECT receipt_id FROM hash_registry
        WHERE content_hash = ? AND registered_at > datetime('now', ?)
        ORDER BY registered_at DESC LIMIT 1
    """, [receipt["hash"], f"-{DEDUP_WINDOW} seconds"])

    if existing:
        return {
            "receipt": receipt,
            "signature": get_existing_signature(existing["receipt_id"]),
            "deduplicated": True,
            "original_receipt_id": existing["receipt_id"]
        }
    # Proceed with normal signing
```

Dedup key: `content_hash` only (not `content_hash + uid`). Different users attesting the same content is a legitimate multi-person review.

-----

## Feature Specifications

### FEATURE 1: AI Model Auto-Detection (extended)

**Executive question:** Which AI tools are being used? Unapproved tools?

**Free-tier capture (both surfaces):**

Chrome extension — detect from active tab URL:

```javascript
const AI_DOMAINS = {
  "claude.ai": {model: "claude", provider: "anthropic"},
  "chat.openai.com": {model: "chatgpt", provider: "openai"},
  "chatgpt.com": {model: "chatgpt", provider: "openai"},
  "gemini.google.com": {model: "gemini", provider: "google"},
  "aistudio.google.com": {model: "gemini", provider: "google"},
  "copilot.microsoft.com": {model: "copilot", provider: "microsoft"},
  "github.com": {model: "github-copilot", provider: "microsoft"},
  "poe.com": {model: "poe", provider: "quora"},
  "perplexity.ai": {model: "perplexity", provider: "perplexity"},
  "cursor.sh": {model: "cursor", provider: "cursor"},
};
```

Desktop agent — detect from active window title:

```python
AI_PATTERNS = {
    "claude": ("claude", "anthropic"),
    "chatgpt": ("chatgpt", "openai"),
    "copilot": ("copilot", "microsoft"),
    "gemini": ("gemini", "google"),
    "cursor": ("cursor", "cursor"),
    "perplexity": ("perplexity", "perplexity"),
}
```

### FEATURE 1b: Concurrent AI App Enumeration (commercial only)

**Executive question:** Which AI tools are open but NOT being used for attested work? (Shadow AI.)

**Desktop agent — enumerate running AI processes at attest moment:**

```python
import psutil

AI_PROCESS_PATTERNS = {
    "ChatGPT.exe": "chatgpt-desktop",
    "Claude.exe": "claude-desktop",
    "Cursor.exe": "cursor",
    "Copilot.exe": "copilot-desktop",
    "Perplexity.exe": "perplexity-desktop",
    "Poe.exe": "poe-desktop",
    "GitHubDesktop.exe": None,  # not an AI app — excluded
}

def enumerate_concurrent_ai_processes():
    """
    Returns list of currently-running AI applications.
    Only matches against a known allowlist — we never record arbitrary
    process names (privacy: avoid capturing non-AI user activity).
    """
    found = set()
    for proc in psutil.process_iter(['name']):
        name = proc.info['name']
        if name in AI_PROCESS_PATTERNS:
            marker = AI_PROCESS_PATTERNS[name]
            if marker:
                found.add(marker)
    return sorted(found)

# Only called when tier == "enterprise"
# Result stored in receipt.concurrent_ai_apps
```

**Chrome extension — enumerate open tabs with AI domains:**

```javascript
async function enumerateConcurrentAIApps() {
  if (tier !== "enterprise") return null;
  const tabs = await chrome.tabs.query({});
  const found = new Set();
  for (const tab of tabs) {
    try {
      const host = new URL(tab.url).hostname;
      if (AI_DOMAINS[host]) {
        found.add(AI_DOMAINS[host].model + "-web");
      }
    } catch (e) { /* invalid URL, skip */ }
  }
  return [...found].sort();
}
```

**Privacy safeguards:**
- Allowlist only — unknown processes/domains are never recorded
- Enumerated only at attest moment, not continuously
- Free-tier clients never run this code
- Disclosed in Enterprise User Guide FAQ

**Server change:** None. Field accepted on schema.

-----

### FEATURE 2: Time-to-Attest (TTA) — commercial only

Unchanged from prior spec except: free-tier clients skip this capture.

-----

### FEATURE 3: Content Length — both tiers

```javascript
payload.len = text.length;
```

-----

### FEATURE 4: File Type Detection + AI Marker Detection

**Free tier + commercial — both capture file_type and ai_markers.**

File type detection: unchanged from prior spec (extension + magic bytes).

**AI marker detection (new):**

```python
# Desktop agent — during file attestation

def detect_ai_markers(filepath):
    """
    Returns: {"source": str, "verified": bool} or None
    """
    ext = os.path.splitext(filepath)[1].lower()

    # Office documents
    if ext == ".xlsx":
        try:
            from openpyxl import load_workbook
            wb = load_workbook(filepath, read_only=True)
            for prop in wb.custom_doc_props.props:
                if "Copilot" in prop.name or "AI" in prop.name:
                    return {"source": "xlsx-copilot", "verified": True}
        except Exception:
            pass

    elif ext == ".docx":
        try:
            from docx import Document
            doc = Document(filepath)
            for prop in doc.core_properties.__dict__:
                if "copilot" in str(prop).lower():
                    return {"source": "docx-copilot", "verified": True}
        except Exception:
            pass

    elif ext == ".pptx":
        try:
            from pptx import Presentation
            prs = Presentation(filepath)
            if any("copilot" in str(p).lower() for p in prs.core_properties.__dict__):
                return {"source": "pptx-copilot", "verified": True}
        except Exception:
            pass

    # PDFs
    elif ext == ".pdf":
        try:
            import pikepdf
            with pikepdf.open(filepath) as pdf:
                producer = str(pdf.docinfo.get("/Producer", ""))
                creator = str(pdf.docinfo.get("/Creator", ""))
                combined = (producer + creator).lower()
                if "chatgpt" in combined or "openai" in combined:
                    return {"source": "pdf-chatgpt", "verified": True}
                if "claude" in combined or "anthropic" in combined:
                    return {"source": "pdf-claude", "verified": True}
                if "gemini" in combined or "bard" in combined:
                    return {"source": "pdf-gemini", "verified": True}
                if "copilot" in combined:
                    return {"source": "pdf-copilot", "verified": True}
        except Exception:
            pass

    # Images (C2PA)
    elif ext in (".jpg", ".jpeg", ".png", ".tiff", ".webp"):
        try:
            import c2pa
            manifest = c2pa.read_file(filepath)
            if manifest:
                return {"source": "c2pa", "verified": manifest.is_valid()}
        except Exception:
            pass

    return None
```

**Browser: no file access** — ai_markers is always null for browser text attestations.

-----

### FEATURE 5: Session Grouping — commercial only

(Unchanged)

-----

### FEATURE 6: Destination Detection — commercial only

(Unchanged)

-----

### FEATURE 7: Document ID (Persistent File Tracking) — both tiers

(Unchanged)

-----

### FEATURE 8: Classification — commercial only

(Unchanged)

-----

### FEATURE 9: Right-Click File Attestation (Windows)

(Unchanged)

-----

### FEATURE 10: Enterprise Policy Engine (extended)

```python
POLICIES = [
    {"id": "dual-review-financial",
     "condition": "classification == 'financial' AND chain_unique_attesters < 2",
     "severity": "high"},
    {"id": "no-rubber-stamping",
     "condition": "tta < 10 AND len > 500",
     "severity": "medium"},
    {"id": "approved-tools-only",
     "condition": "model NOT IN approved_models",
     "severity": "high"},
    {"id": "external-must-attest",
     "condition": "dest_ext == true AND review_status IS NULL",
     "severity": "critical"},
    {"id": "unverified-financial",
     "condition": "client_integrity == 'none' AND classification == 'financial'",
     "severity": "medium"},
    {"id": "stale-pending",
     "condition": "signed == false AND age_hours > 24",
     "severity": "low"},
    {"id": "shadow-ai-detected",
     "condition": "concurrent_ai_apps contains tool_not_in source_app",
     "severity": "low",
     "description": "AI app open but not used for the attested work"},
    {"id": "ungoverned-ai-content",
     "condition": "ai_markers.verified == true AND parent IS NULL",
     "severity": "medium",
     "description": "AI-authored artifact entered chain without prior attestation"},
]
```

-----

### FEATURE 11: Department Mapping

(Unchanged)

-----

### FEATURE 12: Enterprise Compliance Dashboard (extended)

New views added:

11. **Shadow AI Heatmap** — `concurrent_ai_apps` matrix, departments × open-but-not-attested apps.
12. **AI Authorship Detection** — artifacts where `ai_markers.verified = true`, broken down by source (Copilot / ChatGPT / C2PA).
13. **Prompt-to-Output Chain** — selects a receipt with prompt_hash, shows all other receipts attesting content derived from the same prompt.

-----

### FEATURE 13: Account Identity System

(Unchanged)

-----

### FEATURE 14: Commercial Demo Templates (extended)

Synthetic data generator must output all v0.5.0 fields including the new three. The `shadow_ai_heatmap` and `ai_authorship` sections of the dashboard data contract must be populated with realistic synthetic patterns.

-----

## System-Wide Installation

(Unchanged from prior spec.)

-----

## Behavioral Intelligence (Derived From Metadata) — extended

|Insight                |Derived from                     |Tier       |
|-----------------------|---------------------------------|-----------|
|Work velocity          |tta (time-to-attest)             |Commercial |
|AI dependency ratio    |Attestation volume / total output|Commercial |
|Collaboration topology |Chain parent→child uid patterns  |Both       |
|Confidence patterns    |approved/modified/rejected ratios|Both       |
|Content lifecycle      |Chain length per doc_id          |Both       |
|Tool migration         |model/provider trends over time  |Both       |
|Absence patterns       |Who doesn't attest               |Commercial |
|Rubber-stamp detection |tta < 10 AND len > 500           |Commercial |
|AI round-trip detection|model→none→model in chain        |Both       |
|Cross-org provenance   |Different org_domains in chain   |Both       |
|Personal→corporate port|Linked account attestation count |Commercial |
|Client trust profile   |client_integrity distribution    |Commercial |
|Offline attestation lag|Time between local attest and sign|Both      |
|Shadow AI usage        |concurrent_ai_apps vs source_app |Commercial |
|AI-authored artifacts  |ai_markers.verified              |Both       |
|Prompt-chain genealogy |prompt_hash clustering           |Both (enterprise dashboard)|

-----

## Monetization

|Tier                  |Price           |Data AIAuth stores                |Fields captured                     |
|----------------------|----------------|----------------------------------|------------------------------------|
|Free individual       |$0 forever      |Hash registry (anonymous) + email |Free-tier fields only               |
|Enterprise self-hosted|$3–8/user/mo    |Nothing (they host)               |All fields                          |
|Enterprise hosted     |$5–12/user/mo   |Their data under contract         |All fields                          |
|Compliance platform   |$8–15/user/mo   |Their data under contract         |All fields + policy engine + DSAR   |

**Free tier capture is STRICTLY minimal** by design — it proves chain of custody without observing the user. Behavioral data is the paid product.

-----

## Build Priority

### Phase 1: Ship current product (NOW)

**Already live:** Landing page, /check, /guide, /docs, /public-key, /privacy

- [ ] Chrome Web Store submission
- [ ] Windows .exe build + Microsoft Store submission
- [ ] Landing page messaging update
- [ ] Update /guide with receipt code format documentation
- [ ] First personal attestation

### Phase 2: Auto-detection + Identity + Infrastructure Hardening (v0.5.0)

- [ ] Zero-Data Server Principle section in spec + public-facing privacy page
- [ ] Content hashing rules implementation
- [ ] **Prompt hashing (new — free tier)**
- [ ] **AI marker detection (new — free tier)**
- [ ] **Concurrent AI apps enumeration (new — commercial tier)**
- [ ] **Tier gating logic in clients (free vs. enterprise capture modes)**
- [ ] Error handling standard format
- [ ] Duplicate attestation handling (5-minute dedup window)
- [ ] Key management migration (single key → versioned key list)
- [ ] Rate limiting on public endpoints (including /v1/verify/prompt)
- [ ] Schema versioning policy enforcement
- [ ] Offline-first client architecture
- [ ] User onboarding flow (extension popup states 1–5)
- [ ] Feature 1: AI model auto-detection
- [ ] Feature 1b: Concurrent AI process enumeration (commercial)
- [ ] Feature 2: Time-to-attest (commercial)
- [ ] Feature 3: Content length
- [ ] Feature 4: File type detection + AI markers
- [ ] Feature 5: Session grouping (commercial)
- [ ] Feature 13: Account identity system (magic link auth)
- [ ] Feature 14: Commercial demo templates (updated for new fields)
- [ ] **POST /v1/verify/prompt endpoint**
- [ ] Client integrity: Level 2 (extension-attested) for Chrome extension

### Phase 3: File lifecycle + Enterprise Data Flow (v0.6.0)

(Unchanged — see full list in original spec.)

### Phase 4: Enterprise Dashboard + Policy + Compliance (v1.0.0)

- [ ] Dashboard Data Contract implementation
- [ ] Feature 10: Policy engine (including new shadow-ai and ungoverned-ai-content policies)
- [ ] Feature 11: Department mapping
- [ ] Feature 12: Compliance dashboard (including Shadow AI Heatmap + AI Authorship view)
- [ ] Pilot report generation
- [ ] DSAR tooling
- [ ] Data rights documentation
- [ ] Compliance report template

### Phase 5: Platform expansion + Enterprise Hardening

(Unchanged.)

-----

## Server File Layout

```
/opt/aiauth/
├── server.py              ← Main server
├── index.html             ← Landing page (LIVE)
├── verify.html            ← Public verification page /check (LIVE)
├── privacy.html           ← Privacy policy (LIVE)
├── public-key.html        ← Public key page (LIVE)
├── guide.html             ← User guide rendered page (LIVE)
├── logo.png               ← Site logo (LIVE)
├── venv/                  ← Python venv
├── .env                   ← AIAUTH_MASTER_KEY, SERVER_SECRET, etc.
├── keys/                  ← Versioned signing keys — BACK UP
├── aiauth_registry.db     ← Hash registry (anonymous — 5 columns only)
├── aiauth.db              ← Accounts, orgs, enterprise attestations, etc.
├── templates/
│   └── commercial/        ← Dashboard demo templates
└── docs/
    ├── USER_GUIDE.md
    ├── ENTERPRISE_ADMIN_GUIDE.md
    └── ENTERPRISE_USER_GUIDE.md
```

-----

## Data Architecture Integrity Rules

1. **Receipt schema is the single source of truth for analytics.**
2. **The account layer is an index, not a data store.**
3. **The registry stays anonymous.** Five columns only. **No prompt_hash, no uid, no model — ever.**
4. **Department is a JOIN, not a receipt field.**
5. **Synthetic data mirrors the Dashboard Data Contract exactly.**
6. **Consent is auditable.** Append-only `consent_log`.
7. **Schema changes are additive only.**
8. **Two databases, not three.**
9. **PII is pseudonymizable.**
10. **Authentication is mandatory for identity operations.**
11. **Tier gating is client-side.** The server accepts both free and commercial receipt shapes without distinguishing them at sign time. The client (based on deployment configuration or linked-org status) determines which fields to populate. This preserves the property that the public signing path identifies no one and stores no behavior data. Any feature proposal that requires the server to know a user's tier at sign time must be redesigned.
12. **Prompt hashes never enter the public registry.** Only content_hash, receipt_id, parent_hash, doc_id, registered_at. Adding prompt_hash would allow correlation attacks (guess the prompt → confirm the content). prompt_hash exists only in the signed receipt (client-side) and the enterprise attestation store (enterprise-tier only).
13. **Concurrent AI app enumeration uses an allowlist.** Unknown processes are never recorded. This prevents capture of non-AI user activity and limits the privacy impact of the feature.
14. **AI marker detection is read-only and local.** The detection code runs on the user's machine, reads file metadata, and records only the `{source, verified}` result. The file's content and its full metadata are never transmitted.

-----

## Operations & Deployment

This section consolidates the operational procedures previously tracked in CLAUDE_1.md. It is the authoritative deployment reference.

### Environment Variables

| Variable | Where | Purpose | Required |
|----------|-------|---------|----------|
| `AIAUTH_MODE` | Server | `public` or `enterprise` | No (defaults to `public`) |
| `AIAUTH_MASTER_KEY` | Server `.env` | Admin key for license generation | Yes |
| `AIAUTH_KEY_DIR` | Server | Directory for signing keys | No (defaults to `/opt/aiauth/keys` in v0.5.0, `.` prior) |
| `AIAUTH_DB_PATH` | Server | Enterprise database path | No (defaults to `aiauth.db`) |
| `AIAUTH_REGISTRY_PATH` | Server | Hash registry database path | No (defaults to `aiauth_registry.db`) |
| `AIAUTH_LICENSE_KEY` | Customer server | Enterprise license key | Only for enterprise mode |
| `AIAUTH_DEDUP_WINDOW` | Server | Seconds to dedup identical content_hash | No (defaults to `300`) |
| `AIAUTH_REGISTRY_PRUNE` | Server | Enable 180-day registry pruning | No (defaults to `false`) |
| `SERVER_SECRET` | Server `.env` | HMAC secret for magic-link / session tokens | Yes (v0.5.0+) |
| `CLIENT_SECRET` | Server `.env` | HMAC secret for client-integrity validation | Yes (v0.5.0+) |

### Deployment Target

Production host: DigitalOcean droplet `167.172.250.174` (Ubuntu 24.04, 1 vCPU, 1 GB RAM). Application root: `/opt/aiauth/`. Service managed by `systemd` as unit `aiauth`. Reverse proxy via `nginx` with Let's Encrypt TLS.

### Troubleshooting Checklist

Run these from an SSH session on the server to diagnose state:

```bash
# 1. File inventory
ls -la /opt/aiauth/
ls -la /opt/aiauth/keys/ 2>/dev/null || echo "No keys directory (pre-v0.5.0 layout)"
ls -la /opt/aiauth/docs/ 2>/dev/null

# 2. Version and schema check
head -20 /opt/aiauth/server.py
grep "VERSION\|schema_version" /opt/aiauth/server.py | head -5
grep "prompt_hash\|ai_markers\|concurrent_ai_apps" /opt/aiauth/server.py | head -5
grep "hash_registry" /opt/aiauth/server.py | head -3
grep "key_manifest\|key_id" /opt/aiauth/server.py | head -3
grep "rate.limit\|throttle\|DEDUP_WINDOW" /opt/aiauth/server.py | head -3

# 3. Service status
systemctl status aiauth
ps aux | grep uvicorn

# 4. Local health check
curl -s http://localhost:8100/health
curl -s http://localhost:8100/v1/public-key | head -c 200

# 5. nginx and SSL
nginx -t
systemctl status nginx
cat /etc/nginx/sites-enabled/aiauth 2>/dev/null || echo "No nginx config"
certbot certificates 2>/dev/null

# 6. Firewall (check BOTH UFW on the host AND the DigitalOcean cloud firewall via dashboard)
ufw status

# 7. DNS resolution
dig aiauth.app +short  # expect 167.172.250.174
```

### Deploying an Update (Standard Flow)

Every update to `server.py`, HTML pages, docs, or the Chrome extension follows this pattern. Run commands **from Windows PowerShell** for scp (the file paths are Windows), and **from the SSH session** for everything else.

```powershell
# From Windows PowerShell — upload changed files
scp C:\Users\ChaseFinch\Downloads\aiauth\server.py root@167.172.250.174:/opt/aiauth/server.py
scp C:\Users\ChaseFinch\Downloads\aiauth\verify.html root@167.172.250.174:/opt/aiauth/verify.html
scp C:\Users\ChaseFinch\Downloads\aiauth\index.html root@167.172.250.174:/opt/aiauth/index.html
# Repeat for any other files changed
```

```bash
# From SSH — reload and verify
systemctl restart aiauth
systemctl status aiauth
curl -s http://localhost:8100/health
journalctl -u aiauth -n 50 --no-pager    # check for errors in the last 50 log lines
```

If the health check fails, run the Troubleshooting Checklist above and inspect `journalctl -u aiauth -n 200 --no-pager` for the traceback.

### nginx Reverse Proxy Configuration

```nginx
# /etc/nginx/sites-available/aiauth
server {
    listen 80;
    server_name aiauth.app www.aiauth.app api.aiauth.app;

    location / {
        proxy_pass http://127.0.0.1:8100;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

After editing:
```bash
ln -sf /etc/nginx/sites-available/aiauth /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

### systemd Service Definition

```ini
# /etc/systemd/system/aiauth.service
[Unit]
Description=AIAuth Signing Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/aiauth
EnvironmentFile=/opt/aiauth/.env
Environment=AIAUTH_MODE=public
Environment=AIAUTH_KEY_DIR=/opt/aiauth/keys
ExecStart=/opt/aiauth/venv/bin/uvicorn server:app --host 127.0.0.1 --port 8100 --workers 2
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Apply:
```bash
systemctl daemon-reload
systemctl enable aiauth
systemctl restart aiauth
systemctl status aiauth
```

### SSL Certificate (Let's Encrypt)

Initial issuance:
```bash
certbot --nginx -d aiauth.app -d www.aiauth.app -d api.aiauth.app
```

Renewal is automatic via the `certbot.timer` systemd unit. Verify with `certbot renew --dry-run`.

### Key Backup (CRITICAL)

The signing keys at `/opt/aiauth/keys/` are the root of trust. If lost, every receipt signed with that key becomes unverifiable forever. There is no recovery path.

```bash
# On the server
tar czf /root/aiauth_keys_backup_$(date +%Y%m%d).tar.gz -C /opt/aiauth keys/
```

```powershell
# From Windows PowerShell — pull the backup off the server
scp root@167.172.250.174:/root/aiauth_keys_backup_*.tar.gz C:\aiauth-backups\
```

Store the backup on an encrypted USB drive and in a separate offline location. Rotate keys annually per the Key Management section; retain all historical private keys so that historical receipts remain verifiable.

### License Key Generation (Enterprise)

```bash
curl -X POST https://aiauth.app/v1/admin/license/generate \
  -H "Content-Type: application/json" \
  -d '{
    "company": "Acme Corp",
    "tier": "enterprise",
    "expires": "2027-12-31",
    "master_key": "<value from /opt/aiauth/.env>"
  }'
```

Returns a license key string. Record it in the enterprise accounts database and deliver to the customer alongside their activation instructions.

### Chrome Extension Deployment (Developer Flow)

```
1. Open chrome://extensions/
2. Enable "Developer mode" (toggle, top right)
3. Click "Load unpacked"
4. Select C:\Users\ChaseFinch\Downloads\aiauth\chrome-extension
5. AIAuth icon appears in toolbar
6. Click it → enter work email + server URL → verify
7. Reload after any code change: click the circular arrow on the extension card
```

For production distribution: zip the `chrome-extension/` folder, upload at https://chrome.google.com/webstore/devconsole. Expect 1–3 business days review.

### Desktop Agent Build (Windows)

```powershell
cd C:\aiauth
.\venv\Scripts\Activate
pip install -r requirements.txt pyinstaller
pyinstaller --onefile --noconsole --name AIAuth aiauth.py
# Output: dist\AIAuth.exe
```

Package as MSIX for Microsoft Store submission using the MSIX Packaging Tool, then submit via Partner Center.

### Infrastructure Costs (Current)

| Item | Cost |
|------|------|
| DigitalOcean droplet | $6 / month |
| Domain (aiauth.app) | ~$12 / year |
| Chrome Web Store developer account | $5 one-time |
| Microsoft Partner Center developer account | $19 one-time |
| Let's Encrypt SSL | Free |
| Email transactional (magic links, v0.5.0+) | ~$0–10 / month (e.g., Resend, Postmark) |
| **Total launch cost** | ~$42 one-time + $6–16 / month |

### Common Issues

**"Could not resolve hostname C:" error during scp** — you're running a Windows command from the Linux SSH session. scp commands with `C:\...` paths must run from Windows PowerShell on your laptop, not on the server.

**Browser can't reach the server** — the DigitalOcean cloud firewall is separate from UFW on the host. Check Networking → Firewalls in the DigitalOcean dashboard. It must allow inbound TCP 80 and 443.

**`Field name register shadows an attribute` Pydantic warning** — harmless in v0.4.0. Ignore. Resolved in v0.5.0 when the field is renamed as part of schema cleanup.

**certbot fails on first issuance** — DNS hasn't propagated yet. Wait 10–30 minutes after adding A records. Confirm with `dig aiauth.app +short`.

**nginx returns 502 Bad Gateway** — the uvicorn process isn't running. `systemctl start aiauth && systemctl status aiauth`. If it crashes on start, check `journalctl -u aiauth -n 200 --no-pager`.

**Signing key lost** — all historical receipts signed with that key become permanently unverifiable. There is no recovery. This is why key backup is non-negotiable. See Key Management section.

**Magic link never arrives (v0.5.0+)** — check the transactional email provider's dashboard for delivery logs. Common causes: missing SPF/DKIM records for the sending domain, the recipient's spam filter, or a typo in the email address. The server does NOT reveal whether an email is registered (enumeration protection), so a silent failure is expected behavior from the user's perspective.

-----

## MANDATORY: Pre-Work Audit Protocol

**Before writing any code, creating any file, or modifying any existing file, Claude MUST complete the following audit. No exceptions.**

### Step 1: Inventory the Repository

Run a full directory listing. Compare every file found against the file list in this document. Identify:
- Files in the repo not mentioned here (investigate)
- Files mentioned but missing (create)
- Files that may be outdated (check versions, schema, feature flags)

### Step 2: Inventory the Production Server

```bash
ls -la /opt/aiauth/
ls -la /opt/aiauth/keys/ 2>/dev/null || echo "No keys directory yet"
cat /opt/aiauth/server.py | head -5
grep "VERSION\|schema_version" /opt/aiauth/server.py | head -3
grep "prompt_hash\|ai_markers\|concurrent_ai_apps" /opt/aiauth/server.py | head -5
grep "tier\|commercial" /opt/aiauth/server.py | head -3
grep "hash_registry" /opt/aiauth/server.py | head -3
grep "key_manifest\|key_id" /opt/aiauth/server.py | head -3
grep "rate.limit\|throttle" /opt/aiauth/server.py | head -3
systemctl status aiauth
curl -s http://localhost:8100/health
```

### Step 3: Build a Delta Report

```
DELTA REPORT
============
ALREADY IMPLEMENTED: [features/endpoints/fields that exist and work]
PARTIALLY IMPLEMENTED: [started but incomplete, with what remains]
NOT YET IMPLEMENTED: [from this document, zero code in repo]
CONFLICTS: [where repo code contradicts this document]
REPO-ONLY: [code not referenced here — investigate]
```

### Step 4: Propose a Work Plan

Follow the Build Priority phases. Complete partial features before starting new ones. Never duplicate existing functionality. Test each change against the running server.

### Step 5: Validate After Every Change

Hit `/health`, test the changed endpoint, verify no regression, state what manual testing the user needs to perform, verify migration path if schema changed.

### Rules for This Document

- **This document is authoritative.**
- **Do not add features not described here** without approval.
- **Do not remove features described here** without approval.
- **Update this document when a feature ships.**
- **Schema changes require updating:** (1) Receipt Schema section, (2) Field Reference table, (3) Traceability Matrix, (4) Dashboard Data Contract, (5) `enterprise_attestations` table, (6) Version History, (7) Tier Gating section. All seven must stay in sync.

-----

*Single source of truth for AIAuth. Update as features ship.*
