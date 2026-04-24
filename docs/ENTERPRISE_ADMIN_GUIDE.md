# AIAuth Enterprise — Admin Guide

This guide is for the IT / Compliance admin deploying AIAuth Enterprise on behalf of their organization. End-user documentation is in the companion **Enterprise User Guide**.

AIAuth Enterprise is **self-hosted only**. You run the server on your infrastructure. Finch Business Services LLC (the software vendor) has no access to your data.

---

## 1. Getting Started

### 1.1 What AIAuth Does for Your Organization

**Chain of custody, not content surveillance.** Your users Right-click and choose "Attest selection with AIAuth" to create a tamper-proof receipt of their AI-assisted work. The receipt carries metadata (who, when, which AI tool, review status) — never the content itself. Your dashboards answer "Who is using which AI tools? Are they reviewing output? Is content flowing externally?" without the privacy cost of screen recording or content capture.

**What you can see:** per-user attestation rates, AI-tool adoption, review quality (time-to-attest, rubber-stamp detection), external-content-flow rates, policy violations, cross-format chain integrity.

**What you cannot see, by design:** the actual text of AI prompts, the content of attested documents, browsing history outside AI sites, screenshots, keystrokes.

### 1.2 Activating Your Enterprise Account

1. Email **sales@aiauth.app** with your company name, estimated user count, and domain(s) you'll deploy to.
2. You receive an invoice and, once paid, a signed license key (a single long string).
3. Paste the license key into `config.yaml` on your server.

No ongoing phone-home. The license validates offline against our public key at server startup.

### 1.3 Your First 30 Minutes (Self-Hosted Quickstart)

**Option A — Docker (recommended for production):**
```bash
git clone https://github.com/chasehfinch-cpu/AIAuth.git
cd AIAuth/self-hosted
cp config.yaml.example config.yaml
# Edit config.yaml: paste license_key, set organization.name, domains, server_url
docker compose up -d
```

**Option B — Python venv (for non-Docker environments):**
```bash
cd AIAuth/self-hosted
./install.sh /path/to/config.yaml
# Creates venv, installs deps, writes systemd unit + nginx vhost, starts service.
```

After either path:
- Your server is running at the URL you set in `config.yaml`.
- Keys have been generated in `/var/lib/aiauth/keys/` (or whatever `storage.key_dir` points at).
- The anonymous hash registry and enterprise_attestations database are initialized.
- Your organization is registered from `organization.name` + `organization.domains`.
- You are the first admin.

**Verify:** `curl $SERVER_URL/health` should return `{"status":"ok","version":"0.5.1",...}`.

---

## 2. Deploying to Your Organization

### 2.1 Chrome Extension Deployment

**Individual pilot (1-10 users):** ask each user to install from the Chrome Web Store and enter `$SERVER_URL` in their Settings panel.

**Full rollout (Workspace-managed):**
1. In **Google Workspace Admin Console → Apps → Chrome → Apps & Extensions**, add the AIAuth extension by ID.
2. Set **Installation Policy** to *Force install* for the target OU.
3. Set the **Managed configuration** JSON:
   ```json
   {
     "enterprise_server": "https://aiauth.yourco.com",
     "org_domain": "yourco.com",
     "tier": "enterprise",
     "require_verification": true
   }
   ```
   When users open the popup, the Server URL is pre-filled, tier is pre-selected as enterprise, and the "Start Attesting (unverified)" button is hidden — they must verify their corporate email.

### 2.2 Desktop Agent Deployment

Windows (v0.5.2+ with MSIX): GPO / Intune / Winget push. Silent-install flags `/S /SERVER=https://aiauth.yourco.com /LICENSE=<key>`.

macOS (roadmap v0.6.0): Jamf / Munki; config delivered via `~/Library/Preferences/aiauth.plist`.

### 2.3 Pilot Deployment (Recommended)

Before an org-wide rollout, deploy to one department (Finance, Legal, or Engineering are good candidates) for 30 days. On day 30, the pilot report generator produces a branded HTML/PDF summary:
```bash
python scripts/render_pilot_report.py \
  --server https://aiauth.yourco.com \
  --session $ADMIN_SESSION \
  --org-id $ORG_ID \
  --admin-email you@yourco.com \
  --department Finance \
  --from 2026-04-01 --to 2026-04-30 \
  --out pilot-report-finance.html --pdf
```

Email the report to leadership; it's the strongest case for the full rollout.

---

## 3. Managing Users

### 3.1 Inviting Users

Current state (v0.5.1): users self-invite by setting the Server URL to your deployment and clicking Verify My Email with their corporate email address. Because their email domain matches one of your claimed domains, they become members of your organization automatically.

Bulk invite via CSV / LDAP / Azure AD sync is on the v0.6.0 roadmap.

### 3.2 User Account Linking

If an employee already has an AIAuth account with a personal email, they can link their corporate email to the same account. This enables:
- Attestation history carries over when they change employers.
- Consent-gated: personal attestations become visible to your org dashboard **only if the user opts in** via `/v1/account/consent`.

### 3.3 Offboarding an Employee

When an employee leaves, run:
```bash
curl -X POST $SERVER_URL/v1/admin/pseudonymize \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_SESSION" \
  -d '{"email": "departed@yourco.com", "org_id": "ORG_abc"}'
```

This:
1. Replaces `uid_encrypted` with NULL on all their attestation rows.
2. Sets `uid_pseudonym` to a one-way hash (audit records still identifiable cross-rows within the org).
3. Marks their `org_members.left_at`.
4. Their `uid_hash` remains so subsequent ingest attempts from that email return `EMAIL_OFFBOARDED`.

### 3.4 Department Mapping

Several dashboard KPIs — the Department Scorecard in the executive summary, the per-department rubber-stamp and review-rate rows in the compliance report — depend on a roster that maps each verified email to a department. Without this, all attestations roll up under "Unmapped" and the scorecard is empty.

**CSV format.** UTF-8, Unix or Windows line endings, no quoting required. Exactly two columns — `email` and `department` — with a mandatory header row:

```csv
email,department
alice@yourco.com,Finance
bob@yourco.com,Engineering
carol@yourco.com,Legal
```

Rules:
- Emails are normalized lowercase server-side before matching.
- An email that isn't yet an AIAuth account is silently skipped; the server returns it in `unmatched_emails` so you can reconcile against HR.
- A blank `department` field clears any existing assignment for that member (useful when someone leaves a team).
- Re-running with the same CSV is idempotent — safe to run nightly from a cron.

**Upload endpoint.** `POST /v1/admin/org/departments?org_id=<your_org_id>`:

```bash
# From an admin session (bearer token from your /v1/admin signin):
curl -X POST "https://aiauth.yourco.com/v1/admin/org/departments?org_id=ORG_YOURCO" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d @- <<'JSON'
{
  "csv": "email,department\nalice@yourco.com,Finance\nbob@yourco.com,Engineering\n"
}
JSON
```

Response:

```json
{
  "org_id": "ORG_YOURCO",
  "updated": 2,
  "unmatched_count": 0,
  "unmatched_emails": []
}
```

**How AIAuth references it.** At dashboard query time, the aggregator joins `enterprise_attestations.uid_hash` against `org_members.uid_hash` and groups by `org_members.department` for the Department Scorecard and per-department breakdowns. Any attestation whose attester isn't in `org_members` for the current org rolls up under "Unmapped".

**What it does NOT do.** This endpoint does not create accounts. Users still self-provision via the magic-link flow (`/v1/account/create`) or via your Workspace/Intune managed policy. The CSV only assigns departments to accounts that already exist.

**Offboarding.** When a user leaves, pair this with the `left_at` update described in §3.3 — setting `left_at` excludes them from forward reporting but preserves their historical attestations in the compliance trail.

A built-in admin UI for department management is planned for v0.6.0. Until then, the endpoint above is the supported path.

---

### 3.5 KPI Data Inputs at a Glance

One reference table for every KPI that needs setup beyond the default extension install. Use this when onboarding a new deployment or auditing why a metric shows zero.

| KPI (report location) | What's required | Format & where | How AIAuth references it |
|---|---|---|---|
| **Department Scorecard** (exec summary §2, compliance §4) | Email → department roster | CSV uploaded via `POST /v1/admin/org/departments` (see §3.4) | JOIN `enterprise_attestations.uid_hash` ↔ `org_members.uid_hash`, GROUP BY department |
| **External Exposures** (exec summary KPI strip) | Your organization's owned domain(s) | `org_domain` field in the managed Chrome extension policy — deployed via Google Workspace Admin or Microsoft Intune (see §2.1). Accepts a single domain or a comma-separated list. | The extension sets `dest_ext = true` on attest when the destination URL's hostname does NOT end with any `org_domain`. Server aggregates the boolean. |
| **Shadow AI Heatmap** (exec summary §5, compliance narrative) | Automatic — no upload | The extension calls `enumerateConcurrentAIApps()` on every attestation when `tier === "enterprise"`. It queries open tabs matching its built-in AI_DOMAINS list. | `SELECT source, COUNT(*)` over `enterprise_attestations.concurrent_ai_apps` using `json_each()` — tools open but never attested become the shadow ratio. |
| **Policy Violations (Critical/High/Medium/Low)** (exec summary §3, compliance §3) | Default policies ship with the server; custom rules are code changes today (YAML-driven rules are v0.6.0) | Rule set defined in `DEFAULT_POLICIES` ([server.py](../server.py) around the `_evaluate_policies` function). Custom rules require a patch + service restart. | `policy_violations` table is written to by the evaluator on every ingest; dashboard groups by `severity`. |
| **Classification tags** (external-exposure breakdowns) | Automatic — heuristic | Extension's `suggestClassification()` tags each attestation as `financial` / `legal` / `client-facing` / `internal`. Override by customizing the function in a self-hosted build. | Stored on `enterprise_attestations.classification`. Aggregated by department and destination. |
| **Multi-Format Documents** (compliance §6) | Canonical text hash from the desktop agent | Install the self-hosted desktop agent from [self-hosted/aiauth_canonical.py](../self-hosted/aiauth_canonical.py). The agent extracts text from xlsx/csv/pdf/docx, SHA-256s the canonical string, and includes it as `content_hash_canonical` in the sign payload. The Chrome extension does not compute this today — deferred to a later Data Depth tier. | `SELECT content_hash_canonical, COUNT(DISTINCT hash) HAVING count > 1` — the canonical hash identifies the same logical document across format conversions. |
| **Ungoverned AI Content** (compliance §6) | Automatic — policy rule is built-in | `ungoverned-ai-content` policy defined in [server.py](../server.py) `DEFAULT_POLICIES`. Fires when a receipt has `ai_markers.verified === true` AND no `parent` receipt (root AI-authored attestation). | `SELECT COUNT(*) FROM policy_violations WHERE policy_id = 'ungoverned-ai-content'` for the reporting window. |
| **Prompt-chain coverage** (exec summary KPI strip) | Automatic — extension populates when user prompt is visible | The content script's `getLastUserPromptText()` reads the last user turn from the AI tool's DOM and passes it to the background worker, which hashes it and sends `prompt_hash`. | `SUM(CASE WHEN prompt_hash IS NOT NULL)` / total. |
| **Rubber-stamp alerts** (free + paid) | Automatic | Extension captures `tta` (time-to-attest) and `len` on every attestation in every tier as of v1.3.0. | `COUNT(*) WHERE tta < 10 AND len > 500`. |
| **AI-Authored Artifacts** (free + paid) | Automatic | Extension sets `ai_markers` when a known AI tool is detected from the page URL or C2PA manifest. | `COUNT(*) WHERE ai_markers IS NOT NULL`. |

**Tier summary:**

- **Free tier users** get: Total attestations, Unique users, Review rate, Rubber-stamp alerts, AI-authored artifacts, Prompt-chain coverage, Model adoption, Chain integrity (from `parent_hash`), C2PA claim data (v1.4.0+).
- **Team / Enterprise tier users** additionally get: Department Scorecard, External Exposures, Shadow AI Heatmap, Policy Violations, Classification breakdowns.
- **Self-hosted + desktop agent** additionally gets: Multi-Format Documents, cross-format chain integrity.

This hierarchy is reflected on every commercial report via the `Team / Enterprise Tier Only` badge.

---

## 4. Reading the Dashboard

Your dashboard lives at `https://aiauth.yourco.com/v1/admin/dashboard` (admin session required). Also accessible at `https://aiauth.yourco.com/demo` with a managed session token.

### 4.1 Dashboard Overview

Top KPIs: Total Attestations, Unique Users, Review Rate, Rubber-Stamp Alerts, External Exposures, Shadow AI Alerts, AI-Authored Artifacts, Prompt-Chain Coverage.

### 4.2 AI Usage Heatmap

Departments × AI tools. Cell intensity = attestation count. Look for:
- Cells where an unapproved AI tool dominates.
- Rows where a single tool is concentrated (possible tool lock-in).

### 4.3 Shadow AI Heatmap

`concurrent_ai_apps` reveals which AI apps your users have OPEN at attestation time — even the ones they're not using for this specific attestation. A high ratio of "times open" to "times attested from" flags ungoverned AI tool usage.

### 4.4 Review Rate Scorecard

Letter grades per department:
- **A:** ≥95% reviewed, 0 critical violations.
- **B:** ≥85%.
- **C:** ≥70%.
- **D:** ≥50%.
- **F:** <50%.

A low grade means someone is attesting without reviewing. This is usually a process problem, not a people problem — consider enforcing a mandatory-review-delay policy.

### 4.5 Time-to-Attest Distribution

Histogram of `tta` (seconds between AI output and attestation). The `0-10s` bucket is flagged red — under 10 seconds on >500 characters of content almost always means the user didn't read it (rubber-stamping).

### 4.6 Chain Integrity Monitor

Shows broken chains: documents whose `parent` receipt can't be found. Common causes:
- Document was attested by someone outside your org (intentional boundary).
- Pre-AIAuth history (OK to leave).
- Receipt was deleted via DSAR (noted in consent_log).

### 4.7 Policy Violations

The built-in policy engine evaluates each attestation against:
- `dual-review-financial` (high) — financial content attested by only one person.
- `no-rubber-stamping` (medium) — tta<10 AND len>500.
- `external-must-attest` (critical) — content flowing externally without review.
- `unverified-financial` (medium) — financial content from an unverified extension.
- `shadow-ai-detected` (low) — AI app open but not used for this attestation.
- `ungoverned-ai-content` (medium) — AI-authored file with no parent chain.

### 4.8 External Exposure Report

Attestations where `dest_ext=true`. By destination (email, messaging, code-repo), by classification.

### 4.9 AI Authorship Detection

Counts of receipts where `ai_markers.verified=true` (Copilot docProps, ChatGPT/Claude/Gemini PDF markers, C2PA image manifests). Identifies AI-authored content even when no one attested it through AIAuth — useful for catching shadow usage.

---

## 5. Running Reports

### 5.1 Pilot Report (30-day)

See `scripts/render_pilot_report.py` in the repo. Produces a standalone HTML with your org's logo, prospect sign-off block, observations, and recommendations.

### 5.2 Compliance Report (Quarterly)

`https://aiauth.yourco.com/samples/compliance-report?source=live&org_id=$ORG&session=$TOK` serves a print-friendly 8-section audit report.

### 5.3 Custom Exports

`GET /v1/admin/dashboard/data?org_id=$ORG&from=$D1&to=$D2` returns the full data contract as JSON. Pipe into your own BI pipeline.

---

## 6. Data, Privacy, Compliance

### 6.1 What AIAuth Stores

- **Anonymous hash registry (6 columns)** — no PII.
- **`accounts` + `account_emails`** — emails stored as HMAC hashes. Only the hashes; never plaintext.
- **`enterprise_attestations`** — full receipt metadata. `uid` stored as HMAC hash + AES-GCM encrypted ciphertext. Decryptable only by authenticated admins on demand.
- **`consent_log`** — append-only audit trail. Details stored as AES-GCM ciphertext.

### 6.2 Data Hardening

If your server is compromised, a filesystem attacker gets:
- Email hashes (irreversible without SERVER_SECRET)
- Fernet ciphertext (decryptable only with SERVER_SECRET)
- The anonymous registry (PII-free)

**Residual risks:**
- The signing keys are plaintext PEM on disk. Keep backups offline; rotate annually.
- `SERVER_SECRET` in `.env` is plaintext. `chmod 600`, not in any off-server backup.

### 6.3 GDPR + DSAR Handling

`POST /v1/admin/dsar` supports:
- `export` — return all data tied to an email (decrypts ciphertext in-response).
- `pseudonymize` — replaces uid_encrypted with NULL, keeps audit record with uid_pseudonym.
- `delete` — hard delete of all attestations (nuclear; chain integrity affected).

Pseudonymize is the recommended default for offboarding; delete is for explicit DSAR requests.

### 6.4 Self-Hosted Data Sovereignty

Your server, your jurisdiction, your control. Finch Business Services LLC has no access. The one outbound call — license validation — happens once at startup via HMAC verification against our public key; no personal data is transmitted.

---

## 2.5 Operations: Backup and Recovery

### 2.5.1 Non-optional: keys backup

Run `backup.sh --install-cron daily` during initial setup. Archives land in `/var/backups/aiauth/` by default.

```bash
./self-hosted/scripts/backup.sh --encrypt age:$PUBKEY --to s3://yourco-backups/aiauth/ --retain 30d
```

Encrypt with age (or GPG), push to off-server storage (S3, SFTP). Keep the age private key in a password manager or HSM — **never on the AIAuth server itself**.

### 2.5.2 Restore

```bash
systemctl stop aiauth
./self-hosted/scripts/restore.sh /path/to/backup.tar.gz.age --decrypt age
systemctl start aiauth
```

### 2.5.3 Key Rotation

Annually:
```bash
# 1. Generate new key in keys/key_002_active.pem
# 2. Update key_manifest.json:
#    - set key_002 status=active, current_signing_key=key_002
#    - set key_001 status=retired, valid_until=<today>
# 3. Restart service
# Both keys remain loaded; new receipts sign with key_002, old receipts verify with key_001.
```

### 2.5.4 SERVER_SECRET Rotation

If `SERVER_SECRET` leaks:
```bash
systemctl stop aiauth
NEW=$(python -c "import secrets; print(secrets.token_hex(32))")
# In config.yaml, move current server_secret -> server_secret_previous,
# set server_secret to $NEW.
systemctl start aiauth
# Server runs in DUAL-SECRET mode — old tokens and hashes still validate.
# All active users will be asked to re-authenticate on next /me call.
python ./self-hosted/scripts/rotate_server_secret.py --re-encrypt
# Wait 7 days for users to re-auth naturally. Then:
# Remove server_secret_previous from config.yaml; restart.
python ./self-hosted/scripts/rotate_server_secret.py --prune-orphaned
```

### 2.5.5 Disaster Recovery Playbook

| Scenario | Recovery |
|---|---|
| Signing keys lost, backup intact | `./restore.sh --keys-only` + restart |
| Signing keys lost, NO backup | Issue new license with fresh keys; historical receipts become unverifiable (document this in compliance record). |
| SERVER_SECRET lost, ciphertext unreadable | Follow 2.5.4 rotation flow (email hashes and tokens orphan gracefully). |
| `aiauth.db` corruption | `./restore.sh --db-only` + any missed ingests replay from client queue. |
| Full server loss | New box → `docker compose up` with old config.yaml → `./restore.sh` full archive. ~30 min downtime. |

---

## 7. What AIAuth Provides Post-Handoff

After your initial deployment, AIAuth's involvement is **minimal**:

- **Software updates:** GitHub Releases. You choose when to `git pull` + redeploy.
- **License renewals:** annual. We email a new key 30 days before expiry. Expired licenses enter a 30-day grace period before losing enterprise features; attestation signing always continues.
- **Bug reports:** GitHub Issues.
- **Optional paid support:** direct Slack + SLA, pricing on request.

What AIAuth does **not** provide post-handoff:
- Access to your attestation data (we don't have it).
- Account recovery (you manage your own signing keys).
- Real-time monitoring (that's your ops team's responsibility).
