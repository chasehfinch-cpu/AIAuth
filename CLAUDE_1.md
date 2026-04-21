# CLAUDE.md — AIAuth Build & Launch Guide

## Project Overview

AIAuth is a cryptographic attestation service for AI-generated content.
Users press Ctrl+Shift+A to create signed receipts proving they reviewed
AI output. The server signs receipts using Ed25519 and stores nothing
about the user. Receipts are kept on the user's machine. A public hash
registry enables chain discovery without exposing user data.

**Owner:** Chase (Finch Business Services LLC)
**Domain target:** aiauth.app (or whatever domain was purchased)
**Server:** DigitalOcean droplet at 167.172.250.174 (Ubuntu 24.04, 1 vCPU, 1GB RAM)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ USERS (free tier)                                               │
│                                                                 │
│   Chrome Extension          Desktop Agent (Windows)             │
│   - Installs from store     - Installs from Microsoft Store     │
│   - Ctrl+Shift+A or         - Ctrl+Shift+A from anywhere       │
│     right-click on AI text  - System tray app                   │
│   - Stores receipts in      - Stores receipts in                │
│     Chrome local storage      %APPDATA%\AIAuth\receipts\        │
└────────────────────┬────────────────────┬───────────────────────┘
                     │                    │
                     ▼                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ AIAUTH SERVER (DigitalOcean)                                    │
│                                                                 │
│   Public mode (default):                                        │
│     POST /v1/sign        → signs receipt, forgets immediately   │
│     POST /v1/verify      → checks signature Y/N + chain disc.  │
│     POST /v1/verify/chain → checks full chain Y/N              │
│     GET  /v1/discover/{hash} → finds related receipts           │
│     GET  /v1/public-key  → Ed25519 public key                  │
│     GET  /check          → public verification webpage          │
│     GET  /guide          → user guide                           │
│     GET  /health         → server status                        │
│                                                                 │
│   Stores ONLY:                                                  │
│     - aiauth_private.pem (signing key — BACK THIS UP)           │
│     - aiauth_registry.db (hash→receipt_id mappings, no names)   │
│                                                                 │
│   Enterprise mode (license-gated, for paying customers):        │
│     - All public endpoints PLUS                                 │
│     - POST /v1/review/{id}     → human review with history      │
│     - GET  /v1/attestations    → query stored attestations      │
│     - GET  /v1/stats           → usage analytics                │
│     - GET  /v1/chain/{root}    → stored chain queries           │
│     - POST /v1/admin/license/generate → create license keys     │
│     - Stores full attestation data in aiauth.db                 │
│     - Requires AIAUTH_LICENSE_KEY env var                        │
│                                                                 │
│   Tech stack:                                                   │
│     - Python 3 + FastAPI + uvicorn                              │
│     - cryptography (Ed25519 signing)                            │
│     - SQLite (registry + enterprise DB)                         │
│     - nginx reverse proxy + certbot SSL                         │
│     - systemd service for auto-restart                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Current State — What Has Been Done

### Completed
- [x] All source code written and tested in conversation
- [x] DigitalOcean droplet created (167.172.250.174)
- [x] SSH access working
- [x] apt packages installed (python3, pip, venv, nginx, certbot, ufw)
- [x] Python venv created at /opt/aiauth/venv
- [x] pip packages installed (fastapi, uvicorn, cryptography)
- [x] UFW firewall configured (ports 22, 80, 443, 8100 open)
- [x] Server tested locally with curl (health endpoint returns OK)
- [x] .env file created with AIAUTH_MASTER_KEY

### Needs Verification / May Be Incomplete
- [ ] server.py uploaded to /opt/aiauth/server.py (may be old version)
- [ ] verify.html uploaded to /opt/aiauth/verify.html
- [ ] docs/USER_GUIDE.md uploaded to /opt/aiauth/docs/USER_GUIDE.md
- [ ] Domain registered and DNS A records pointing to 167.172.250.174
- [ ] nginx configured as reverse proxy
- [ ] SSL certificate obtained via certbot
- [ ] systemd service created and enabled
- [ ] Private key backed up locally
- [ ] Desktop agent tested on Windows
- [ ] Chrome extension tested locally
- [ ] Chrome Web Store submission
- [ ] Microsoft Store submission

---

## File Inventory — What Should Exist on the Server

```
/opt/aiauth/
├── server.py              ← Main server (730 lines, v0.4.0)
├── verify.html            ← Public verification page
├── venv/                  ← Python virtual environment
├── .env                   ← Environment variables (AIAUTH_MASTER_KEY)
├── aiauth_private.pem     ← Ed25519 private key (auto-generated on first run)
├── aiauth_public.pem      ← Ed25519 public key (auto-generated on first run)
├── aiauth_registry.db     ← Hash registry (auto-generated on first run)
└── docs/
    └── USER_GUIDE.md      ← Plain-English user guide
```

### Files on Chase's Windows Machine (to be uploaded)

The latest versions of all files are in the downloaded `aiauth` folder.
Key files to upload from Windows to the server:

```
C:\Users\ChaseFinch\Downloads\aiauth\server.py       → /opt/aiauth/server.py
C:\Users\ChaseFinch\Downloads\aiauth\verify.html      → /opt/aiauth/verify.html
C:\Users\ChaseFinch\Downloads\aiauth\docs\USER_GUIDE.md → /opt/aiauth/docs/USER_GUIDE.md
```

IMPORTANT: Upload commands must be run FROM WINDOWS POWERSHELL, not from
the SSH session. The SSH session is on the Linux server which cannot
access Windows file paths (C:\...).

---

## Troubleshooting Checklist

Run these commands on the server (via SSH) to diagnose the current state:

### 1. Check what files exist
```bash
ls -la /opt/aiauth/
ls -la /opt/aiauth/docs/ 2>/dev/null
```

### 2. Check if server.py is the latest version
```bash
head -20 /opt/aiauth/server.py
grep "VERSION" /opt/aiauth/server.py | head -3
grep "hash_registry" /opt/aiauth/server.py | head -3
grep "register" /opt/aiauth/server.py | head -3
```
Expected: VERSION = "0.4.0", hash_registry references present,
register field in SignRequest.

### 3. Check if the server process is running
```bash
systemctl status aiauth 2>/dev/null || echo "No systemd service yet"
ps aux | grep uvicorn
```

### 4. Test the server locally
```bash
cd /opt/aiauth
source venv/bin/activate
source .env
export AIAUTH_MASTER_KEY
# If not already running:
uvicorn server:app --host 127.0.0.1 --port 8100 &
sleep 2
curl http://localhost:8100/health
curl http://localhost:8100/v1/public-key
# Kill the test process after:
kill %1
```

### 5. Check nginx status
```bash
nginx -t
systemctl status nginx
cat /etc/nginx/sites-enabled/aiauth 2>/dev/null || echo "No nginx config yet"
```

### 6. Check SSL certificate
```bash
certbot certificates
```

### 7. Check DNS (replace aiauth.app with actual domain)
```bash
dig aiauth.app +short
# Should return 167.172.250.174
```

### 8. Check firewall
```bash
ufw status
```

### 9. Check DigitalOcean cloud firewall
This must be checked in the DigitalOcean web dashboard:
Networking → Firewalls. If a firewall exists and is attached to the
droplet, it must allow inbound TCP on ports 80 and 443.

---

## Step-by-Step: Complete the Launch

### PHASE 1: Upload Latest Files

FROM WINDOWS POWERSHELL (not SSH):

```powershell
# Upload server.py
scp C:\Users\ChaseFinch\Downloads\aiauth\server.py root@167.172.250.174:/opt/aiauth/server.py

# Upload verify.html
scp C:\Users\ChaseFinch\Downloads\aiauth\verify.html root@167.172.250.174:/opt/aiauth/verify.html

# Create docs directory and upload user guide
ssh root@167.172.250.174 "mkdir -p /opt/aiauth/docs"
scp C:\Users\ChaseFinch\Downloads\aiauth\docs\USER_GUIDE.md root@167.172.250.174:/opt/aiauth/docs/USER_GUIDE.md
```

Each command will ask for the server password.

If scp is not working from PowerShell, alternative approach — SSH into
the server and use nano to paste file contents:

```bash
# On the server via SSH:
nano /opt/aiauth/server.py
# Paste the full contents of server.py, then Ctrl+X, Y, Enter

nano /opt/aiauth/verify.html
# Paste the full contents of verify.html, then Ctrl+X, Y, Enter

mkdir -p /opt/aiauth/docs
nano /opt/aiauth/docs/USER_GUIDE.md
# Paste contents, Ctrl+X, Y, Enter
```

### PHASE 2: Verify Server Runs

ON THE SERVER (via SSH):

```bash
cd /opt/aiauth
source venv/bin/activate
source .env
export AIAUTH_MASTER_KEY

# Test run
uvicorn server:app --host 0.0.0.0 --port 8100
```

Expected output:
```
[AIAuth] ...  (key generation messages on first run)
INFO:     Started server process [xxxxx]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8100
```

The UserWarning about "register" field shadowing is harmless — ignore it.

Test from server:
```bash
# In another SSH session:
curl http://localhost:8100/health
# Expected: {"status":"ok","service":"aiauth","mode":"public","version":"0.4.0"}

curl http://localhost:8100/v1/public-key
# Expected: {"algorithm":"Ed25519","public_key_pem":"-----BEGIN PUBLIC KEY-----\n..."}
```

Press Ctrl+C to stop the test run.

### PHASE 3: Configure Domain & DNS

1. Purchase domain (aiauth.app or alternative) if not done
2. In domain registrar DNS settings, add:
   ```
   Type: A    Name: @      Value: 167.172.250.174    TTL: 300
   Type: A    Name: api    Value: 167.172.250.174    TTL: 300
   ```
3. Wait 5-30 minutes for propagation
4. Test: `ping aiauth.app` (or your domain) should resolve to 167.172.250.174

### PHASE 4: Configure nginx

ON THE SERVER (via SSH):

```bash
cat > /etc/nginx/sites-available/aiauth << 'NGINX'
server {
    listen 80;
    server_name aiauth.app api.aiauth.app;

    location / {
        proxy_pass http://127.0.0.1:8100;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX

ln -sf /etc/nginx/sites-available/aiauth /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx
```

IMPORTANT: Replace `aiauth.app` with your actual domain in the
server_name line if you bought a different domain.

Test: `curl http://localhost/health` should return the health JSON.

### PHASE 5: SSL Certificate

ON THE SERVER (replace domain names with yours):

```bash
certbot --nginx -d aiauth.app -d api.aiauth.app
```

- Enter your email when prompted
- Agree to terms (Y)
- Choose to redirect HTTP to HTTPS when asked (option 2)

Test: Open browser, go to https://aiauth.app/health
Expected: JSON response over HTTPS with padlock icon.

Also test:
- https://aiauth.app/check → verification page
- https://aiauth.app/guide → user guide
- https://aiauth.app/.well-known/aiauth-public-key → public key
- https://aiauth.app/docs → API documentation

### PHASE 6: Create systemd Service

ON THE SERVER:

```bash
cat > /etc/systemd/system/aiauth.service << 'SERVICE'
[Unit]
Description=AIAuth Signing Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/aiauth
EnvironmentFile=/opt/aiauth/.env
Environment=AIAUTH_MODE=public
Environment=AIAUTH_KEY_DIR=/opt/aiauth
ExecStart=/opt/aiauth/venv/bin/uvicorn server:app --host 127.0.0.1 --port 8100 --workers 2
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable aiauth
systemctl start aiauth
systemctl status aiauth
```

Expected: "active (running)" in the status output.

Verify: `curl https://aiauth.app/health`

### PHASE 7: Back Up the Private Key

The private key at /opt/aiauth/aiauth_private.pem is the root of trust.
If lost, all existing receipts become unverifiable. Back it up.

ON THE SERVER:
```bash
cp /opt/aiauth/aiauth_private.pem /root/aiauth_private.pem.backup
```

FROM WINDOWS POWERSHELL:
```powershell
mkdir C:\aiauth -ErrorAction SilentlyContinue
scp root@167.172.250.174:/opt/aiauth/aiauth_private.pem C:\aiauth\aiauth_private.pem.backup
```

Store this file somewhere safe and offline (USB drive, safe, etc.).

### PHASE 8: Generate First License Key

Test the enterprise licensing system:

```bash
curl -X POST https://aiauth.app/v1/admin/license/generate \
  -H "Content-Type: application/json" \
  -d '{
    "company": "Finch Business Services LLC",
    "tier": "enterprise",
    "expires": "2027-12-31",
    "master_key": "YOUR_ACTUAL_MASTER_KEY"
  }'
```

Replace YOUR_ACTUAL_MASTER_KEY with the value in /opt/aiauth/.env

Expected: Returns a license_key string. Save this — it's your first
enterprise license.

### PHASE 9: Test Desktop Agent on Windows

ON WINDOWS:

```powershell
mkdir C:\aiauth -ErrorAction SilentlyContinue
cd C:\aiauth
python -m venv venv
.\venv\Scripts\Activate
pip install pystray Pillow keyboard requests
```

Copy desktop-agent/aiauth.py from the download to C:\aiauth\aiauth.py

```powershell
python aiauth.py
```

First run setup:
```
Email or name: chase@finchbusiness.com
Server: https://aiauth.app
```

Test: Go to claude.ai, get a response, copy it, press Ctrl+Shift+A.
Should see Windows notification and [AIAuth:xxxx] in clipboard.

Check receipt was saved: look in %APPDATA%\AIAuth\receipts\

### PHASE 10: Test Chrome Extension

1. Open Chrome → chrome://extensions/
2. Enable "Developer mode" (toggle top right)
3. Click "Load unpacked"
4. Select the chrome-extension folder from the download
5. AIAuth icon appears in toolbar
6. Click it → enter your email and server URL (https://aiauth.app)
7. Go to claude.ai or chatgpt.com
8. Select AI text → press Ctrl+Shift+A
9. Should see toast notification

### PHASE 11: Submit to Chrome Web Store

1. ZIP the chrome-extension folder
2. Go to https://chrome.google.com/webstore/devconsole
3. Click New Item → upload ZIP
4. Fill in listing:
   - Name: AIAuth — Notarize Your AI Work
   - Category: Productivity
   - Description: (see README.md for suggested copy)
5. Add screenshots of popup and toast
6. Submit for review (1-3 business days)

### PHASE 12: Build and Submit Windows App

ON WINDOWS:

```powershell
cd C:\aiauth
.\venv\Scripts\Activate
pip install pyinstaller
pyinstaller --onefile --noconsole --name AIAuth aiauth.py
```

Test: run dist\AIAuth.exe — should appear in system tray.

Package as MSIX using MSIX Packaging Tool (from Microsoft Store) and
submit via Partner Center dashboard.

---

## Key Environment Variables

| Variable | Where | Purpose | Required |
|----------|-------|---------|----------|
| AIAUTH_MODE | Server | "public" or "enterprise" | No (defaults to "public") |
| AIAUTH_MASTER_KEY | Server .env | Admin key for license generation | Yes |
| AIAUTH_KEY_DIR | Server | Directory for key files | No (defaults to ".") |
| AIAUTH_DB_PATH | Server | Enterprise database path | No (defaults to "aiauth.db") |
| AIAUTH_REGISTRY_PATH | Server | Hash registry database path | No (defaults to "aiauth_registry.db") |
| AIAUTH_LICENSE_KEY | Customer server | Enterprise license key | Only for enterprise mode |

---

## Common Issues

### "Could not resolve hostname C:" error
You're running a Windows command (scp with C:\ path) from the Linux
SSH session. Run it from Windows PowerShell instead.

### Server starts but browser can't connect
Check DigitalOcean cloud firewall (Networking → Firewalls in dashboard).
It's separate from UFW on the server. Must allow TCP 80 and 443 inbound.

### "Field name register shadows an attribute" warning
Harmless. Ignore it. Does not affect functionality.

### certbot fails
DNS hasn't propagated yet. Wait 10-30 minutes after adding A records.
Test with: `dig yourdomain.com +short` — should return server IP.

### nginx returns 502 Bad Gateway
The uvicorn process isn't running. Start the systemd service:
`systemctl start aiauth && systemctl status aiauth`

### Private key lost
CRITICAL: All existing receipts become unverifiable. This is why
backing up aiauth_private.pem is essential. There is no recovery —
a new key means a new trust root.

---

## Monetization Summary

| Tier | What User Gets | What Server Stores | Price |
|------|---------------|-------------------|-------|
| Free (public) | Signing + verification + chain discovery | Hash registry only (no names) | $0 |
| Enterprise self-hosted | License to run enterprise mode | Nothing (they store it) | $500-2,000/mo |
| Enterprise hosted | You run their server | Their data, under contract | $1,000-5,000/mo |

License keys are generated via POST /v1/admin/license/generate (protected
by AIAUTH_MASTER_KEY). Currently manual — generate key, email to customer,
collect payment via invoice/Venmo/wire.

---

## Infrastructure Costs

| Item | Cost |
|------|------|
| DigitalOcean droplet | $6/month |
| Domain (aiauth.app) | ~$12/year |
| Chrome Web Store | $5 one-time |
| Microsoft Partner Center | $19 one-time |
| SSL certificate | Free (Let's Encrypt) |
| **Total launch cost** | **~$42 + $6/month** |

---

## Source Code Locations

All source files are in the downloaded aiauth folder:

```
aiauth/
├── server.py                  ← Server (upload to /opt/aiauth/)
├── verify.html                ← Verification page (upload to /opt/aiauth/)
├── aiauth_callback.py         ← LiteLLM plugin (for developer API tier)
├── config.yaml                ← LiteLLM proxy config
├── requirements.txt           ← Python dependencies
├── README.md                  ← Project overview
├── docs/
│   └── USER_GUIDE.md          ← Non-technical user guide
├── desktop-agent/
│   └── aiauth.py              ← Windows tray agent
└── chrome-extension/
    ├── manifest.json
    ├── background.js
    ├── popup.html
    ├── popup.js
    ├── content.js
    ├── content.css
    └── icons/
        ├── icon16.png
        ├── icon48.png
        └── icon128.png
```
