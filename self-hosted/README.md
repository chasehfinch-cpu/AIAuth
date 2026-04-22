# AIAuth Enterprise — Self-Hosted

Three-route install guide for customers deploying AIAuth Enterprise on their own infrastructure.

**TL;DR:** copy `config.yaml.example` to `config.yaml`, paste your license key, then pick ONE of the three install routes below.

---

## Prerequisites

- A Linux server (Debian 12 / Ubuntu 22.04+ / RHEL 9 tested; other distros likely work).
- A domain name pointing at the server (e.g., `aiauth.yourco.com`).
- An AIAuth Enterprise license key — email `sales@aiauth.app` to get one.
- (Optional) A Resend API key if you want real magic-link email delivery.

---

## Install Routes

### Route 1: Docker (recommended for production)

```bash
git clone https://github.com/chasehfinch-cpu/AIAuth.git
cd AIAuth
cp self-hosted/config.yaml.example config.yaml
# Edit config.yaml: paste license_key, set organization, server_url
docker compose -f self-hosted/docker-compose.yml up -d

# Verify
curl http://localhost:8100/health
docker logs -f aiauth
```

Data persists in the `aiauth_data` Docker volume. See `self-hosted/docker-compose.yml`.

### Route 2: Python + systemd (for non-Docker environments)

```bash
git clone https://github.com/chasehfinch-cpu/AIAuth.git
cd AIAuth
cp self-hosted/config.yaml.example config.yaml
# Edit config.yaml

sudo ./self-hosted/install.sh $PWD/config.yaml
# Sets up venv, installs deps, bootstraps, starts systemd service,
# configures nginx vhost, and suggests certbot command for TLS.

sudo systemctl status aiauth
curl http://localhost:8100/health
```

### Route 3: Development / manual (Windows, macOS, or any Python env)

Suitable for testing your license on a laptop before full deployment.

```bash
git clone https://github.com/chasehfinch-cpu/AIAuth.git
cd AIAuth
python -m venv venv
source venv/bin/activate    # or venv\Scripts\activate on Windows
pip install -r requirements.txt

cp self-hosted/config.yaml.example config.yaml
# Edit config.yaml

python self-hosted/scripts/bootstrap.py --config config.yaml
python -m uvicorn server:app --host 127.0.0.1 --port 8100
```

---

## What `bootstrap.py` Does

1. Validates your license key signature against our public key (offline, no phone-home).
2. Generates `SERVER_SECRET` + `CLIENT_SECRET` if they're empty in `config.yaml` (writes them back).
3. Generates Ed25519 signing keys in `storage.key_dir`.
4. Initializes both databases (anonymous hash registry + application DB).
5. Registers your organization with its claimed domains.

Idempotent — safe to re-run on an existing install. Does nothing destructive.

---

## After Install

1. Point your DNS A record at the server.
2. On Route 2: `sudo certbot --nginx -d aiauth.yourco.com` to obtain TLS.
3. Set up daily backups: `sudo ./self-hosted/scripts/backup.sh --install-cron daily`.
4. Deploy the Chrome extension to your users (see Enterprise Admin Guide Section 2.1).

---

## Configuration Reference

See `config.yaml.example` for every option with inline docs. Key fields:

- `license_key` (required) — single-line string from sales.
- `organization.name` (required) — displayed on the dashboard.
- `organization.domains` (required) — email domains your users verify from.
- `server_url` (required) — public URL. Must match your TLS cert.
- `email.provider` / `email.api_key` — for magic-link delivery. If blank, links log to stdout (dev only).
- `storage.*` — where keys and databases live. Defaults work for most deployments.
- `secrets.*` — auto-generated if empty.
- `hardening.*` / `rate_limits.*` — operational tuning.

---

## Operational Runbooks

See `docs/ENTERPRISE_ADMIN_GUIDE.md` for:

- **Section 2.5.1:** Backup setup (`backup.sh --install-cron daily`).
- **Section 2.5.2:** Restore procedure (`restore.sh`).
- **Section 2.5.3:** Annual key rotation.
- **Section 2.5.4:** `SERVER_SECRET` rotation (dual-secret window).
- **Section 2.5.5:** Full disaster-recovery playbook.

---

## Support

- **Bug reports:** https://github.com/chasehfinch-cpu/AIAuth/issues
- **Security advisories:** security@aiauth.app
- **Paid support tier:** pricing on request from sales@aiauth.app

Finch Business Services LLC (the software vendor) has no access to your deployment's data. Your server runs on your infrastructure; your IT team operates it.
