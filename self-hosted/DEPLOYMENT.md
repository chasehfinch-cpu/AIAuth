# AIAuth Enterprise — Deployment Guide

Operator checklist for running AIAuth on your own infrastructure. The
installer (`install.sh`) is idempotent — re-running is safe.

## Pre-flight

- A clean Linux host with `sudo`. Tested on Ubuntu 22.04/24.04, Debian 12, RHEL 9. Both ARM64 and x86_64.
- DNS A record pointing your hostname (e.g. `aiauth.company.com`) at the host's public IP. **TLS will fail without DNS.**
- Inbound TCP 80 and 443 open in **both** any cloud firewall AND host `ufw`.
- An enterprise license key from `hello@aiauth.app`. Without it the server starts in `public` mode and enterprise endpoints stay disabled.
- ≈1 vCPU / 1 GB RAM / 10 GB disk for ~10 users; scale vertically before horizontally.

## Install

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/chasehfinch-cpu/AIAuth/main/self-hosted/install.sh)
```

The installer:

1. Creates `/opt/aiauth/` with a Python venv and installs requirements.
2. Generates an Ed25519 signing keypair in `/opt/aiauth/keys/`.
3. Writes a systemd unit (port 8100, 2 workers).
4. Writes an nginx vhost in front of port 8100.
5. Prompts to run `certbot --nginx` for Let's Encrypt TLS.
6. Copies `config.yaml.example` to `/opt/aiauth/config.yaml`.

## Configure

Edit `/opt/aiauth/config.yaml` (or set env vars in the systemd `EnvironmentFile`) before first start:

| Setting | Required? | Notes |
|---|---|---|
| `AIAUTH_MODE=enterprise` | Required for enterprise | Otherwise public mode |
| `AIAUTH_LICENSE_KEY` | Required for enterprise | From `hello@aiauth.app` |
| `AIAUTH_MASTER_KEY` | Always | Random 32-byte hex; admin key |
| `SERVER_SECRET` | Always | Random 32-byte hex; HMAC for tokens |
| `CLIENT_SECRET` | Always | Random 32-byte hex; client integrity |
| `RESEND_API_KEY` | Recommended | For magic-link email delivery |
| `RESEND_FROM` | If `RESEND_API_KEY` set | e.g. `AIAuth <auth@aiauth.company.com>` |
| `AIAUTH_DEDUP_WINDOW` | Optional | Defaults to 300 seconds |
| `AIAUTH_REGISTRY_PRUNE` | Optional | `true` enables 180-day pruning |

Generate any random secret with `python3 -c 'import secrets; print(secrets.token_hex(32))'`.

## Start

```bash
sudo systemctl enable aiauth
sudo systemctl start aiauth
sudo systemctl status aiauth
curl -s http://localhost:8100/health
```

If `mode` shows `public` when you expected `enterprise`, the license key didn't validate — check `journalctl -u aiauth -n 100`.

## Bootstrap your org

Run once after the service is healthy:

```bash
sudo /opt/aiauth/venv/bin/python /opt/aiauth/scripts/bootstrap.py \
  --org-name "Acme Corp" \
  --domain acme.com \
  --admin-email admin@acme.com
```

Claims your domain, creates the admin user, emails them a magic-link login. The admin can then push the Chrome extension via Google Workspace Admin Console with this server's URL pre-configured.

## Backup

The signing keys are the **only non-recoverable failure mode**. Back them up after every config change and at least weekly:

```bash
sudo /opt/aiauth/scripts/backup.sh /var/backups/aiauth
```

Pull the archive off-host:

```powershell
scp root@aiauth.company.com:/var/backups/aiauth/aiauth-*.tar.gz C:\backups\
```

Restore: `sudo /opt/aiauth/scripts/restore.sh <archive.tar.gz>`.

## Routine operations

| Task | Cadence | Command |
|---|---|---|
| Backup keys + DB | Weekly + post-config | `backup.sh` |
| Rotate signing key | Annually | `scripts/rotate_server_secret.py --rotate-signing` |
| Rotate `SERVER_SECRET` | Annually | Edit env file; `systemctl restart aiauth` |
| Renew TLS cert | Auto via `certbot.timer` | Verify: `certbot renew --dry-run` |
| Prune registry | Optional, monthly | Set `AIAUTH_REGISTRY_PRUNE=true` |
| Review logs | As needed | `journalctl -u aiauth -n 200 --no-pager` |
| External health probe | Every 60s | `GET /health` from monitoring |

`rotate_server_secret.py --rotate-signing` follows the dual-key transition window — old key stays valid for verification for 30 days, new key signs from issuance.

## Logging & monitoring

- App logs to stdout, captured by systemd-journald. Tail: `journalctl -u aiauth -f`.
- For longer retention point a log shipper (Vector, Fluent Bit, OTel Collector) at the journal.
- Recommended alerts:
  - 5xx rate > 1% over 5 minutes
  - `/health` non-200 for 3 consecutive probes
  - Disk usage > 80%
  - License expiry < 30 days (response header `X-AIAuth-License-Grace-Days`)

## Firewall

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow OpenSSH
sudo ufw enable
```

Cloud firewalls live outside the host — configure them too. Inbound 8100 is **not** required externally; nginx proxies localhost:8100.

## Updating

```bash
cd /opt/aiauth
sudo git pull origin main
sudo /opt/aiauth/venv/bin/pip install -r requirements.txt
sudo systemctl restart aiauth
sudo systemctl status aiauth
curl -s http://localhost:8100/health
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `502 Bad Gateway` | uvicorn not running. `systemctl start aiauth` |
| Health returns `mode: public` when enterprise expected | License invalid/expired |
| Magic-link email never arrives | `RESEND_API_KEY` unset or domain SPF/DKIM missing |
| Cert renewal failed | DNS changed or port 80 blocked. `certbot renew --dry-run` |
| `SERVER_MISCONFIGURED` 500s | `SERVER_SECRET` env var missing |
| Receipts verify locally but registry lookup empty | DB write failed silently. Check disk + permissions |

## Decommissioning

1. `backup.sh` and pull the archive off-host.
2. Export DSAR data on outstanding requests (`/v1/admin/dsar`).
3. Pseudonymize departed users (`/v1/admin/pseudonymize`).
4. `systemctl stop aiauth && systemctl disable aiauth`.
5. **Keep the keys archive** at least as long as your retention policy — signed receipts remain verifiable forever, and losing the public key breaks verification.
