# Status Page Setup — `status.aiauth.app`

This document covers the out-of-repo work to wire `status.aiauth.app` to an external uptime monitor so that the footer "Status" link on `aiauth.app` resolves to a live status page.

The code changes (footer link + `/health/db` endpoint) are already merged. What's left is DNS + monitor configuration, which is operator work and lives outside the repo.

---

## Endpoints to monitor

| Path | Purpose | Expected | Alert on |
|---|---|---|---|
| `https://aiauth.app/health` | Liveness. Basic "server is up". | `200` with `{"status":"ok",...}` | Non-200 for > 2 minutes |
| `https://aiauth.app/health/db` | Readiness + key-age signal | `200` with `"status":"ok"`; `db_latency_ms` under 250; `active_key_age_days` under 400 | `"status":"degraded"` body flag, OR latency > 500ms sustained, OR `rotation_overdue: true` |
| `https://aiauth.app/v1/public-key` | Key manifest reachable | `200` with a `keys` array | Non-200 for > 5 minutes |
| `https://aiauth.app/.well-known/aiauth-public-key` | Well-known discovery endpoint | `200` with a `keys` array | Non-200 for > 5 minutes |

Polling every 60 seconds is a good default. Tighter than that mostly just consumes monitor quota.

---

## Option A — UptimeRobot (free tier, fastest)

1. Create an account at <https://uptimerobot.com>.
2. Add four "HTTP(s)" monitors, one per row above.
3. For each monitor, set **Keyword** alerting:
   - `/health`: keyword = `"status":"ok"`, fail if not present.
   - `/health/db`: keyword = `"status":"ok"`, fail if not present (this catches the `"degraded"` path).
4. Set the alert contact to an email you actually read (ideally distinct from `sales@aiauth.app`).
5. In the UptimeRobot dashboard, create a **public status page**. Under its settings:
   - Title: "AIAuth"
   - Custom domain: `status.aiauth.app`
   - Announcement banner when needed: toggle from the dashboard.
6. In your DNS provider, add a `CNAME`:
   ```
   status   CNAME   stats.uptimerobot.com.
   ```
   (UptimeRobot will show the exact CNAME target on the custom-domain page.)
7. Wait 5–10 minutes for DNS + their cert provisioning to settle.

Free tier limits: 50 monitors, 5-minute polling intervals. Sufficient for AIAuth.

---

## Option B — Instatus (more polished, $0 hobby tier)

Instatus is a better-looking status page with component grouping and incident write-ups, if you plan to formalize incident comms.

1. Sign up at <https://instatus.com>.
2. Add components: **API**, **Signing server**, **Key manifest**. Map each to the corresponding endpoint above.
3. Add a **CNAME** record `status CNAME <your-instatus-subdomain>.instatus.com`.
4. Enable **HTTP monitors** under Settings → Monitors for the four URLs.

Instatus hobby tier (free): 1 status page, 10 components, public access, custom domain.

---

## Option C — Self-hosted Cachet or Kuma

If you want to keep the status page on your own infrastructure — consistent with AIAuth's self-hosted ethos — deploy **Uptime Kuma** (<https://github.com/louislam/uptime-kuma>) in a small VM.

1. Run Kuma in Docker on the same VM that hosts the signing server (or a separate one).
2. Add the four monitors manually.
3. Expose the Kuma status page at `status.aiauth.app` behind nginx or Caddy with TLS.
4. Configure SMTP for alerts.

Upside: no SaaS dependency, matches the self-hosted posture. Downside: now you have another service to keep alive.

**Recommendation:** start with Option A (UptimeRobot) today — 10 minutes of work. Migrate to Option B or C if the status page becomes something you iterate on frequently.

---

## Alerting

Whichever monitor you pick, configure:

- **Primary channel**: email to the operator inbox (the one wired to `AIAUTH_OPERATOR_EMAIL`).
- **Escalation**: SMS to the operator's phone if downtime > 5 minutes. Most monitors offer this — Twilio or the monitor's built-in SMS add-on.
- **Dampening**: don't alert on single-poll failures. Require two consecutive failed polls before paging. Avoids false positives from transient network hiccups.

---

## Verification checklist

After setup:

- [ ] `https://status.aiauth.app` resolves to the status page (not a 404 or the monitor's default landing).
- [ ] All four monitors show "up" from at least two geographic probes.
- [ ] Deliberately cause a short outage (stop the server for 30 seconds) and confirm the monitor catches it.
- [ ] Alert email arrives in the operator inbox.
- [ ] Footer link on `aiauth.app` resolves correctly (already wired in code).

---

## What this does NOT give you

- **Root-cause analysis.** The status page tells users *that* something is down, not *why*. Keep separate runbooks for that.
- **SLA enforcement.** The free tier Terms of Service explicitly states there is no SLA. The status page is for transparency, not contractual commitments.
- **Per-customer status.** Self-hosted enterprise deployments run their own server and have their own uptime; `status.aiauth.app` reflects the free tier only.
