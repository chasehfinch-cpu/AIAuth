"""
render_pilot_report.py — produce a prospect-specific 30-day pilot
report from live AIAuth data.

Reads /v1/admin/dashboard/data from a customer's self-hosted server
(or a session-authenticated admin session), substitutes the placeholder
tokens in templates/commercial/pilot-report-template.html, and writes
a standalone HTML file ready to send.

Not served by the web — this is a sales-side tool.

Usage:
  python scripts/render_pilot_report.py \\
      --server https://aiauth.acme.com \\
      --session "eyJhY2NvdW50..." \\
      --org-id ORG_abc123 \\
      --out pilot-report-acme.html
  # optional:
  #   --from 2026-04-01 --to 2026-04-30
  #   --admin-email admin@acme.com    # for the signoff block
  #   --department Finance            # highlight one department
  #   --pdf                            # also produce a PDF via wkhtmltopdf if available
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "commercial" / "pilot-report-template.html"


def fetch_dashboard(server: str, session: str, org_id: str,
                    from_: str = None, to: str = None, department: str = None) -> dict:
    params = {"org_id": org_id}
    if from_: params["from"] = from_
    if to: params["to"] = to
    if department: params["department"] = department
    url = f"{server.rstrip('/')}/v1/admin/dashboard/data?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {session}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def pct(v): return f"{round((v or 0) * 100, 1)}%"
def fmt(v): return f"{int(v or 0):,}"


def dept_table(data: dict) -> str:
    rows = data.get("by_department") or []
    if not rows:
        return "<p style='color:#64748b;font-size:13px;'>No departments configured during the pilot.</p>"
    html = ["<table><thead><tr>",
            "<th>Department</th><th>Attestations</th><th>Users</th>",
            "<th>Review rate</th><th>Rubber-stamp</th><th>Grade</th></tr></thead><tbody>"]
    for d in rows:
        html.append(
            f"<tr><td>{d.get('department','—')}</td>"
            f"<td>{fmt(d.get('total'))}</td>"
            f"<td>{fmt(d.get('unique_users'))}</td>"
            f"<td>{pct(d.get('review_rate'))}</td>"
            f"<td>{pct(d.get('rubber_stamp_rate'))}</td>"
            f"<td><strong>{d.get('grade','—')}</strong></td></tr>"
        )
    html.append("</tbody></table>")
    return "\n".join(html)


def violation_table(data: dict) -> str:
    pv = (data.get("summary") or {}).get("policy_violations") or {}
    rows = []
    for sev in ("critical", "high", "medium", "low"):
        n = pv.get(sev, 0)
        if n:
            rows.append(
                f"<tr><td>{sev.title()}</td><td>{fmt(n)}</td>"
                f"<td style='color:#64748b;font-size:12px;'>{_severity_note(sev)}</td></tr>"
            )
    if not rows:
        return "<p style='color:#16a34a;font-size:13px;'>No policy violations during the pilot window.</p>"
    return (
        "<table><thead><tr><th>Severity</th><th>Count</th><th>Notes</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>"
    )


def _severity_note(sev: str) -> str:
    return {
        "critical": "Address within 48 hours. Usually external-exposure or ungoverned-AI findings.",
        "high":     "Weekly review cadence. Typically dual-review gaps on financial content.",
        "medium":   "Monthly review. Includes rubber-stamp and unverified-source flags.",
        "low":      "Informational. Shadow AI signals and other ambient patterns.",
    }.get(sev, "")


def observations(data: dict) -> str:
    s = data.get("summary") or {}
    notes = []
    if s.get("rubber_stamp_count"):
        notes.append(f"Rubber-stamp alerts: {fmt(s['rubber_stamp_count'])} attestations had "
                     f"&lt;10 seconds of review time on content &gt;500 characters.")
    if s.get("shadow_ai_alerts"):
        notes.append(f"Shadow AI: {fmt(s['shadow_ai_alerts'])} unique app(s) were running but not used "
                     f"for attested work — potential ungoverned AI usage.")
    if s.get("ai_authored_detected"):
        notes.append(f"AI-authored artifacts: {fmt(s['ai_authored_detected'])} files carried embedded "
                     f"AI-authorship markers (Copilot docProps, C2PA, ChatGPT PDF, etc.).")
    if s.get("external_exposure_count"):
        notes.append(f"External content flow: {fmt(s['external_exposure_count'])} attested artifacts "
                     f"flowed to external destinations (email, messaging, external docs).")
    if s.get("chain_break_count"):
        notes.append(f"Chain integrity: {fmt(s['chain_break_count'])} document chain(s) had a missing "
                     f"parent receipt — either pre-AIAuth history or a cross-deployment transfer.")
    if not notes:
        notes.append("No material issues flagged during the pilot window.")
    return "<ul>" + "".join(f"<li>{n}</li>" for n in notes) + "</ul>"


def recommendations(data: dict) -> str:
    s = data.get("summary") or {}
    recs = []
    pv = s.get("policy_violations") or {}
    if pv.get("critical"):
        recs.append(f"Resolve the {fmt(pv['critical'])} critical violation(s) before the next reporting window.")
    if (s.get("rubber_stamp_rate") or 0) > 0.03:
        recs.append("Rubber-stamp rate &gt;3% — roll out the mandatory-review-delay policy "
                    "to reviewers most affected (see Department Breakdown).")
    if (s.get("prompt_hash_coverage") or 0) < 0.5:
        recs.append("Less than half of attestations carry a prompt_hash. Consider enabling the "
                    "prompt-capture setting in the Chrome extension for stronger audit trails.")
    if (s.get("ai_authored_detected") or 0) and not (data.get("ai_authorship") or {}).get("by_source"):
        recs.append("Enable AI-authorship marker scanning in the desktop agent configuration.")
    if not recs:
        recs.append("Continue current operations; no changes recommended based on this pilot window.")
    return "<ol>" + "".join(f"<li>{r}</li>" for r in recs) + "</ol>"


def highlight_text(data: dict) -> str:
    s = data.get("summary") or {}
    total = s.get("total_attestations") or 0
    users = s.get("unique_users") or 0
    rate = pct(s.get("review_rate"))
    return (f"AIAuth recorded {fmt(total)} attestations across {fmt(users)} user(s) during the pilot, "
            f"with a {rate} review rate. Full chain-of-custody preserved across "
            f"{fmt((data.get('chain_integrity') or {}).get('complete_chains'))} document lineages.")


def render(data: dict, out_path: Path, admin_email: str = "", department: str = "") -> None:
    s = data.get("summary") or {}
    meta = data.get("meta") or {}
    ci = data.get("chain_integrity") or {}

    subs = {
        "ORG_NAME": meta.get("org_name") or "—",
        "PILOT_START": (meta.get("date_range") or {}).get("from", "—")[:10] if (meta.get("date_range") or {}).get("from") else "—",
        "PILOT_END": (meta.get("date_range") or {}).get("to", "—")[:10] if (meta.get("date_range") or {}).get("to") else "—",
        "PILOT_DEPARTMENT": department or "all",
        "GENERATED_AT": datetime.now(timezone.utc).isoformat(timespec="seconds") + "Z",
        "SCHEMA_VERSION": meta.get("schema_version") or "—",
        "ADMIN_EMAIL": admin_email or "—",
        "HIGHLIGHT_TEXT": highlight_text(data),
        "TOTAL_ATTESTATIONS": fmt(s.get("total_attestations")),
        "UNIQUE_USERS": fmt(s.get("unique_users")),
        "AI_TOOLS": fmt(len(data.get("by_model") or [])),
        "FILE_ATTESTATIONS": fmt(sum(f.get("count", 0) for f in (data.get("file_types") or [])
                                     if f.get("type") not in ("text", "snippet", "prose"))),
        "REVIEW_RATE": pct(s.get("review_rate")),
        "RUBBER_STAMP_COUNT": fmt(s.get("rubber_stamp_count")),
        "AVG_TTA": f"{int(s['avg_tta_seconds'])}s" if s.get("avg_tta_seconds") else "—",
        "MEDIAN_TTA": f"{int(s['median_tta_seconds'])}s" if s.get("median_tta_seconds") else "—",
        "SHADOW_AI_ALERTS": fmt(s.get("shadow_ai_alerts")),
        "AI_AUTHORED": fmt(s.get("ai_authored_detected")),
        "EXTERNAL_EXPOSURE": fmt(s.get("external_exposure_count")),
        "CHAIN_INTEGRITY": pct((ci.get("complete_chains", 0) / ci.get("total_chains"))
                               if ci.get("total_chains") else 0),
        "DEPT_TABLE": dept_table(data),
        "VIOLATION_TABLE": violation_table(data),
        "OBSERVATIONS_LIST": observations(data),
        "RECOMMENDATIONS_LIST": recommendations(data),
    }

    tpl = TEMPLATE_PATH.read_text(encoding="utf-8")
    for key, val in subs.items():
        tpl = tpl.replace("{{" + key + "}}", str(val))
    out_path.write_text(tpl, encoding="utf-8")
    print(f"Wrote {out_path} ({len(tpl):,} bytes)")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--server", required=True, help="URL of the customer's self-hosted AIAuth server")
    p.add_argument("--session", required=True, help="Admin session token (Bearer)")
    p.add_argument("--org-id", required=True, help="Organization ID")
    p.add_argument("--from", dest="from_", default=None, help="Window start (YYYY-MM-DD)")
    p.add_argument("--to", default=None, help="Window end (YYYY-MM-DD)")
    p.add_argument("--department", default=None, help="Filter to one department")
    p.add_argument("--admin-email", default="", help="Admin email for the sign-off block")
    p.add_argument("--out", default="pilot-report.html", help="Output HTML file")
    p.add_argument("--pdf", action="store_true", help="Also emit a PDF via wkhtmltopdf if installed")
    args = p.parse_args()

    data = fetch_dashboard(args.server, args.session, args.org_id,
                           from_=args.from_, to=args.to, department=args.department)
    out_path = Path(args.out)
    render(data, out_path, admin_email=args.admin_email, department=args.department or "")

    if args.pdf:
        import shutil
        import subprocess
        wk = shutil.which("wkhtmltopdf")
        if not wk:
            print("wkhtmltopdf not installed; skipping PDF.", file=sys.stderr)
            return 0
        pdf_path = out_path.with_suffix(".pdf")
        subprocess.check_call([wk, "--quiet", "--enable-local-file-access",
                               str(out_path), str(pdf_path)])
        print(f"Wrote {pdf_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
