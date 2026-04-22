// AIAuth popup — v0.5.0 onboarding state machine
// See CLAUDE.md "User Onboarding Flow" for the five states:
//   1 NOT_CONFIGURED     — no email yet
//   2 AWAITING_VERIFY    — email sent, pending magic-link click
//   3 VERIFIED           — session active, personal tier
//   4 ENTERPRISE_LINKED  — session active, org linked
//   5 SESSION_EXPIRED    — session gone but attestation still works

const $ = (id) => document.getElementById(id);
const status = $("status");

const DEFAULT_SERVER = "https://aiauth.app";

function setStatus(msg, kind = "") {
  status.textContent = msg;
  status.className = kind;
  if (msg) setTimeout(() => { if (status.textContent === msg) setStatus(""); }, 4000);
}

function showState(n) {
  // n may be "1" | "2" | "3" | "3u" | "5"
  for (const s of ["state1", "state2", "state3", "state3u", "state5"]) {
    const el = $(s);
    if (el) el.classList.remove("active");
  }
  const target = $("state" + n);
  if (target) target.classList.add("active");
}

async function loadSessionState() {
  const data = await chrome.storage.local.get([
    "userId", "server", "session", "pendingEmail", "org", "tier",
    "emailVerified", "managedConfig",
  ]);
  return {
    userId: data.userId || "",
    server: data.server || DEFAULT_SERVER,
    session: data.session || null,           // {token, expires_at, account_id, email}
    pendingEmail: data.pendingEmail || "",
    org: data.org || null,                   // {org_id, name}
    tier: data.tier || "free",
    emailVerified: data.emailVerified === true,
    managedConfig: data.managedConfig || null,  // populated from chrome.storage.managed at startup
  };
}

function sessionStillValid(session) {
  if (!session || !session.token || !session.expires_at) return false;
  return new Date(session.expires_at) > new Date();
}

async function determineState() {
  const s = await loadSessionState();
  // No identity yet → State 1
  if (!s.userId && !s.pendingEmail) return { n: "1", s };
  // Waiting on magic link → State 2 (user chose Verify My Email)
  if (s.pendingEmail && !sessionStillValid(s.session)) return { n: "2", s };
  // Session expired → State 5 (was previously verified)
  if (s.userId && s.session && !sessionStillValid(s.session) && s.emailVerified) return { n: "5", s };
  // Session valid, org linked → State 4
  if (sessionStillValid(s.session) && s.org && s.org.org_id) return { n: "4", s };
  // Session valid → State 3 (verified personal tier)
  if (sessionStillValid(s.session)) return { n: "3", s };
  // Unverified Start-Attesting path: userId set, emailVerified=false, no session
  if (s.userId && !s.emailVerified) return { n: "3u", s };
  // Fallback
  return { n: "3", s };
}

function fmtTime(iso) {
  try {
    const d = new Date(iso);
    const diff = (new Date() - d) / 1000;
    if (diff < 60) return "just now";
    if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
    return d.toLocaleDateString();
  } catch { return ""; }
}

async function copy(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    setStatus(`${label} copied to clipboard.`, "ok");
  } catch {
    setStatus("Could not copy — clipboard blocked.", "err");
  }
}

async function renderReceipts() {
  const { receipts = [] } = await chrome.storage.local.get("receipts");
  const list = $("receipts");
  if (!list) return;
  list.innerHTML = "";
  receipts.slice(0, 10).forEach((r) => {
    const row = document.createElement("div");
    row.className = "rcpt";

    const left = document.createElement("div");
    const code = document.createElement("div");
    code.className = "rcpt-code";
    code.textContent = r.code;
    const st = document.createElement("span");
    st.className = "rcpt-status" + (r.status === "pending" ? " pending" : "");
    st.textContent = r.status === "pending" ? "◐ pending" : "✓ signed";
    code.appendChild(st);

    const meta = document.createElement("div");
    meta.className = "rcpt-meta";
    const src = r.source_domain || (() => {
      try { return new URL(r.source || "").hostname; } catch { return r.source || ""; }
    })();
    meta.textContent = `${fmtTime(r.ts)}${src ? " · " + src : ""}${r.file_type ? " · " + r.file_type : ""}`;
    left.appendChild(code);
    left.appendChild(meta);

    const actions = document.createElement("div");
    actions.className = "rcpt-actions";

    const copyCode = document.createElement("button");
    copyCode.className = "tiny secondary";
    copyCode.textContent = "Code";
    copyCode.title = "Copy short receipt code";
    copyCode.onclick = () => copy(r.code, "Code");

    const copyJson = document.createElement("button");
    copyJson.className = "tiny";
    copyJson.textContent = "Share";
    copyJson.title = "Copy full signed receipt JSON — paste at aiauth.app/check";
    copyJson.onclick = () => copy(
      JSON.stringify({ receipt: r.receipt, signature: r.signature }, null, 2),
      "Full receipt JSON"
    );

    actions.appendChild(copyCode);
    actions.appendChild(copyJson);
    row.appendChild(left);
    row.appendChild(actions);
    list.appendChild(row);
  });
}

async function renderStats() {
  const { receipts = [] } = await chrome.storage.local.get("receipts");
  const today = new Date().toISOString().slice(0, 10);
  const todayCount = receipts.filter(r => (r.ts || "").startsWith(today)).length;
  const pending = receipts.filter(r => r.status === "pending").length;
  $("statToday") && ($("statToday").textContent = todayCount);
  $("statTotal") && ($("statTotal").textContent = receipts.length);
  $("statPending") && ($("statPending").textContent = pending);
}

async function renderIdentity(s) {
  if ($("currentIdent")) $("currentIdent").textContent = s.userId || (s.session && s.session.email) || "";
  if ($("tierBadge")) {
    $("tierBadge").textContent = s.tier === "enterprise" ? "Enterprise" : "Free";
    $("tierBadge").className = "badge " + (s.tier === "enterprise" ? "enterprise" : "free");
  }
  if (s.org && s.org.org_id && $("orgBanner")) {
    $("orgBanner").style.display = "";
    $("orgName").textContent = `🏢 ${s.org.name || s.org.org_id}`;
  } else if ($("orgBanner")) {
    $("orgBanner").style.display = "none";
  }
  if ($("server")) $("server").value = s.server;
  if ($("tierEnterprise")) $("tierEnterprise").checked = s.tier === "enterprise";
}

// ---------- Server calls ----------

async function callServerJson(path, opts = {}) {
  const { server } = await loadSessionState();
  const resp = await fetch(`${server}${path}`, {
    method: opts.method || "GET",
    headers: {
      "Content-Type": "application/json",
      "X-AIAuth-Client": "chrome-extension/0.5.0",
      ...(opts.headers || {}),
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let json = null;
  try { json = await resp.json(); } catch {}
  return { ok: resp.ok, status: resp.status, json };
}

async function sendMagicLink(email) {
  return callServerJson("/v1/account/create", {
    method: "POST",
    body: { email },
  });
}

async function verifyToken(token) {
  return callServerJson("/v1/account/verify", {
    method: "POST",
    body: { token },
  });
}

async function getMe(sessionToken) {
  return callServerJson("/v1/account/me", {
    headers: { Authorization: `Bearer ${sessionToken}` },
  });
}

async function logout(sessionToken) {
  return callServerJson("/v1/account/logout", {
    method: "POST",
    headers: { Authorization: `Bearer ${sessionToken}` },
  });
}

// Extract a magic-link token from either a bare token or a full URL
function extractToken(input) {
  const s = (input || "").trim();
  if (!s) return "";
  try {
    const u = new URL(s);
    return u.searchParams.get("token") || "";
  } catch {
    return s; // bare token
  }
}

// ---------- State transitions ----------

async function onboardStart() {
  // "Verify My Email" button — full magic-link flow.
  const email = ($("onboardEmail").value || "").trim().toLowerCase();
  if (!email || !email.includes("@")) {
    setStatus("Enter a valid email.", "err"); return;
  }
  setStatus("Sending magic link…");
  const r = await sendMagicLink(email);
  if (r.ok) {
    await chrome.storage.local.set({
      pendingEmail: email, userId: email, emailVerified: false,
    });
    setStatus("Check your email.", "ok");
    await render();
  } else {
    const code = r.json?.error?.code || "UNKNOWN";
    setStatus(`Could not start: ${code}`, "err");
  }
}

async function startAttesting() {
  // "Start Attesting" button — unverified path. No magic link sent.
  const email = ($("onboardEmail").value || "").trim().toLowerCase();
  if (!email || !email.includes("@") || !email.includes(".")) {
    setStatus("Enter a valid email.", "err"); return;
  }
  await chrome.storage.local.set({
    userId: email,
    emailVerified: false,
    pendingEmail: "",
  });
  setStatus("Ready. Press Ctrl+Shift+A to attest.", "ok");
  await render();
}

async function requestVerificationFromUnverified() {
  // "Verify Now" link inside State 3u — upgrades an unverified user.
  const { userId } = await loadSessionState();
  if (!userId) return;
  setStatus("Sending verification link…");
  const r = await sendMagicLink(userId);
  if (r.ok) {
    await chrome.storage.local.set({ pendingEmail: userId });
    setStatus("Check your email.", "ok");
    await render();
  } else {
    setStatus("Could not send link. Try again later.", "err");
  }
}

async function verifyPasted() {
  const raw = $("pasteLink").value;
  const token = extractToken(raw);
  if (!token) { setStatus("Paste the full link or token.", "err"); return; }
  setStatus("Verifying…");
  const r = await verifyToken(token);
  if (!r.ok) {
    const code = r.json?.error?.code || "TOKEN_INVALID";
    setStatus(`Verification failed: ${code}`, "err");
    return;
  }
  const s = r.json;
  await chrome.storage.local.set({
    userId: s.email,
    pendingEmail: "",
    emailVerified: true,     // magic-link click is proof of email ownership
    session: {
      token: s.session_token,
      expires_at: s.expires_at,
      account_id: s.account_id,
      email: s.email,
    },
  });
  // Fetch account info to detect org linkage
  await refreshMe();
  setStatus("Verified!", "ok");
  await render();
}

async function refreshMe() {
  const { session } = await loadSessionState();
  if (!session || !session.token) return;
  const r = await getMe(session.token);
  if (r.ok && r.json) {
    const me = r.json;
    const corp = (me.emails || []).find(e => e.email_type === "corporate" && e.verified);
    const org = (me.organizations || [])[0];
    const orgInfo = org ? { org_id: org.org_id, name: org.name } :
                    (corp ? { org_id: corp.org_id || "pending", name: corp.email.split("@")[1] || "Company" } : null);
    await chrome.storage.local.set({ org: orgInfo });
  } else if (r.status === 401) {
    // Session expired — drop session, keep userId
    await chrome.storage.local.remove("session");
  }
}

async function resendLink() {
  const { pendingEmail, userId } = await loadSessionState();
  const email = pendingEmail || userId;
  if (!email) { setStatus("No email on file.", "err"); return; }
  setStatus("Resending…");
  const r = await callServerJson("/v1/account/auth", { method: "POST", body: { email } });
  setStatus(r.ok ? "Link sent (if the email exists)." : "Rate-limited. Try again later.",
            r.ok ? "ok" : "err");
}

async function changeEmail() {
  await chrome.storage.local.remove(["pendingEmail", "session", "userId", "org"]);
  await render();
}

async function onLogout() {
  const { session } = await loadSessionState();
  if (session && session.token) {
    await logout(session.token);
  }
  await chrome.storage.local.remove(["session", "pendingEmail", "org"]);
  setStatus("Logged out. Attestation still works.", "ok");
  await render();
}

async function saveSettings() {
  const server = ($("server").value.trim() || DEFAULT_SERVER).replace(/\/+$/, "");
  const tier = $("tierEnterprise") && $("tierEnterprise").checked ? "enterprise" : "free";
  await chrome.storage.local.set({ server, tier });
  setStatus("Saved.", "ok");
  await render();
}

async function checkHealth() {
  setStatus("Checking…");
  const r = await callServerJson("/health");
  if (r.ok && r.json) {
    setStatus(`OK — ${r.json.service} v${r.json.version} (${r.json.mode})`, "ok");
  } else {
    setStatus(`Unreachable`, "err");
  }
}

async function signManualText() {
  const text = $("manual").value;
  if (!text.trim()) { setStatus("Paste some text first.", "err"); return; }
  setStatus("Signing…");
  const resp = await chrome.runtime.sendMessage({
    type: "AIAUTH_SIGN_TEXT", text, source: "popup",
  });
  if (resp && resp.ok) {
    setStatus(`Receipt: ${resp.receipt_code}`, "ok");
    try { await navigator.clipboard.writeText(resp.receipt_code); } catch {}
    $("manual").value = "";
    renderReceipts();
    renderStats();
  } else {
    setStatus((resp && resp.error) || "Failed", "err");
  }
}

// ---------- File attestation ----------

async function sha256File(file) {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function attestFile(file) {
  const drop = $("drop");
  if (!drop) return;
  drop.classList.add("busy");
  setStatus(`Hashing ${file.name}…`);
  try {
    const hash = await sha256File(file);
    setStatus(`Signing ${file.name}…`);
    const note = `file=${file.name}; size=${file.size}; type=${file.type || "unknown"}`;
    const resp = await chrome.runtime.sendMessage({
      type: "AIAUTH_SIGN_HASH",
      hash,
      source: `file:${file.name}`,
      note,
    });
    if (resp && resp.ok) {
      setStatus(`Receipt: ${resp.receipt_code}`, "ok");
      try { await navigator.clipboard.writeText(resp.receipt_code); } catch {}
      renderReceipts();
      renderStats();
    } else {
      setStatus((resp && resp.error) || "Failed", "err");
    }
  } catch (e) {
    setStatus(String(e.message || e), "err");
  } finally {
    drop.classList.remove("busy");
  }
}

function bindFileDrop() {
  const drop = $("drop");
  const picker = $("filePicker");
  if (!drop || !picker) return;
  drop.addEventListener("click", () => picker.click());
  picker.addEventListener("change", () => {
    if (picker.files && picker.files[0]) attestFile(picker.files[0]);
    picker.value = "";
  });
  ["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, (e) => {
    e.preventDefault(); e.stopPropagation(); drop.classList.add("hover");
  }));
  ["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, (e) => {
    e.preventDefault(); e.stopPropagation(); drop.classList.remove("hover");
  }));
  drop.addEventListener("drop", (e) => {
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) attestFile(f);
  });
}

// ---------- Render loop ----------

async function render() {
  const { n, s } = await determineState();
  showState(n);
  if (n === "2" && $("pendingEmail")) {
    $("pendingEmail").textContent = s.pendingEmail;
  }
  if (n === "3" || n === "4") {
    await renderIdentity(s);
    await renderReceipts();
    await renderStats();
  }
  if (n === "3u") {
    // Unverified dashboard — populate the "U" mirror IDs.
    if ($("currentIdentU")) $("currentIdentU").textContent = s.userId;
    if ($("serverU")) $("serverU").value = s.server;
    await renderReceiptsTo("receiptsU");
    await renderStatsTo({ today: "statTodayU", total: "statTotalU", pending: "statPendingU" });
  }
}

// Render receipts into a specific DOM id (so State 3u can reuse the same
// list without colliding with State 3's #receipts div).
async function renderReceiptsTo(targetId) {
  const list = $(targetId);
  if (!list) return;
  const prev = list.id;
  list.id = "receipts";
  try { await renderReceipts(); } finally { list.id = prev; }
}

async function renderStatsTo(ids) {
  const { receipts = [] } = await chrome.storage.local.get("receipts");
  const today = new Date().toISOString().slice(0, 10);
  const todayCount = receipts.filter(r => (r.ts || "").startsWith(today)).length;
  const pending = receipts.filter(r => r.status === "pending").length;
  if ($(ids.today)) $(ids.today).textContent = todayCount;
  if ($(ids.total)) $(ids.total).textContent = receipts.length;
  if ($(ids.pending)) $(ids.pending).textContent = pending;
}

// ---------- Event wiring ----------

document.addEventListener("DOMContentLoaded", async () => {
  // Check managed config first (Phase C.3: enterprise-deployed extensions
  // may force verified flow). If the Workspace admin has pushed a policy,
  // it overrides DEFAULT_SERVER and hides the Start-Attesting button.
  try {
    const managed = await chrome.storage.managed?.get?.(null);
    if (managed && (managed.enterprise_server || managed.org_domain)) {
      await chrome.storage.local.set({
        managedConfig: managed,
        server: managed.enterprise_server || DEFAULT_SERVER,
        tier: managed.tier || "enterprise",
      });
      // In managed mode, hide the unverified path.
      const btn = $("startAttesting");
      if (btn) btn.style.display = "none";
    }
  } catch {}

  // State 1 handlers
  $("onboardStart")?.addEventListener("click", onboardStart);
  $("startAttesting")?.addEventListener("click", startAttesting);
  $("onboardEmail")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") onboardStart(); // Enter defaults to the recommended "Verify" path
  });

  // State 2 handlers
  $("useLink")?.addEventListener("click", verifyPasted);
  $("resendLink")?.addEventListener("click", resendLink);
  $("changeEmail")?.addEventListener("click", changeEmail);

  // State 3/4 handlers
  $("save")?.addEventListener("click", saveSettings);
  $("health")?.addEventListener("click", checkHealth);
  $("logout")?.addEventListener("click", onLogout);
  $("sign")?.addEventListener("click", signManualText);

  // State 3u (unverified) handlers
  $("verifyNow")?.addEventListener("click", (e) => { e.preventDefault(); requestVerificationFromUnverified(); });
  $("signU")?.addEventListener("click", async () => {
    const ta = $("manualU"); if (!ta) return;
    const text = ta.value;
    if (!text.trim()) { setStatus("Paste some text first.", "err"); return; }
    setStatus("Signing…");
    const resp = await chrome.runtime.sendMessage({
      type: "AIAUTH_SIGN_TEXT", text, source: "popup",
    });
    if (resp && resp.ok) {
      setStatus(`Receipt: ${resp.receipt_code}`, "ok");
      try { await navigator.clipboard.writeText(resp.receipt_code); } catch {}
      ta.value = "";
      await render();
    } else {
      setStatus((resp && resp.error) || "Failed", "err");
    }
  });
  $("saveU")?.addEventListener("click", async () => {
    const server = ($("serverU")?.value.trim() || DEFAULT_SERVER).replace(/\/+$/, "");
    await chrome.storage.local.set({ server });
    setStatus("Saved.", "ok");
  });
  $("changeEmailU")?.addEventListener("click", changeEmail);

  // State 5 handler
  $("reauthSend")?.addEventListener("click", async () => {
    const { userId } = await loadSessionState();
    if (!userId) { await changeEmail(); return; }
    setStatus("Sending login link…");
    const r = await callServerJson("/v1/account/auth", { method: "POST", body: { email: userId } });
    if (r.ok) {
      await chrome.storage.local.set({ pendingEmail: userId });
      setStatus("Check your email.", "ok");
      await render();
    } else {
      setStatus("Rate-limited. Try again later.", "err");
    }
  });

  bindFileDrop();
  await render();
});

// Live updates
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.receipts || changes.session || changes.pendingEmail || changes.userId || changes.org || changes.tier) {
    render();
  }
});
