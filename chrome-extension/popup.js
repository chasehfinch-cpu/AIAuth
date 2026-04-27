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
    // v1.3.0 Tier 1: surface time-to-attest on the receipt row. If tta is
    // short and content length is substantial, add a rubber-stamp warning
    // signal (matches the server's policy rule at server.py).
    let ttaBit = "";
    if (typeof r.tta === "number") {
      const rubberStamp = r.tta < 10 && (r.len || 0) > 500;
      ttaBit = ` · ${rubberStamp ? "⚠ " : ""}attested in ${r.tta}s`;
    }
    // v1.4.0: if the receipt carries C2PA claim data, surface the
    // generator name as a small pill so users see at a glance which
    // tool produced the image.
    let c2paBit = "";
    const gen = r.ai_markers && r.ai_markers.c2pa && r.ai_markers.c2pa.claim_generator;
    if (typeof gen === "string" && gen.length) {
      c2paBit = ` · C2PA: ${gen}`;
    }
    meta.textContent = `${fmtTime(r.ts)}${src ? " · " + src : ""}${r.file_type ? " · " + r.file_type : ""}${ttaBit}${c2paBit}`;
    if (typeof r.tta === "number" && r.tta < 10 && (r.len || 0) > 500) {
      meta.style.color = "#b45309"; // amber — matches /check rubber-stamp accent
    }
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
  // polling=true asks the server to register a pending_logins row so we
  // can pick up the session automatically when the user clicks the link
  // on any device (e.g. their phone). The server returns a pending_id
  // we then poll /v1/account/auth/status with.
  return callServerJson("/v1/account/create", {
    method: "POST",
    body: { email, polling: true },
  });
}

async function pollAuthStatus(pendingId) {
  return callServerJson(`/v1/account/auth/status?pending_id=${encodeURIComponent(pendingId)}`);
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
    const pendingId = r.json?.pending_id || "";
    await chrome.storage.local.set({
      pendingEmail: email, userId: email, emailVerified: false,
      pendingLoginId: pendingId,
    });
    setStatus("Check your email.", "ok");
    await render();
    if (pendingId) startLoginPolling(pendingId);
  } else {
    const code = r.json?.error?.code || "UNKNOWN";
    setStatus(`Could not start: ${code}`, "err");
  }
}

// ---------- Cross-device login polling ----------
//
// When the user clicks the magic link on their phone, /v1/account/verify
// stashes the issued session into pending_logins. We poll that endpoint
// every ~4s for up to 15 min. On success, we promote to State 3 and
// stop. Polling also stops on popup close (per-popup-instance var) or
// if the user changes email / logs out.
let _pollHandle = null;

function stopLoginPolling() {
  if (_pollHandle) {
    clearInterval(_pollHandle);
    _pollHandle = null;
  }
}

async function startLoginPolling(pendingId) {
  stopLoginPolling();
  const startedAt = Date.now();
  const POLL_MS = 4000;
  const MAX_MS = 15 * 60 * 1000;
  _pollHandle = setInterval(async () => {
    if (Date.now() - startedAt > MAX_MS) {
      stopLoginPolling();
      await chrome.storage.local.remove("pendingLoginId");
      return;
    }
    let r;
    try { r = await pollAuthStatus(pendingId); } catch { return; }
    if (!r.ok) {
      // 404 PENDING_NOT_FOUND or 429 RATE_LIMITED — give up on 404.
      if (r.status === 404) {
        stopLoginPolling();
        await chrome.storage.local.remove("pendingLoginId");
      }
      return;
    }
    if (r.json?.status === "ready" && r.json.session_token) {
      stopLoginPolling();
      const s = r.json;
      const { pendingEmail } = await loadSessionState();
      await chrome.storage.local.set({
        userId: pendingEmail || s.email || "",
        pendingEmail: "",
        pendingLoginId: "",
        emailVerified: true,
        session: {
          token: s.session_token,
          expires_at: s.expires_at,
          account_id: s.account_id,
          email: pendingEmail || s.email || "",
        },
      });
      await refreshMe();
      setStatus("Verified — welcome back.", "ok");
      await render();
    }
  }, POLL_MS);
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
  setStatus('Ready. Right-click and choose "Attest selection with AIAuth" to attest.', "ok");
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
  const r = await callServerJson("/v1/account/auth", { method: "POST", body: { email, polling: true } });
  if (r.ok) {
    const pendingId = r.json?.pending_id || "";
    if (pendingId) {
      await chrome.storage.local.set({ pendingLoginId: pendingId });
      startLoginPolling(pendingId);
    }
    setStatus("Link sent (if the email exists).", "ok");
  } else {
    setStatus("Rate-limited. Try again later.", "err");
  }
}

async function changeEmail() {
  stopLoginPolling();
  await chrome.storage.local.remove(["pendingEmail", "session", "userId", "org", "pendingLoginId"]);
  await render();
}

async function onLogout() {
  stopLoginPolling();
  const { session } = await loadSessionState();
  if (session && session.token) {
    await logout(session.token);
  }
  // Clear every identity field. Without removing userId + emailVerified,
  // determineState() falls through to State 3 (verified personal tier)
  // and the popup keeps showing the prior user's receipts and a Logout
  // button — the opposite of what Logout should do.
  await chrome.storage.local.remove([
    "session", "pendingEmail", "org", "pendingLoginId",
    "userId", "emailVerified", "tier",
  ]);
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
    // v1.4.0: read the bytes once, then reuse them for both the SHA-256
    // and for C2PA enrichment in the background. Avoids a second read.
    const buf = await file.arrayBuffer();
    const digest = await crypto.subtle.digest("SHA-256", buf);
    const hash = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
    setStatus(`Signing ${file.name}…`);
    const note = `file=${file.name}; size=${file.size}; type=${file.type || "unknown"}`;
    const resp = await chrome.runtime.sendMessage({
      type: "AIAUTH_SIGN_HASH",
      hash,
      source: `file:${file.name}`,
      note,
      // Serialize as plain array for message passing.
      imageBytes: Array.from(new Uint8Array(buf)),
      // v1.5.0: file descriptor for canonical-text dispatch.
      fileDescriptor: { name: file.name, type: file.type, size: file.size },
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

// Wire up one drop-zone + file-picker pair. Factored out so both
// State 3 (verified) and State 3u (unverified) can share the same flow.
function bindDropPair(dropId, pickerId) {
  const drop = $(dropId);
  const picker = $(pickerId);
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

function bindFileDrop() {
  // Bind both the verified (State 3) and unverified (State 3u) drop
  // zones. v1.4.0 fix: previously only State 3 was wired, so unverified
  // users saw the popup bypass the extension and navigate to the file.
  bindDropPair("drop", "filePicker");
  bindDropPair("dropU", "filePickerU");

  // Safety net: if a user drops a file anywhere else in the popup
  // (over the stats strip, the receipt list, etc.), Chrome's default
  // is to navigate away and open the file. Swallow those drops at the
  // window level so the popup stays put.
  ["dragover", "drop"].forEach(ev => {
    window.addEventListener(ev, (e) => {
      // Let nested handlers (on drop / dropU) run first; they stopPropagation.
      // Anything that reaches the window gets a preventDefault so Chrome
      // doesn't hijack the popup.
      e.preventDefault();
    });
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
    const r = await callServerJson("/v1/account/auth", { method: "POST", body: { email: userId, polling: true } });
    if (r.ok) {
      const pendingId = r.json?.pending_id || "";
      await chrome.storage.local.set({ pendingEmail: userId, pendingLoginId: pendingId });
      setStatus("Check your email.", "ok");
      await render();
      if (pendingId) startLoginPolling(pendingId);
    } else {
      setStatus("Rate-limited. Try again later.", "err");
    }
  });

  bindFileDrop();
  await render();

  // Resume cross-device login polling if the popup was closed and re-opened
  // mid-flow. The pending_id is server-scoped and survives popup teardown.
  const { pendingLoginId } = await chrome.storage.local.get("pendingLoginId");
  if (pendingLoginId) startLoginPolling(pendingLoginId);
});

// Live updates
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.receipts || changes.session || changes.pendingEmail || changes.userId || changes.org || changes.tier) {
    render();
  }
});
