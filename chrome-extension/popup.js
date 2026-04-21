const $ = (id) => document.getElementById(id);
const status = $("status");

function setStatus(msg, kind = "") {
  status.textContent = msg;
  status.className = kind;
  if (msg) setTimeout(() => { if (status.textContent === msg) setStatus(""); }, 4000);
}

function fmtTime(iso) {
  try {
    const d = new Date(iso);
    const now = new Date();
    const diff = (now - d) / 1000;
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
  list.innerHTML = "";
  receipts.slice(0, 10).forEach((r) => {
    const row = document.createElement("div");
    row.className = "rcpt";

    const left = document.createElement("div");
    const code = document.createElement("div");
    code.className = "rcpt-code";
    code.textContent = r.code;
    const meta = document.createElement("div");
    meta.className = "rcpt-meta";
    const src = (() => { try { return new URL(r.source).hostname; } catch { return r.source || ""; } })();
    meta.textContent = `${fmtTime(r.ts)}${src ? " · " + src : ""}`;
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
    copyJson.title = "Copy full signed receipt JSON — paste this at aiauth.app/check";
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

async function loadSettings() {
  const { userId = "", server = "https://aiauth.app" } = await chrome.storage.local.get(["userId", "server"]);
  $("userId").value = userId;
  $("server").value = server;
}

$("save").addEventListener("click", async () => {
  const userId = $("userId").value.trim();
  const server = ($("server").value.trim() || "https://aiauth.app").replace(/\/+$/, "");
  if (!userId) { setStatus("Enter an email or name.", "err"); return; }
  await chrome.storage.local.set({ userId, server });
  setStatus("Saved.", "ok");
});

$("health").addEventListener("click", async () => {
  setStatus("Checking…");
  const resp = await chrome.runtime.sendMessage({ type: "AIAUTH_HEALTH" });
  if (resp?.ok) setStatus(`OK — ${resp.data.service} v${resp.data.version} (${resp.data.mode})`, "ok");
  else setStatus(`Unreachable: ${resp?.error || "unknown"}`, "err");
});

$("sign").addEventListener("click", async () => {
  const text = $("manual").value;
  if (!text.trim()) { setStatus("Paste some text first.", "err"); return; }
  setStatus("Signing…");
  const resp = await chrome.runtime.sendMessage({ type: "AIAUTH_SIGN_TEXT", text, source: "popup" });
  if (resp?.ok) {
    setStatus(`Receipt: ${resp.receipt_code}`, "ok");
    try { await navigator.clipboard.writeText(resp.receipt_code); } catch {}
    $("manual").value = "";
    renderReceipts();
  } else {
    setStatus(resp?.error || "Failed", "err");
  }
});

// File drop zone
async function sha256File(file) {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function attestFile(file) {
  const drop = $("drop");
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
    if (resp?.ok) {
      setStatus(`Receipt: ${resp.receipt_code}`, "ok");
      try { await navigator.clipboard.writeText(resp.receipt_code); } catch {}
      renderReceipts();
    } else {
      setStatus(resp?.error || "Failed", "err");
    }
  } catch (e) {
    setStatus(String(e.message || e), "err");
  } finally {
    drop.classList.remove("busy");
  }
}

const drop = $("drop");
const picker = $("filePicker");
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
  const f = e.dataTransfer?.files?.[0];
  if (f) attestFile(f);
});

// Live-update the receipts list if storage changes while popup is open
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.receipts) renderReceipts();
});

loadSettings();
renderReceipts();
