// AIAuth background service worker (v0.5.0)
// Handles: hotkey command, context menu, and calls to /v1/sign.
//
// v0.5.0 additions: populates prompt_hash, model/provider auto-detection,
// source_domain, file_type heuristic, content length, and ai_markers.
// Text hashing is normalized (whitespace collapsed, trimmed) to match
// the server's normalize_text() — see CLAUDE.md "Content Hashing Rules".
//
// Tier gating: this build is free-tier only. Commercial-only fields
// (tta, sid, dest, dest_ext, classification, concurrent_ai_apps) are
// NEVER populated here. Piece 9 will add enterprise-tier capture mode.

const DEFAULT_SERVER = "https://aiauth.app";
const EXTENSION_VERSION = "0.5.0";

// AI domain → {model, provider} map for auto-detection (Feature 1)
const AI_DOMAINS = {
  "claude.ai":              { model: "claude",         provider: "anthropic" },
  "chat.openai.com":        { model: "chatgpt",        provider: "openai" },
  "chatgpt.com":            { model: "chatgpt",        provider: "openai" },
  "gemini.google.com":      { model: "gemini",         provider: "google" },
  "aistudio.google.com":    { model: "gemini",         provider: "google" },
  "copilot.microsoft.com":  { model: "copilot",        provider: "microsoft" },
  "github.com":             { model: "github-copilot", provider: "microsoft" },
  "poe.com":                { model: "poe",            provider: "quora" },
  "perplexity.ai":          { model: "perplexity",     provider: "perplexity" },
  "cursor.sh":              { model: "cursor",         provider: "cursor" },
};

async function getConfig() {
  const { server, userId } = await chrome.storage.local.get(["server", "userId"]);
  return {
    server: server || DEFAULT_SERVER,
    userId: userId || "",
  };
}

// Canonical text normalization: collapse any whitespace runs to single
// space, trim. MUST match server's normalize_text() exactly.
function normalizeText(text) {
  if (text == null) return "";
  return String(text).replace(/\s+/g, " ").trim();
}

async function sha256Hex(text) {
  const buf = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

// Hash text using the normalized rules (used for both content hash and
// prompt hash on browser-originated attestations).
async function hashNormalized(text) {
  return sha256Hex(normalizeText(text));
}

// Lightweight file-type heuristic for browser text attestations.
// Returns one of: spreadsheet, document, presentation, code, snippet, prose.
function detectFileType(url, text) {
  try {
    if (url) {
      const u = new URL(url);
      if (u.hostname.endsWith("docs.google.com")) {
        if (u.pathname.includes("/spreadsheets/")) return "spreadsheet";
        if (u.pathname.includes("/document/"))     return "document";
        if (u.pathname.includes("/presentation/")) return "presentation";
      }
      if (u.hostname.endsWith("github.com") || u.hostname.endsWith("replit.com")) {
        return "code";
      }
    }
  } catch {}
  // Code signals — require 2+ to reduce false positives
  const codeSignals = ["function ", "def ", "class ", "import ", "const ",
                       "return ", "if (", "for (", "while (", "=>", "#!/", "</"];
  const hits = codeSignals.reduce((n, s) => n + (text.includes(s) ? 1 : 0), 0);
  if (hits >= 2) return "code";
  // Length-based fallback
  if (text.length < 200) return "snippet";
  return "prose";
}

// Source-tier detection: free for now. Piece 9 introduces enterprise mode.
async function getTier() {
  const { tier } = await chrome.storage.local.get("tier");
  return tier === "enterprise" ? "enterprise" : "free";
}

// Build the v0.5.0 sign-request body. Fields populated here are free-tier
// fields; commercial-only fields are NEVER added by this build.
async function buildSignBody({ text, sourceUrl, userId, promptText }) {
  const normalized = normalizeText(text);
  const output_hash = await sha256Hex(normalized);

  let hostname = "";
  let model = null, provider = null;
  try {
    if (sourceUrl) {
      const u = new URL(sourceUrl);
      hostname = u.hostname;
      const match = AI_DOMAINS[hostname];
      if (match) { model = match.model; provider = match.provider; }
    }
  } catch {}

  const body = {
    output_hash,
    user_id: userId,
    source: "chrome-extension",
    review_status: "approved",
    reviewer_id: userId,
    register: true,
    // v0.5.0 free-tier fields
    len: normalized.length,
    source_domain: hostname || null,
    source_app: "Google Chrome",
    file_type: detectFileType(sourceUrl || "", text),
    client_integrity: "none", // Piece 6 will upgrade to "extension" with HMAC
  };
  if (model) body.model = model;
  if (provider) body.provider = provider;

  // prompt_hash: if the content script detected a user prompt, hash it
  // with the same normalization rules.
  if (promptText && String(promptText).trim()) {
    body.prompt_hash = await hashNormalized(promptText);
  }

  // ai_markers: browser text attestations cannot inspect file metadata,
  // so we leave this null. Desktop agent populates it on file attests.
  // (Explicitly omitted — server treats absence as null.)

  return body;
}

async function signContent(text, sourceUrl, promptText) {
  if (!text || !text.trim()) throw new Error("No text to attest.");
  const { server, userId } = await getConfig();
  if (!userId) throw new Error("Set your email/name in the AIAuth popup first.");

  const body = await buildSignBody({ text, sourceUrl, userId, promptText });

  const res = await fetch(`${server}/v1/sign`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-AIAuth-Client": `chrome-extension/${EXTENSION_VERSION}`,
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    // Parse v0.5.0 standard error format if present
    try {
      const errJson = await res.json();
      if (errJson && errJson.error) {
        throw new Error(`${errJson.error.code}: ${errJson.error.message}`);
      }
    } catch {}
    throw new Error(`Server returned ${res.status}`);
  }
  const data = await res.json();

  // Save receipt locally — includes the full signed receipt object, which
  // in v0.5.0 carries the extra fields (prompt_hash, etc.)
  const { receipts = [] } = await chrome.storage.local.get("receipts");
  receipts.unshift({
    id: data.receipt.id,
    code: data.receipt_code,
    hash: body.output_hash,
    ts: data.receipt.ts,
    source: "chrome-extension",
    source_domain: body.source_domain,
    prompt_hash: body.prompt_hash || null,
    file_type: body.file_type,
    len: body.len,
    status: "signed",          // Piece 4+ will use "pending" for offline queueing
    receipt: data.receipt,
    signature: data.signature,
  });
  const capped = receipts.slice(0, 500);
  await chrome.storage.local.set({ receipts: capped });
  updateBadge(capped);

  return data;
}

// Manual hash-based signing (for file attestation via popup — no prompt text)
async function signHash(output_hash, source, note) {
  const { server, userId } = await getConfig();
  if (!userId) throw new Error("Set your email/name in the AIAuth popup first.");
  if (!/^[0-9a-f]{64}$/i.test(output_hash)) throw new Error("Invalid hash.");

  const body = {
    output_hash,
    user_id: userId,
    source: source || "chrome-extension",
    review_status: "approved",
    reviewer_id: userId,
    register: true,
    client_integrity: "none",
  };
  if (note) body.note = note;

  const res = await fetch(`${server}/v1/sign`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-AIAuth-Client": `chrome-extension/${EXTENSION_VERSION}`,
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    try {
      const errJson = await res.json();
      if (errJson && errJson.error) {
        throw new Error(`${errJson.error.code}: ${errJson.error.message}`);
      }
    } catch {}
    throw new Error(`Server returned ${res.status}`);
  }
  const data = await res.json();

  const { receipts = [] } = await chrome.storage.local.get("receipts");
  receipts.unshift({
    id: data.receipt.id,
    code: data.receipt_code,
    hash: output_hash,
    ts: data.receipt.ts,
    source: source || "chrome-extension",
    note: note || null,
    status: "signed",
    receipt: data.receipt,
    signature: data.signature,
  });
  const capped = receipts.slice(0, 500);
  await chrome.storage.local.set({ receipts: capped });
  updateBadge(capped);

  return data;
}

function updateBadge(receipts) {
  const todayPrefix = new Date().toISOString().slice(0, 10);
  const todayCount = (receipts || []).filter(r => (r.ts || "").startsWith(todayPrefix)).length;
  const text = todayCount > 0 ? String(todayCount) : "";
  chrome.action.setBadgeText({ text });
  if (text) chrome.action.setBadgeBackgroundColor({ color: "#2563eb" });
}

chrome.runtime.onStartup?.addListener(async () => {
  const { receipts = [] } = await chrome.storage.local.get("receipts");
  updateBadge(receipts);
});
chrome.runtime.onInstalled.addListener(async () => {
  const { receipts = [] } = await chrome.storage.local.get("receipts");
  updateBadge(receipts);
});

async function notify(title, message) {
  try {
    await chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon128.png",
      title,
      message,
    });
  } catch (e) {}
}

async function handleAttest(text, sourceUrl, tabId, promptText) {
  try {
    const data = await signContent(text, sourceUrl, promptText);
    if (tabId) {
      chrome.tabs.sendMessage(tabId, {
        type: "AIAUTH_RESULT",
        ok: true,
        receipt_code: data.receipt_code,
      }).catch(() => {});
    }
    await notify("AIAuth — receipt created", data.receipt_code);
    return { ok: true, receipt_code: data.receipt_code };
  } catch (err) {
    if (tabId) {
      chrome.tabs.sendMessage(tabId, {
        type: "AIAUTH_RESULT",
        ok: false,
        error: String(err.message || err),
      }).catch(() => {});
    }
    await notify("AIAuth — error", String(err.message || err));
    return { ok: false, error: String(err.message || err) };
  }
}

// Hotkey: Ctrl+Shift+A
chrome.commands.onCommand.addListener(async (command) => {
  if (command !== "aiauth-attest") return;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) return;

  try {
    const resp = await chrome.tabs.sendMessage(tab.id, { type: "AIAUTH_GET_SELECTION" });
    const text = (resp && resp.text) || "";
    const promptText = (resp && resp.prompt_text) || null;
    if (!text) {
      await notify("AIAuth", "Select some AI-generated text first, then press Ctrl+Shift+A.");
      return;
    }
    await handleAttest(text, tab.url, tab.id, promptText);
  } catch (e) {
    await notify("AIAuth", "Open a supported AI site (Claude, ChatGPT, Gemini, Copilot) and select text.");
  }
});

// Right-click menu on selected text
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "aiauth-attest-selection",
    title: "Attest selection with AIAuth",
    contexts: ["selection"],
  }, () => void chrome.runtime.lastError);
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "aiauth-attest-selection") return;
  const text = info.selectionText || "";
  // Context menu can't reach the content script synchronously, so try
  // to fetch the last user prompt if the tab has our content script injected.
  let promptText = null;
  if (tab?.id) {
    try {
      const resp = await chrome.tabs.sendMessage(tab.id, { type: "AIAUTH_GET_SELECTION" });
      promptText = (resp && resp.prompt_text) || null;
    } catch {}
  }
  await handleAttest(text, tab?.url, tab?.id, promptText);
});

// Messages from popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "AIAUTH_SIGN_TEXT") {
    handleAttest(msg.text, msg.source || "popup", null, msg.prompt_text || null).then(sendResponse);
    return true;
  }
  if (msg?.type === "AIAUTH_SIGN_HASH") {
    (async () => {
      try {
        const data = await signHash(msg.hash, msg.source || "file", msg.note || null);
        await notify("AIAuth — receipt created", data.receipt_code);
        sendResponse({ ok: true, receipt_code: data.receipt_code });
      } catch (err) {
        sendResponse({ ok: false, error: String(err.message || err) });
      }
    })();
    return true;
  }
  if (msg?.type === "AIAUTH_HEALTH") {
    getConfig().then(async ({ server }) => {
      try {
        const r = await fetch(`${server}/health`);
        const j = await r.json();
        sendResponse({ ok: true, data: j, server });
      } catch (e) {
        sendResponse({ ok: false, error: String(e), server });
      }
    });
    return true;
  }
});
