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

// CLIENT_SECRET is embedded in the extension and rotated per release.
// The server holds a matching value in its env var CLIENT_SECRET.
// Not tamper-proof (determined user can extract) but raises the bar
// for forged metadata. See CLAUDE.md "Metadata Integrity".
const CLIENT_SECRET = "aiauth-ext-v0.5.0-dev-secret-rotate-per-release";

// Per-tab session IDs grouping attestations from the same AI conversation.
// Regenerated on any navigation within a tab.
const tabSessions = {};
chrome.tabs.onUpdated?.addListener((tabId, changeInfo) => {
  if (changeInfo.url) {
    tabSessions[tabId] = (crypto.randomUUID().replace(/-/g, "")).slice(0, 12);
  }
});
chrome.tabs.onRemoved?.addListener((tabId) => { delete tabSessions[tabId]; });
function getTabSessionId(tabId) {
  if (tabId == null) return null;
  if (!tabSessions[tabId]) {
    tabSessions[tabId] = (crypto.randomUUID().replace(/-/g, "")).slice(0, 12);
  }
  return tabSessions[tabId];
}

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

// HMAC-SHA256 over "<version>:<timestamp>:<content_hash>". Server validates
// the same input using CLIENT_SECRET from its env var. Gives us
// client_integrity: "extension" on the signed receipt when valid.
async function clientIntegrityHmac(contentHash, timestamp) {
  const input = `${EXTENSION_VERSION}:${timestamp}:${contentHash}`;
  const keyBytes = new TextEncoder().encode(CLIENT_SECRET);
  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(input));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}

// Destination domain classification from a URL. Returns a spec-level
// category (email/messaging/document-platform/code-repository) or null.
const DEST_HOST_MAP = {
  "mail.google.com": "email",
  "outlook.office.com": "email",
  "outlook.live.com": "email",
  "slack.com": "messaging",
  "app.slack.com": "messaging",
  "teams.microsoft.com": "messaging",
  "discord.com": "messaging",
  "docs.google.com": "document-platform",
  "notion.so": "document-platform",
  "www.notion.so": "document-platform",
  "github.com": "code-repository",
  "gitlab.com": "code-repository",
  "bitbucket.org": "code-repository",
};
function detectDestination(url) {
  try {
    const u = new URL(url);
    for (const [host, kind] of Object.entries(DEST_HOST_MAP)) {
      if (u.hostname === host || u.hostname.endsWith("." + host)) return kind;
    }
  } catch {}
  return null;
}

// Enumerate open tabs that match known AI domains (commercial tier).
async function enumerateConcurrentAIApps() {
  try {
    const tabs = await chrome.tabs.query({});
    const found = new Set();
    for (const tab of tabs) {
      try {
        const host = new URL(tab.url).hostname;
        const match = AI_DOMAINS[host];
        if (match) found.add(`${match.model}-web`);
      } catch {}
    }
    return [...found].sort();
  } catch {
    return [];
  }
}

// Classification heuristic — weak but better than nothing at attest time.
// Returns: "financial" | "legal" | "client-facing" | "internal" | null
function suggestClassification(sourceDomain, fileType, destExt) {
  if (destExt === true) return "client-facing";
  if (fileType === "spreadsheet") return "financial";
  if (fileType === "code") return "internal";
  if (sourceDomain && /legal|compliance/.test(sourceDomain)) return "legal";
  return null;
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

// Build the v0.5.0 sign-request body. Free-tier fields are always
// included. Commercial-only fields (tta, sid, dest, dest_ext,
// classification, concurrent_ai_apps) are ADDED ONLY when tier
// === "enterprise" (CLAUDE.md Integrity Rule #11).
async function buildSignBody({ text, sourceUrl, userId, promptText, tta, tabId }) {
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

  const file_type = detectFileType(sourceUrl || "", text);
  const tier = await getTier();

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
    file_type,
    // Claim "extension" integrity; server validates HMAC and downgrades
    // to "none" if the header is missing/invalid.
    client_integrity: CLIENT_SECRET ? "extension" : "none",
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

  // ---------- Enterprise-tier ONLY fields ----------
  if (tier === "enterprise") {
    if (tta != null) body.tta = tta;
    const sid = getTabSessionId(tabId);
    if (sid) body.sid = sid;

    // Destination detection: what category of app did they paste INTO?
    // Heuristic: if the current tab hostname matches a destination
    // mapping AND is NOT an AI domain, treat the tab as the destination.
    // For browser workflows the destination usually isn't known at
    // attest time (user may paste later), so this is best-effort.
    const destKind = (() => {
      if (AI_DOMAINS[hostname]) return null; // AI tab, not a destination
      return detectDestination(sourceUrl || "");
    })();
    if (destKind) {
      body.dest = destKind;
      // dest_ext: whether destination appears external to the user's org.
      // Without an explicit org-domain config in the browser, we can't
      // determine this reliably. Leave null; Piece 10 will let enterprise
      // clients pre-configure owned domains.
    }

    const classification = suggestClassification(hostname, file_type, null);
    if (classification) body.classification = classification;

    const apps = await enumerateConcurrentAIApps();
    if (apps.length) body.concurrent_ai_apps = apps;
  }

  return body;
}

async function signContent(text, sourceUrl, promptText, tta, tabId) {
  if (!text || !text.trim()) throw new Error("No text to attest.");
  const { server, userId } = await getConfig();
  if (!userId) throw new Error("Set your email/name in the AIAuth popup first.");

  const body = await buildSignBody({ text, sourceUrl, userId, promptText, tta, tabId });

  // Build HMAC headers for client_integrity="extension" validation
  const timestamp = new Date().toISOString();
  const clientHash = await clientIntegrityHmac(body.output_hash, timestamp);

  const res = await fetch(`${server}/v1/sign`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-AIAuth-Client": `chrome-extension/${EXTENSION_VERSION}`,
      "X-AIAuth-Extension-Version": EXTENSION_VERSION,
      "X-AIAuth-Timestamp": timestamp,
      "X-AIAuth-Client-Hash": clientHash,
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
    client_integrity: CLIENT_SECRET ? "extension" : "none",
  };
  if (note) body.note = note;

  const timestamp = new Date().toISOString();
  const clientHash = await clientIntegrityHmac(output_hash, timestamp);

  const res = await fetch(`${server}/v1/sign`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-AIAuth-Client": `chrome-extension/${EXTENSION_VERSION}`,
      "X-AIAuth-Extension-Version": EXTENSION_VERSION,
      "X-AIAuth-Timestamp": timestamp,
      "X-AIAuth-Client-Hash": clientHash,
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

async function handleAttest(text, sourceUrl, tabId, promptText, tta) {
  try {
    const data = await signContent(text, sourceUrl, promptText, tta, tabId);
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
  let tta = null;
  if (tab?.id) {
    try {
      const resp = await chrome.tabs.sendMessage(tab.id, { type: "AIAUTH_GET_SELECTION" });
      promptText = (resp && resp.prompt_text) || null;
      tta = (resp && typeof resp.tta === "number") ? resp.tta : null;
    } catch {}
  }
  await handleAttest(text, tab?.url, tab?.id, promptText, tta);
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
