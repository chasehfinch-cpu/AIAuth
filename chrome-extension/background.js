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

// v1.4.0: Load the C2PA JUMBF parser + minimal CBOR decoder into the
// service worker scope. Both modules are pure — no DOM access, no
// network — so running them in the background is safe.
try {
  importScripts("c2pa_parser.js", "cbor_decoder.js");
} catch (e) {
  // If a future CWS packaging change breaks the import, log but keep
  // the worker alive. C2PA enrichment will be skipped on every
  // attestation, but regular sign/verify still works.
  console.warn("[AIAuth] C2PA modules failed to load:", e);
}

const DEFAULT_SERVER = "https://aiauth.app";
const EXTENSION_VERSION = "1.4.0";

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

  // Data Depth v1.3.0 Tier 1: populate ai_markers with a minimal AI
  // authorship signal when we detected a known AI domain. File-level
  // signals (C2PA, docProps, PDF XMP) remain deferred to a future tier.
  if (model) {
    body.ai_markers = {
      source: model,
      provider: provider || null,
      verified: true,
    };
  }

  // v1.3.0 Tier 1: tta is a free-tier field now. Previously gated to
  // enterprise only. The server surfaces a rubber-stamp warning on
  // /check when tta < 10 and len > 500.
  if (tta != null) body.tta = tta;

  // ---------- Enterprise-tier ONLY fields ----------
  if (tier === "enterprise") {
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

// ===================================================================
// C2PA enrichment (v1.4.0, Data Depth Tier 2.5)
// ===================================================================
//
// enrichWithC2PA(body, imageBytes) — if the given bytes carry a C2PA
// JUMBF manifest, decode the active manifest's claim and populate
// body.ai_markers.c2pa (canonical location per RECEIPT_SPEC §3.2.1) and
// body.c2pa_manifest_hash (first-class SignRequest field, validated
// server-side since v1.3.0).
//
// Returns the (possibly mutated) body. On any parsing failure (not a
// PNG, no caBX chunk, CBOR subset violation, etc.) returns body
// unchanged — attestation proceeds without C2PA data. Never throws:
// graceful degradation is the contract.
async function enrichWithC2PA(body, imageBytes) {
  if (!imageBytes || !self.AIAuthC2PA || !self.AIAuthCBOR) return body;
  try {
    const u8 = imageBytes instanceof Uint8Array
      ? imageBytes
      : new Uint8Array(imageBytes);
    const jumbf = self.AIAuthC2PA.extractJumbfFromPng(u8);
    if (!jumbf) return body;

    const tree = self.AIAuthC2PA.parseJumbfBoxTree(jumbf);
    const active = self.AIAuthC2PA.activeManifest(tree);
    if (!active) return body;

    // Locate and decode the claim CBOR.
    const claimBox = active.children.find(c => c.label === "c2pa.claim");
    const sigBox = active.children.find(c => c.label === "c2pa.signature");
    if (!claimBox) return body;
    const cborChild = claimBox.children.find(c => c.type === "cbor");
    if (!cborChild) return body;
    const cborBytes = self.AIAuthC2PA.getBoxContentBytes(cborChild, jumbf);

    let claim;
    try {
      claim = self.AIAuthCBOR.decodeCbor(cborBytes);
    } catch (e) {
      // CBOR subset violation — skip enrichment, attest without C2PA.
      return body;
    }

    // SHA-256 the entire JUMBF superbox as the manifest hash. This is
    // the opaque identity used by /v1/verify/file-signals.
    const manifestHash = await self.AIAuthC2PA.sha256Hex(jumbf);

    // Pull out the assertion labels (URLs of the form
    // "self#jumbf=c2pa.assertions/c2pa.hash.data"). Strip the prefix.
    let assertionLabels = [];
    if (Array.isArray(claim.assertions)) {
      assertionLabels = claim.assertions
        .map(a => {
          if (a && typeof a === "object" && typeof a.url === "string") {
            const idx = a.url.lastIndexOf("/");
            return idx >= 0 ? a.url.slice(idx + 1) : a.url;
          }
          return null;
        })
        .filter(x => typeof x === "string" && x.length > 0);
    }

    // Build the c2pa sub-object. Skip fields the claim doesn't supply.
    const c2pa = { manifest_hash: manifestHash };
    if (typeof claim.claim_generator === "string") {
      c2pa.claim_generator = claim.claim_generator;
    }
    if (assertionLabels.length) c2pa.assertions = assertionLabels;
    if (typeof claim.alg === "string") c2pa.alg = claim.alg;
    if (sigBox) c2pa.has_signature = true;

    // Fold into ai_markers.c2pa, preserving any existing ai_markers fields.
    body.ai_markers = body.ai_markers || {};
    body.ai_markers.c2pa = c2pa;

    // Also set the first-class top-level field so server validation and
    // dashboard counters see it. This was shipped in v1.3.0.
    body.c2pa_manifest_hash = manifestHash;

    return body;
  } catch (e) {
    console.warn("[AIAuth] C2PA enrichment failed:", e);
    return body;
  }
}

// Fetch image bytes — try the content script first (page origin, CORS
// friendly for same-origin), fall back to the service worker's fetch.
// Returns Uint8Array on success or null on failure.
async function fetchImageBytes(imageUrl, tabId) {
  if (tabId) {
    try {
      const resp = await chrome.tabs.sendMessage(tabId, {
        type: "AIAUTH_FETCH_IMAGE_BYTES",
        url: imageUrl,
      });
      if (resp && resp.ok && Array.isArray(resp.bytes)) {
        return new Uint8Array(resp.bytes);
      }
    } catch (e) { /* content script not injected — fall through */ }
  }
  try {
    const r = await fetch(imageUrl);
    if (!r.ok) return null;
    return new Uint8Array(await r.arrayBuffer());
  } catch (e) {
    return null;
  }
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
    tta: body.tta != null ? body.tta : null,
    ai_markers: body.ai_markers || null,
    status: "signed",          // Piece 4+ will use "pending" for offline queueing
    receipt: data.receipt,
    signature: data.signature,
  });
  const capped = receipts.slice(0, 500);
  await chrome.storage.local.set({ receipts: capped });
  updateBadge(capped);

  return data;
}

// Manual hash-based signing (for file attestation via popup — no prompt text).
// v1.4.0: accepts an optional imageBytes payload so the popup drag-drop
// and right-click-image paths can surface C2PA data into the receipt.
async function signHash(output_hash, source, note, imageBytes) {
  const { server, userId } = await getConfig();
  if (!userId) throw new Error("Set your email/name in the AIAuth popup first.");
  if (!/^[0-9a-f]{64}$/i.test(output_hash)) throw new Error("Invalid hash.");

  let body = {
    output_hash,
    user_id: userId,
    source: source || "chrome-extension",
    review_status: "approved",
    reviewer_id: userId,
    register: true,
    client_integrity: CLIENT_SECRET ? "extension" : "none",
  };
  if (note) body.note = note;

  // v1.4.0: C2PA Tier 2.5 enrichment — if the caller passed image bytes,
  // probe for a JUMBF manifest and populate ai_markers.c2pa.
  if (imageBytes) {
    body = await enrichWithC2PA(body, imageBytes);
  }

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
    // v1.4.0: carry ai_markers back to the popup so it can render the
    // C2PA pill on the receipt row.
    ai_markers: body.ai_markers || null,
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

// Right-click menus. v1.4.0 adds a second entry for images so users can
// attest any picture (including Firefly / DALL-E / Midjourney output)
// and pick up the C2PA manifest if one is embedded.
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "aiauth-attest-selection",
    title: "Attest selection with AIAuth",
    contexts: ["selection"],
  }, () => void chrome.runtime.lastError);
  chrome.contextMenus.create({
    id: "aiauth-attest-image",
    title: "Attest image with AIAuth",
    contexts: ["image"],
  }, () => void chrome.runtime.lastError);
});

// v1.4.0: handler for right-click image attestation. Fetches bytes,
// hashes them, runs C2PA enrichment, signs.
async function handleAttestImage(imageUrl, tabId) {
  try {
    const bytes = await fetchImageBytes(imageUrl, tabId);
    if (!bytes) {
      await notify(
        "AIAuth — image unreachable",
        "Couldn't fetch the image bytes. Try saving it locally and dragging it onto the popup."
      );
      return { ok: false, error: "image fetch failed" };
    }
    // Hash the raw image bytes as output_hash.
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    const hash = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
    // signHash is the shared signing path used by popup drag-drop too.
    // Passing imageBytes triggers C2PA enrichment inside signHash.
    let source = "image:right-click";
    try {
      const u = new URL(imageUrl);
      source = `image:${u.hostname}`;
    } catch {}
    const data = await signHash(hash, source, `url=${imageUrl.slice(0, 256)}`, bytes);
    await notify("AIAuth — image attested", data.receipt_code);
    return { ok: true, receipt_code: data.receipt_code };
  } catch (err) {
    await notify("AIAuth — error", String(err.message || err));
    return { ok: false, error: String(err.message || err) };
  }
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "aiauth-attest-selection") {
    const text = info.selectionText || "";
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
    return;
  }
  if (info.menuItemId === "aiauth-attest-image") {
    const imageUrl = info.srcUrl || info.linkUrl || info.pageUrl;
    if (!imageUrl) {
      await notify("AIAuth — no image URL", "Could not determine the image to attest.");
      return;
    }
    await handleAttestImage(imageUrl, tab?.id);
    return;
  }
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
        // v1.4.0: popup drag-drop / file-picker path passes imageBytes
        // as a plain array so enrichWithC2PA can probe for a JUMBF
        // manifest without a second read of the file.
        const imageBytes = Array.isArray(msg.imageBytes)
          ? new Uint8Array(msg.imageBytes)
          : null;
        const data = await signHash(msg.hash, msg.source || "file", msg.note || null, imageBytes);
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
