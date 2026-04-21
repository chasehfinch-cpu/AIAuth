// AIAuth background service worker
// Handles: hotkey command, context menu, and calls to /v1/sign

const DEFAULT_SERVER = "https://aiauth.app";

async function getConfig() {
  const { server, userId } = await chrome.storage.local.get(["server", "userId"]);
  return {
    server: server || DEFAULT_SERVER,
    userId: userId || "",
  };
}

async function sha256Hex(text) {
  const buf = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function signContent(text, sourceUrl) {
  if (!text || !text.trim()) throw new Error("No text to attest.");
  const output_hash = await sha256Hex(text);
  return signHash(output_hash, sourceUrl || "chrome-extension", null);
}

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
  };
  if (note) body.note = note;

  const res = await fetch(`${server}/v1/sign`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    throw new Error(`Server returned ${res.status}`);
  }
  const data = await res.json();

  // Save receipt locally
  const { receipts = [] } = await chrome.storage.local.get("receipts");
  receipts.unshift({
    id: data.receipt.id,
    code: data.receipt_code,
    hash: output_hash,
    ts: data.receipt.ts,
    source: source || "chrome-extension",
    note: note || null,
    receipt: data.receipt,
    signature: data.signature,
  });
  // Cap stored history
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

// Refresh badge when the service worker wakes up
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
  } catch (e) {
    // notifications permission edge case — swallow
  }
}

async function handleAttest(text, sourceUrl, tabId) {
  try {
    const data = await signContent(text, sourceUrl);
    // Send to content script so it can toast + copy receipt code
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

  // Ask content script for current selection
  try {
    const resp = await chrome.tabs.sendMessage(tab.id, { type: "AIAUTH_GET_SELECTION" });
    const text = (resp && resp.text) || "";
    if (!text) {
      await notify("AIAuth", "Select some AI-generated text first, then press Ctrl+Shift+A.");
      return;
    }
    await handleAttest(text, tab.url, tab.id);
  } catch (e) {
    await notify("AIAuth", "Open a supported AI site (Claude, ChatGPT, Gemini, Copilot) and select text.");
  }
});

// Right-click menu on selected text (created once on install)
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
  await handleAttest(text, tab?.url, tab?.id);
});

// Messages from popup (manual attest, health check)
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "AIAUTH_SIGN_TEXT") {
    handleAttest(msg.text, msg.source || "popup", null).then(sendResponse);
    return true; // async
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
