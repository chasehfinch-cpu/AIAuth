// AIAuth content script — runs on supported AI sites.
// Responsibilities:
//   1. Return the current text selection when asked
//   2. Detect the most recent user prompt on the page (for prompt_hash)
//   3. Show a toast with the receipt code after signing
//   4. Copy the receipt code to clipboard

function getSelectionText() {
  const sel = window.getSelection();
  return sel ? sel.toString() : "";
}

// Detect the most recent user-turn prompt text on the current AI page.
// Returns the inner text of the last user turn, or null if not detectable.
// This runs in the page context so we can read the DOM; the background
// service worker cannot. We only return plain text — no selectors or
// page state are transmitted.
function getLastUserPromptText() {
  const host = location.hostname;
  try {
    // Claude (claude.ai)
    if (host.endsWith("claude.ai")) {
      const els = document.querySelectorAll('[data-testid="user-message"], div[data-test-render-count][class*="font-user"]');
      if (els.length) return els[els.length - 1].innerText || null;
    }
    // ChatGPT (chat.openai.com, chatgpt.com)
    if (host.endsWith("chatgpt.com") || host.endsWith("openai.com")) {
      const els = document.querySelectorAll('[data-message-author-role="user"]');
      if (els.length) return els[els.length - 1].innerText || null;
    }
    // Gemini (gemini.google.com) — user turns have a distinctive container
    if (host.endsWith("google.com")) {
      const els = document.querySelectorAll('user-query, [class*="user-query-container"]');
      if (els.length) return els[els.length - 1].innerText || null;
    }
    // Copilot (copilot.microsoft.com) — user turns use role="user"
    if (host.endsWith("microsoft.com")) {
      const els = document.querySelectorAll('[role="user"], [data-author="user"]');
      if (els.length) return els[els.length - 1].innerText || null;
    }
    // Generic fallback: last <textarea> or contenteditable with visible value
    // (heuristic — not guaranteed to be the actual last submitted prompt)
    const ta = document.querySelector("textarea");
    if (ta && ta.value) return ta.value;
  } catch (e) {
    // DOM access errors — return null (signer will proceed without prompt_hash)
  }
  return null;
}

function showToast(message, isError = false) {
  let toast = document.getElementById("__aiauth_toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "__aiauth_toast";
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  toast.className = isError ? "aiauth-toast aiauth-toast-error show" : "aiauth-toast show";
  clearTimeout(toast._hideTimer);
  toast._hideTimer = setTimeout(() => {
    toast.classList.remove("show");
  }, 4000);
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch {}
    document.body.removeChild(ta);
    return ok;
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "AIAUTH_GET_SELECTION") {
    sendResponse({
      text: getSelectionText(),
      prompt_text: getLastUserPromptText(),
    });
    return;
  }
  if (msg?.type === "AIAUTH_RESULT") {
    if (msg.ok) {
      copyToClipboard(msg.receipt_code).then(copied => {
        showToast(
          copied
            ? `AIAuth receipt ${msg.receipt_code} — copied to clipboard`
            : `AIAuth receipt ${msg.receipt_code}`
        );
      });
    } else {
      showToast(`AIAuth error: ${msg.error}`, true);
    }
  }
});
