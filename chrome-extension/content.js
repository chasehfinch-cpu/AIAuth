// AIAuth content script — runs on supported AI sites.
// Responsibilities:
//   1. Return the current text selection when asked
//   2. Show a toast with the receipt code after signing
//   3. Copy the receipt code to clipboard

function getSelectionText() {
  const sel = window.getSelection();
  return sel ? sel.toString() : "";
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
    // Fallback
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
    sendResponse({ text: getSelectionText() });
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
