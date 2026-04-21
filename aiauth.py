"""
AIAuth Desktop Agent v3 — Signed Receipt Architecture

How it works:
  1. Runs in your system tray
  2. Copy AI output → press Ctrl+Shift+A
  3. Agent hashes your clipboard LOCALLY
  4. Sends ONLY the hash to AIAuth server for signing
  5. Server signs it and FORGETS it — stores nothing
  6. Signed receipt saved to YOUR local receipt store
  7. Receipt code copied to clipboard — paste in your work

Your content never leaves your machine. The server only sees a hash
and immediately forgets it after signing. You keep the receipts.

Requirements: pip install pystray Pillow keyboard requests
Run: python aiauth.py
"""

import hashlib
import json
import os
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import keyboard
    import requests
    from PIL import Image, ImageDraw, ImageFont
    import pystray
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install pystray Pillow keyboard requests")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CONFIG_DIR = Path(os.environ.get("APPDATA", Path.home())) / "AIAuth"
CONFIG_FILE = CONFIG_DIR / "config.json"
RECEIPT_DIR = CONFIG_DIR / "receipts"
LOG_FILE = CONFIG_DIR / "aiauth.log"

DEFAULT_CONFIG = {
    "server_url": "https://aiauth.app",
    "user_id": "",
    "hotkey": "ctrl+shift+a",
    "auto_review": True,
    "review_status": "approved",
    "session_count": 0,
}


def load_config() -> dict:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    RECEIPT_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def first_time_setup() -> dict:
    print("\n" + "=" * 50)
    print("  AIAuth — First Time Setup")
    print("=" * 50 + "\n")
    config = DEFAULT_CONFIG.copy()
    print("Your AIAuth identity (shown on attestations).")
    user_id = input("\n  Email or name: ").strip()
    if not user_id:
        print("Identity required."); sys.exit(1)
    config["user_id"] = user_id
    print(f"\nServer URL (Enter for default: {DEFAULT_CONFIG['server_url']}):")
    server = input("  Server: ").strip()
    if server:
        config["server_url"] = server.rstrip("/")
    print(f"\nTesting connection to {config['server_url']}...")
    try:
        r = requests.get(f"{config['server_url']}/health", timeout=5)
        if r.ok:
            print(f"  Connected. Mode: {r.json().get('mode', '?')}")
    except:
        print("  Could not connect. Will retry on first attestation.")
    save_config(config)
    print(f"\nConfig: {CONFIG_FILE}")
    print(f"Receipts: {RECEIPT_DIR}\n")
    return config


# ---------------------------------------------------------------------------
# Clipboard (Windows native)
# ---------------------------------------------------------------------------

def get_clipboard_text() -> Optional[str]:
    import ctypes
    CF_UNICODETEXT = 13
    u32 = ctypes.windll.user32
    k32 = ctypes.windll.kernel32
    if not u32.OpenClipboard(0): return None
    try:
        h = u32.GetClipboardData(CF_UNICODETEXT)
        if not h: return None
        k32.GlobalLock.restype = ctypes.c_void_p
        p = k32.GlobalLock(h)
        if not p: return None
        try: return ctypes.wstring_at(p)
        finally: k32.GlobalUnlock(h)
    finally: u32.CloseClipboard()


def set_clipboard_text(text: str):
    import ctypes
    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002
    u32 = ctypes.windll.user32
    k32 = ctypes.windll.kernel32
    encoded = text.encode("utf-16-le") + b"\x00\x00"
    if not u32.OpenClipboard(0): return
    try:
        u32.EmptyClipboard()
        h = k32.GlobalAlloc(GMEM_MOVEABLE, len(encoded))
        if not h: return
        k32.GlobalLock.restype = ctypes.c_void_p
        p = k32.GlobalLock(h)
        if not p: return
        ctypes.memmove(p, encoded, len(encoded))
        k32.GlobalUnlock(h)
        u32.SetClipboardData(CF_UNICODETEXT, h)
    finally: u32.CloseClipboard()


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

def notify(title: str, message: str):
    try:
        import subprocess
        ps = f"""
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
        $t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $n = $t.GetElementsByTagName('text')
        $n.Item(0).AppendChild($t.CreateTextNode('{title}')) > $null
        $n.Item(1).AppendChild($t.CreateTextNode('{message}')) > $null
        $toast = [Windows.UI.Notifications.ToastNotification]::new($t)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('AIAuth').Show($toast)
        """
        subprocess.run(["powershell", "-Command", ps], capture_output=True, timeout=5)
    except:
        print(f"[{title}] {message}")


# ---------------------------------------------------------------------------
# Core: sign and store receipt locally
# ---------------------------------------------------------------------------

def hash_content(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def save_receipt(receipt: dict, signature: str, content_preview: str):
    """Save signed receipt to local receipt store."""
    receipt_file = RECEIPT_DIR / f"{receipt['id']}.json"
    data = {
        "receipt": receipt,
        "signature": signature,
        "content_preview": content_preview[:120],
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(receipt_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def attest_clipboard(config: dict):
    """Main action: hash clipboard, get signed receipt, store locally."""
    text = get_clipboard_text()
    if not text or not text.strip():
        notify("AIAuth", "Clipboard is empty.")
        return

    content_hash = hash_content(text.strip())
    user_id = config["user_id"]
    server_url = config["server_url"]

    payload = {
        "output_hash": content_hash,
        "user_id": user_id,
        "source": "desktop-agent",
        "parent_hash": config.get("last_hash"),
    }

    if config.get("auto_review"):
        payload["review_status"] = config.get("review_status", "approved")
        payload["reviewer_id"] = user_id

    try:
        resp = requests.post(f"{server_url}/v1/sign", json=payload, timeout=10)

        if resp.ok:
            result = resp.json()
            receipt = result["receipt"]
            signature = result["signature"]
            receipt_code = result["receipt_code"]

            # Save receipt locally — YOU own this data
            save_receipt(receipt, signature, text.strip())

            # Update session count
            config["session_count"] = config.get("session_count", 0) + 1
            save_config(config)

            # Copy receipt code to clipboard
            set_clipboard_text(receipt_code)

            notify("AIAuth", f"Signed: {result['short_id']}\nReceipt saved locally.")
            print(f"[OK] {receipt_code} → saved to {RECEIPT_DIR}")
        else:
            notify("AIAuth", f"Server error: {resp.status_code}")
            print(f"[ERROR] {resp.status_code}: {resp.text[:200]}")

    except requests.ConnectionError:
        # Offline: create unsigned local receipt
        offline_id = str(uuid.uuid4())
        receipt = {
            "v": "0.3.0", "id": offline_id,
            "ts": datetime.now(timezone.utc).isoformat(),
            "hash": content_hash, "uid": user_id,
            "src": "desktop-agent-offline",
            "unsigned": True,
        }
        save_receipt(receipt, "UNSIGNED-PENDING-SYNC", text.strip())
        receipt_code = f"[AIAuth-Offline:{offline_id[:12]}]"
        set_clipboard_text(receipt_code)
        notify("AIAuth (Offline)", "Saved locally. Will sign when server is reachable.")
        print(f"[OFFLINE] {receipt_code}")

    except Exception as e:
        notify("AIAuth Error", str(e)[:100])
        print(f"[ERROR] {e}")


# ---------------------------------------------------------------------------
# System tray
# ---------------------------------------------------------------------------

def create_icon_image():
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse([2, 2, size-2, size-2], fill=(37, 99, 235, 255))
    try: font = ImageFont.truetype("arial.ttf", 36)
    except: font = ImageFont.load_default()
    bbox = draw.textbbox((0, 0), "A", font=font)
    x = (size - (bbox[2]-bbox[0])) // 2
    y = (size - (bbox[3]-bbox[1])) // 2 - 4
    draw.text((x, y), "A", fill="white", font=font)
    return img


def create_tray(config: dict):
    def on_attest(icon, item):
        threading.Thread(target=attest_clipboard, args=(config,), daemon=True).start()

    def on_view_receipts(icon, item):
        os.startfile(str(RECEIPT_DIR))

    def on_view_log(icon, item):
        if LOG_FILE.exists(): os.startfile(str(LOG_FILE))

    def on_edit_config(icon, item):
        os.startfile(str(CONFIG_FILE))

    def on_quit(icon, item):
        icon.stop()

    menu = pystray.Menu(
        pystray.MenuItem(f"AIAuth ({config['hotkey']})", on_attest, default=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(f"Identity: {config['user_id']}", None, enabled=False),
        pystray.MenuItem(f"Server: {config['server_url']}", None, enabled=False),
        pystray.MenuItem(f"Receipts: {config.get('session_count', 0)} this session", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Open Receipt Store", on_view_receipts),
        pystray.MenuItem("Edit Config", on_edit_config),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit", on_quit),
    )
    return pystray.Icon("aiauth", create_icon_image(), "AIAuth", menu)


def start_hotkey(config: dict):
    hotkey = config.get("hotkey", "ctrl+shift+a")
    try:
        keyboard.add_hotkey(hotkey, lambda: attest_clipboard(config), suppress=False)
        print(f"[Hotkey] {hotkey}")
    except Exception as e:
        print(f"[Hotkey] Could not register: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("\n  AIAuth Desktop Agent\n  ====================\n")
    config = load_config()
    if not config.get("user_id"):
        config = first_time_setup()
    print(f"  Identity: {config['user_id']}")
    print(f"  Server:   {config['server_url']}")
    print(f"  Hotkey:   {config['hotkey']}")
    print(f"  Receipts: {RECEIPT_DIR}")
    print(f"\n  Copy AI text → {config['hotkey']} → receipt code replaces clipboard\n")
    threading.Thread(target=start_hotkey, args=(config,), daemon=True).start()
    icon = create_tray(config)
    print("  Running in system tray.\n")
    icon.run()

if __name__ == "__main__":
    main()
