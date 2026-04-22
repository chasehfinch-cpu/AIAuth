"""
AIAuth Desktop Agent v0.5.0 — Signed Receipt Architecture

How it works:
  1. Runs in your system tray
  2. Copy AI output → press Ctrl+Shift+A
  3. Agent hashes your clipboard LOCALLY (normalized)
  4. Sends ONLY the hash and free-tier metadata to AIAuth server
  5. Server signs it and FORGETS it — stores nothing about free users
  6. Signed receipt saved to YOUR local receipt store
  7. Receipt code copied to clipboard — paste in your work

Your content never leaves your machine. Prompt text (if detected)
is hashed locally; only the hash is transmitted. On the free tier,
behavioral fields (tta/sid/dest/classification/concurrent_ai_apps)
are NEVER populated.

File attestation: run  python aiauth.py --attest-file "C:\\path\\to\\file"
This reads the file, detects AI authorship markers (Copilot docProps,
ChatGPT PDF producer strings, C2PA manifests), and creates a receipt.

Requirements: pip install pystray Pillow keyboard requests
Optional (enable features): pip install psutil pikepdf python-docx openpyxl c2pa-python

Run: python aiauth.py
"""

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any

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

AGENT_VERSION = "0.5.0"
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
    # v0.5.0 addition: tier gating. "free" or "enterprise". Enterprise
    # deployments should pre-populate this via MSI/Intune config.
    "tier": "free",
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
            data = r.json()
            print(f"  Connected. Mode: {data.get('mode', '?')} | Server version: {data.get('version', '?')}")
    except Exception:
        print("  Could not connect. Will retry on first attestation.")
    save_config(config)
    print(f"\nConfig: {CONFIG_FILE}")
    print(f"Receipts: {RECEIPT_DIR}\n")
    return config


# ---------------------------------------------------------------------------
# Canonical text normalization — MUST match server's normalize_text().
# Clipboard and prompt text are normalized before hashing so that
# equivalent text (differing only in whitespace) produces the same hash
# on client and server.
# ---------------------------------------------------------------------------

_WS_RE = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    if text is None:
        return ""
    return _WS_RE.sub(" ", text).strip()


def hash_normalized(text: str) -> str:
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Windows-native helpers: clipboard, active window, notifications
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


def get_active_window_title() -> str:
    """Windows ForegroundWindow title. Returns empty string on failure.
    Safe to call — swallows all exceptions."""
    try:
        import ctypes
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
        if not length:
            return ""
        buf = ctypes.create_unicode_buffer(length + 1)
        ctypes.windll.user32.GetWindowTextW(hwnd, buf, length + 1)
        return buf.value or ""
    except Exception:
        return ""


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
    except Exception:
        print(f"[{title}] {message}")


# ---------------------------------------------------------------------------
# AI model / provider auto-detection from active window title (Feature 1)
# ---------------------------------------------------------------------------

AI_PATTERNS = [
    ("claude",     ("claude", "anthropic")),
    ("chatgpt",    ("chatgpt", "openai")),
    ("openai",     ("chatgpt", "openai")),
    ("copilot",    ("copilot", "microsoft")),
    ("gemini",     ("gemini", "google")),
    ("cursor",     ("cursor", "cursor")),
    ("perplexity", ("perplexity", "perplexity")),
    ("poe",        ("poe", "quora")),
]


def detect_model_from_title(title: str) -> Tuple[Optional[str], Optional[str]]:
    low = (title or "").lower()
    for pattern, (model, provider) in AI_PATTERNS:
        if pattern in low:
            return model, provider
    return None, None


# ---------------------------------------------------------------------------
# File type detection + magic bytes validation (Feature 4)
# ---------------------------------------------------------------------------

FILE_TYPES = {
    ".xlsx": "spreadsheet", ".csv": "spreadsheet", ".xls": "spreadsheet",
    ".docx": "document", ".doc": "document",
    ".pdf": "pdf",
    ".pptx": "presentation", ".ppt": "presentation",
    ".py": "code", ".js": "code", ".ts": "code", ".java": "code",
    ".cpp": "code", ".c": "code", ".go": "code", ".rs": "code",
    ".rb": "code", ".php": "code", ".sh": "code", ".ps1": "code",
    ".jpg": "image", ".jpeg": "image", ".png": "image",
    ".svg": "image", ".gif": "image", ".webp": "image", ".tiff": "image",
    ".md": "text", ".txt": "text", ".rtf": "text",
    ".json": "data", ".xml": "data", ".yaml": "data", ".yml": "data",
}

MAGIC_BYTES = [
    (b"%PDF",      "pdf"),
    (b"\x89PNG",   "image"),
    (b"\xff\xd8",  "image"),  # JPEG
    (b"GIF8",      "image"),
    (b"PK\x03\x04", None),    # ZIP-based: xlsx/docx/pptx — trust extension
]


def detect_file_type(filepath: Path) -> str:
    ext = filepath.suffix.lower()
    ext_type = FILE_TYPES.get(ext, "unknown")
    try:
        with open(filepath, "rb") as f:
            header = f.read(8)
        for magic, magic_type in MAGIC_BYTES:
            if header.startswith(magic):
                if magic_type is not None and ext_type != magic_type and ext_type != "unknown":
                    # Extension claims one thing, magic bytes say another — trust bytes
                    return magic_type
                break
    except Exception:
        pass
    return ext_type


# ---------------------------------------------------------------------------
# AI authorship marker detection (free tier, file attestations)
# Reads file metadata to detect Copilot / ChatGPT / C2PA markers.
# All library imports are optional — missing libs silently disable
# that format's detection.
# ---------------------------------------------------------------------------

def detect_ai_markers(filepath: Path) -> Optional[Dict[str, Any]]:
    ext = filepath.suffix.lower()
    try:
        if ext == ".pdf":
            try:
                import pikepdf
                with pikepdf.open(str(filepath)) as pdf:
                    info = pdf.docinfo or {}
                    producer = str(info.get("/Producer", ""))
                    creator = str(info.get("/Creator", ""))
                    combined = (producer + " " + creator).lower()
                    if "chatgpt" in combined or "openai" in combined:
                        return {"source": "pdf-chatgpt", "verified": True}
                    if "claude" in combined or "anthropic" in combined:
                        return {"source": "pdf-claude", "verified": True}
                    if "gemini" in combined or "bard" in combined:
                        return {"source": "pdf-gemini", "verified": True}
                    if "copilot" in combined:
                        return {"source": "pdf-copilot", "verified": True}
            except ImportError:
                pass
        elif ext == ".docx":
            try:
                from docx import Document
                doc = Document(str(filepath))
                props_blob = " ".join(
                    str(getattr(doc.core_properties, a, ""))
                    for a in dir(doc.core_properties)
                    if not a.startswith("_")
                ).lower()
                if "copilot" in props_blob:
                    return {"source": "docx-copilot", "verified": True}
            except ImportError:
                pass
        elif ext == ".xlsx":
            try:
                from openpyxl import load_workbook
                wb = load_workbook(filepath, read_only=True)
                cp = getattr(wb, "custom_doc_props", None)
                if cp:
                    for prop in getattr(cp, "props", []):
                        nm = (getattr(prop, "name", "") or "").lower()
                        if "copilot" in nm or "ai.model" in nm or "aicontent" in nm:
                            return {"source": "xlsx-copilot", "verified": True}
            except ImportError:
                pass
        elif ext == ".pptx":
            try:
                from pptx import Presentation
                prs = Presentation(str(filepath))
                props_blob = " ".join(
                    str(getattr(prs.core_properties, a, ""))
                    for a in dir(prs.core_properties)
                    if not a.startswith("_")
                ).lower()
                if "copilot" in props_blob:
                    return {"source": "pptx-copilot", "verified": True}
            except ImportError:
                pass
        elif ext in (".jpg", ".jpeg", ".png", ".tiff", ".webp"):
            try:
                import c2pa  # type: ignore
                manifest = c2pa.read_file(str(filepath))  # type: ignore[attr-defined]
                if manifest:
                    # c2pa-python API varies; we record presence conservatively
                    valid = getattr(manifest, "is_valid", lambda: True)()
                    return {"source": "c2pa", "verified": bool(valid)}
            except ImportError:
                pass
            except Exception:
                pass
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Concurrent AI app enumeration (commercial tier ONLY)
# Uses an allowlist — unknown processes never recorded.
# See CLAUDE.md Integrity Rule #13.
# ---------------------------------------------------------------------------

AI_PROCESS_ALLOWLIST = {
    "ChatGPT.exe":      "chatgpt-desktop",
    "Claude.exe":       "claude-desktop",
    "Cursor.exe":       "cursor",
    "Copilot.exe":      "copilot-desktop",
    "Perplexity.exe":   "perplexity-desktop",
    "Poe.exe":          "poe-desktop",
}


def enumerate_concurrent_ai_apps() -> List[str]:
    """Allowlisted AI process enumeration. Returns sorted list of
    canonical identifiers for any running AI apps. Empty list if psutil
    is unavailable (feature silently disabled)."""
    try:
        import psutil
    except ImportError:
        return []
    found = set()
    try:
        for proc in psutil.process_iter(["name"]):
            name = (proc.info.get("name") or "")
            if name in AI_PROCESS_ALLOWLIST:
                found.add(AI_PROCESS_ALLOWLIST[name])
    except Exception:
        pass
    return sorted(found)


# ---------------------------------------------------------------------------
# Prompt detection from clipboard (heuristic, best-effort)
# If clipboard contains a recognizable Q/A separator, treat the portion
# before it as the prompt and the portion after as the output. Otherwise
# return (None, content) and let the caller treat the whole clipboard
# as the output with no prompt_hash.
# ---------------------------------------------------------------------------

_PROMPT_SEPARATORS = [
    r"\n-{3,}\s*(?:prompt|output|answer|response)\s*-{3,}\n",
    r"\n\s*A:\s+",
    r"\n\s*ANSWER:\s+",
    r"\n\s*RESPONSE:\s+",
]


def split_prompt_and_output(text: str) -> Tuple[Optional[str], str]:
    for sep in _PROMPT_SEPARATORS:
        m = re.search(sep, text, flags=re.IGNORECASE)
        if m:
            return text[:m.start()].strip(), text[m.end():].strip()
    return None, text


# ---------------------------------------------------------------------------
# Payload builder — respects tier gating
# Free tier: only free-tier fields populated.
# Enterprise tier: commercial fields (tta, sid, dest, dest_ext,
# classification, concurrent_ai_apps) added.
# ---------------------------------------------------------------------------

def build_sign_payload(
    content_hash: str,
    config: dict,
    *,
    source: str,
    source_app: Optional[str] = None,
    prompt_text: Optional[str] = None,
    file_type: Optional[str] = None,
    content_length: Optional[int] = None,
    ai_markers: Optional[Dict[str, Any]] = None,
    parent_hash: Optional[str] = None,
    doc_id: Optional[str] = None,
) -> dict:
    tier = config.get("tier", "free")
    user_id = config["user_id"]

    # Feature 1: model/provider from active window title
    window_title = source_app or get_active_window_title()
    model, provider = detect_model_from_title(window_title)

    payload: Dict[str, Any] = {
        "output_hash": content_hash,
        "user_id": user_id,
        "source": source,
        "client_integrity": "none",  # Piece 6 upgrades to os-verified with agent signing
        "register": True,
    }

    if config.get("auto_review"):
        payload["review_status"] = config.get("review_status", "approved")
        payload["reviewer_id"] = user_id

    if parent_hash:
        payload["parent_hash"] = parent_hash
    if doc_id:
        payload["doc_id"] = doc_id
    if model:
        payload["model"] = model
    if provider:
        payload["provider"] = provider
    if window_title:
        payload["source_app"] = window_title
    if file_type:
        payload["file_type"] = file_type
    if content_length is not None:
        payload["len"] = content_length
    if ai_markers:
        payload["ai_markers"] = ai_markers
    if prompt_text and prompt_text.strip():
        payload["prompt_hash"] = hash_normalized(prompt_text)

    # Commercial-tier fields — ONLY populated when tier == "enterprise".
    # See CLAUDE.md Tier Gating section and Integrity Rule #11.
    if tier == "enterprise":
        apps = enumerate_concurrent_ai_apps()
        if apps:
            payload["concurrent_ai_apps"] = apps
        # tta/sid/dest/dest_ext/classification are future additions that
        # require timing/IPC infrastructure not yet present in the agent.
        # Piece 9 will complete the enterprise capture surface.

    return payload


# ---------------------------------------------------------------------------
# Server communication
# ---------------------------------------------------------------------------

def post_sign(payload: dict, server_url: str, timeout: int = 10) -> requests.Response:
    return requests.post(
        f"{server_url}/v1/sign",
        json=payload,
        headers={
            "Content-Type": "application/json",
            "X-AIAuth-Client": f"desktop-agent/{AGENT_VERSION}",
        },
        timeout=timeout,
    )


def format_server_error(resp: requests.Response) -> str:
    """Render v0.5.0 standard error format or legacy response as a string."""
    try:
        j = resp.json()
        if isinstance(j, dict) and "error" in j and isinstance(j["error"], dict):
            e = j["error"]
            msg = f"{e.get('code', 'ERROR')}: {e.get('message', '')}"
            details = e.get("details") or {}
            if details:
                msg += f" ({json.dumps(details)})"
            return msg
    except Exception:
        pass
    return f"HTTP {resp.status_code}: {resp.text[:200]}"


# ---------------------------------------------------------------------------
# Receipt storage
# ---------------------------------------------------------------------------

def save_receipt(receipt: dict, signature: str, content_preview: str):
    receipt_file = RECEIPT_DIR / f"{receipt['id']}.json"
    data = {
        "receipt": receipt,
        "signature": signature,
        "content_preview": content_preview[:120],
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "status": "signed" if signature and signature != "UNSIGNED-PENDING-SYNC" else "pending",
    }
    with open(receipt_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ---------------------------------------------------------------------------
# Attestation flows
# ---------------------------------------------------------------------------

def attest_clipboard(config: dict):
    """Clipboard-text attestation (browser text paste, chat output, etc.)."""
    raw = get_clipboard_text()
    if not raw or not raw.strip():
        notify("AIAuth", "Clipboard is empty.")
        return

    # Heuristic prompt/output split
    prompt_text, output_text = split_prompt_and_output(raw)
    normalized = normalize_text(output_text)
    content_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    payload = build_sign_payload(
        content_hash,
        config,
        source="desktop-agent",
        prompt_text=prompt_text,
        content_length=len(normalized),
        parent_hash=config.get("last_hash"),
    )

    server_url = config["server_url"]
    try:
        resp = post_sign(payload, server_url)
        if resp.ok:
            result = resp.json()
            receipt = result["receipt"]
            signature = result["signature"]
            receipt_code = result["receipt_code"]
            save_receipt(receipt, signature, output_text.strip())
            config["session_count"] = config.get("session_count", 0) + 1
            save_config(config)
            set_clipboard_text(receipt_code)
            short_id = result.get("short_id") or receipt["id"][:12]
            notify("AIAuth", f"Signed: {short_id}\nReceipt saved locally.")
            print(f"[OK] {receipt_code} → saved to {RECEIPT_DIR}")
        elif resp.status_code == 409:
            # Duplicate — the client likely has the original receipt cached.
            err = resp.json().get("error", {})
            existing_id = (err.get("details") or {}).get("existing_receipt_id", "?")
            notify("AIAuth", f"Already attested recently (id {existing_id[:12]}).")
            print(f"[DEDUP] {format_server_error(resp)}")
        else:
            msg = format_server_error(resp)
            notify("AIAuth", f"Server error: {msg[:80]}")
            print(f"[ERROR] {msg}")
    except requests.ConnectionError:
        offline_id = str(uuid.uuid4())
        receipt = {
            "v": AGENT_VERSION,
            "id": offline_id,
            "ts": datetime.now(timezone.utc).isoformat(),
            "hash": content_hash,
            "uid": config["user_id"],
            "src": "desktop-agent-offline",
            "unsigned": True,
            "len": len(normalized),
        }
        save_receipt(receipt, "UNSIGNED-PENDING-SYNC", output_text.strip())
        receipt_code = f"[AIAuth-Offline:{offline_id[:12]}]"
        set_clipboard_text(receipt_code)
        notify("AIAuth (Offline)", "Saved locally. Will sign when server is reachable.")
        print(f"[OFFLINE] {receipt_code}")
    except Exception as e:
        notify("AIAuth Error", str(e)[:100])
        print(f"[ERROR] {e}")


def attest_file(filepath_str: str, config: dict):
    """File attestation entry point (invoked by --attest-file CLI)."""
    filepath = Path(filepath_str)
    if not filepath.exists() or not filepath.is_file():
        notify("AIAuth", f"File not found: {filepath_str}")
        print(f"[ERROR] Not a file: {filepath_str}")
        return

    # Files are hashed RAW (no normalization) per CLAUDE.md Content Hashing Rules.
    with open(filepath, "rb") as f:
        raw_bytes = f.read()
    content_hash = hash_bytes(raw_bytes)

    file_type = detect_file_type(filepath)
    ai_markers = detect_ai_markers(filepath)

    payload = build_sign_payload(
        content_hash,
        config,
        source="desktop-agent-file",
        source_app=filepath.name,
        file_type=file_type,
        content_length=filepath.stat().st_size,
        ai_markers=ai_markers,
    )

    server_url = config["server_url"]
    try:
        resp = post_sign(payload, server_url, timeout=20)
        if resp.ok:
            result = resp.json()
            save_receipt(result["receipt"], result["signature"], f"FILE: {filepath.name}")
            receipt_code = result["receipt_code"]
            set_clipboard_text(receipt_code)
            short_id = result.get("short_id") or result["receipt"]["id"][:12]
            markers_note = f" (marker: {ai_markers['source']})" if ai_markers else ""
            notify("AIAuth", f"File signed: {short_id}{markers_note}")
            print(f"[OK] {receipt_code} — {filepath.name}{markers_note}")
        elif resp.status_code == 409:
            err = resp.json().get("error", {})
            existing_id = (err.get("details") or {}).get("existing_receipt_id", "?")
            notify("AIAuth", f"File already attested recently (id {existing_id[:12]}).")
            print(f"[DEDUP] {format_server_error(resp)}")
        else:
            msg = format_server_error(resp)
            notify("AIAuth File Error", msg[:80])
            print(f"[ERROR] {msg}")
    except requests.ConnectionError:
        offline_id = str(uuid.uuid4())
        receipt = {
            "v": AGENT_VERSION,
            "id": offline_id,
            "ts": datetime.now(timezone.utc).isoformat(),
            "hash": content_hash,
            "uid": config["user_id"],
            "src": "desktop-agent-file-offline",
            "unsigned": True,
            "file_type": file_type,
        }
        if ai_markers:
            receipt["ai_markers"] = ai_markers
        save_receipt(receipt, "UNSIGNED-PENDING-SYNC", f"FILE: {filepath.name}")
        receipt_code = f"[AIAuth-Offline:{offline_id[:12]}]"
        set_clipboard_text(receipt_code)
        notify("AIAuth (Offline)", f"File saved locally: {filepath.name}")
        print(f"[OFFLINE] {receipt_code}")
    except Exception as e:
        notify("AIAuth File Error", str(e)[:100])
        print(f"[ERROR] {e}")


# ---------------------------------------------------------------------------
# System tray UI
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

    def on_edit_config(icon, item):
        os.startfile(str(CONFIG_FILE))

    def on_quit(icon, item):
        icon.stop()

    tier_label = f"Tier: {config.get('tier', 'free')}"
    menu = pystray.Menu(
        pystray.MenuItem(f"AIAuth ({config['hotkey']})", on_attest, default=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(f"Identity: {config['user_id']}", None, enabled=False),
        pystray.MenuItem(f"Server: {config['server_url']}", None, enabled=False),
        pystray.MenuItem(tier_label, None, enabled=False),
        pystray.MenuItem(f"Receipts: {config.get('session_count', 0)} this session", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Open Receipt Store", on_view_receipts),
        pystray.MenuItem("Edit Config", on_edit_config),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit", on_quit),
    )
    return pystray.Icon("aiauth", create_icon_image(), f"AIAuth {AGENT_VERSION}", menu)


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

def parse_args():
    p = argparse.ArgumentParser(description=f"AIAuth Desktop Agent v{AGENT_VERSION}")
    p.add_argument("--attest-file", metavar="PATH", help="Attest a file and exit (no tray).")
    p.add_argument("--version", action="version", version=f"AIAuth Desktop Agent v{AGENT_VERSION}")
    return p.parse_args()


def main():
    args = parse_args()
    config = load_config()

    # File attestation mode — run once and exit.
    if args.attest_file:
        if not config.get("user_id"):
            print("AIAuth is not configured. Run the agent once to set your identity.")
            sys.exit(1)
        attest_file(args.attest_file, config)
        return

    # Normal tray mode
    print(f"\n  AIAuth Desktop Agent v{AGENT_VERSION}\n  =========================\n")
    if not config.get("user_id"):
        config = first_time_setup()
    print(f"  Identity: {config['user_id']}")
    print(f"  Server:   {config['server_url']}")
    print(f"  Tier:     {config.get('tier', 'free')}")
    print(f"  Hotkey:   {config['hotkey']}")
    print(f"  Receipts: {RECEIPT_DIR}")
    print(f"\n  Copy AI text → {config['hotkey']} → receipt code replaces clipboard\n")
    threading.Thread(target=start_hotkey, args=(config,), daemon=True).start()
    icon = create_tray(config)
    print("  Running in system tray.\n")
    icon.run()


if __name__ == "__main__":
    main()
