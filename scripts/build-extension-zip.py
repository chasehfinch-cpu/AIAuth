#!/usr/bin/env python3
"""Build a Chrome Web Store-ready ZIP of the AIAuth extension.

Produces ``dist/aiauth-extension-vX.Y.Z.zip`` where the version comes from
``chrome-extension/manifest.json``. The ZIP has ``manifest.json`` at its
root (CWS requirement) and contains only the files the manifest actually
references — no dev scripts, no source artwork, no docs.

Usage (from repo root, on Windows or Unix):

    python scripts/build-extension-zip.py

Re-run any time you change the extension. Overwrites the ZIP if present.
"""
from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXT_DIR = REPO_ROOT / "chrome-extension"
DIST_DIR = REPO_ROOT / "dist"

# Files that ship in the ZIP. Anything outside this allowlist is excluded.
# Keep this list in sync with manifest.json references.
INCLUDE = [
    "manifest.json",
    "background.js",
    "content.js",
    "content.css",
    "popup.html",
    "popup.js",
    "managed_schema.json",
    # v1.4.0: C2PA Tier 2.5 — JUMBF parser and minimal CBOR decoder.
    # Imported into the service worker via importScripts() in background.js.
    "c2pa_parser.js",
    "cbor_decoder.js",
    "icons/icon16.png",
    "icons/icon48.png",
    "icons/icon128.png",
    # Ship Apache 2.0 license alongside the code so the CWS package is
    # self-contained for forks and security reviewers.
    "LICENSE",
]


def main() -> int:
    manifest_path = EXT_DIR / "manifest.json"
    if not manifest_path.exists():
        print(f"ERROR: {manifest_path} not found", file=sys.stderr)
        return 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    version = manifest.get("version", "0.0.0")

    missing = [rel for rel in INCLUDE if not (EXT_DIR / rel).exists()]
    if missing:
        print("ERROR: files required by manifest are missing:", file=sys.stderr)
        for m in missing:
            print(f"  - {m}", file=sys.stderr)
        return 1

    DIST_DIR.mkdir(exist_ok=True)
    zip_path = DIST_DIR / f"aiauth-extension-v{version}.zip"
    if zip_path.exists():
        zip_path.unlink()

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in INCLUDE:
            src = EXT_DIR / rel
            zf.write(src, arcname=rel)

    size_kb = zip_path.stat().st_size / 1024
    print(f"Built {zip_path.relative_to(REPO_ROOT)}  ({size_kb:.1f} KB, "
          f"{len(INCLUDE)} files, version {version})")

    print("\nContents:")
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            print(f"  {info.filename}  ({info.file_size} bytes)")

    print("\nReady to upload at https://chrome.google.com/webstore/devconsole")
    return 0


if __name__ == "__main__":
    sys.exit(main())
