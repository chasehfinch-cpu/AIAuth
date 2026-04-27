#!/usr/bin/env python3
"""Build a Web-Store-ready ZIP of the AIAuth extension.

By default produces a Chrome / Edge MV3 zip from ``chrome-extension/``:

    python scripts/build-extension-zip.py
    → dist/aiauth-extension-vX.Y.Z.zip

With ``--firefox``, produces a Firefox MV3 zip from the same source by
injecting a ``browser_specific_settings.gecko`` block into the manifest
at zip time. Firefox 109+ supports the ``chrome.*`` namespace as an alias
for ``browser.*``, so the JS is shared verbatim — only the manifest
differs.

    python scripts/build-extension-zip.py --firefox
    → dist/aiauth-extension-firefox-vX.Y.Z.zip

Re-run any time you change the extension. Overwrites the ZIP if present.
"""
from __future__ import annotations

import argparse
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
    # v1.5.0: cross-format chain integrity — canonical-text extractor
    # (plain text / DOCX / XLSX / PPTX) and a minimal PDF text extractor.
    # Same importScripts pattern.
    "canonical_text.js",
    "pdf_text.js",
    "icons/icon16.png",
    "icons/icon48.png",
    "icons/icon128.png",
    # Ship Apache 2.0 license alongside the code so the package is
    # self-contained for forks and security reviewers.
    "LICENSE",
]

# Firefox-specific manifest additions. Injected only when --firefox is
# passed. The id is the AMO listing slug; strict_min_version 121 is the
# first Firefox release with stable MV3 service-worker support.
#
# data_collection_permissions reflects Mozilla's new built-in
# data-consent requirement (https://mzl.la/firefox-builtin-data-consent).
# AIAuth only sends two things to a server: the user's email (magic-link
# auth) and SHA-256 hashes of content the user explicitly attests. Email
# is authenticationInfo. The hash is one-way and not user-specific
# enough to fit any other category, so authenticationInfo is the sole
# required category.
FIREFOX_GECKO_SETTINGS = {
    "id": "aiauth@aiauth.app",
    "strict_min_version": "121.0",
    "data_collection_permissions": {
        "required": ["authenticationInfo"],
    },
}


def build_manifest_for(target: str, base: dict) -> bytes:
    """Return the manifest bytes to write into the ZIP for the given target.

    Chrome/Edge: manifest is unmodified.
    Firefox: inject browser_specific_settings.gecko AND pair the MV3
    service_worker background with a `scripts` fallback so older Firefox
    (and Firefox Android, which doesn't yet support MV3 service workers)
    can still load the extension. Chrome MV3 rejects `scripts` in the
    background block, so this is firefox-only.
    """
    if target == "firefox":
        manifest = dict(base)
        bss = dict(manifest.get("browser_specific_settings", {}))
        bss["gecko"] = dict(FIREFOX_GECKO_SETTINGS)
        manifest["browser_specific_settings"] = bss
        bg = dict(manifest.get("background", {}))
        sw = bg.get("service_worker")
        if sw and "scripts" not in bg:
            bg["scripts"] = [sw]
        manifest["background"] = bg
    else:
        manifest = base
    return json.dumps(manifest, indent=2).encode("utf-8") + b"\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--firefox",
        action="store_true",
        help="Build a Firefox MV3 zip (injects browser_specific_settings.gecko).",
    )
    args = parser.parse_args()

    target = "firefox" if args.firefox else "chrome"

    manifest_path = EXT_DIR / "manifest.json"
    if not manifest_path.exists():
        print(f"ERROR: {manifest_path} not found", file=sys.stderr)
        return 1

    base_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    version = base_manifest.get("version", "0.0.0")

    missing = [rel for rel in INCLUDE if not (EXT_DIR / rel).exists()]
    if missing:
        print("ERROR: files required by manifest are missing:", file=sys.stderr)
        for m in missing:
            print(f"  - {m}", file=sys.stderr)
        return 1

    DIST_DIR.mkdir(exist_ok=True)
    if target == "firefox":
        zip_path = DIST_DIR / f"aiauth-extension-firefox-v{version}.zip"
        upload_url = "https://addons.mozilla.org/developers/"
    else:
        zip_path = DIST_DIR / f"aiauth-extension-v{version}.zip"
        upload_url = "https://chrome.google.com/webstore/devconsole"
    if zip_path.exists():
        zip_path.unlink()

    manifest_bytes = build_manifest_for(target, base_manifest)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in INCLUDE:
            if rel == "manifest.json":
                zf.writestr(rel, manifest_bytes)
            else:
                zf.write(EXT_DIR / rel, arcname=rel)

    size_kb = zip_path.stat().st_size / 1024
    print(f"Built {zip_path.relative_to(REPO_ROOT)}  ({size_kb:.1f} KB, "
          f"{len(INCLUDE)} files, version {version}, target={target})")

    print("\nContents:")
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            print(f"  {info.filename}  ({info.file_size} bytes)")

    print(f"\nReady to upload at {upload_url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
