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
# passed.
#
# strict_min_version values: data_collection_permissions (Mozilla's
# built-in data-consent UI, https://mzl.la/firefox-builtin-data-consent)
# requires Firefox 140 desktop and Firefox for Android 142, so we set
# both floors there. Users on older Firefox versions can't install,
# but Firefox 140 was released mid-2025 — current releases as of early
# 2026 are well past that.
#
# data_collection_permissions: AIAuth only sends two things to a server:
# the user's email (magic-link auth) and SHA-256 hashes of content the
# user explicitly attests. Email is authenticationInfo. The hash is
# one-way and not user-specific enough to fit any other category, so
# authenticationInfo is the sole required category.
FIREFOX_GECKO_SETTINGS = {
    "id": "aiauth@aiauth.app",
    "strict_min_version": "140.0",
    "data_collection_permissions": {
        "required": ["authenticationInfo"],
    },
}

# Android-only block; mirrors the desktop gecko settings but with the
# Android-specific minimum version (142 is when data_collection_permissions
# arrived on Firefox for Android).
FIREFOX_GECKO_ANDROID_SETTINGS = {
    "strict_min_version": "142.0",
}


def build_manifest_for(target: str, base: dict) -> bytes:
    """Return the manifest bytes to write into the ZIP for the given target.

    Chrome/Edge: manifest is unmodified.
    Firefox: inject browser_specific_settings.gecko (and gecko_android),
    AND replace the MV3 background block with the legacy `scripts: [...]`
    form. Firefox does not honor `service_worker` and emits a warning if
    it's present alongside `scripts`, so we drop service_worker entirely
    in the Firefox build. The same JS file is used either way.
    Chrome MV3 rejects `scripts` in the background block, so this is
    firefox-only.
    """
    if target == "firefox":
        manifest = dict(base)
        bss = dict(manifest.get("browser_specific_settings", {}))
        bss["gecko"] = dict(FIREFOX_GECKO_SETTINGS)
        bss["gecko_android"] = dict(FIREFOX_GECKO_ANDROID_SETTINGS)
        manifest["browser_specific_settings"] = bss
        bg = dict(manifest.get("background", {}))
        sw = bg.pop("service_worker", None)
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
