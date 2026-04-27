#!/usr/bin/env python3
"""Build the source-code zip required by Mozilla AMO when the extension
ships with a build step.

AMO asks for the full source code in an uploadable zip whenever the
submitted extension is produced by any tool (even a packaging tool that
doesn't transform the JS). Our packaging tool is
``scripts/build-extension-zip.py`` — it copies files verbatim and
injects a small Firefox-specific manifest block. AMO still wants the
sources in zip form so a reviewer can rebuild from scratch and
byte-compare.

This script produces ``dist/aiauth-extension-firefox-vX.Y.Z-source.zip``
containing exactly what a reviewer needs to reproduce the submitted
Firefox zip:

  - chrome-extension/      (the canonical source — JS, HTML, CSS,
                            manifest, icons, LICENSE)
  - scripts/build-extension-zip.py
                           (the packaging tool itself)
  - LICENSE                (Apache 2.0)
  - SOURCE_BUILD.md        (how-to-reproduce instructions, generated
                            inline so the source zip is fully
                            self-contained)

What's deliberately NOT included: the FastAPI server code (server.py),
tests, plans, deployment scripts, and any other repo content unrelated
to building the extension. AMO only needs to verify the extension zip;
including unrelated source would be both larger and (in the case of
internal docs) potentially leak strategy notes.

Usage:

    python scripts/build-source-zip.py

Re-run after any chrome-extension/ change. Overwrites the zip if present.
"""
from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXT_DIR = REPO_ROOT / "chrome-extension"
DIST_DIR = REPO_ROOT / "dist"
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build-extension-zip.py"
LICENSE_FILE = REPO_ROOT / "LICENSE"

# Files inside chrome-extension/ that ship in the source zip. Same set
# as build-extension-zip.py's INCLUDE list — keep in sync.
CHROME_EXTENSION_FILES = [
    "manifest.json",
    "background.js",
    "content.js",
    "content.css",
    "popup.html",
    "popup.js",
    "managed_schema.json",
    "c2pa_parser.js",
    "cbor_decoder.js",
    "canonical_text.js",
    "pdf_text.js",
    "icons/icon16.png",
    "icons/icon48.png",
    "icons/icon128.png",
    "LICENSE",
]


def build_readme(version: str) -> str:
    return f"""# AIAuth Firefox Extension v{version} — Source Build Instructions

This is the source-code archive that accompanies the submitted Firefox
extension zip (`aiauth-extension-firefox-v{version}.zip`). A Mozilla
AMO reviewer can use it to reproduce the submitted zip byte-for-byte
and verify that no unexpected transformations are applied.

## Prerequisites
- Python 3.10 or newer (no other dependencies — only the standard library
  is used).

## Reproduce the submitted zip

From the root of this archive:

```
python scripts/build-extension-zip.py --firefox
```

This produces `dist/aiauth-extension-firefox-v{version}.zip`.

## What the build script does

The packaging tool (`scripts/build-extension-zip.py`) does only two
things:

1. **Copies** every file listed in its `INCLUDE` array from
   `chrome-extension/` into the output zip, verbatim. No
   transpilation, no minification, no bundling.

2. **Generates the Firefox manifest** by reading
   `chrome-extension/manifest.json` and injecting:

   - `browser_specific_settings.gecko` with the AMO add-on id
     (`aiauth@aiauth.app`), `strict_min_version` 140.0, and
     `data_collection_permissions.required = ["authenticationInfo"]`.
   - `browser_specific_settings.gecko_android.strict_min_version` 142.0.
   - Replaces `background.service_worker` with
     `background.scripts: ["background.js"]` (Firefox does not honor
     `service_worker`, so the legacy `scripts` form is used; the same
     `background.js` file runs either way).

The Chrome/Edge zip variant (built without `--firefox`) does none of
these manifest injections.

## What's in this archive

| Path                                | Purpose |
| ----------------------------------- | ------- |
| `chrome-extension/`                 | Canonical extension source — JS, HTML, CSS, manifest, icons, LICENSE. |
| `scripts/build-extension-zip.py`    | The packaging tool. |
| `LICENSE`                           | Apache 2.0 license for the entire archive. |
| `SOURCE_BUILD.md`                   | This file. |

The full upstream repository is at
https://github.com/chasehfinch-cpu/AIAuth — this archive contains only
the subset of files needed to build the Firefox extension.
"""


def main() -> int:
    manifest_path = EXT_DIR / "manifest.json"
    if not manifest_path.exists():
        print(f"ERROR: {manifest_path} not found", file=sys.stderr)
        return 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    version = manifest.get("version", "0.0.0")

    # Verify all chrome-extension/ files exist.
    missing = [rel for rel in CHROME_EXTENSION_FILES if not (EXT_DIR / rel).exists()]
    if missing:
        print("ERROR: chrome-extension files missing:", file=sys.stderr)
        for m in missing:
            print(f"  - {m}", file=sys.stderr)
        return 1
    if not BUILD_SCRIPT.exists():
        print(f"ERROR: {BUILD_SCRIPT} not found", file=sys.stderr)
        return 1
    if not LICENSE_FILE.exists():
        print(f"ERROR: {LICENSE_FILE} not found", file=sys.stderr)
        return 1

    DIST_DIR.mkdir(exist_ok=True)
    zip_path = DIST_DIR / f"aiauth-extension-firefox-v{version}-source.zip"
    if zip_path.exists():
        zip_path.unlink()

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # chrome-extension/ tree
        for rel in CHROME_EXTENSION_FILES:
            zf.write(EXT_DIR / rel, arcname=f"chrome-extension/{rel}")
        # Build script
        zf.write(BUILD_SCRIPT, arcname="scripts/build-extension-zip.py")
        # Top-level LICENSE
        zf.write(LICENSE_FILE, arcname="LICENSE")
        # Generated build-instructions README
        zf.writestr("SOURCE_BUILD.md", build_readme(version))

    size_kb = zip_path.stat().st_size / 1024
    print(f"Built {zip_path.relative_to(REPO_ROOT)}  ({size_kb:.1f} KB, version {version})")

    print("\nContents:")
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            print(f"  {info.filename}  ({info.file_size} bytes)")

    print("\nUpload this file to AMO when prompted for the extension's source code.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
