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

This archive accompanies the submitted Firefox extension zip
`aiauth-extension-firefox-v{version}.zip`. A Mozilla AMO reviewer can
use it to reproduce the submitted extension and verify that no
unexpected transformations are applied to the source.

---

## 1. Operating system and build environment

The build runs on any operating system that has a Python 3.10+
interpreter. There are no other system dependencies. Verified on:

- **Windows 11** (Python 3.13 from python.org, Git Bash for the shell)
- **Ubuntu 24.04** (Python 3.12 from `apt install python3`)
- **macOS 14+** (Python 3.13 from python.org or `brew install python@3.13`)

The build script uses only the Python standard library — no `pip
install` step is needed. There is no Node, no npm, no webpack, no
bundler, no transpiler, no minifier.

## 2. Required programs

| Program | Required version | Where to get it |
| ------- | ---------------- | --------------- |
| Python  | 3.10 or newer    | https://www.python.org/downloads/ — pick the latest 3.x installer for your OS. On Linux, your distro's `python3` package (3.10+) works. On macOS, `brew install python@3.13`. |

That is the entire prerequisite list.

## 3. Step-by-step build

From the root of this archive (the directory that contains
`chrome-extension/`, `scripts/`, `LICENSE`, and this README):

```
python scripts/build-extension-zip.py --firefox
```

That single command produces `dist/aiauth-extension-firefox-v{version}.zip`.

If `python` is not on your PATH, try `python3 scripts/build-extension-zip.py --firefox`
on Linux/macOS, or `py -3 scripts\\build-extension-zip.py --firefox` on
Windows.

The script prints a list of every file it placed into the zip. Cross-check
that list against the contents of the submitted extension zip — they
should match exactly.

## 4. Verify the rebuild matches the submission

```
python -c "import zipfile, json; print(json.dumps(json.loads(zipfile.ZipFile('dist/aiauth-extension-firefox-v{version}.zip').read('manifest.json')), indent=2))"
```

The printed manifest must show:

- `manifest_version: 3`
- `version: "{version}"`
- `background.scripts: ["background.js"]` (no `service_worker` key)
- `browser_specific_settings.gecko.id = "aiauth@aiauth.app"`
- `browser_specific_settings.gecko.strict_min_version = "140.0"`
- `browser_specific_settings.gecko.data_collection_permissions.required = ["authenticationInfo"]`
- `browser_specific_settings.gecko_android.strict_min_version = "142.0"`

## 5. What the build script does

The packaging tool (`scripts/build-extension-zip.py`) does only two
things:

1. **Copies** every file listed in its `INCLUDE` array from
   `chrome-extension/` into the output zip, verbatim. No
   transpilation, no minification, no bundling.

2. **Generates the Firefox manifest** by reading
   `chrome-extension/manifest.json` and injecting:

   - `browser_specific_settings.gecko` (id, `strict_min_version` 140.0,
     `data_collection_permissions.required = ["authenticationInfo"]`).
   - `browser_specific_settings.gecko_android.strict_min_version` 142.0.
   - Replaces `background.service_worker` with
     `background.scripts: ["background.js"]` (Firefox does not honor
     `service_worker`, so the legacy `scripts` form is used; the same
     `background.js` file runs either way).

The Chrome/Edge variant (built without `--firefox`) does none of those
injections — that is the only target-specific divergence in the build.

## 6. Source files are not transpiled / concatenated / minified

Every `.js`, `.html`, `.css`, `.json`, and `.png` file inside
`chrome-extension/` is shipped exactly as it appears in this archive.
No third-party libraries are bundled — there are no node_modules, no
vendor/ directory, no `.min.js` files. Two small JS files in
`chrome-extension/` are minimal hand-written implementations of common
parsers (`cbor_decoder.js` for CBOR, `c2pa_parser.js` for C2PA JUMBF).
They are deliberately self-contained and unminified.

## 7. What's in this archive

| Path                                | Purpose |
| ----------------------------------- | ------- |
| `chrome-extension/`                 | Canonical extension source (JS, HTML, CSS, manifest, icons, LICENSE). |
| `scripts/build-extension-zip.py`    | The packaging tool. Pure Python stdlib. |
| `LICENSE`                           | Apache 2.0 license for the entire archive. |
| `SOURCE_BUILD.md`                   | This file. |

The full upstream repository is at
https://github.com/chasehfinch-cpu/AIAuth — this archive is a subset
limited to the files needed to build the Firefox extension. Everything
included here matches that repo's `main` branch verbatim at the time of
submission.
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
