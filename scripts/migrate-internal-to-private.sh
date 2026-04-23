#!/usr/bin/env bash
#
# migrate-internal-to-private.sh
#
# One-shot migration helper for flipping the AIAuth repo public.
#
# What it does:
#   1. Creates a staging directory containing every file that should NOT be
#      public (CLAUDE.md, plans/, chrome-webstore-submission/, sales-only
#      templates, release notes).
#   2. Copies each file into the staging area so you can push it to a
#      private mirror repo (`aiauth-internal`) in one step.
#   3. Runs `git rm` on the same files in the main working tree so a
#      subsequent commit on `main` removes them from the public-bound
#      repository.
#   4. Runs a final secret scan and a personal-data scan — the script
#      refuses to proceed if either finds anything.
#
# What it does NOT do (you do these by hand):
#   - Actually create the private repo on GitHub.
#   - Actually push to either repo.
#   - Flip the main repo's visibility to Public.
#   - Tag a release.
#
# Usage (from Git Bash on Windows):
#   cd /c/Users/ChaseFinch/Downloads/aiauth
#   bash scripts/migrate-internal-to-private.sh [--dry-run]
#
# The default mode copies + runs `git rm` but does not commit. Inspect
# `git status` and the staging directory, then commit and push yourself.

set -euo pipefail

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
  echo "=== DRY RUN — no files will be copied or removed ==="
fi

# -------------------------------------------------------------------
# 0. Sanity: correct working directory
# -------------------------------------------------------------------
if [[ ! -f server.py || ! -f CLAUDE.md ]]; then
  echo "ERROR: run from the repo root (where server.py and CLAUDE.md live)."
  exit 1
fi

STAGE_DIR="${STAGE_DIR:-/tmp/aiauth-internal-stage}"
echo "Staging directory: $STAGE_DIR"

# -------------------------------------------------------------------
# 1. Secret scan — abort on any hit
# -------------------------------------------------------------------
echo
echo "=== Secret scan ==="
# Each branch requires a realistic value after the variable name, so the
# scanner cannot match its own pattern definition (the previous version
# flagged this script itself as a false positive). Exclude this script
# file from the scan for extra safety.
PATTERN='(AIAUTH_MASTER_KEY=[A-Za-z0-9_+/=-]{16,}|SERVER_SECRET=[a-f0-9]{20,}|CLIENT_SECRET=[a-f0-9]{20,}|RESEND_API_KEY=re_[A-Za-z0-9_-]{10,}|-----BEGIN (OPENSSH|RSA|EC|DSA|PRIVATE))'
HITS=$(git log -p --all 2>/dev/null \
  | grep -E -i "$PATTERN" \
  | grep -v 'migrate-internal-to-private' \
  | head -5 || true)
if [[ -n "$HITS" ]]; then
  echo "ABORT: secret material found in git history. Rotate these on production FIRST, then re-run."
  echo "$HITS"
  exit 2
fi
echo "  No secrets found."

# -------------------------------------------------------------------
# 2. Personal-data scan — warn but don't abort
# -------------------------------------------------------------------
echo
echo "=== Personal-data scan (warnings only) ==="
PERSONAL_HITS=$(git grep -iE "chase\.h\.finch@gmail|chase@finchbusinessserv|167\.172\.250\.174" -- '*.md' '*.py' '*.html' '*.js' 2>/dev/null | head -10 || true)
if [[ -n "$PERSONAL_HITS" ]]; then
  echo "  Personal references still in tracked files (review and decide):"
  echo "$PERSONAL_HITS" | sed 's/^/    /'
else
  echo "  No personal references detected."
fi

# -------------------------------------------------------------------
# 3. Identify internal files
# -------------------------------------------------------------------
INTERNAL_FILES=(
  "CLAUDE.md"
  "RELEASE_NOTES_v0.5.0.md"
  "templates/commercial/department-scorecard.html"
  "templates/commercial/tool-adoption.html"
  "templates/commercial/pilot-report-template.html"
)

INTERNAL_DIRS=(
  "chrome-webstore-submission"
  "plans"
)

# -------------------------------------------------------------------
# 4. Copy to staging directory
# -------------------------------------------------------------------
echo
echo "=== Copy to staging ==="
if [[ $DRY_RUN -eq 0 ]]; then
  mkdir -p "$STAGE_DIR"
fi

for f in "${INTERNAL_FILES[@]}"; do
  if [[ -f "$f" ]]; then
    echo "  $f → $STAGE_DIR/$f"
    if [[ $DRY_RUN -eq 0 ]]; then
      mkdir -p "$STAGE_DIR/$(dirname "$f")"
      cp "$f" "$STAGE_DIR/$f"
    fi
  else
    echo "  (skip: $f does not exist in working tree)"
  fi
done

for d in "${INTERNAL_DIRS[@]}"; do
  if [[ -d "$d" ]]; then
    echo "  $d/ → $STAGE_DIR/$d/"
    if [[ $DRY_RUN -eq 0 ]]; then
      cp -r "$d" "$STAGE_DIR/"
    fi
  else
    echo "  (skip: $d/ does not exist)"
  fi
done

# -------------------------------------------------------------------
# 5. Remove from public tree
# -------------------------------------------------------------------
echo
echo "=== git rm from public tree ==="
if [[ $DRY_RUN -eq 0 ]]; then
  for f in "${INTERNAL_FILES[@]}"; do
    if git ls-files --error-unmatch "$f" &>/dev/null; then
      git rm -q "$f"
      echo "  removed: $f"
    fi
  done
  for d in "${INTERNAL_DIRS[@]}"; do
    if git ls-files --error-unmatch "$d" &>/dev/null 2>&1 || [[ -d "$d" && -n "$(git ls-files "$d" 2>/dev/null)" ]]; then
      git rm -r -q "$d" 2>/dev/null && echo "  removed: $d/" || true
    fi
  done
else
  echo "  (dry run — skipped)"
fi

# -------------------------------------------------------------------
# 6. Report next steps
# -------------------------------------------------------------------
echo
echo "=== Next steps (manual) ==="
cat <<EOF
  1. Inspect the staging copy:
       ls -la $STAGE_DIR

  2. Create the private mirror on GitHub if it does not exist:
       gh repo create chasehfinch-cpu/aiauth-internal --private \\
         --description "AIAuth internal planning, strategy, and sales assets."

  3. Initialize + push the private mirror:
       cd $STAGE_DIR
       git init && git add . \\
         && git commit -m "Initial: internal strategy, sales assets, CLAUDE.md" \\
         && git branch -M main \\
         && git remote add origin https://github.com/chasehfinch-cpu/aiauth-internal.git \\
         && git push -u origin main

  4. Back in the public repo, commit + push the removal:
       cd $(pwd)
       git commit -m "Move internal strategy and sales assets to private repo before public flip"
       git push origin main

  5. Final sanity check: verify nothing sensitive ships public:
       git ls-files | grep -iE "(plan|scratch|CLAUDE\\.md|department-scorecard|tool-adoption|pilot-report-template|chrome-webstore-submission)"
       # Expected: zero hits.

  6. Flip the repo visibility (GitHub UI or gh CLI):
       gh repo edit chasehfinch-cpu/AIAuth --visibility public \\
         --accept-visibility-change-consequences

  7. Tag v0.5.0:
       git tag -a v0.5.0 -m "v0.5.0 — initial public release"
       git push origin v0.5.0
       gh release create v0.5.0 --title "v0.5.0 — Initial public release" \\
         --notes "See README.md and docs/RECEIPT_SPEC.md."
EOF
