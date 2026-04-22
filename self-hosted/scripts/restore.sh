#!/usr/bin/env bash
# AIAuth Enterprise — Restore script (Piece 13)
#
# Inverse of backup.sh. Takes a backup archive (optionally encrypted)
# and restores into AIAUTH_HOME. Does NOT touch a running service —
# run `systemctl stop aiauth` BEFORE and `systemctl start aiauth`
# AFTER.
#
# Usage:
#   ./restore.sh /path/to/aiauth-backup.tar.gz
#   ./restore.sh /path/to/aiauth-backup.tar.gz.age --decrypt age
#   ./restore.sh /path/to/aiauth-backup.tar.gz.gpg --decrypt gpg
#   ./restore.sh archive.tar.gz --keys-only       # only restore keys/
#   ./restore.sh archive.tar.gz --db-only         # only aiauth.db
#   ./restore.sh archive.tar.gz --to /custom/path # restore to alt location
#   ./restore.sh archive.tar.gz --dry-run         # show what would restore

set -euo pipefail

AIAUTH_HOME="${AIAUTH_HOME:-/opt/aiauth}"

[[ $# -ge 1 ]] || { echo "Usage: $0 ARCHIVE [--decrypt age|gpg] [--keys-only|--db-only] [--to PATH] [--dry-run]"; exit 1; }
SOURCE="$1"; shift

DECRYPT=""
SCOPE="all"
DEST="$AIAUTH_HOME"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --decrypt) DECRYPT="$2"; shift 2 ;;
    --keys-only) SCOPE="keys"; shift ;;
    --db-only) SCOPE="db"; shift ;;
    --to) DEST="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

log() { echo "[restore $(date -u +%H:%M:%SZ)] $*"; }
die() { echo "ERROR: $*" >&2; exit 2; }

[[ -f "$SOURCE" ]] || die "Archive not found: $SOURCE"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Decrypt if needed
case "$DECRYPT" in
  age)
    command -v age >/dev/null || die "'age' not installed"
    [[ -n "${AGE_IDENTITY_FILE:-}" ]] || die "Set AGE_IDENTITY_FILE=/path/to/key.txt"
    DECRYPTED="$TMP_DIR/archive.tar.gz"
    age -d -i "$AGE_IDENTITY_FILE" -o "$DECRYPTED" "$SOURCE"
    SOURCE="$DECRYPTED"
    log "Decrypted age archive"
    ;;
  gpg)
    command -v gpg >/dev/null || die "'gpg' not installed"
    DECRYPTED="$TMP_DIR/archive.tar.gz"
    gpg --batch --yes --output "$DECRYPTED" --decrypt "$SOURCE"
    SOURCE="$DECRYPTED"
    log "Decrypted GPG archive"
    ;;
  "")
    # Detect by extension
    case "$SOURCE" in
      *.age) die "Archive is .age but --decrypt not specified" ;;
      *.gpg) die "Archive is .gpg but --decrypt not specified" ;;
    esac
    ;;
  *) die "Unknown --decrypt: $DECRYPT (use age or gpg)" ;;
esac

# Peek contents
log "Archive contents:"
tar tzf "$SOURCE" | sed 's/^/  /'

if [[ $DRY_RUN -eq 1 ]]; then
  log "Dry-run — no files modified."
  exit 0
fi

# Extract to staging dir, then move into place
STAGING="$TMP_DIR/staging"
mkdir -p "$STAGING"
tar xzf "$SOURCE" -C "$STAGING"

mkdir -p "$DEST"

case "$SCOPE" in
  all)
    # Move everything in the staging dir over
    for item in "$STAGING"/*; do
      name="$(basename "$item")"
      log "Restoring $name -> $DEST/$name"
      rm -rf "$DEST/$name"
      mv "$item" "$DEST/$name"
    done
    ;;
  keys)
    [[ -d "$STAGING/keys" ]] || die "Archive doesn't contain keys/"
    rm -rf "$DEST/keys"
    mv "$STAGING/keys" "$DEST/keys"
    log "Restored keys/"
    ;;
  db)
    if [[ -f "$STAGING/aiauth.db" ]]; then
      mv "$STAGING/aiauth.db" "$DEST/aiauth.db"
      log "Restored aiauth.db"
    fi
    if [[ -f "$STAGING/aiauth_registry.db" ]]; then
      mv "$STAGING/aiauth_registry.db" "$DEST/aiauth_registry.db"
      log "Restored aiauth_registry.db"
    fi
    ;;
esac

# Enforce permissions on keys
if [[ -d "$DEST/keys" ]]; then
  chmod 700 "$DEST/keys"
  find "$DEST/keys" -type f -name '*.pem' -exec chmod 600 {} \;
fi

log "Done. Start the service: systemctl start aiauth"
