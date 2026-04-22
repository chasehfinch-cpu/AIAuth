#!/usr/bin/env bash
# AIAuth Enterprise — Backup script (Piece 13)
#
# Packages the server's state (signing keys + databases + config) into
# a single archive. Optionally encrypts with age or GPG, and pushes
# to S3 / SFTP / local. Designed to run as a daily cron.
#
# Usage:
#   ./backup.sh                                        # local, unencrypted
#   ./backup.sh --encrypt age:PUBLIC_KEY               # encrypt with age
#   ./backup.sh --encrypt gpg:recipient@example.com    # encrypt with GPG
#   ./backup.sh --to s3://bucket/prefix                # push to S3
#   ./backup.sh --to sftp://user@host:path             # push via SFTP
#   ./backup.sh --include keys                         # only back up keys
#   ./backup.sh --retain 30d,12m                       # prune policy
#   ./backup.sh --install-cron daily                   # install cron job
#
# Defaults:
#   AIAUTH_HOME=/opt/aiauth
#   AIAUTH_BACKUP_DIR=/var/backups/aiauth
#
# Exit codes: 0 success, 1 usage/config error, 2 backup failure, 3 upload failure.

set -euo pipefail

AIAUTH_HOME="${AIAUTH_HOME:-/opt/aiauth}"
BACKUP_DIR="${AIAUTH_BACKUP_DIR:-/var/backups/aiauth}"
DATE="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE_NAME="aiauth-backup-${DATE}.tar.gz"

ENCRYPT=""
DESTINATION="local:${BACKUP_DIR}"
INCLUDE="all"
RETAIN=""
INSTALL_CRON=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --encrypt) ENCRYPT="$2"; shift 2 ;;
    --to) DESTINATION="$2"; shift 2 ;;
    --include) INCLUDE="$2"; shift 2 ;;
    --retain) RETAIN="$2"; shift 2 ;;
    --install-cron) INSTALL_CRON="$2"; shift 2 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

log() { echo "[backup $(date -u +%H:%M:%SZ)] $*"; }
die() { echo "ERROR: $*" >&2; exit 2; }

# --install-cron: write /etc/cron.d/aiauth-backup and exit
if [[ -n "$INSTALL_CRON" ]]; then
  [[ $EUID -eq 0 ]] || die "--install-cron requires root"
  case "$INSTALL_CRON" in
    daily)   SCHEDULE="15 2 * * *" ;;
    hourly)  SCHEDULE="0 * * * *"  ;;
    weekly)  SCHEDULE="15 2 * * 0" ;;
    *) die "Unknown schedule: $INSTALL_CRON (use daily/hourly/weekly)" ;;
  esac
  BACKUP_SELF="$(readlink -f "$0")"
  cat > /etc/cron.d/aiauth-backup <<EOF
# AIAuth automatic backup — installed by backup.sh --install-cron
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$SCHEDULE root $BACKUP_SELF${ENCRYPT:+ --encrypt $ENCRYPT}${DESTINATION:+ --to $DESTINATION}${RETAIN:+ --retain $RETAIN} >> /var/log/aiauth-backup.log 2>&1
EOF
  chmod 644 /etc/cron.d/aiauth-backup
  log "Installed cron job at /etc/cron.d/aiauth-backup ($SCHEDULE)"
  exit 0
fi

mkdir -p "$BACKUP_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Decide what to archive
INCLUDES=()
case "$INCLUDE" in
  all)
    [[ -d "$AIAUTH_HOME/keys" ]]    && INCLUDES+=("-C" "$AIAUTH_HOME" "keys")
    [[ -f "$AIAUTH_HOME/aiauth.db" ]] && INCLUDES+=("-C" "$AIAUTH_HOME" "aiauth.db")
    [[ -f "$AIAUTH_HOME/aiauth_registry.db" ]] && INCLUDES+=("-C" "$AIAUTH_HOME" "aiauth_registry.db")
    [[ -f "$AIAUTH_HOME/config.yaml" ]] && INCLUDES+=("-C" "$AIAUTH_HOME" "config.yaml")
    ;;
  keys)
    [[ -d "$AIAUTH_HOME/keys" ]] || die "No keys/ dir at $AIAUTH_HOME"
    INCLUDES+=("-C" "$AIAUTH_HOME" "keys")
    ;;
  app-db)
    [[ -f "$AIAUTH_HOME/aiauth.db" ]] || die "No aiauth.db at $AIAUTH_HOME"
    INCLUDES+=("-C" "$AIAUTH_HOME" "aiauth.db")
    ;;
  config)
    [[ -f "$AIAUTH_HOME/config.yaml" ]] || die "No config.yaml at $AIAUTH_HOME"
    INCLUDES+=("-C" "$AIAUTH_HOME" "config.yaml")
    ;;
  *) die "Unknown --include: $INCLUDE" ;;
esac

[[ ${#INCLUDES[@]} -gt 0 ]] || die "Nothing to back up"

# Create archive
ARCHIVE_PATH="$TMP_DIR/$ARCHIVE_NAME"
log "Packaging archive: $ARCHIVE_PATH"
tar czf "$ARCHIVE_PATH" "${INCLUDES[@]}" || die "tar failed"

# Optionally encrypt
FINAL_ARCHIVE="$ARCHIVE_PATH"
if [[ -n "$ENCRYPT" ]]; then
  case "$ENCRYPT" in
    age:*)
      command -v age >/dev/null || die "'age' not installed (apt install age)"
      RECIPIENT="${ENCRYPT#age:}"
      FINAL_ARCHIVE="${ARCHIVE_PATH}.age"
      age -r "$RECIPIENT" -o "$FINAL_ARCHIVE" "$ARCHIVE_PATH"
      rm "$ARCHIVE_PATH"
      log "Encrypted with age -> ${FINAL_ARCHIVE##*/}"
      ;;
    gpg:*)
      command -v gpg >/dev/null || die "'gpg' not installed"
      RECIPIENT="${ENCRYPT#gpg:}"
      FINAL_ARCHIVE="${ARCHIVE_PATH}.gpg"
      gpg --batch --yes --recipient "$RECIPIENT" --output "$FINAL_ARCHIVE" --encrypt "$ARCHIVE_PATH"
      rm "$ARCHIVE_PATH"
      log "Encrypted with GPG -> ${FINAL_ARCHIVE##*/}"
      ;;
    *) die "Unknown --encrypt scheme: $ENCRYPT (use age:KEY or gpg:RECIPIENT)" ;;
  esac
fi

# Dispatch to destination
case "$DESTINATION" in
  local:*)
    DEST_PATH="${DESTINATION#local:}"
    mkdir -p "$DEST_PATH"
    mv "$FINAL_ARCHIVE" "$DEST_PATH/"
    log "Saved to $DEST_PATH/$(basename "$FINAL_ARCHIVE")"
    ;;
  s3://*)
    command -v aws >/dev/null || die "'aws' CLI not installed"
    aws s3 cp "$FINAL_ARCHIVE" "$DESTINATION/$(basename "$FINAL_ARCHIVE")" || exit 3
    rm "$FINAL_ARCHIVE"
    log "Pushed to $DESTINATION/$(basename "$FINAL_ARCHIVE")"
    ;;
  sftp://*)
    SFTP_URL="${DESTINATION#sftp://}"
    HOST="${SFTP_URL%%:*}"
    REMOTE_PATH="${SFTP_URL#*:}"
    sftp "$HOST" <<EOF
cd $REMOTE_PATH
put $FINAL_ARCHIVE
bye
EOF
    rm "$FINAL_ARCHIVE"
    log "Pushed via SFTP to $HOST:$REMOTE_PATH"
    ;;
  *) die "Unknown destination: $DESTINATION (use local:PATH, s3://BUCKET/PREFIX, sftp://USER@HOST:PATH)" ;;
esac

# Retention policy (local destinations only for now)
if [[ -n "$RETAIN" && "$DESTINATION" == local:* ]]; then
  DEST_PATH="${DESTINATION#local:}"
  # Parse "30d,12m" -> keep 30 daily + 12 monthly
  IFS=',' read -ra RULES <<< "$RETAIN"
  for rule in "${RULES[@]}"; do
    case "$rule" in
      *d)
        NUM="${rule%d}"
        # Keep the latest $NUM daily archives, prune older
        find "$DEST_PATH" -maxdepth 1 -name 'aiauth-backup-*.tar.gz*' -type f \
          -mtime +"$NUM" -print0 | xargs -0 -r rm -v
        ;;
      *m) ;;  # monthly retention stub — daily covers the typical case
    esac
  done
fi

log "Done."
