#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/opt/email-sandbox-automation"
CONF="$BASE_DIR/conf/config.env"
LOG_DIR="$BASE_DIR/logs"
RUNS_DIR="$LOG_DIR/runs"
LOCK="/tmp/gma_job.lock"

mkdir -p "$LOG_DIR" "$RUNS_DIR" "$BASE_DIR/tmp/attachments"

RUN_ID="$(date -Is | tr ':' '-')"
RUN_LOG="$RUNS_DIR/$RUN_ID.log"
MAIN_LOG="$LOG_DIR/job.log"

exec 9>"$LOCK"
if ! flock -n 9; then
  echo "$(date -Is) [INFO] Another job is already running. Exiting." >> "$MAIN_LOG"
  exit 0
fi

log() { echo "$(date -Is) $*" | tee -a "$RUN_LOG" >> "$MAIN_LOG"; }

if [[ ! -f "$CONF" ]]; then
  log "[ERROR] Missing config: $CONF"
  exit 1
fi

command -v python3 >/dev/null 2>&1 || { log "[ERROR] python3 not found"; exit 1; }

set -a
source "$CONF"
set +a

log "[INFO] ===== Job start (run_id=$RUN_ID) ====="
python3 "$BASE_DIR/bin/analyze_inbox.py" 2>&1 | tee -a "$RUN_LOG" >> "$MAIN_LOG" || {
  log "[ERROR] analyze_inbox.py failed"
  exit 1
}

# Cleanup old temp files (older than 1 day)
find "$ATTACH_DIR" -type f -mtime +1 -print -delete >> "$RUN_LOG" 2>/dev/null || true

log "[INFO] ===== Job end (run_id=$RUN_ID) ====="
