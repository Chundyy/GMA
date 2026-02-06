
#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/opt/email-sandbox-automation"
GET_REPORT="$BASE_DIR/bin/get_report.sh"
CONF="$BASE_DIR/conf/config.env"
RUN_JOB="$BASE_DIR/bin/run_job.sh"
SELF_CHECK="$BASE_DIR/bin/self_check.sh"
LOG_MAIN="$BASE_DIR/logs/job.log"
BANNER="$BASE_DIR/bin/banner.txt"
DEFAULT_VERSION="1.1"

require_files() {
  [[ -x "$RUN_JOB" ]] || { echo "[ERROR] $RUN_JOB not found"; exit 1; }
  [[ -x "$SELF_CHECK" ]] || { echo "[ERROR] $SELF_CHECK not found"; exit 1; }
  [[ -f "$CONF" ]] || { echo "[ERROR] $CONF not found"; exit 1; }
  [[ -x "$GET_REPORT" ]] || { echo "[ERROR] $GET_REPORT not found"; exit 1; }
}

get_env() {
  awk -F= -v k="$1" '$1==k {gsub(/^"/,"",$2); gsub(/"$/,"",$2); print $2}' "$CONF" | tail -n 1
}

set_env() {
  if grep -qE "^$1=" "$CONF"; then
    sed -i "s|^$1=.*|$1=\"$2\"|g" "$CONF"
  else
    echo "$1=\"$2\"" >> "$CONF"
  fi
  chmod 600 "$CONF" || true
}

get_version() {
  local v
  v="$(get_env GMA_VERSION || true)"
  [[ -n "$v" ]] && echo "$v" || echo "$DEFAULT_VERSION"
}

show_banner() {
  clear
  [[ -f "$BANNER" ]] && cat "$BANNER" || echo "GMA - Gmail Malware Automation"
  echo "Version: $(get_version)"
  echo
}

show_help() {
  cat <<EOF
GMA - Gmail Malware Automation

Usage:
  gma                     Start interactive menu
  gma --help              Show help
  gma --version           Show version
  gma --demo              Run: self-check -> status -> imap-test -> cuckoo-test -> run job

Direct:
  gma --self-check        Run diagnostics
  gma --run               Run job now
  gma --status            Show config (no secrets)

Tests:
  gma --imap-test         Test IMAP login
  gma --cuckoo-test       Test Cuckoo URL endpoints (HTTP)

Dry-run:
  gma --dry-run on|off    Toggle simulation mode

Cron:
  gma --install-cron      Install cron (every 5 minutes)
  gma --remove-cron       Remove cron

Logs:
  gma --get-report        Generate HTML report and email it
  gma --tail-log          Tail main log
EOF
}

install_cron() {
  set -a; source "$CONF"; set +a

  day="${MONTHLY_REPORT_DAY:-1}"
  hour="${MONTHLY_REPORT_HOUR:-9}"
  min="${MONTHLY_REPORT_MIN:-0}"

  ( crontab -l 2>/dev/null | grep -v "$RUN_JOB" | grep -v "$BASE_DIR/bin/monthly_report.sh" || true
    echo "*/5 * * * * $RUN_JOB"
    echo "$min $hour $day * * $BASE_DIR/bin/monthly_report.sh"
  ) | crontab -

  echo "[OK] Cron installed:"
  echo "     - every 5 minutes: $RUN_JOB"
  echo "     - monthly report:  $min $hour day $day -> $BASE_DIR/bin/monthly_report.sh"
}

remove_cron() {
  ( crontab -l 2>/dev/null \
    | grep -v "$RUN_JOB" \
    | grep -v "$BASE_DIR/bin/monthly_report.sh" \
    || true
  ) | crontab -
  echo "[OK] Cron entries removed."
}

show_status() {
  echo "GMA_VERSION=$(get_version)"
  echo "DRY_RUN=$(get_env DRY_RUN)"
  echo "IMAP_HOST=$(get_env IMAP_HOST)"
  echo "IMAP_PORT=$(get_env IMAP_PORT)"
  echo "GMAIL_USER=$(get_env GMAIL_USER)"
  echo "LABEL_INFECTED=$(get_env LABEL_INFECTED)"
  echo "LABEL_CLEAN=$(get_env LABEL_CLEAN)"
  echo "LABEL_SUSPECT=$(get_env LABEL_SUSPECT)"
  echo "CUCKOO_URL=$(get_env CUCKOO_URL)"
}

imap_test() {
  echo "== IMAP Test (login) =="
  set -a; source "$CONF"; set +a
  python3 - <<'PY'
import os, socket, imaplib
host=os.environ.get("IMAP_HOST","imap.gmail.com")
port=int(os.environ.get("IMAP_PORT","993"))
user=os.environ.get("GMAIL_USER","")
pw=os.environ.get("GMAIL_APP_PASS","")
print(f"[INFO] Host={host} Port={port}")
s=socket.socket(); s.settimeout(5); s.connect((host,port)); s.close()
print("[OK]   TCP connect OK")
M=imaplib.IMAP4_SSL(host, port)
typ,_=M.login(user,pw)
print("[OK]   IMAP login OK" if typ=="OK" else "[FAIL] IMAP login failed")
M.logout()
PY
}

cuckoo_test() {
  echo "== Cuckoo Test (HTTP probes) =="
  set -a; source "$CONF"; set +a

  if [[ -z "${CUCKOO_URL:-}" ]]; then
    echo "[WARN] CUCKOO_URL is empty (expected until Cuckoo is installed)"
    return 0
  fi
  command -v curl >/dev/null 2>&1 || { echo "[FAIL] curl not installed"; return 1; }

  base="${CUCKOO_URL%/}"

  # Build auth header args (if enabled)
  AUTH_ARGS=()
  if [[ "${CUCKOO_API_AUTH:-0}" == "1" ]]; then
    if [[ -z "${CUCKOO_API_TOKEN:-}" ]]; then
      echo "[WARN] CUCKOO_API_AUTH=1 but CUCKOO_API_TOKEN is empty"
    else
      scheme="$(echo "${CUCKOO_AUTH_SCHEME:-bearer}" | tr '[:upper:]' '[:lower:]')"
      case "$scheme" in
        bearer|"")
          AUTH_ARGS=(-H "Authorization: Bearer ${CUCKOO_API_TOKEN}")
          ;;
        token)
          AUTH_ARGS=(-H "Authorization: Token ${CUCKOO_API_TOKEN}")
          ;;
        x-api-key)
          AUTH_ARGS=(-H "X-API-Key: ${CUCKOO_API_TOKEN}")
          ;;
        *)
          echo "[WARN] Unknown CUCKOO_AUTH_SCHEME='$scheme' -> defaulting to Bearer"
          AUTH_ARGS=(-H "Authorization: Bearer ${CUCKOO_API_TOKEN}")
          ;;
      esac
    fi
  fi

  for p in  "/cuckoo/status"  "/tasks/list"; do
    code="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 4 "${AUTH_ARGS[@]}" "$base$p" || true)"
    echo "[INFO] GET $p -> HTTP $code"
  done

  # Extra: show a success hint
  code_status="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 4 "${AUTH_ARGS[@]}" "$base/cuckoo/status" || true)"
  if [[ "$code_status" == "200" ]]; then
    echo "[OK]   Authorized: /cuckoo/status returned 200"
  elif [[ "$code_status" == "401" ]]; then
    echo "[FAIL] Unauthorized: /cuckoo/status returned 401 (token/header mismatch)"
  else
    echo "[WARN] /cuckoo/status returned HTTP $code_status (expected 200)"
  fi
}

set_dry_run() {
  case "${2:-}" in
    on)  set_env DRY_RUN 1; echo "[OK] DRY_RUN enabled";;
    off) set_env DRY_RUN 0; echo "[OK] DRY_RUN disabled";;
    *) echo "[ERROR] Use: gma --dry-run on|off"; exit 1;;
  esac
}

run_demo() {
  echo "== GMA Demo =="
  "$SELF_CHECK" || return 1
  echo; show_status
  echo; imap_test || true
  echo; cuckoo_test || true
  echo; "$RUN_JOB"
  echo; echo "[OK] Demo complete."
}

interactive_menu() {
  show_banner
  echo "1) Self-check"
  echo "2) Run job now"
  echo "3) Status"
  echo "4) IMAP test"
  echo "5) Cuckoo test"
  echo "6) Install cron"
  echo "7) Remove cron"
  echo "8) Demo"
  echo "9) Get Report (generate + email)"
  echo "0) Exit"
  echo
  read -r -p "Select option: " opt
  case "$opt" in
    1) "$SELF_CHECK" ;;
    2) "$RUN_JOB" ;;
    3) show_status ;;
    4) imap_test ;;
    5) cuckoo_test ;;
    6) install_cron ;;
    7) remove_cron ;;
    8) run_demo ;;
    9) "$GET_REPORT" ;;
    0) exit 0 ;;
    *) echo "[WARN] Invalid option" ;;
  esac
  read -r -p $'\n(Press Enter to continue...) ' _
}

require_files
case "${1:-}" in
  --help|-h) show_help ;;
  --version|-V) echo "GMA $(get_version)" ;;
  --demo) run_demo ;;
  --self-check) "$SELF_CHECK" ;;
  --run) "$RUN_JOB" ;;
  --status) show_status ;;
  --imap-test) imap_test ;;
  --cuckoo-test) cuckoo_test ;;
  --dry-run) set_dry_run "$@" ;;
  --install-cron) install_cron ;;
  --remove-cron) remove_cron ;;
  --tail-log) tail -f "$LOG_MAIN" ;;
  --get-report) "$GET_REPORT" ;;
  "") interactive_menu ;;
  *) echo "[ERROR] Unknown option: $1"; echo; show_help; exit 1 ;;
esac
