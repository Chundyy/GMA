#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/opt/email-sandbox-automation"
CONF="$BASE_DIR/conf/config.env"

ok()   { echo "[OK]   $*"; }
warn() { echo "[WARN] $*"; }
fail() { echo "[FAIL] $*"; }

echo "== GMA Self-check =="
echo "Date: $(date -Is)"
echo

[[ -d "$BASE_DIR" ]] && ok "Base directory exists" || { fail "Base directory missing"; exit 1; }
[[ -f "$CONF" ]] && ok "Config exists: $CONF" || { fail "Missing config.env"; exit 1; }

perm="$(stat -c "%a" "$CONF" 2>/dev/null || true)"
[[ "$perm" == "600" ]] && ok "config.env perms = 600" || warn "config.env perms = $perm (recommended 600)"

for c in python3 curl flock ip; do
  command -v "$c" >/dev/null 2>&1 && ok "Dependency OK: $c" || warn "Missing dependency: $c"
done

echo
set -a
# shellcheck disable=SC1090
source "$CONF"
set +a

req=(IMAP_HOST IMAP_PORT GMAIL_USER LABEL_INFECTED LABEL_CLEAN LABEL_SUSPECT ATTACH_DIR CUCKOO_URL)
missing=0
for v in "${req[@]}"; do
  [[ -n "${!v:-}" ]] && ok "Var set: $v" || { fail "Var missing: $v"; missing=1; }
done
[[ -n "${GMAIL_APP_PASS:-}" ]] && ok "Var set: GMAIL_APP_PASS (hidden)" || { fail "Var missing: GMAIL_APP_PASS"; missing=1; }
[[ "$missing" -eq 0 ]] || exit 1

echo
for d in "$BASE_DIR/bin" "$BASE_DIR/conf" "$BASE_DIR/logs" "$BASE_DIR/logs/runs" "$ATTACH_DIR"; do
  [[ -d "$d" ]] && ok "Dir OK: $d" || { warn "Dir missing: $d (creating)"; mkdir -p "$d"; ok "Created: $d"; }
done

echo
echo "Network (expect Host-Only 10.10.10.0/24 somewhere):"
ip -br a || true

# =========================================================
# Cuckoo API probes (with Bearer token if enabled)
# =========================================================
echo
echo "== Cuckoo Test (HTTP probes) =="

base="${CUCKOO_URL%/}"

# Build curl auth header array safely
AUTH_ARGS=()
if [[ "${CUCKOO_API_AUTH:-1}" == "1" ]]; then
  if [[ -n "${CUCKOO_API_TOKEN:-}" ]]; then
    # Only bearer supported here (matches your server message)
    AUTH_ARGS=(-H "Authorization: Bearer ${CUCKOO_API_TOKEN}")
  else
    warn "CUCKOO_API_AUTH=1 but CUCKOO_API_TOKEN is empty"
  fi
fi

probe() {
  local path="$1"
  local code
  code="$(curl -sS -o /dev/null -w "%{http_code}" "${AUTH_ARGS[@]}" "${base}${path}" || echo "000")"
  echo "[INFO] GET ${path} -> HTTP ${code}"
}

probe "/"
probe "/status"
probe "/cuckoo/status"
probe "/tasks/list"

# quick sanity: we expect /cuckoo/status to be 200 when auth is correct
code_status="$(curl -sS -o /dev/null -w "%{http_code}" "${AUTH_ARGS[@]}" "${base}/cuckoo/status" || echo "000")"
if [[ "$code_status" == "200" ]]; then
  ok "Cuckoo API reachable and authorized (/cuckoo/status=200)"
elif [[ "$code_status" == "401" ]]; then
  fail "Cuckoo API unauthorized (401). Check CUCKOO_API_TOKEN / Bearer header."
else
  warn "Cuckoo API probe returned HTTP ${code_status} for /cuckoo/status (expected 200)"
fi

echo
ok "Self-check complete"
