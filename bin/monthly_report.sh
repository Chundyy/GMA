#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="/opt/email-sandbox-automation"
CONF="$BASE_DIR/conf/config.env"

set -a
# shellcheck disable=SC1090
source "$CONF"
set +a

# Gera e envia
report_path="$("$BASE_DIR/bin/generate_report.sh")"
python3 "$BASE_DIR/bin/send_report.py" "$report_path"
