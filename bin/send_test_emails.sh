#!/usr/bin/env bash
set -euo pipefail

# GMA - Safe Test Email Sender (CLEAN / SUSPECT / EICAR-ZIP)
# Uses config.env SMTP settings. Sends emails to your own mailbox for pipeline testing.

BASE_DIR="/opt/email-sandbox-automation"
CONF="$BASE_DIR/conf/config.env"
WORKDIR="$BASE_DIR/tmp/test_sender"
CLEAN_DIR="$WORKDIR/clean_attachments"
SUS_DIR="$WORKDIR/suspect_attachments"
INF_DIR="$WORKDIR/infected_attachments"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

if [[ ! -f "$CONF" ]]; then
  echo -e "${RED}[ERROR] Missing config: $CONF${NC}"
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$CONF"
set +a

: "${SMTP_HOST:=smtp.gmail.com}"
: "${SMTP_PORT:=587}"
: "${SMTP_USER:=${GMAIL_USER:-}}"
: "${SMTP_APP_PASS:=}"
: "${REPORT_TO:=${GMAIL_USER:-}}"

NUM_EMAILS="${NUM_EMAILS:-6}"
INFECTED_PERCENTAGE="${INFECTED_PERCENTAGE:-30}"   # % of emails with EICAR zip
SUSPECT_PERCENTAGE="${SUSPECT_PERCENTAGE:-40}"     # % of emails with suspect ext

if [[ -z "${SMTP_USER:-}" || -z "${SMTP_APP_PASS:-}" || -z "${REPORT_TO:-}" ]]; then
  echo -e "${RED}[ERROR] Missing SMTP config. Need SMTP_USER, SMTP_APP_PASS, REPORT_TO (or GMAIL_USER).${NC}"
  exit 1
fi

mkdir -p "$CLEAN_DIR" "$SUS_DIR" "$INF_DIR"

echo -e "${CYAN}== Preparing safe attachments ==${NC}"

# CLEAN files
cat > "$CLEAN_DIR/clean.txt" <<'EOF'
Hello! This is a clean test attachment.
EOF

cat > "$CLEAN_DIR/meeting_minutes.txt" <<'EOF'
Meeting Minutes
- All tasks completed
- Next steps: demo + report
EOF

# Simple “pdf-like” stub (not a real PDF but harmless)
cat > "$CLEAN_DIR/report.pdf" <<'EOF'
%PDF-1.4
% Simple harmless PDF-like content for testing.
EOF

# SUSPECT files (benign content with risky extensions)
cat > "$SUS_DIR/invoice.js" <<'EOF'
console.log("This is a benign JS test file (no malware).");
EOF

cat > "$SUS_DIR/update.ps1" <<'EOF'
Write-Output "Benign PowerShell test (no execution performed by pipeline)."
EOF

cat > "$SUS_DIR/notice.vbs" <<'EOF'
WScript.Echo "Benign VBScript test file."
EOF

# INFECTED test using EICAR (safe standard test string)
EICAR_TXT="$INF_DIR/eicar.txt"
cat > "$EICAR_TXT" <<'EOF'
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
EOF

# Zip it (Gmail may block raw EICAR; ZIP often passes)
EICAR_ZIP="$INF_DIR/eicar.zip"
if command -v zip >/dev/null 2>&1; then
  (cd "$INF_DIR" && zip -q -j "eicar.zip" "eicar.txt")
else
  # fallback using python zipfile
  python3 - <<PY
import zipfile
from pathlib import Path
inf = Path("$INF_DIR")
with zipfile.ZipFile(str(inf/"eicar.zip"), "w", compression=zipfile.ZIP_DEFLATED) as z:
    z.write(str(inf/"eicar.txt"), arcname="eicar.txt")
PY
fi

echo -e "${GREEN}[OK] Attachments ready:${NC}"
echo "  CLEAN:    $(ls -1 "$CLEAN_DIR" | wc -l) files"
echo "  SUSPECT:  $(ls -1 "$SUS_DIR" | wc -l) files"
echo "  INFECTED: $(ls -1 "$INF_DIR" | wc -l) files (includes eicar.zip)"

echo -e "${CYAN}\n== Sending $NUM_EMAILS emails to $REPORT_TO ==${NC}"
echo -e "${YELLOW}Mix: ${INFECTED_PERCENTAGE}% INFECTED (EICAR-ZIP), ${SUSPECT_PERCENTAGE}% SUSPECT, rest CLEAN${NC}\n"

python3 - <<PY
import os, random, smtplib, time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path

SMTP_HOST=os.environ.get("SMTP_HOST","smtp.gmail.com")
SMTP_PORT=int(os.environ.get("SMTP_PORT","587"))
SMTP_USER=os.environ["SMTP_USER"]
SMTP_PASS=os.environ["SMTP_APP_PASS"]
TO=os.environ["REPORT_TO"]

NUM=int(os.environ.get("NUM_EMAILS","6"))
INF_PCT=int(os.environ.get("INFECTED_PERCENTAGE","30"))
SUS_PCT=int(os.environ.get("SUSPECT_PERCENTAGE","40"))

clean_dir=Path(r"$CLEAN_DIR")
sus_dir=Path(r"$SUS_DIR")
inf_dir=Path(r"$INF_DIR")

clean_files=[p for p in clean_dir.iterdir() if p.is_file()]
sus_files=[p for p in sus_dir.iterdir() if p.is_file()]
eicar_zip=inf_dir/"eicar.zip"

subjects_clean=[
  "TEST CLEAN - Weekly Update",
  "TEST CLEAN - Meeting Notes",
  "TEST CLEAN - Status Report"
]
subjects_sus=[
  "TEST SUSPECT - Invoice Attached",
  "TEST SUSPECT - Urgent Update",
  "TEST SUSPECT - Document Review"
]
subjects_inf=[
  "TEST INFECTED - Sample Attached (EICAR)",
  "TEST INFECTED - Security Test Attachment"
]

def attach_file(msg, path: Path):
    part = MIMEBase("application","octet-stream")
    part.set_payload(path.read_bytes())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f'attachment; filename="{path.name}"')
    msg.attach(part)

print(f"[INFO] Connecting SMTP {SMTP_HOST}:{SMTP_PORT} as {SMTP_USER} ...")
server=smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
server.ehlo()
server.starttls()
server.login(SMTP_USER, SMTP_PASS)
print("[OK] SMTP login OK")

for i in range(NUM):
    r=random.randint(1,100)
    if r <= INF_PCT and eicar_zip.exists():
        kind="INFECTED"
        subj=random.choice(subjects_inf)
        body="Teste académico com EICAR em ZIP (não é malware real)."
        att=eicar_zip
    elif r <= INF_PCT + SUS_PCT and sus_files:
        kind="SUSPECT"
        subj=random.choice(subjects_sus)
        body="Teste académico com extensão de risco mas conteúdo benigno."
        att=random.choice(sus_files)
    else:
        kind="CLEAN"
        subj=random.choice(subjects_clean)
        body="Teste académico com anexo benigno."
        att=random.choice(clean_files) if clean_files and random.randint(1,100)<=70 else None

    msg=MIMEMultipart()
    msg["From"]=SMTP_USER
    msg["To"]=TO
    msg["Subject"]=subj
    msg.attach(MIMEText(body, "plain"))

    if att:
        attach_file(msg, att)

    server.send_message(msg)
    print(f"[{kind}] Sent {i+1}/{NUM}: {subj}  attachment={att.name if att else 'none'}")
    time.sleep(2)

server.quit()
print("[OK] Done.")
PY

echo -e "${GREEN}\n[OK] Test emails sent.${NC}"
echo -e "${YELLOW}Agora corre: gma --run  (com DRY_RUN off) e confirma as labels no Gmail.${NC}"
