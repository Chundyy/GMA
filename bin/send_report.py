#!/usr/bin/env python3
import os
import sys
import smtplib
from email.message import EmailMessage
from pathlib import Path
from datetime import datetime

def env(name: str, default: str = "") -> str:
    v = os.environ.get(name, default)
    return v if v is not None else default

def env_bool(name: str, default: str = "0") -> bool:
    return str(env(name, default)).strip().lower() in ("1","true","yes","y","on")

def token_hint(tok: str) -> str:
    tok = (tok or "").strip()
    if not tok:
        return "EMPTY"
    if len(tok) <= 8:
        return "SET"
    return f"{tok[:3]}...{tok[-3:]}"

def main() -> int:
    if len(sys.argv) < 2:
        print("[ERROR] Usage: send_report.py /path/to/report.html", file=sys.stderr)
        return 2

    report_path = Path(sys.argv[1])
    if not report_path.exists():
        print(f"[ERROR] Report not found: {report_path}", file=sys.stderr)
        return 2

    if not env_bool("SEND_REPORT", "0"):
        print("[INFO] SEND_REPORT=0 -> skipping email")
        return 0

    smtp_host = env("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(env("SMTP_PORT", "587"))
    smtp_user = env("SMTP_USER", "")
    smtp_pass = env("SMTP_APP_PASS", "")
    report_to = env("REPORT_TO", "")
    prefix = env("REPORT_SUBJECT_PREFIX", "[GMA REPORT]")
    attach_report = env_bool("ATTACH_REPORT", "1")

    if not smtp_user or not smtp_pass or not report_to:
        print("[ERROR] Missing SMTP_USER/SMTP_APP_PASS/REPORT_TO in env", file=sys.stderr)
        print(f"[DEBUG] SMTP_USER={smtp_user} SMTP_APP_PASS={token_hint(smtp_pass)} REPORT_TO={report_to}", file=sys.stderr)
        return 3

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subject = f"{prefix} {ts}"

    msg = EmailMessage()
    msg["From"] = smtp_user
    msg["To"] = report_to
    msg["Subject"] = subject

    msg.set_content(
        "Relatório automático do GMA (Gmail Malware Automation).\n"
        f"Data: {ts}\n\n"
        f"Relatório: {report_path.name}\n\n"
        "Abra o anexo HTML no browser.\n"
    )

    if attach_report:
        data = report_path.read_bytes()
        msg.add_attachment(data, maintype="text", subtype="html", filename=report_path.name)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=25) as s:
        s.ehlo()
        s.starttls()
        s.login(smtp_user, smtp_pass)
        s.send_message(msg)

    print(f"[OK] Report sent to {report_to}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
