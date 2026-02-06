#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, sys, imaplib, email, time, hashlib
from email.header import decode_header
from email.utils import parseaddr
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Tuple, Dict
import time
from urllib.parse import urlparse

URL_REGEX = re.compile(r"""(?ix)
\b(
  https?://[^\s<>"'()]+
)
""")

# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def now() -> str:
    return datetime.now().isoformat(timespec="seconds")

def log(level: str, msg: str) -> None:
    print(f"{now()} [{level}] {msg}", flush=True)

def env(name: str, default: str = "") -> str:
    v = os.environ.get(name, default)
    return v if v is not None else default

def env_bool(name: str, default: str = "0") -> bool:
    return str(env(name, default)).strip().lower() in ("1","true","yes","y","on")

def decode_mime(s: Optional[str]) -> str:
    if not s:
        return ""
    out = []
    for part, enc in decode_header(s):
        if isinstance(part, bytes):
            out.append(part.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(part)
    return "".join(out)

def safe_filename(name: str) -> str:
    name = (name or "").strip().replace("\x00", "")
    name = re.sub(r"[\/\\]+", "_", name)
    name = re.sub(r"[^a-zA-Z0-9._ -]+", "_", name)
    name = re.sub(r"\s+", " ", name).strip()
    return (name or "attachment.bin")[:180]

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

# ---------------------------------------------------------
# Gmail IMAP wrapper
# ---------------------------------------------------------

class GmailIMAP:
    def __init__(self, host: str, port: int, user: str, app_pass: str):
        self.host, self.port, self.user, self.app_pass = host, port, user, app_pass
        self.conn: Optional[imaplib.IMAP4_SSL] = None

    def connect(self) -> None:
        log("INFO", f"Connecting IMAP {self.host}:{self.port} ...")
        self.conn = imaplib.IMAP4_SSL(self.host, self.port)
        typ, _ = self.conn.login(self.user, self.app_pass)
        if typ != "OK":
            raise RuntimeError("IMAP login failed")
        log("INFO", "IMAP login OK")

    def select_inbox(self) -> None:
        assert self.conn
        typ, _ = self.conn.select("INBOX")
        if typ != "OK":
            raise RuntimeError("Cannot SELECT INBOX")

    def search_unseen_uids(self) -> List[bytes]:
        assert self.conn
        typ, data = self.conn.uid("search", None, "UNSEEN")
        if typ != "OK":
            raise RuntimeError("SEARCH UNSEEN failed")
        if not data or not data[0]:
            return []
        return data[0].split()

    def fetch_raw(self, uid: bytes) -> bytes:
        assert self.conn
        typ, data = self.conn.uid("fetch", uid, "(RFC822)")
        if typ != "OK" or not data or not data[0]:
            raise RuntimeError(f"FETCH failed for UID {uid!r}")
        return data[0][1]

    def move_to_label(self, uid: bytes, label: str) -> None:
        """
        Gmail "move" = add label + remove \\Inbox label.
        """
        assert self.conn
        typ, _ = self.conn.uid("store", uid, "+X-GM-LABELS", f"({label})")
        if typ != "OK":
            raise RuntimeError(f"Failed to add label {label}")

        typ, _ = self.conn.uid("store", uid, "-X-GM-LABELS", "(\\Inbox)")
        if typ != "OK":
            typ2, _ = self.conn.uid("store", uid, "-X-GM-LABELS", "(INBOX)")
            if typ2 != "OK":
                raise RuntimeError("Failed to remove INBOX label")

    def logout(self) -> None:
        if self.conn:
            try:
                self.conn.logout()
            except Exception:
                pass
            self.conn = None

# ---------------------------------------------------------
# Attachment extraction (only true attachments)
# ---------------------------------------------------------

def html_to_text(html: str) -> str:
    # simples e suficiente para extrair URLs de href
    html = re.sub(r"(?is)<script.*?>.*?</script>", " ", html)
    html = re.sub(r"(?is)<style.*?>.*?</style>", " ", html)
    return re.sub(r"(?s)<.*?>", " ", html)

def extract_text_parts(msg) -> List[str]:
    texts: List[str] = []
    for part in msg.walk():
        ctype = (part.get_content_type() or "").lower()
        disp = (part.get("Content-Disposition") or "").lower()

        # ignora attachments
        if disp.startswith("attachment"):
            continue

        if ctype in ("text/plain", "text/html"):
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                s = payload.decode(charset, errors="replace")
            except Exception:
                s = payload.decode("utf-8", errors="replace")

            if ctype == "text/html":
                s = html_to_text(s)
            texts.append(s)
    return texts

def normalize_url(u: str) -> Optional[str]:
    u = u.strip().rstrip(").,;]}>\"'")
    if not u.lower().startswith(("http://", "https://")):
        return None
    try:
        p = urlparse(u)
        if not p.netloc:
            return None
        return u
    except Exception:
        return None

def domain_allowlisted(domain: str) -> bool:
    allow = [d.strip().lower() for d in env("URL_ALLOWLIST_DOMAINS", "").split(",") if d.strip()]
    if not allow:
        return False
    domain = domain.lower()
    return any(domain == a or domain.endswith("." + a) for a in allow)

def extract_urls_from_email(raw_email: bytes) -> List[str]:
    msg = email.message_from_bytes(raw_email)
    texts = extract_text_parts(msg)
    found: List[str] = []
    for t in texts:
        for m in URL_REGEX.findall(t):
            u = normalize_url(m)
            if not u:
                continue
            dom = urlparse(u).netloc
            if domain_allowlisted(dom):
                continue
            found.append(u)

    # dedupe mantendo ordem
    dedup = []
    seen = set()
    for u in found:
        if u not in seen:
            seen.add(u)
            dedup.append(u)

    max_urls = int(env("MAX_URLS_PER_EMAIL", "10"))
    return dedup[:max_urls]

def extract_attachments(raw_email: bytes, attach_dir: Path, uid_str: str) -> Tuple[Dict[str,str], List[Path]]:
    msg = email.message_from_bytes(raw_email)

    subject = decode_mime(msg.get("Subject", ""))
    from_name, from_addr = parseaddr(msg.get("From", ""))
    from_name = decode_mime(from_name)

    meta = {
        "uid": uid_str,
        "message_id": (msg.get("Message-ID") or f"<no-message-id-uid-{uid_str}>").strip(),
        "from": f"{from_name} <{from_addr}>".strip(),
        "subject": subject,
    }

    attach_dir.mkdir(parents=True, exist_ok=True)
    saved: List[Path] = []
    idx = 0

    for part in msg.walk():
        disp = (part.get("Content-Disposition") or "").lower()

        # Only real attachments (avoid inline images/signatures)
        if not disp.startswith("attachment"):
            continue

        filename = part.get_filename()
        filename = safe_filename(decode_mime(filename or "")) if filename else f"attachment-{uid_str}-{idx}.bin"
        payload = part.get_payload(decode=True)
        if payload is None:
            continue

        out = attach_dir / f"uid-{uid_str}__{idx:02d}__{filename}"
        out.write_bytes(payload)
        saved.append(out)
        idx += 1

    return meta, saved

# ---------------------------------------------------------
# Static analysis (simple but effective)
# ---------------------------------------------------------

def analyze_url_with_cuckoo(url: str) -> Tuple[str, str]:
    import requests

    base = env("CUCKOO_URL", "http://127.0.0.1:8090").rstrip("/")
    headers = cuckoo_headers()

    # healthcheck
    hc = requests.get(f"{base}/cuckoo/status", headers=headers, timeout=5)
    if hc.status_code != 200:
        return "suspect", f"Cuckoo healthcheck HTTP {hc.status_code}"

    # submit url
    resp = requests.post(
        f"{base}/tasks/create/url",
        headers=headers,
        data={"url": url},
        timeout=20
    )
    if resp.status_code != 200:
        return "suspect", f"URL submit HTTP {resp.status_code}"

    j = resp.json()
    task_id = j.get("task_id") or (j.get("task_ids", [None])[0])
    if not task_id:
        return "suspect", "No task_id for URL"

    poll_s = int(env("POLL_SECONDS", "10"))
    max_tries = int(env("POLL_MAX_TRIES", "60"))

    for _ in range(max_tries):
        time.sleep(poll_s)
        view = requests.get(f"{base}/tasks/view/{task_id}", headers=headers, timeout=10)
        if view.status_code != 200:
            continue
        status = view.json().get("task", {}).get("status") or view.json().get("status")

        if status == "reported":
            rep = requests.get(f"{base}/tasks/report/{task_id}", headers=headers, timeout=20)
            if rep.status_code != 200:
                return "suspect", f"URL reported but report fetch failed (task_id={task_id})"
            report = rep.json()
            score = report.get("info", {}).get("score", 0)
            try:
                score = float(score)
            except Exception:
                score = 0.0

            inf_t = float(env("SCORE_INFECTED", "8.0"))
            sus_t = float(env("SCORE_SUSPECT", "4.0"))

            if score >= inf_t:
                return "infected", f"URL score {score:.1f} (task_id={task_id})"
            if score >= sus_t:
                return "suspect", f"URL score {score:.1f} (task_id={task_id})"
            return "clean", f"URL score {score:.1f} (task_id={task_id})"

        if status in ("failed", "error"):
            return "suspect", f"URL task status {status} (task_id={task_id})"

    return "suspect", f"URL analysis timeout (task_id={task_id})"


def analyze_file_static(file_path: Path) -> Tuple[str, str, List[str]]:
    ext = file_path.suffix.lower()
    fname = file_path.name
    warnings: List[str] = []

    high_risk_ext = {".exe", ".scr", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".lnk"}
    medium_risk_ext = {".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt", ".pdf", ".iso", ".img", ".zip"}
    macro_ext = {".docm", ".xlsm", ".pptm"}

    if ext in high_risk_ext:
        warnings.append(f"High-risk extension {ext}")
    elif ext in medium_risk_ext:
        warnings.append(f"Medium-risk extension {ext}")

    # Size
    try:
        size = file_path.stat().st_size
        max_mb = float(env("MAX_ATTACHMENT_MB", "50"))
        if size > int(max_mb * 1024 * 1024):
            warnings.append(f"Oversized attachment ({size} bytes)")
    except Exception:
        pass

    # Double extension
    if re.search(r"\.[a-z0-9]{2,4}\.[a-z0-9]{2,4}$", fname, re.IGNORECASE):
        warnings.append("Double extension detected")

    # Suspicious names (very light)
    suspicious_words = ["invoice", "payment", "urgent", "scan", "document", "delivery", "order"]
    if any(w in fname.lower() for w in suspicious_words):
        warnings.append("Suspicious filename keywords")

    # Macro policy
    if ext in macro_ext and env_bool("FLAG_MACRO_AS_INFECTED", "1"):
        return "infected", "Office macro type (policy)", ["macro-policy"]

    if warnings:
        return "suspect", "; ".join(warnings[:3]), warnings

    return "clean", "Static analysis passed", []

# ---------------------------------------------------------
# Cuckoo API (Bearer) + score
# ---------------------------------------------------------

def cuckoo_headers() -> Dict[str, str]:
    token = env("CUCKOO_API_TOKEN", "").strip()
    use_auth = env_bool("CUCKOO_API_AUTH", "1")
    scheme = env("CUCKOO_AUTH_SCHEME", "bearer").strip().lower()

    if not use_auth or not token:
        return {}

    if scheme in ("bearer", ""):
        return {"Authorization": f"Bearer {token}"}
    if scheme == "token":
        return {"Authorization": f"Token {token}"}
    # fallback
    return {"Authorization": f"Bearer {token}"}

def analyze_with_cuckoo_api(file_path: Path) -> Tuple[str, str, Optional[float], Optional[int]]:
    """
    Returns: (verdict, reason, score, task_id)
    verdict: clean|suspect|infected|error
    """
    import requests

    base = env("CUCKOO_URL", "http://127.0.0.1:8090").rstrip("/")
    headers = cuckoo_headers()

    # healthcheck
    try:
        hc = requests.get(f"{base}/cuckoo/status", headers=headers, timeout=5)
        if hc.status_code != 200:
            return "error", f"Healthcheck HTTP {hc.status_code}", None, None
    except Exception as e:
        return "error", f"Healthcheck error: {e}", None, None

    # submit
    try:
        with open(file_path, "rb") as f:
            files = {"file": (file_path.name, f)}
            resp = requests.post(f"{base}/tasks/create/file", headers=headers, files=files, timeout=30)
        if resp.status_code != 200:
            return "error", f"Submit HTTP {resp.status_code}", None, None

        j = resp.json()
        task_id = j.get("task_id") or (j.get("task_ids", [None])[0])
        if not task_id:
            return "error", "No task_id returned", None, None

        poll_s = int(env("POLL_SECONDS", "10"))
        max_tries = int(env("POLL_MAX_TRIES", "60"))

        for _ in range(max_tries):
            time.sleep(poll_s)
            view = requests.get(f"{base}/tasks/view/{task_id}", headers=headers, timeout=10)
            if view.status_code != 200:
                continue
            data = view.json()
            status = data.get("task", {}).get("status") or data.get("status")  # depends on build

            if status == "reported":
                rep = requests.get(f"{base}/tasks/report/{task_id}", headers=headers, timeout=20)
                if rep.status_code != 200:
                    return "suspect", "Reported but report fetch failed", None, int(task_id)

                report = rep.json()
                score_raw = report.get("info", {}).get("score", 0)
                try:
                    score = float(score_raw)
                except Exception:
                    score = 0.0

                inf_t = float(env("SCORE_INFECTED", "8.0"))
                sus_t = float(env("SCORE_SUSPECT", "4.0"))

                if score >= inf_t:
                    return "infected", f"Cuckoo score {score:.1f}", score, int(task_id)
                if score >= sus_t:
                    return "suspect", f"Cuckoo score {score:.1f}", score, int(task_id)
                return "clean", f"Cuckoo score {score:.1f}", score, int(task_id)

            if status in ("failed", "error"):
                return "suspect", f"Task status {status}", None, int(task_id)

        return "suspect", "Cuckoo timeout", None, int(task_id)

    except Exception as e:
        return "suspect", f"Cuckoo exception: {e}", None, None

# ---------------------------------------------------------
# Multifactor fusion
# ---------------------------------------------------------

def analyze_file_with_sandbox(file_path: Path) -> Tuple[str, str]:
    """
    Multifactor:
    - Try Cuckoo API (hybrid) and use score strongly when available.
    - If Cuckoo fails/timeouts: fall back to static for low-risk; fail-safe for high-risk.
    """
    sandbox_mode = env("SANDBOX_MODE", "hybrid").lower()  # api|hybrid|static
    ext = file_path.suffix.lower()

    high_risk_ext = {".exe",".js",".vbs",".scr",".ps1",".bat",".cmd",".dll",".jar",".msi",".lnk",".iso"}

    # static always available
    static_v, static_r, static_warn = analyze_file_static(file_path)

    if sandbox_mode == "static":
        return static_v, static_r

    v, r, score, task_id = analyze_with_cuckoo_api(file_path)
    if task_id is not None:
        r = f"{r} (task_id={task_id})"

    if sandbox_mode == "api":
        # API-only: already fail-safe in analyze_with_cuckoo_api
        return v, r

    # hybrid fusion
    if score is not None:
        # low score -> only suspect if high-risk ext or static had warnings
        if v == "clean" and score <= 0.1:
            if ext in high_risk_ext:
                return "suspect", f"Low score {score:.1f} but high-risk extension {ext} (task_id={task_id})"
            if static_warn:
                return "suspect", f"Low score {score:.1f} + static: {static_r} (task_id={task_id})"
            return "clean", f"Low score {score:.1f} and no static alerts (task_id={task_id})"
        return v, r

    # No score (timeout/error): fail-safe for high-risk; otherwise trust static
    if ext in high_risk_ext:
        return "suspect", f"Cuckoo unavailable ({r}); high-risk extension {ext}"
    return static_v, f"Cuckoo unavailable ({r}); static: {static_r}"

def decide_label(verdicts: List[Tuple[str, str]], infected: str, clean: str, suspect: str) -> str:
    verdicts_only = [v[0] for v in verdicts]
    if any(v == "infected" for v in verdicts_only):
        return infected
    if any(v == "suspect" for v in verdicts_only):
        return suspect
    return clean

# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main() -> int:
    dry = env_bool("DRY_RUN", "1")

    host = env("IMAP_HOST", "imap.gmail.com")
    port = int(env("IMAP_PORT", "993"))
    user = env("GMAIL_USER")
    pw = env("GMAIL_APP_PASS")

    label_inf = env("LABEL_INFECTED", "INFETADOS")
    label_clean = env("LABEL_CLEAN", "NAO_INFETADOS")
    label_susp = env("LABEL_SUSPECT", "SUSPEITOS")

    attach_dir = Path(env("ATTACH_DIR", "/opt/email-sandbox-automation/tmp/attachments"))
    attach_dir.mkdir(parents=True, exist_ok=True)

    log("INFO", f"DRY_RUN={'ON' if dry else 'OFF'}")
    log("INFO", f"Attachments dir: {attach_dir}")
    log("INFO", f"Labels: infected={label_inf} clean={label_clean} suspect={label_susp}")

    if not user or not pw:
        log("ERROR", "Missing GMAIL_USER or GMAIL_APP_PASS in config.env")
        return 2

    c = GmailIMAP(host, port, user, pw)
    try:
        c.connect()
        c.select_inbox()
        uids = c.search_unseen_uids()
        log("INFO", f"UNSEEN emails found: {len(uids)}")

        processed = 0
        attachments_processed = 0

        for uid in uids:
            uid_str = uid.decode(errors="replace")
            raw = c.fetch_raw(uid)

            meta, attachments = extract_attachments(raw, attach_dir, uid_str)
            log("INFO", f"Processing UID={uid_str} | From={meta['from']} | Subject={meta['subject']}")

            # ============================
            # URL EXTRACTION
            # ============================
            urls = []
            if env_bool("ENABLE_URL_ANALYSIS", "1"):
                urls = extract_urls_from_email(raw)
                if urls:
                    log("INFO", f"Found {len(urls)} URL(s) in email body")
                else:
                    log("INFO", "No URLs found in email body")

            verdicts = []

            # ============================
            # ATTACHMENT ANALYSIS
            # ============================
            if attachments:
                log("INFO", f"Found {len(attachments)} attachment(s)")
                for a in attachments:
                    attachments_processed += 1
                    verdict, reason = analyze_file_with_sandbox(a)
                    verdicts.append((verdict, reason))
                    log("INFO", f"Attachment {a.name} -> verdict={verdict}, reason={reason}")

            # ============================
            # URL ANALYSIS
            # ============================
            if urls:
                for u in urls:
                    v, r = analyze_url_with_cuckoo(u)
                    verdicts.append((v, f"url={u} | {r}"))
                    log("INFO", f"URL {u} -> verdict={v}, reason={r}")

            # ============================
            # FINAL DECISION
            # ============================
            if not verdicts:
                final_label = label_clean
                log("INFO", f"No attachments and no URLs -> label={final_label}")
            else:
                final_label = decide_label(verdicts, label_inf, label_clean, label_susp)
                log("INFO", f"Final decision UID={uid_str}: {final_label}")

            processed += 1

            if dry:
                log("INFO", f"[DRY_RUN] Would move UID={uid_str} to label '{final_label}'")
            else:
                c.move_to_label(uid, final_label)
                log("INFO", f"Moved UID={uid_str} to label '{final_label}'")


        log("INFO", "=" * 50)
        log("INFO", "PROCESSING COMPLETE")
        log("INFO", f"Emails processed: {processed}")
        log("INFO", f"Attachments analyzed: {attachments_processed}")
        return 0

    except imaplib.IMAP4.error as e:
        log("ERROR", f"IMAP error: {e}")
        return 3
    except Exception as e:
        log("ERROR", f"Unhandled error: {e}")
        return 4
    finally:
        c.logout()

if __name__ == "__main__":
    raise SystemExit(main())
