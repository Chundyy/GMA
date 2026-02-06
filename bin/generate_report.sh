#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/opt/email-sandbox-automation"
CONF="$BASE_DIR/conf/config.env"
RUNS_DIR="$BASE_DIR/logs/runs"
LOG_MAIN="$BASE_DIR/logs/job.log"

mkdir -p "$RUNS_DIR"

set -a
# shellcheck disable=SC1090
source "$CONF"
set +a

ts="$(date +%Y%m%d-%H%M%S)"
out_dir="$RUNS_DIR/$ts"
mkdir -p "$out_dir"
report="$out_dir/report.html"
tmp_tsv="$out_dir/parsed.tsv"

# Parse log (mawk-safe)
tail -n 5000 "$LOG_MAIN" 2>/dev/null | awk '
BEGIN{
  uid=""; subject=""; from=""; det="";
}

# Processing UID=51 | From=... | Subject=...
$0 ~ /Processing UID=/{
  uid=""; subject=""; from=""; det="";
  line=$0

  sub(/^.*UID=/,"",line)
  split(line,a," ")
  uid=a[1]

  # From=
  line=$0
  sub(/^.*From=/,"",line)
  split(line,b,"|")
  from=b[1]
  gsub(/^[ \t]+|[ \t]+$/,"",from)

  # Subject=
  line=$0
  sub(/^.*Subject=/,"",line)
  subject=line
  gsub(/^[ \t]+|[ \t]+$/,"",subject)
  next
}

# Older: Processing email UID=123 Subject='...'
$0 ~ /Processing email UID=/{
  uid=""; subject=""; from=""; det="";
  line=$0
  sub(/^.*UID=/,"",line)
  split(line,a," ")
  uid=a[1]

  # Subject='...'
  subject=$0
  sub(/^.*Subject='\''/,"",subject)
  sub(/'\''$/,"",subject)
  next
}

# Attachment ... -> verdict=... reason=...
$0 ~ /^.*Attachment .* -> verdict=/{
  line=$0
  sub(/^.*Attachment[ \t]+/,"",line)
  split(line,a," ")
  file=a[1]

  verdict=line
  sub(/^.*verdict=/,"",verdict)
  split(verdict,v," ")
  verdict=v[1]

  reason=$0
  sub(/^.*reason=/,"",reason)

  entry=file " (" verdict ")"
  if (reason != "" && reason != $0) entry=entry "<br><span class=\"muted\">" reason "</span>"

  if (det == "") det=entry
  else det=det "<br>" entry
  next
}

# URL http... -> verdict=... reason=...
$0 ~ /^.*URL https?:\/\//{
  url=$0
  sub(/^.*URL[ \t]+/,"",url)
  split(url,u," ")
  url=u[1]

  verdict=$0
  sub(/^.*verdict=/,"",verdict)
  split(verdict,v," ")
  verdict=v[1]

  reason=$0
  sub(/^.*reason=/,"",reason)

  entry="URL: " url " (" verdict ")"
  if (reason != "" && reason != $0) entry=entry "<br><span class=\"muted\">" reason "</span>"

  if (det == "") det=entry
  else det=det "<br>" entry
  next
}

# Moved UID=51 to label 'SUSPEITOS'
$0 ~ /Moved UID=/{
  moved_uid=$0
  sub(/^.*Moved UID=/,"",moved_uid)
  split(moved_uid,a," ")
  moved_uid=a[1]

  moved_label=$0
  sub(/^.*label '\''/,"",moved_label)
  sub(/'\''.*$/,"",moved_label)

  if (uid != "" && moved_uid == uid) {
    if (subject == "") subject="(no subject)"
    if (from == "") from="(unknown)"
    if (det == "") det="(no attachments/urls detected)"
    print moved_label "\t" uid "\t" subject "\t" from "\t" det
  }
  next
}
' > "$tmp_tsv" || true

count_label() {
  local L="$1"
  awk -F'\t' -v L="$L" '$1==L{c++} END{print c+0}' "$tmp_tsv" 2>/dev/null || echo 0
}

count_clean="$(count_label "${LABEL_CLEAN:-NAO_INFETADOS}")"
count_susp="$(count_label "${LABEL_SUSPECT:-SUSPEITOS}")"
count_inf="$(count_label "${LABEL_INFECTED:-INFETADOS}")"

# Build HTML
{
cat <<HTML
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>GMA Report $ts</title>
  <style>
    body{font-family:Arial, sans-serif; margin:20px; background:#fafafa;}
    .card{background:#fff; border:1px solid #e6e6e6; border-radius:14px; padding:16px; margin-bottom:14px; box-shadow:0 1px 2px rgba(0,0,0,.03);}
    .top{display:flex; gap:12px; flex-wrap:wrap;}
    .pill{padding:8px 12px; border-radius:999px; border:1px solid #e6e6e6; background:#fff;}
    h2{margin:0 0 10px 0;}
    h3{margin:0 0 8px 0;}
    .muted{color:#666; font-size:12px;}
    .list{margin:0; padding-left:18px;}
    .item{margin:10px 0;}
    .label{font-weight:700;}
    .small{font-size:13px;}
    details{background:#fff; border:1px solid #eee; border-radius:12px; padding:10px 12px; margin-top:10px;}
    summary{cursor:pointer; font-weight:700;}
    .empty{color:#666; font-style:italic;}
    .det{margin-top:6px; line-height:1.35;}
  </style>
</head>
<body>

<div class="card">
  <h2>GMA — Relatório</h2>
  <div class="muted">Timestamp: $ts • Host: $(hostname) • CUCKOO: ${CUCKOO_URL:-"(not set)"} • DRY_RUN: ${DRY_RUN:-"(not set)"} • URL_ANALYSIS: ${ENABLE_URL_ANALYSIS:-0}</div>
</div>

<div class="card">
  <h3>Resumo por label</h3>
  <div class="top">
    <div class="pill"><span class="label">${LABEL_INFECTED:-INFETADOS}</span>: ${count_inf} encontrados</div>
    <div class="pill"><span class="label">${LABEL_SUSPECT:-SUSPEITOS}</span>: ${count_susp} encontrados</div>
    <div class="pill"><span class="label">${LABEL_CLEAN:-NAO_INFETADOS}</span>: ${count_clean} encontrados</div>
  </div>
</div>
HTML

print_section() {
  local label="$1"
  local title="$2"

  echo "<div class=\"card\">"
  echo "  <h3>${title}</h3>"

  if ! awk -F'\t' -v L="$label" '$1==L{found=1} END{exit !found}' "$tmp_tsv"; then
    echo "  <div class=\"empty\">Sem emails nesta categoria.</div>"
    echo "</div>"
    return
  fi

  echo "  <ul class=\"list\">"
  awk -F'\t' -v L="$label" '
    $1==L{
      uid=$2; subj=$3; from=$4; det=$5;

      gsub(/&/,"\\&amp;",uid); gsub(/</,"\\&lt;",uid); gsub(/>/,"\\&gt;",uid);
      gsub(/&/,"\\&amp;",subj); gsub(/</,"\\&lt;",subj); gsub(/>/,"\\&gt;",subj);
      gsub(/&/,"\\&amp;",from); gsub(/</,"\\&lt;",from); gsub(/>/,"\\&gt;",from);

      printf "    <li class=\"item\">"
      printf "<div class=\"small\"><b>UID:</b> %s</div>", uid
      printf "<div class=\"small\"><b>Subject:</b> %s</div>", subj
      if (from != "") printf "<div class=\"small\"><b>From:</b> %s</div>", from
      printf "<details><summary>Anexos / URLs</summary><div class=\"small det\">%s</div></details>", det
      printf "</li>\n"
    }
  ' "$tmp_tsv"
  echo "  </ul>"
  echo "</div>"
}

print_section "${LABEL_INFECTED:-INFETADOS}" "INFETADOS"
print_section "${LABEL_SUSPECT:-SUSPEITOS}" "SUSPEITOS"
print_section "${LABEL_CLEAN:-NAO_INFETADOS}" "NÃO INFETADOS"

cat <<HTML
</body>
</html>
HTML
} > "$report"

echo "$report"
