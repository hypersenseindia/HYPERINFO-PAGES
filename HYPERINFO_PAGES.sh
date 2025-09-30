#!/usr/bin/env bash
# HYPERINFO_PAGES.sh
# HYPERINFO — page-by-page GUI report for single IP/hostname
# Developer: MASTER S ASWIN
# Protect code: 321
# Usage: chmod +x HYPERINFO_PAGES.sh && ./HYPERINFO_PAGES.sh

set -euo pipefail
IFS=$'\n\t'

PASSCODE_EXPECTED="321"
REPORT_DIR=".hyperinfo_pages"
mkdir -p "$REPORT_DIR"

SHODAN_API_KEY="${SHODAN_API_KEY:-}"
HUNTER_API_KEY="${HUNTER_API_KEY:-}"
IPINFO_TOKEN="${IPINFO_TOKEN:-}"

# helper: require command
require_cmd(){ command -v "$1" >/dev/null 2>&1 || echo "[WARN] missing: $1" >&2; }

require_cmd dialog
require_cmd curl
require_cmd jq
require_cmd whois
require_cmd nslookup
require_cmd openssl

# small visual helpers
ascii_bar(){
  # ascii_bar value max width -> returns string of █
  local val=$1 max=$2 width=${3:-30}
  if [[ $max -le 0 ]]; then max=1; fi
  local len=$(( (val * width) / max ))
  local bar=""
  for ((i=0;i<len;i++)); do bar+="█"; done
  printf "%s" "$bar"
}

pause_msg(){ dialog --msgbox "$1" 8 60; }

# 1) passcode
PASS=$(dialog --title "HYPERINFO - PAGES" --insecure --inputbox "Enter passcode:" 8 40 3>&1 1>&2 2>&3 3>&-)
if [[ "$PASS" != "$PASSCODE_EXPECTED" ]]; then
  dialog --msgbox "Wrong passcode. Exiting." 6 40
  clear
  exit 1
fi

# 2) target
TARGET=$(dialog --title "HYPERINFO - PAGES" --inputbox "IP or hostname:" 8 50 3>&1 1>&2 2>&3 3>&-)
if [[ -z "$TARGET" ]]; then
  dialog --msgbox "No target. Exiting." 6 40
  clear
  exit 1
fi

# safe name
SAFE=$(echo "$TARGET" | tr -c 'A-Za-z0-9._-' '_')
TS=$(date +"%Y%m%d_%H%M%S")
BASE="$REPORT_DIR/$SAFE_$TS"
mkdir -p "$REPORT_DIR"

# files for pages
FILE_OVERVIEW="$BASE.overview.txt"
FILE_WHOIS="$BASE.whois.txt"
FILE_GEO="$BASE.geo.txt"
FILE_PTR="$BASE.ptr.txt"
FILE_CERTS="$BASE.certs.txt"
FILE_SHODAN="$BASE.shodan.txt"
FILE_PORTS="$BASE.ports.txt"
FILE_EXTRACT="$BASE.extract.txt"
FILE_SUM="$BASE.summary.txt"

# collect data (passive)
echo "HYPERINFO PAGES Report" > "$FILE_OVERVIEW"
echo "Target: $TARGET" >> "$FILE_OVERVIEW"
echo "Generated: $(date -u) UTC" >> "$FILE_OVERVIEW"
echo "----------------------------------------" >> "$FILE_OVERVIEW"

# resolve IP
RESOLVED="$TARGET"
if [[ "$TARGET" =~ [a-zA-Z] ]]; then
  RESOLVED=$(getent ahosts "$TARGET" 2>/dev/null | awk '/STREAM|RAW|STREAM/ {print $1; exit}' || true)
  if [[ -z "$RESOLVED" ]]; then
    RESOLVED=$(dig +short A "$TARGET" | head -n1 || true)
    [[ -z "$RESOLVED" ]] && RESOLVED="$TARGET"
  fi
fi
echo "Resolved IP: $RESOLVED" | tee -a "$FILE_OVERVIEW"

# WHOIS
echo "Collecting WHOIS..." >/dev/null
{
  echo "----- WHOIS -----"
  whois "$RESOLVED" 2>/dev/null || echo "whois failed"
} > "$FILE_WHOIS"

# GeoIP (ipinfo or ip-api)
{
  echo "----- GEOIP -----"
  if [[ -n "$IPINFO_TOKEN" ]]; then
    curl -s "https://ipinfo.io/${RESOLVED}/json?token=${IPINFO_TOKEN}" || echo "ipinfo failed"
  else
    curl -s "http://ip-api.com/json/${RESOLVED}?fields=status,country,regionName,city,zip,lat,lon,isp,org,as,query" || echo "ip-api failed"
  fi
} > "$FILE_GEO"

# PTR
{
  echo "----- PTR -----"
  dig +short -x "$RESOLVED" || nslookup "$RESOLVED" 2>/dev/null | sed -n '1,6p'
} > "$FILE_PTR"

# TLS certs via crt.sh / openssl SANs
{
  echo "----- crt.sh results (domains) -----"
  curl -s "https://crt.sh/?q=%25${TARGET}&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sed '/^$/d' | sort -u | sed 's/,/\n/g' || echo "crt.sh query failed"
  echo
  echo "----- TLS cert SANs (direct) -----"
  if timeout 5 bash -c "</dev/tcp/${RESOLVED}/443" >/dev/null 2>&1; then
    echo | openssl s_client -connect "${RESOLVED}:443" -servername "$TARGET" 2>/dev/null | openssl x509 -noout -text 2>/dev/null | grep -E "DNS:|Subject:" | sed 's/ *, */\n/g' || true
  else
    echo "port 443 not reachable"
  fi
} > "$FILE_CERTS"

# Shodan (if key)
if [[ -n "$SHODAN_API_KEY" ]]; then
  curl -s "https://api.shodan.io/shodan/host/${RESOLVED}?key=${SHODAN_API_KEY}" > "$FILE_SHODAN" || echo "shodan request failed" > "$FILE_SHODAN"
else
  echo "Shodan key not set" > "$FILE_SHODAN"
fi

# DNSBL simple check (spamhaus etc)
{
  echo "----- DNSBL -----"
  if [[ "$RESOLVED" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    I1=${BASH_REMATCH[1]}; I2=${BASH_REMATCH[2]}; I3=${BASH_REMATCH[3]}; I4=${BASH_REMATCH[4]}
    REV="$I4.$I3.$I2.$I1"
    for bl in zen.spamhaus.org bl.spamcop.net dnsbl.sorbs.net; do
      chk=$(dig +short "${REV}.${bl}" A || true)
      if [[ -n "$chk" ]]; then
        echo "$bl: LISTED ($chk)"
      else
        echo "$bl: not listed"
      fi
    done
  else
    echo "Not IPv4 - DNSBL skipped"
  fi
} >> "$FILE_OVERVIEW"

# Ports (nmap) - optional - quick scan if nmap exists
if command -v nmap >/dev/null 2>&1; then
  echo "Running quick nmap..." >/dev/null
  nmap -Pn --min-rate 1000 -T4 -F "$RESOLVED" -oG - 2>/dev/null | tee "$FILE_PORTS"
else
  echo "nmap not installed" > "$FILE_PORTS"
fi

# Extract emails / phones / socials from WHOIS, Shodan, certs
{
  echo "----- Extracted Contacts -----"
  cat "$FILE_WHOIS" "$FILE_SHODAN" "$FILE_CERTS" 2>/dev/null | \
    grep -Eio "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}" | sort -u | sed -n '1,200p' || true
  echo
  cat "$FILE_WHOIS" "$FILE_SHODAN" "$FILE_CERTS" 2>/dev/null | \
    grep -Eo "\+?[0-9][0-9\-\(\) ]{6,}[0-9]" | sed 's/[()]//g' | tr -s ' ' | sort -u | sed -n '1,200p' || true
  echo
  cat "$FILE_WHOIS" "$FILE_SHODAN" "$FILE_CERTS" 2>/dev/null | \
    grep -Eio "(twitter.com/[A-Za-z0-9_/-]+|instagram.com/[A-Za-z0-9_./-]+|facebook.com/[A-Za-z0-9_./-]+|linkedin.com/in/[A-Za-z0-9_/-]+|github.com/[A-Za-z0-9_/-]+)" | sort -u | sed -n '1,200p' || true
} > "$FILE_EXTRACT"

# Build summary and small charts
{
  echo "HYPERINFO — Summary for $TARGET"
  echo "Generated: $(date -u) UTC"
  echo
  # Geo brief
  if [[ -s "$FILE_GEO" ]]; then
    GEOJSON=$(cat "$FILE_GEO")
    echo "Geo Info:"
    echo "$GEOJSON" | sed -n '1,6p'
    lat=$(echo "$GEOJSON" | jq -r '.lat // .latitude // empty' 2>/dev/null || true)
    lon=$(echo "$GEOJSON" | jq -r '.lon // .longitude // empty' 2>/dev/null || true)
    # simple lat/lon bars
    if [[ -n "$lat" && -n "$lon" ]]; then
      latv=${lat/./}; lonv=${lon/./}
      # Normalize small numeric values to 0..100
      latn=$(awk -v v="$lat" 'BEGIN{printf("%d", (v+90)*1)}')
      lonn=$(awk -v v="$lon" 'BEGIN{printf("%d", (v+180)*1)}')
      echo
      echo "Latitude: $lat  [$(ascii_bar $latn 180 40)]"
      echo "Longitude: $lon [$(ascii_bar $lonn 360 40)]"
    fi
  fi
  echo
  # Ports chart
  if [[ -s "$FILE_PORTS" ]]; then
    echo "Open Ports (quick nmap):"
    # parse greppable output or raw nmap
    ports=$(grep -E "Ports:" "$FILE_PORTS" 2>/dev/null || true)
    if [[ -n "$ports" ]]; then
      # example: Ports: 22/open/tcp//ssh//,80/open/tcp//http//
      portlist=$(echo "$ports" | sed 's/Ports: //' | tr ',' '\n' | grep -E "open" | awk -F'/' '{print $1}' | tr '\n' ' ')
      count=$(echo "$portlist" | wc -w)
      echo "Open ports: $portlist"
      echo "Count: $count [$(ascii_bar $count 50 40)]"
    else
      # fallback count lines with /open/
      count=$(grep -E "/open/" -c "$FILE_PORTS" || true)
      echo "Open ports count (parsed): $count [$(ascii_bar $count 50 40)]"
    fi
  else
    echo "No port scan results."
  fi
  echo
  # Services from shodan (if present)
  if [[ -f "$FILE_SHODAN" && -s "$FILE_SHODAN" ]]; then
    echo "Shodan quick services summary (if available):"
    jq -r '.data[]?.product // .data[]?.service // empty' "$FILE_SHODAN" 2>/dev/null | sort -u | sed -n '1,10p' || echo "none"
  fi
  echo
  # Contacts summary
  echo "Contacts (emails/phones/socials) — top lines:"
  sed -n '1,12p' "$FILE_EXTRACT" || true
} > "$FILE_SUM"

# Now page GUI: present menu with pages
while true; do
  CHOICE=$(dialog --title "HYPERINFO — Pages for $TARGET" --menu "View sections (open each page):" 20 70 12 \
    1 "Overview" \
    2 "WHOIS (raw)" \
    3 "GeoIP (json/summary)" \
    4 "PTR (reverse DNS)" \
    5 "TLS Certs (crt.sh + SANs)" \
    6 "Shodan raw" \
    7 "Open Ports (scan)" \
    8 "Extracted Contacts" \
    9 "Summary + Charts" \
    10 "Save & Exit" 3>&1 1>&2 2>&3 3>&-)

  case $CHOICE in
    1) dialog --title "Overview" --textbox "$FILE_OVERVIEW" 20 70 ;;
    2) dialog --title "WHOIS" --textbox "$FILE_WHOIS" 20 80 ;;
    3) dialog --title "GeoIP" --textbox "$FILE_GEO" 20 70 ;;
    4) dialog --title "PTR" --textbox "$FILE_PTR" 10 60 ;;
    5) dialog --title "Certificates" --textbox "$FILE_CERTS" 20 80 ;;
    6) dialog --title "Shodan (raw)" --textbox "$FILE_SHODAN" 20 80 ;;
    7) dialog --title "Open Ports" --textbox "$FILE_PORTS" 20 80 ;;
    8) dialog --title "Contacts" --textbox "$FILE_EXTRACT" 20 80 ;;
    9) dialog --title "Summary & Charts" --textbox "$FILE_SUM" 20 80 ;;
    10) clear; echo "Report files in $REPORT_DIR"; exit 0 ;;
    *) dialog --msgbox "Invalid option" 6 40 ;;
  esac
done
