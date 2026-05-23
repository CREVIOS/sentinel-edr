#!/usr/bin/env bash
# End-to-end pipeline assertions against a running Sentinel server.
# Verifies: enrollment → ingest → detection (Sigma + behavioral + DLP) → auto-response
# → SIEM export. Exits non-zero on any failed assertion.
set -uo pipefail

URL="${SENTINEL_URL:-http://localhost:8080}"
USER="${SENTINEL_ADMIN_USER:-admin}"
PASS="${SENTINEL_ADMIN_PASS:-sentinel-admin}"
DEADLINE=$(( $(date +%s) + 90 ))
PASS_N=0; FAIL_N=0

j() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)" 2>/dev/null; }

login() {
  curl -s -X POST "$URL/api/v1/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" | j "d.get('token','')"
}

echo "▶ authenticating to $URL"
TOKEN=""
while [ -z "$TOKEN" ] && [ "$(date +%s)" -lt "$DEADLINE" ]; do
  TOKEN=$(login); [ -z "$TOKEN" ] && sleep 2
done
[ -z "$TOKEN" ] && { echo "✗ could not authenticate"; exit 1; }
AUTH=(-H "Authorization: Bearer $TOKEN")
echo "✓ authenticated"

check() { # name  jqexpr  expected_min
  local name="$1" expr="$2" min="$3" url="$4"
  local n; n=$(curl -s "${AUTH[@]}" "$URL$url" | j "$expr")
  n=${n:-0}
  if [ "$n" -ge "$min" ] 2>/dev/null; then
    echo "  ✓ $name = $n (>= $min)"; PASS_N=$((PASS_N+1))
  else
    echo "  ✗ $name = $n (want >= $min)"; FAIL_N=$((FAIL_N+1))
  fi
}

echo "▶ waiting for telemetry to flow…"
ok=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  d=$(curl -s "${AUTH[@]}" "$URL/api/v1/detections?limit=500" | j "len(d)")
  [ "${d:-0}" -gt 0 ] && { ok=1; sleep 6; break; }   # let auto-response settle
  sleep 3
done
[ "$ok" -eq 0 ] && echo "  (no detections yet — is an agent running with --scenario?)"

echo "▶ assertions"
check "endpoints enrolled"     "len(d)"                                   1 "/api/v1/agents"
check "events stored"          "len(d)"                                   1 "/api/v1/events?limit=500"
check "detections raised"      "len(d)"                                   1 "/api/v1/detections?limit=500"
check "critical detections"    "len([x for x in d if x['severity']=='critical'])" 1 "/api/v1/detections?limit=500"
check "behavioral detections"  "len([x for x in d if x['engine']=='behavior'])"   1 "/api/v1/detections?limit=500"
check "dlp detections"         "len([x for x in d if x['engine']=='dlp'])"        1 "/api/v1/detections?limit=500"
check "response actions"       "len(d)"                                   1 "/api/v1/responses"

# specific rule presence
RULES=$(curl -s "${AUTH[@]}" "$URL/api/v1/detections?limit=500")
for rid in proc-reverse-shell behavior-ssh-bruteforce; do
  if echo "$RULES" | j "any(x['rule_id']=='$rid' for x in d)" | grep -qi true; then
    echo "  ✓ rule fired: $rid"; PASS_N=$((PASS_N+1))
  else
    echo "  ✗ rule missing: $rid"; FAIL_N=$((FAIL_N+1))
  fi
done

# SIEM export non-empty
LINES=$(curl -s "${AUTH[@]}" "$URL/api/v1/siem/export?kind=detections&format=cef" | grep -c "CEF:0")
if [ "${LINES:-0}" -ge 1 ]; then echo "  ✓ SIEM CEF export ($LINES lines)"; PASS_N=$((PASS_N+1));
else echo "  ✗ SIEM CEF export empty"; FAIL_N=$((FAIL_N+1)); fi

echo "────────────────────────────────"
echo "  PASS: $PASS_N   FAIL: $FAIL_N"
[ "$FAIL_N" -eq 0 ] && echo "✓ end-to-end PASSED" || { echo "✗ end-to-end FAILED"; exit 1; }
