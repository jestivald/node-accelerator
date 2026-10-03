#!/usr/bin/env bash
#
# na-report-unit.sh — ИСПОЛНЯЕТ scripts/na-report.sh (--json и человекочитаемый отчёт) против
# стабов journalctl/nft/cscli/whois/dig. Что стережём (v4.2, аудит флота):
#   1. CrowdSec считается по строкам `decisions list -o raw` с числовым id: заголовок CSV
#      и запятая в имени AS не в счёт, а `"value"` из `-o json` (×33 на ноде флота) — тем
#      более; отдельно `-a` (с CAPI/списками) → crowdsec_decisions_all;
#   2. ban_rate_5m сохранён (совместимость), рядом честные events_5m и unique_src_5m;
#   3. asn_enrichment: ok | partial | unavailable — «ASN пуст» отличим от «не спросили»;
#   4. строки JSON экранируются через json_escape: управляющий символ в имени AS из whois
#      не ломает документ; новые поля — только в хвосте.
#
# Не требует root/сети/nft/CrowdSec. Запуск: bash tests/na-report-unit.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
BIN="$T/bin"; mkdir -p "$BIN"
export NA_T="$T"

pick_bash() {
    local c
    for c in bash /opt/homebrew/bin/bash /usr/local/bin/bash; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" -c 'set -u; a=(); : "${a[@]}"; [[ -v HOME ]]' 2>/dev/null; then command -v "$c"; return 0; fi
    done
    return 1
}
WBASH="$(pick_bash)" || { echo "[x] не нашёл bash ≥ 4.4"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "[x] нужен python3 для валидации JSON"; exit 1; }

NOW="$(date +%s)"
# drop-лог: 3 события за последние 5 минут от 2 адресов + 2 старых (час назад) от третьего
{
  printf '%s.000001 node kernel: [na portscan] IN=eth0 OUT= SRC=203.0.113.10 DST=192.0.2.1 PROTO=TCP DPT=22\n' "$(( NOW - 100 ))"
  printf '%s.000001 node kernel: [na portscan] IN=eth0 OUT= SRC=203.0.113.10 DST=192.0.2.1 PROTO=TCP DPT=23\n' "$(( NOW - 90 ))"
  printf '%s.000001 node kernel: [na synflood] IN=eth0 OUT= SRC=203.0.113.20 DST=192.0.2.1 PROTO=TCP DPT=443\n' "$(( NOW - 80 ))"
  printf '%s.000001 node kernel: [na portscan] IN=eth0 OUT= SRC=198.51.100.30 DST=192.0.2.1 PROTO=TCP DPT=25\n' "$(( NOW - 3000 ))"
  printf '%s.000001 node kernel: [na portscan] IN=eth0 OUT= SRC=198.51.100.30 DST=192.0.2.1 PROTO=TCP DPT=26\n' "$(( NOW - 3100 ))"
} > "$T/klog"

cat > "$BIN/journalctl" <<'JC'
#!/bin/sh
case "$*" in
  *"-k -b all"*) cat "$NA_T/klog" ;;
  *short-unix*)  printf '%s.000000 node kernel: Linux version\n' "$(( $(date +%s) - 72*3600 ))" ;;
esac
exit 0
JC
cat > "$BIN/nft" <<'NF'
#!/bin/sh
case "$*" in
  "list set inet na_filter autoban_v4")
      printf 'table inet na_filter {\n\tset autoban_v4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t\telements = { 203.0.113.10 timeout 1d expires 23h }\n\t}\n}\n' ;;
esac
exit 0
NF
# 2 локальных решения (имя AS с запятой — внутри кавычек CSV), с -a ещё 33 CAPI. В -o json
# у каждого решения несколько полей "value" — по ним v4.1 и насчитывал ×N.
cat > "$BIN/cscli" <<'CS'
#!/bin/sh
case "$*" in
  "decisions list -o raw"|"decisions list -a -o raw")
    echo "id,source,ip,reason,action,country,as,events_count,expiration,simulated,alert_id"
    echo '1,crowdsec,Ip:203.0.113.10,crowdsecurity/ssh-bf,ban,ZZ,"64500 EXAMPLE, Inc",5,3h,false,1'
    echo '2,cscli,Ip:203.0.113.20,manual,ban,ZZ,,0,24h,false,2'
    if [ "$*" = "decisions list -a -o raw" ]; then
        i=0; while [ "$i" -lt 33 ]; do i=$((i+1)); echo "$((100+i)),CAPI,Ip:198.18.0.$i,crowdsecurity/http-probing,ban,,,0,160h,false,0"; done
    fi ;;
  "decisions list -o json")
    i=0; while [ "$i" -lt 2 ]; do i=$((i+1)); printf '{"decisions":[{"value":"x","scope":"Ip"}],"source":{"value":"y"},"meta":[{"value":"z"}]}\n'; done ;;
esac
exit 0
CS
# whois (bulk-режим Cymru): NA_TEST_WHOIS = all | first | none. В имени AS — управляющий
# символ (\001) и таб: сырой он ломал JSON.
cat > "$BIN/whois" <<'WH'
#!/bin/sh
in="$(cat)"
mode="${NA_TEST_WHOIS:-all}"
[ "$mode" = none ] && exit 0
echo "Bulk mode; whois.cymru.com [2026-10-03 00:00:00 +0000]"
n=0
for ip in $(printf '%s\n' "$in" | grep -E '^[0-9]+\.'); do
    n=$((n+1))
    [ "$mode" = first ] && [ "$n" -gt 1 ] && break
    printf '64500   | %s | 203.0.113.0/24 | ZZ | arin | 2000-01-01 | EXAMPLE\001NET\tSUB, ZZ\n' "$ip"
done
WH
printf '#!/bin/sh\nexit 1\n' > "$BIN/dig"
chmod +x "$BIN"/*
export PATH="$BIN:$PATH"

PASS=0; FAIL=0
check() { if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); echo "  ok   $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1: ожидалось [$2], получено [$3]"; fi; }
jget() {
    python3 - "$1" "$2" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("<НЕВАЛИДНЫЙ JSON: %s>" % e); sys.exit(0)
v = d
for k in sys.argv[2].split("."):
    v = v.get(k, "<НЕТ ПОЛЯ>") if isinstance(v, dict) else "<НЕТ ПОЛЯ>"
print(v)
PY
}
R="$REPO_ROOT/scripts/na-report.sh"

echo "== 1. --json: CrowdSec, честные метрики 5 мин, ASN (v4.2) =="
NA_TEST_WHOIS=all TERM=dumb "$WBASH" "$R" --json > "$T/o1.json" 2>"$T/e1" || true
check "одна строка"                                     1 "$(wc -l < "$T/o1.json" | tr -d ' ')"
check "JSON валиден (управляющий символ в имени AS экранирован)" ok \
      "$(python3 -c 'import json,sys; json.load(open(sys.argv[1])); print("ok")' "$T/o1.json" 2>&1 | tail -1)"
check "drops_by_reason.crowdsec = 2 локальных (не ×N по \"value\")" 2 "$(jget "$T/o1.json" drops_by_reason.crowdsec)"
check "crowdsec_decisions_all = 35 (с CAPI)"            35 "$(jget "$T/o1.json" crowdsec_decisions_all)"
check "ban_rate_5m сохранён (совместимость) = 3"         3 "$(jget "$T/o1.json" ban_rate_5m)"
check "events_5m = 3"                                    3 "$(jget "$T/o1.json" events_5m)"
check "unique_src_5m = 2"                                2 "$(jget "$T/o1.json" unique_src_5m)"
check "asn_enrichment = ok"                              ok "$(jget "$T/o1.json" asn_enrichment)"
check "top_asn: имя без управляющего символа, таб не рвёт строку" "EXAMPLE" \
      "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["top_asn"][0]["name"].split("\t")[0][:7])' "$T/o1.json")"
check "новые поля — строго в хвосте, после top_ips" ok "$(python3 - "$T/o1.json" <<'PY'
import json, sys
k = list(json.load(open(sys.argv[1])))
i = k.index("top_ips")
print("ok" if k[i+1:] == ["events_5m", "unique_src_5m", "crowdsec_decisions_all", "asn_enrichment"] else k[i+1:])
PY
)"

echo "== 2. asn_enrichment: partial и unavailable =="
NA_TEST_WHOIS=first TERM=dumb "$WBASH" "$R" --json > "$T/o2.json" 2>/dev/null || true
check "обогащён 1 из 3 адресов → partial" partial "$(jget "$T/o2.json" asn_enrichment)"
NA_TEST_WHOIS=none TERM=dumb "$WBASH" "$R" --json > "$T/o3.json" 2>/dev/null || true
check "Cymru не ответил → unavailable" unavailable "$(jget "$T/o3.json" asn_enrichment)"

echo "== 3. человекочитаемый отчёт =="
NA_TEST_WHOIS=none TERM=dumb "$WBASH" "$R" > "$T/o4.txt" 2>/dev/null || true
txt="$(sed $'s/\033\\[[0-9;]*m//g' "$T/o4.txt")"
if grep -qF 'за 5 мин: 3 от 2 адрес(ов)' <<<"$txt"; then PASS=$((PASS+1)); echo "  ok   шапка: события и уникальные адреса за 5 мин"
else FAIL=$((FAIL+1)); echo "  FAIL шапка без уникальных адресов за 5 мин"; fi
if grep -qF '2 активных локальных решений (с CAPI/списками: 35)' <<<"$txt"; then PASS=$((PASS+1)); echo "  ok   crowdsec: локальные и с CAPI раздельно"
else FAIL=$((FAIL+1)); echo "  FAIL crowdsec: нет строки «2 активных локальных решений (с CAPI/списками: 35)»"; fi
if grep -qF 'ASN не обогащён: Team Cymru не ответил' <<<"$txt"; then PASS=$((PASS+1)); echo "  ok   ASN: «не ответил» отличим от «нет dig/whois»"
else FAIL=$((FAIL+1)); echo "  FAIL ASN: нет пояснения про неответивший Cymru"; fi

echo
echo "  прогон: $PASS ok, $FAIL fail"
if [[ "$FAIL" -ne 0 ]]; then echo "NA-REPORT-UNIT: FAIL"; exit 1; fi
echo "NA-REPORT-UNIT: OK (CrowdSec по строкам raw, честные метрики 5 мин, asn_enrichment, JSON экранирован)"
