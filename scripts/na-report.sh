#!/usr/bin/env bash
#
# na-report.sh — 🔥 форензика атак на ноду (read-only): кто, откуда, чем, когда.
# Источники — данные, которые УЖЕ есть на ноде: журнал ядра (nft log prefix
# "[na …]"), nft-сеты (autoban/suspect/blocklist), CrowdSec-решения. Обогащение
# ASN/гео — Team Cymru whois (best-effort: нет whois/сети → пропускаем).
#
#   na-report.sh                 — человекочитаемый отчёт (окно 24ч)
#   na-report.sh --json          — один JSON-объект для панели/мониторинга
#   na-report.sh --hours 6       — окно анализа 6 часов
#   na-report.sh --top 20        — сколько top-IP/ASN показывать
#   na-report.sh --ip 1.2.3.4    — глубокий вердикт по IP (rDNS, nft-сеты, conntrack, таймлайн)
#   na-report.sh --port 443      — топ дроп-источников по порту + кто слушает
#   na-report.sh --proxyware     — self-audit: следы proxyware/residential-proxy (для abuse-тикетов; + --json)
#
# JSON-схема:
#   {window_hours, generated_at, events_total, ban_rate_5m,
#    drops_by_reason{portscan,synflood,ssh-flood,badflags,crowdsec},
#    timeline[12],                                  # последние 60 мин, бакеты по 5 мин
#    top_asn[{asn,name,country,pct}], top_ips[{ip,asn,country,hits,verdict}],
#    events_5m, unique_src_5m, crowdsec_decisions_all, asn_enrichment}
#   ban_rate_5m — исторически так названное ЧИСЛО СОБЫТИЙ drop-лога за 5 мин (не банов);
#   оставлено ради совместимости, честные имена — events_5m / unique_src_5m.
#   drops_by_reason.crowdsec — активные ЛОКАЛЬНЫЕ решения CrowdSec; crowdsec_decisions_all
#   — вместе с CAPI/списками (-1 = cscli нет). asn_enrichment: ok|partial|unavailable.
#
# JSON-схема (--proxyware --json):
#   {verdict:"clean|suspect", generated_at,
#    hits{processes[],services[],cron[],files[],docker[]},
#    c2_connections[], external_listeners[]}

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

# ─── Аргументы ────────────────────────────────────────────────────────────────
JSON=0; HOURS=24; TOPN=15; FOCUS_IP=""; FOCUS_PORT=""; PROXYAUDIT=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) JSON=1 ;;
        --hours) HOURS="${2:-24}"; shift ;;
        --top) TOPN="${2:-15}"; shift ;;
        --ip) FOCUS_IP="${2:-}"; shift ;;
        --port) FOCUS_PORT="${2:-}"; shift ;;
        --proxyware) PROXYAUDIT=1 ;;
        -h|--help) awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; exit 0 ;;
        *) err "Неизвестный аргумент: $1"; exit 1 ;;
    esac
    shift
done
[[ "$HOURS" =~ ^[0-9]+$ && "$HOURS" -ge 1 && "$HOURS" -le 720 ]] || { err "--hours 1..720"; exit 1; }
[[ "$TOPN"  =~ ^[0-9]+$ && "$TOPN" -ge 1 && "$TOPN" -le 100 ]] || { err "--top 1..100"; exit 1; }
[[ -z "$FOCUS_PORT" || "$FOCUS_PORT" =~ ^[0-9]+$ ]] || { err "--port должен быть числом"; exit 1; }

NOW="$(date +%s)"
# Глубина журнала в часах (возраст самой старой записи; -1 = не измерить). Без неё
# оператор не отличает «атак не было» от «журнал уже вытеснен» — на публичной ноде
# лог анти-скана съедал 300M меньше чем за сутки (issue #35/#41).
journal_span_h() {
    local first
    command -v journalctl >/dev/null 2>&1 || { echo -1; return 0; }
    first="$(journalctl -q --no-pager -o short-unix 2>/dev/null | head -n1 | awk '{print $1}' | cut -d. -f1)"
    [[ "$first" =~ ^[0-9]+$ && "$NOW" -gt "$first" ]] || { echo -1; return 0; }
    echo $(( (NOW - first) / 3600 ))
}
JSPAN="$(journal_span_h)"
TMP="$(mktemp "${TMPDIR:-/tmp}/na-report.XXXXXX")"
trap 'rm -f "$TMP" "$TMP".ab' EXIT

# ─── 1. Парс журнала: nft log "[na <reason>]" → TSV  epoch \t reason \t src ──────
# Только loggable-причины несут SRC= (autoban/blocklist дропают без лога — для них
# есть счётчики/сеты). Окно --hours.
# `-b all` обязателен: `-k` подразумевает `-b` (ТОЛЬКО текущая загрузка), и после ребута
# отчёт «за 24ч» молча становился отчётом «с момента загрузки» — на ноде флота 2 298
# событий против 72 485 реальных, ×31 (issue #41). Граница по времени (--since) остаётся.
collect_events() {
    journalctl -k -b all --since "-${HOURS}h" --no-pager -o short-unix 2>/dev/null \
      | grep -aF '[na ' \
      | sed -nE 's/^([0-9]+)\.[0-9]+ .*\[na ([a-z-]+)\].*SRC=([0-9a-fA-F.:]+).*/\1\t\2\t\3/p' \
      > "$TMP" || true
}

# ─── helpers ──────────────────────────────────────────────────────────────────
# Через общий json_escape: сырой \r/\t из ответа whois (имя AS) ломал бы документ.
json_str() { json_escape "$1"; }

# Множество забаненных (autoban v4+v6) — для вердикта.
load_autoban() {
    { nft list set inet na_filter autoban_v4 2>/dev/null
      nft list set inet na_filter autoban_v6 2>/dev/null
    } | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}|([0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}' \
      | sort -u > "$TMP".ab || true
}
is_banned() { grep -qxF "$1" "$TMP".ab 2>/dev/null; }

count_reason() { awk -F'\t' -v r="$1" '$2==r{c++} END{print c+0}' "$TMP"; }
events_total() { wc -l < "$TMP" | tr -d ' '; }
ban_rate_5m()  { awk -F'\t' -v now="$NOW" '$1>=now-300{c++} END{print c+0}' "$TMP"; }
# уникальные источники за 5 мин — то, что ban_rate_5m обещал названием
unique_src_5m() { awk -F'\t' -v now="$NOW" '$1>=now-300 && !s[$3]++{c++} END{print c+0}' "$TMP"; }
# crowdsec_count [-a] — активные решения CrowdSec: строки CSV `-o raw` с числовым id
# (заголовок не в счёт). Раньше считались строки `"value"` в `-o json`: одно решение
# содержит несколько таких полей — на ноде флота выходило ×33 к реальности. Без `-a` —
# только локальные (crowdsec/cscli), с `-a` — плюс CAPI/списки. Ровно ОДНО целое на
# stdout (уходит в JSON); cscli нет — 0 без `-a`, −1 с `-a`.
crowdsec_count() {
    local all="" c
    [[ "${1:-}" == -a ]] && all=-a
    command -v cscli >/dev/null 2>&1 || { [[ -n "$all" ]] && echo -1 || echo 0; return; }
    c="$(cscli decisions list $all --limit 0 -o raw 2>/dev/null | awk -F, '$1 ~ /^[0-9]+$/ {c++} END {print c+0}')"
    [[ "$c" =~ ^[0-9]+$ ]] || c=0
    echo "$c"
}
# asn_enrichment <всего IP> <обогащено> — ok | partial | unavailable: без флага «ASN
# пуст» не отличить от «атакуют адреса без ASN» (на ноде без dig/whois — всегда пусто)
asn_status() {
    local tot="$1" got="$2"
    command -v dig >/dev/null 2>&1 || command -v whois >/dev/null 2>&1 || { echo unavailable; return; }
    if (( tot == 0 )); then echo ok
    elif (( got == 0 )); then echo unavailable
    elif (( got < tot )); then echo partial
    else echo ok; fi
}

# timeline: 12 бакетов по 5 мин за последний час, число событий в каждом.
timeline_csv() {
    awk -F'\t' -v now="$NOW" '
        BEGIN{ for(i=0;i<12;i++) b[i]=0; start=now-3600 }
        $1>=start { k=int(($1-start)/300); if(k<0)k=0; if(k>11)k=11; b[k]++ }
        END{ s=""; for(i=0;i<12;i++) s=s (i?",":"") (b[i]+0); print s }
    ' "$TMP"
}

# top IP по числу попаданий: "<hits> <ip>"
top_ips_raw() { awk -F'\t' '{c[$3]++} END{for(ip in c) print c[ip], ip}' "$TMP" | sort -rn | head -n "$TOPN"; }

# ─── ASN/гео через Team Cymru (bulk, best-effort) ───────────────────────────────
# Заполняет ассоц-массивы ASN[ip] / CC[ip] / ANAME[ip]. Тихо пропускает без сети.
declare -A ASN CC ANAME

# Тот же справочник Cymru, но по DNS: origin.asn.cymru.com отдаёт «ASN | префикс | CC |…»
# для перевёрнутого адреса, asn.cymru.com — имя оператора. Медленнее bulk-режима whois
# (запрос на адрес), поэтому спрашиваем только про верхушку списка.
enrich_asn_dns() {
    command -v dig >/dev/null 2>&1 || return 0
    local ip rev txt asn name n=0
    for ip in "$@"; do
        [[ "$ip" == *:* ]] && continue          # v6 в этой схеме не спрашиваем
        [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        (( n++ > 24 )) && break                 # верхние 25 адресов отчёта
        rev="$(awk -F. '{print $4"."$3"."$2"."$1}' <<<"$ip")"
        txt="$(dig +short +time=2 +tries=1 "${rev}.origin.asn.cymru.com" TXT 2>/dev/null | head -1 | tr -d '"')"
        [[ -n "$txt" ]] || continue
        asn="$(awk -F'|' '{gsub(/ /,"",$1); print $1}' <<<"$txt")"
        [[ "$asn" =~ ^[0-9]+$ ]] || continue
        ASN["$ip"]="AS$asn"
        CC["$ip"]="$(awk -F'|' '{gsub(/ /,"",$3); print $3}' <<<"$txt")"
        name="$(dig +short +time=2 +tries=1 "AS${asn}.asn.cymru.com" TXT 2>/dev/null | head -1 | tr -d '"' \
                | awk -F'|' '{sub(/^ +/,"",$5); sub(/ +$/,"",$5); print $5}')"
        ANAME["$ip"]="${name%%,*}"
    done
}
enrich_asn() {
    local ips=("$@"); [[ ${#ips[@]} -gt 0 ]] || return 0
    # Пакета whois нет в базовой поставке Debian/Ubuntu, и тулкит его не ставит — то есть
    # на типовой ноде обогащение молча не работало никогда. У Cymru есть тот же сервис
    # через DNS, а dig на ноде уже используется (rDNS ниже), поэтому сперва пробуем его.
    if ! command -v whois >/dev/null 2>&1; then
        enrich_asn_dns "${ips[@]}"; return 0
    fi
    local query out line ip asn cc name
    query=$'begin\nverbose\n'
    for ip in "${ips[@]}"; do
        [[ "$ip" == *:* ]] && continue   # cymru bulk — v4; v6 best-effort пропустим
        query+="$ip"$'\n'
    done
    query+=$'end\n'
    out="$(printf '%s' "$query" | whois -h whois.cymru.com 2>/dev/null)" || return 0
    while IFS= read -r line; do
        # Строки данных Cymru начинаются с ГОЛОГО номера ASN ("15169  | 1.2.3.4 | …"),
        # НЕ с "AS". Старый guard `== AS*\|*` матчил только строку-ЗАГОЛОВОК → все данные
        # отбрасывались, ASN/гео всегда пустые. Берём data-строки (≥2 разделителя),
        # исключая заголовок (AS…) и служебную "Bulk mode…".
        [[ "$line" == *\|*\|* && "$line" != AS*\|* && "$line" != Bulk* ]] || continue
        asn="$(echo "$line"  | awk -F'|' '{gsub(/ /,"",$1); print $1}')"
        ip="$(echo "$line"   | awk -F'|' '{gsub(/ /,"",$2); print $2}')"
        cc="$(echo "$line"   | awk -F'|' '{gsub(/ /,"",$4); print $4}')"
        name="$(echo "$line" | awk -F'|' '{sub(/^ +/,"",$7); sub(/ +$/,"",$7); print $7}')"
        [[ -z "$ip" || "$asn" == "NA" ]] && continue
        ASN["$ip"]="AS$asn"; CC["$ip"]="$cc"; ANAME["$ip"]="${name%%,*}"
    done <<< "$out"
}

verdict() {  # verdict <ip> <hits> <maxhits>
    local ip="$1" hits="$2" max="$3" kind="suspect" conf
    is_banned "$ip" && kind="attacker"
    conf="$(awk -v h="$hits" -v m="$max" 'BEGIN{ if(m<1)m=1; c=0.5+0.49*h/m; if(c>0.99)c=0.99; printf "%.2f", c }')"
    printf '%s · %s' "$kind" "$conf"
}

# ─── JSON-режим ────────────────────────────────────────────────────────────────
emit_json() {
    collect_events; load_autoban
    local total rate tl portscan synflood sshflood badflags crowd crowd_all usrc asnst
    total="$(events_total)"; rate="$(ban_rate_5m)"; tl="$(timeline_csv)"
    portscan="$(count_reason portscan)"; synflood="$(count_reason synflood)"
    sshflood="$(count_reason ssh-flood)"; badflags="$(count_reason badflags)"
    crowd="$(crowdsec_count)"; crowd_all="$(crowdsec_count -a)"; usrc="$(unique_src_5m)"

    # top IP + ASN-обогащение
    local -a ips=() hitsarr=()
    local h ip maxhits=0
    while read -r h ip; do
        [[ -z "${ip:-}" ]] && continue
        ips+=("$ip"); hitsarr+=("$h"); [[ "$h" -gt "$maxhits" ]] && maxhits="$h"
    done < <(top_ips_raw)
    enrich_asn "${ips[@]}"
    local got=0
    for ip in "${ips[@]}"; do [[ -n "${ASN[$ip]:-}" ]] && got=$((got+1)); done
    asnst="$(asn_status "${#ips[@]}" "$got")"

    # top_ips JSON
    local ips_json="" i a c
    for i in "${!ips[@]}"; do
        ip="${ips[$i]}"; h="${hitsarr[$i]}"
        a="${ASN[$ip]:-}"; c="${CC[$ip]:-}"
        ips_json+="${ips_json:+,}{\"ip\":\"$(json_str "$ip")\",\"asn\":\"$(json_str "$a")\",\"country\":\"$(json_str "$c")\",\"hits\":$h,\"verdict\":\"$(json_str "$(verdict "$ip" "$h" "$maxhits")")\"}"
    done

    # top_asn: агрегируем хиты по ASN (среди top-IP), pct от суммы. awk только считает и
    # сортирует (TSV), JSON собирает bash через json_escape: имя AS приходит из whois/DNS
    # как есть, и экранирования одних \ и " (как было) не хватало на управляющие символы.
    local asn_json="" an anm acc apct
    # разделитель \x1f, а не таб: `IFS=$'\t' read` склеивает подряд идущие пустые поля
    # (таб — «пробельный» разделитель), и при пустой стране имя AS уезжало в country
    while IFS=$'\x1f' read -r an apct acc anm; do
        [[ -n "$an" ]] || continue
        asn_json+="${asn_json:+,}{\"asn\":\"$(json_str "$an")\",\"name\":\"$(json_str "$anm")\",\"country\":\"$(json_str "$acc")\",\"pct\":$apct}"
    done < <(
        for i in "${!ips[@]}"; do
            ip="${ips[$i]}"; printf '%s\x1f%s\x1f%s\x1f%s\n' "${ASN[$ip]:-?}" "${hitsarr[$i]}" "${CC[$ip]:-}" "${ANAME[$ip]:-}"
        done | awk -F'\037' '
            $1!="?"{ hit[$1]+=$2; cc[$1]=$3; nm[$1]=$4; tot+=$2 }
            END{
                if(tot<1) exit
                n=0; for(a in hit){ arr[n++]=a }
                # простая сортировка по hit desc
                for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(hit[arr[j]]>hit[arr[i]]){t=arr[i];arr[i]=arr[j];arr[j]=t}
                for(i=0;i<n && i<8;i++){ a=arr[i]; printf "%s\037%d\037%s\037%s\n", a, int(hit[a]*100/tot+0.5), cc[a], nm[a] }
            }'
    )

    printf '{'
    printf '"na_version":"%s","window_hours":%s,"journal_span_h":%s,"generated_at":%s,"events_total":%s,"ban_rate_5m":%s,' "${NA_VERSION:-?}" "$HOURS" "$JSPAN" "$NOW" "$total" "$rate"
    printf '"drops_by_reason":{"portscan":%s,"synflood":%s,"ssh-flood":%s,"badflags":%s,"crowdsec":%s},' \
        "$portscan" "$synflood" "$sshflood" "$badflags" "$crowd"
    printf '"timeline":[%s],' "$tl"
    printf '"top_asn":[%s],' "$asn_json"
    printf '"top_ips":[%s],' "$ips_json"
    # v4.2: новые поля — только в хвост (порядок прежних читает панель)
    printf '"events_5m":%s,"unique_src_5m":%s,"crowdsec_decisions_all":%s,"asn_enrichment":"%s"}\n' \
        "$rate" "$usrc" "$crowd_all" "$asnst"
}

# ─── Вердикт по одному IP ───────────────────────────────────────────────────────
focus_ip() {
    collect_events; load_autoban
    local ip="$FOCUS_IP" hits fam found="" base ptr cc
    hits="$(awk -F'\t' -v x="$ip" '$3==x{c++} END{print c+0}' "$TMP")"
    enrich_asn "$ip"
    title "🔎 Анализ IP $ip"
    status_line "$([[ "$hits" -gt 0 ]] && echo WARN || echo OK)" "попаданий в drop-лог (за ${HOURS}ч): $hits"
    # членство во ВСЕХ наших nft-сетах (точная проверка, не grep)
    fam=v4; [[ "$ip" == *:* ]] && fam=v6
    if command -v nft >/dev/null 2>&1; then
        for base in autoban suspect blocklist na_fleet; do
            nft get element inet na_filter "${base}_${fam}" "{ $ip }" >/dev/null 2>&1 && found="$found ${base}_${fam}"
        done
    fi
    status_line "$([[ "$found" == *autoban* || "$found" == *blocklist* ]] && echo FAIL || { [[ -n "$found" ]] && echo WARN || echo OK; })" "в nft-сетах:${found:- (нет)}"
    # reverse-DNS + паттерн сканера
    ptr="$(getent hosts "$ip" 2>/dev/null | awk '{print $2; exit}')"
    [[ -z "$ptr" ]] && command -v dig >/dev/null 2>&1 && ptr="$(dig +short +time=3 +tries=1 -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//')"
    if [[ -n "$ptr" ]]; then
        printf '%s' "$ptr" | grep -qiE 'scan|probe|crawl|bot|spider|census|shodan' \
            && status_line FAIL "rDNS: $ptr (паттерн сканера/бота)" || info "rDNS: $ptr"
    else info "rDNS: нет PTR (у легит-сервисов обычно есть)"; fi
    [[ -n "${ASN[$ip]:-}" ]] && status_line OK "ASN: ${ASN[$ip]} ${ANAME[$ip]:-} (${CC[$ip]:-?})" || info "ASN: н/д (нет ответа Cymru — нужен dig или whois и исходящий DNS/43)"
    # активные conntrack-сессии (если есть conntrack-tools)
    if command -v conntrack >/dev/null 2>&1; then
        cc="$(conntrack -L 2>/dev/null | grep -Fc -- "$ip")"   # -F: точки IPv4 как литералы, не regex-«любой символ»
        [[ "${cc:-0}" -gt 0 ]] && status_line WARN "активных conntrack-сессий: $cc" || info "активных conntrack-сессий: 0"
    fi
    info "Причины (за ${HOURS}ч):"
    awk -F'\t' -v x="$ip" '$3==x{c[$2]++} END{for(r in c) printf "    %-10s %d\n", r, c[r]}' "$TMP"
    info "Таймлайн по часам (непустые бакеты):"
    awk -F'\t' -v x="$ip" -v now="$NOW" -v H="$HOURS" '$3==x{h=int((now-$1)/3600); if(h>=0&&h<H)b[h]++} END{for(i=H-1;i>=0;i--) if(b[i]) printf "    -%dч: %d\n", i, b[i]}' "$TMP"
    echo "  Вердикт: $(verdict "$ip" "$hits" "$hits")"
}

# ─── Человекочитаемый отчёт ─────────────────────────────────────────────────────
human() {
    collect_events; load_autoban
    clear 2>/dev/null || true
    printf "%b" "$BOLD"
    cat <<'B'
  ┌────────────────────────────────────────────┐
  │   🔥  node-accelerator — форензика атак     │
  └────────────────────────────────────────────┘
B
    printf "%b" "$NC"
    local total rate usrc; total="$(events_total)"; rate="$(ban_rate_5m)"; usrc="$(unique_src_5m)"
    info "Окно: последние ${HOURS}ч   ·   событий в drop-логе: $total   ·   за 5 мин: $rate от $usrc адрес(ов)"
    if [[ "$JSPAN" -ge 0 && "$JSPAN" -lt "$HOURS" ]]; then
        warn "журнал хранит только ~${JSPAN}ч (самая старая запись) — окно ${HOURS}ч фактически урезано; «событий мало» может значить «журнал вытеснен» (снизь PORTSCAN_LOG_RATE / подними NA_JOURNAL_MAX_USE)"
    elif [[ "$JSPAN" -ge 0 ]]; then
        info "глубина журнала: ~${JSPAN}ч (все загрузки, -b all)"
    fi

    title "Дропы по причине"
    for r in portscan synflood ssh-flood badflags; do
        printf "  %-12s %s\n" "$r" "$(count_reason "$r")"
    done
    local cs_all; cs_all="$(crowdsec_count -a)"
    printf "  %-12s %s\n" "crowdsec" "$(crowdsec_count) активных локальных решений$([[ "$cs_all" -ge 0 ]] && echo " (с CAPI/списками: $cs_all)")"

    title "Таймлайн (последний час, бакеты 5 мин)"
    echo "  $(timeline_csv | tr ',' ' ')"

    title "Top-$TOPN источников"
    local -a ips=() hitsarr=(); local h ip maxhits=0
    while read -r h ip; do
        [[ -z "${ip:-}" ]] && continue
        ips+=("$ip"); hitsarr+=("$h"); [[ "$h" -gt "$maxhits" ]] && maxhits="$h"
    done < <(top_ips_raw)
    enrich_asn "${ips[@]}"
    # Колонка ASN остаётся «?», когда обогащать нечем: на боксе без dig И без whois
    # отчёт молча выглядит иначе, чем у соседней ноды, и причина неочевидна.
    local got=0
    for ip in "${ips[@]}"; do [[ -n "${ASN[$ip]:-}" ]] && got=$((got+1)); done
    case "$(asn_status "${#ips[@]}" "$got")" in
        unavailable)
            if command -v dig >/dev/null 2>&1 || command -v whois >/dev/null 2>&1; then
                info "ASN не обогащён: Team Cymru не ответил (нужен исходящий DNS/43) — колонка ASN останется '?'"
            else
                info "ASN не обогащён: нет dig/whois (best-effort — колонка ASN останется '?')"
            fi ;;
        partial) info "ASN обогащён частично ($got из ${#ips[@]}: v6 и хвост списка не спрашиваем)" ;;
    esac
    printf "  %-18s %6s  %-22s %s\n" "IP" "hits" "ASN" "вердикт"
    for i in "${!ips[@]}"; do
        ip="${ips[$i]}"; h="${hitsarr[$i]}"
        printf "  %-18s %6s  %-22s %s\n" "$ip" "$h" "${ASN[$ip]:-?} ${CC[$ip]:-}" "$(verdict "$ip" "$h" "$maxhits")"
    done
    [[ ${#ips[@]} -eq 0 ]] && echo "  (тихо — дроп-событий с SRC в окне нет)"

    title "SSH brute (за ${HOURS}ч)"
    ssh_brute
    title "CrowdSec-сценарии (за ${HOURS}ч)"
    crowdsec_scenarios
    echo
}

# ─── SSH brute-force (журнал sshd, read-only) ───────────────────────────────────
ssh_brute() {
    local since="-${HOURS}h" inv
    inv="$(journalctl --since "$since" --no-pager 2>/dev/null | grep -aiE 'sshd.*(invalid user|failed password)' | grep -c .)"
    if [[ "${inv:-0}" -eq 0 ]]; then info "попыток не видно (или sshd не логирует/нет журнала)"; return; fi
    printf "  всего попыток: %s\n" "$inv"
    echo "  топ юзернеймов:"
    journalctl --since "$since" --no-pager 2>/dev/null | grep -aoE 'invalid user [A-Za-z0-9_.-]+' | awk '{print $3}' | sort | uniq -c | sort -rn | head -8 | sed 's/^/    /'
    echo "  топ source-IP:"
    journalctl --since "$since" --no-pager 2>/dev/null | grep -aiE 'sshd.*(invalid user|failed password)' | grep -aoE 'from [0-9a-fA-F.:]+' | awk '{print $2}' | sort | uniq -c | sort -rn | head -8 | sed 's/^/    /'
}

# ─── CrowdSec: топ сработавших сценариев ─────────────────────────────────────────
crowdsec_scenarios() {
    command -v cscli >/dev/null 2>&1 || { info "CrowdSec не установлен"; return; }
    systemctl is-active --quiet crowdsec 2>/dev/null || { info "CrowdSec не запущен"; return; }
    local rows
    rows="$(cscli alerts list --since "${HOURS}h" -o raw 2>/dev/null | awk -F, 'NR>1{print $4}' | sort | uniq -c | sort -rn | head -8)"
    if [[ -n "$rows" ]]; then echo "  топ сценариев:"; printf '%s\n' "$rows" | sed 's/^/    /'; else info "алертов за окно нет"; fi
}

# ─── Пивот по порту (--port N) ──────────────────────────────────────────────────
port_focus() {
    local p="$FOCUS_PORT" since="-${HOURS}h" lines n
    title "🔌 Порт $p — дроп-источники (за ${HOURS}ч)"
    lines="$(journalctl -k -b all --since "$since" --no-pager 2>/dev/null | grep -aF '[na ' | grep -aF "DPT=$p ")"
    n="$(printf '%s\n' "$lines" | grep -c .)"
    info "drop-событий на DPT=$p: $n"
    if [[ "$n" -gt 0 ]]; then
        echo "  топ source-IP:"
        printf '%s\n' "$lines" | grep -aoE 'SRC=[0-9a-fA-F.:]+' | sed 's/SRC=//' | sort | uniq -c | sort -rn | head -"$TOPN" | sed 's/^/    /'
    fi
    title "Кто слушает :$p"
    if command -v ss >/dev/null 2>&1; then
        ss -tlnH 2>/dev/null | awk -v pat=":$p\$" '$4 ~ pat{print "  "$4}' | head
    else info "ss недоступен"; fi
}

# ─── Self-audit: proxyware / residential-proxy (`--proxyware`) ──────────────────
# Read-only доказательство «нода НЕ резидентный прокси и proxyware-SDK на ней нет».
# Для ответа на abuse-тикеты (IPIDEA/PacketSDK/Honeygain/EarnApp/…). Сигнатуры —
# ТОЛЬКО конкретные имена продуктов: generic «proxy» не матчим, иначе ложно
# сработает на самом xray/VLESS (нода легально — прокси-сервер).
PROXYWARE_SIG='packetsdk|ipidea|honeygain|earnapp|peer2profit|proxyrack|iproyal|pawnsapp|repocket|packetstream|traffmonetizer|bitping|earnfm|proxylite|infatica|nodemaven|gaganode|urnetwork'
PROXYWARE_C2='api-seed.packetsdk.net packetsdk.net api-seed.packetsdk.xyz martianinc.co dnsnb8.net'

# shellcheck disable=SC2009  # нужен match по args, не по имени — pgrep не подходит
pw_proc()     { ps -eo pid=,args= 2>/dev/null | grep -iE "$PROXYWARE_SIG" | grep -ivE 'na-report|--proxyware| grep ' | sed 's/^ *//' | head -20; }
pw_services() { { systemctl list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}'
                  systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}'
                  grep -rilE "$PROXYWARE_SIG" /etc/systemd/system /lib/systemd/system /run/systemd/system 2>/dev/null
                } | grep -iE "$PROXYWARE_SIG" | sort -u | head -20; }
pw_cron()     { { crontab -l 2>/dev/null
                  while IFS=: read -r _u _; do crontab -l -u "$_u" 2>/dev/null; done < /etc/passwd
                  grep -rhsiE "$PROXYWARE_SIG" /etc/crontab /etc/cron.d /etc/cron.* /var/spool/cron 2>/dev/null
                } | grep -iE "$PROXYWARE_SIG" | sort -u | head -20; }
pw_files()    { timeout 20 find /usr/local /opt /usr/bin /usr/sbin /root /home -maxdepth 4 -xdev -type f 2>/dev/null \
                  | grep -iE "$PROXYWARE_SIG" | head -20; }
pw_docker()   { command -v docker >/dev/null 2>&1 || return 0
                docker ps -a --format '{{.Names}} {{.Image}}' 2>/dev/null | grep -iE "$PROXYWARE_SIG" | head -20; }
# Коннекты к C2: резолвим домены → IP, ищем среди ESTABLISHED peer-адресов.
pw_c2conn()   {
    local ips
    ips="$(for d in $PROXYWARE_C2; do getent hosts "$d" 2>/dev/null | awk '{print $1}'; done | sort -u)"
    [[ -z "$ips" ]] && return 0
    ss -tnH state established 2>/dev/null | awk '{print $4}' \
      | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//' \
      | grep -Fxf <(printf '%s\n' "$ips") 2>/dev/null | sort -u | head -20
}
# Внешне-доступные listener'ы — контекст: оператор сверяет, что незнакомых нет.
pw_listeners() {
    ss -tlnHp 2>/dev/null | awk '
        $4 ~ /(^0\.0\.0\.0:)|(^\*:)|(^\[::\]:)|(^\[::ffff:0\.0\.0\.0\]:)/ {
            p=$0; sub(/.*users:\(\(\"/,"",p); sub(/\".*/,"",p); if(p==$0)p="?";
            print $4"  ["p"]" }' | sort -u | head -30
}

# stdin (строка = элемент) → JSON-массив ["a","b"] (json_str экранирует).
_json_arr() {
    local out="" line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        out+="${out:+,}\"$(json_str "$line")\""
    done
    printf '[%s]' "$out"
}

# Секция аудита: печатает и возвращает 1, если есть хиты.
pw_section() {
    local label="$1" data="$2"
    if [[ -n "$data" ]]; then
        status_line FAIL "$label:"; printf '%s\n' "$data" | sed 's/^/        /'; return 1
    fi
    status_line OK "$label — чисто"; return 0
}

proxyware_audit() {
    clear 2>/dev/null || true
    printf "%b" "$BOLD"
    cat <<'B'
  ┌────────────────────────────────────────────┐
  │  🕵  node-accelerator — proxyware self-audit │
  └────────────────────────────────────────────┘
B
    printf "%b" "$NC"
    info "Read-only проверка на residential-proxy / bandwidth-SDK (для abuse-тикетов)."

    local hit=0
    title "Сигнатуры известного proxyware"
    pw_section "процессы"      "$(pw_proc)"     || hit=1
    pw_section "systemd-юниты" "$(pw_services)" || hit=1
    pw_section "cron"          "$(pw_cron)"     || hit=1
    pw_section "файлы"         "$(pw_files)"    || hit=1
    pw_section "docker-образы" "$(pw_docker)"   || hit=1

    title "Соединения к C2-инфраструктуре proxyware"
    local c2; c2="$(pw_c2conn)"
    if [[ -n "$c2" ]]; then
        status_line FAIL "установленные коннекты к C2:"; printf '%s\n' "$c2" | sed 's/^/        /'; hit=1
    else
        status_line OK "активных соединений к C2 нет (проверено: $PROXYWARE_C2)"
    fi

    title "Внешне-доступные слушающие порты (контекст)"
    local lst; lst="$(pw_listeners)"
    if [[ -n "$lst" ]]; then printf '%s\n' "$lst" | sed 's/^/  • /'; else info "внешних listener'ов нет"; fi
    info "для VPN-ноды :443 и порт входа моста — норма; убедись, что незнакомых служб нет"

    hr
    if [[ "$hit" -eq 0 ]]; then
        ok "ВЕРДИКТ: признаков proxyware / residential-proxy НЕ найдено — нода чиста."
    else
        err "ВЕРДИКТ: есть индикаторы proxyware (см. ✘ выше) — разобраться вручную."
    fi
    hr
}

proxyware_json() {
    local proc svc cron files dock c2 lst verdict
    proc="$(pw_proc)";  svc="$(pw_services)"; cron="$(pw_cron)"
    files="$(pw_files)"; dock="$(pw_docker)"; c2="$(pw_c2conn)"; lst="$(pw_listeners)"
    if [[ -n "$proc$svc$cron$files$dock$c2" ]]; then verdict="suspect"; else verdict="clean"; fi
    printf '{'
    printf '"na_version":"%s","verdict":"%s","generated_at":%s,' "${NA_VERSION:-?}" "$verdict" "$NOW"
    printf '"hits":{"processes":%s,"services":%s,"cron":%s,"files":%s,"docker":%s},' \
        "$(printf '%s\n' "$proc"  | _json_arr)" \
        "$(printf '%s\n' "$svc"   | _json_arr)" \
        "$(printf '%s\n' "$cron"  | _json_arr)" \
        "$(printf '%s\n' "$files" | _json_arr)" \
        "$(printf '%s\n' "$dock"  | _json_arr)"
    printf '"c2_connections":%s,"external_listeners":%s}\n' \
        "$(printf '%s\n' "$c2"  | _json_arr)" \
        "$(printf '%s\n' "$lst" | _json_arr)"
}

# ─── Диспетч ────────────────────────────────────────────────────────────────────
if [[ "$PROXYAUDIT" == "1" ]]; then
    if [[ "$JSON" == "1" ]]; then proxyware_json; else proxyware_audit; fi
    exit 0
fi
if [[ "$JSON" == "1" ]]; then emit_json; exit 0; fi
[[ -n "$FOCUS_PORT" ]] && { port_focus; exit 0; }
[[ -n "$FOCUS_IP" ]] && { focus_ip; exit 0; }
human
