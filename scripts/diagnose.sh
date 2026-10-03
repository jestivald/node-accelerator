#!/usr/bin/env bash
#
# diagnose.sh — 🩺 Диагностика ноды (read-only: конфигурацию не меняет; пишет только свой
# снимок счётчиков $STATE_DIR/diag-counters.last, чтобы считать дельты между запусками).
# Проверяет ядро/BBR, sysctl, лимиты, conntrack, MSS-коллапс, NIC/RPS, firewall,
# blocklists/fleet/ctguard, CrowdSec — печатает итог ✔/▲/✘ с рекомендациями.
#   diagnose.sh             — человекочитаемый отчёт
#   diagnose.sh --json      — один JSON-объект для флот-мониторинга (Zabbix/Prometheus)
#   diagnose.sh --retrans [--window N]  — глубокий разбор причин TCP-retransmits
#
# ENV-ручки:
#   NA_NODE_CONTAINER=<имя>   — контейнер node-агента (дефолт remnanode); на панели/
#                               CDN-origin контейнер зовётся иначе или его нет вовсе
#   NA_CERT_PATHS='<p1> <p2>' — доп. пути к fullchain для сенсора сроков TLS

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

OKC=0; WARNC=0; FAILC=0
pass() { status_line OK   "$*"; OKC=$((OKC+1)); }
wrn()  { status_line WARN "$*"; WARNC=$((WARNC+1)); }
bad()  { status_line FAIL "$*"; FAILC=$((FAILC+1)); }
val()  { sysctl -n "$1" 2>/dev/null; }

# diagnose read-only — должен работать и на не-Debian/чужой ОС, поэтому НЕ зовём
# фатальный detect_os (он exit'ит на не-Ubuntu/Debian), просто подтягиваем os-release
# для PRETTY_NAME, если есть.
[[ -f /etc/os-release ]] && { . /etc/os-release 2>/dev/null || true; }

# Имя контейнера node-агента. На панели Remnawave и на CDN-origin контейнер зовётся
# иначе или его нет вовсе, а сенсор жёстко смотрел на `remnanode` — и на таком боксе
# рапортовал «node-агент лежит» (issue #27/#33). Ручка даёт сказать правду обоим.
NA_NODE_CONTAINER="${NA_NODE_CONTAINER:-remnanode}"

# ─── Локальные хелперы сенсоров (нужны и --json, и человекочитаемой ветке) ────

# timeout — coreutils, но diagnose обязан работать и на урезанном боксе: без него
# просто зовём команду как есть.
_to() { if command -v timeout >/dev/null 2>&1; then timeout "$@"; else shift; "$@"; fi; }

# IPv4 → 32-битное целое; rc=1, если это не IPv4 (маска отрезается).
_ip4_int() {
    local o a b c d
    IFS=. read -r a b c d <<<"${1%%/*}"
    for o in "$a" "$b" "$c" "$d"; do
        [[ "$o" =~ ^[0-9]{1,3}$ ]] && (( 10#$o <= 255 )) || return 1
    done
    echo $(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))
}
# ip4_in_cidr <ip> <cidr|ip> — вхождение адреса в сеть, целочисленно. Без ipcalc/python:
# на голой ноде их может не быть, а датчик обязан работать везде.
ip4_in_cidr() {
    local ip="$1" net="${2%%/*}" pfx=32 ipi neti mask
    [[ "$2" == */* ]] && pfx="${2##*/}"
    [[ "$pfx" =~ ^[0-9]{1,2}$ ]] && (( pfx <= 32 )) || return 1
    ipi="$(_ip4_int "$ip")" || return 1
    neti="$(_ip4_int "$net")" || return 1
    (( pfx == 0 )) && return 0
    mask=$(( (0xFFFFFFFF << (32 - pfx)) & 0xFFFFFFFF ))
    (( (ipi & mask) == (neti & mask) ))
}

# Живой whitelist (обе семьи) — нужен и датчику CONN_LIMIT (#31), и сверке дрейфа (#38).
# Читаем ОДИН раз: nft-вызов не бесплатен. Наборы na_fleet_* / na_nodeport_wl_* сюда
# НЕ подмешиваем — это отдельные списки с другой судьбой при ре-ране.
NA_WL4=""; NA_WL6=""; NA_WL_READ=0
wl_live_load() {
    [[ "$NA_WL_READ" == "1" ]] && return 0
    NA_WL_READ=1
    NA_WL4="$(nft_set_elems inet na_filter whitelist_v4 2>/dev/null)"
    NA_WL6="$(nft_set_elems inet na_filter whitelist_v6 2>/dev/null)"
    return 0
}
# in_whitelist <ip> — адрес покрыт живым whitelist'ом? v4 — с учётом CIDR, v6 — точное
# совпадение (интервальных v6-вайтлистов на флоте нет, а разбор /64 стоил бы bigint).
in_whitelist() {
    local ip="$1" e
    wl_live_load
    if [[ "$ip" == *:* ]]; then
        for e in $NA_WL6; do [[ "${e%%/*}" == "$ip" ]] && return 0; done
        return 1
    fi
    for e in $NA_WL4; do
        if [[ "$e" == */* ]]; then ip4_in_cidr "$ip" "$e" && return 0
        elif [[ "$e" == "$ip" ]]; then return 0; fi
    done
    return 1
}

# conn_per_ip_max <csv-портов> — макс. число ВХОДЯЩИХ established с одного пира по тому
# же срезу, что режет правило `ct count`. v4.0 считал ВЕСЬ `ss -tnH state established`:
# туда попадали loopback-пары nginx↔xray (каждая учитывалась дважды), исходящие плечи и
# вайтлист — а до `ct count` ни один из них не доходит (в цепочке выше два accept и
# `iif lo accept`). Отсюда вечное «6790 из 8192» на здоровой ноде (issue #31).
# echo: число (0 = внешних пиров нет); rc=1 = мерить не по чему (портов не задано).
conn_per_ip_max() {
    local ports="${1:-}" p filt="" cnt peer
    for p in ${ports//,/ }; do
        [[ "$p" =~ ^[0-9]+$ ]] || continue
        filt+="${filt:+ or }sport = :$p"
    done
    [[ -n "$filt" ]] || return 1
    while read -r cnt peer; do
        [[ "$cnt" =~ ^[0-9]+$ && -n "$peer" ]] || continue
        [[ "$peer" == 127.* || "$peer" == "::1" ]] && continue
        in_whitelist "$peer" && continue
        echo "$cnt"; return 0
    done < <(ss -tnH state established "( $filt )" 2>/dev/null \
             | awk '{print $NF}' \
             | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//; s/^::ffff:([0-9.]+)$/\1/' \
             | sort | uniq -c | sort -rn)
    echo 0
}

# psi_state — on | off-by-default | absent | unknown. XanMod (и сток Debian) собран с
# CONFIG_PSI_DEFAULT_DISABLED=y: PSI ЕСТЬ, но /proc/pressure появляется только при
# `psi=1` в cmdline. v4.0 знал два состояния и объяснял пропажу «старым ядром» на ядре
# 6.18 — сенсор давления молчал на 100% боксов, и это выглядело как норма (issue #37).
psi_state() {
    [[ -r /proc/pressure/cpu ]] && { echo on; return 0; }
    local kr cfg=""
    kr="$(uname -r 2>/dev/null)"
    if [[ -n "$kr" && -r "/boot/config-$kr" ]]; then
        cfg="$(grep -E '^CONFIG_PSI(_DEFAULT_DISABLED)?=' "/boot/config-$kr" 2>/dev/null)"
    elif [[ -r /proc/config.gz ]] && command -v zcat >/dev/null 2>&1; then
        cfg="$(zcat /proc/config.gz 2>/dev/null | grep -E '^CONFIG_PSI(_DEFAULT_DISABLED)?=')"
    fi
    [[ -n "$cfg" ]] || { echo unknown; return 0; }
    grep -q '^CONFIG_PSI=y' <<<"$cfg" || { echo absent; return 0; }
    if grep -q '^CONFIG_PSI_DEFAULT_DISABLED=y' <<<"$cfg" && ! grep -qw 'psi=1' /proc/cmdline 2>/dev/null; then
        echo off-by-default; return 0
    fi
    echo unknown
}

# journal_span_h — на сколько часов назад хватает journald (возраст самой старой записи).
# Поток `[na portscan]` на публичной ноде (5/сек ≈ 50 МБ/сутки) вытесняет из журнала при
# SystemMaxUse=300M всё остальное, и глубина падает ниже суток: разбор вчерашнего
# инцидента становится невозможен, а на Debian 13 minimal journald — единственный
# источник истории входов (issue #35). rc=1 = не измерено.
journal_span_h() {
    command -v journalctl >/dev/null 2>&1 || return 1
    local first now
    # -o short-unix отдаёт запись с самой старой первой строкой; head закрывает пайп
    # сразу, поэтому цена не зависит от размера журнала.
    first="$(_to 10 journalctl -q --no-pager -o short-unix 2>/dev/null | head -n1 | awk '{print $1}' | cut -d. -f1)"
    [[ "$first" =~ ^[0-9]+$ ]] || return 1
    now="$(date +%s 2>/dev/null)"; [[ "$now" =~ ^[0-9]+$ ]] || return 1
    (( now > first )) || { echo 0; return 0; }
    echo $(( (now - first) / 3600 ))
}

# portscan_log_lines — строк `[na portscan]` за текущую загрузку (сколько журнала съел
# лог анти-скана). echo: число; rc=1 = не измерено (нет journalctl / сборка без `-g` /
# не уложились в таймаут — частичный счёт лучше не выдавать за точный).
portscan_log_lines() {
    local n rc
    command -v journalctl >/dev/null 2>&1 || return 1
    # `-g` (grep по журналу) есть не во всех сборках systemd — спрашиваем help, а не
    # пробный запуск: пустой результат пробы неотличим от «опция не поддержана».
    # Не `journalctl --help | grep -q`: под pipefail grep -q закрывает пайп на первом
    # совпадении, а справка (5 КБ) уходит в него двумя записями — вторая ловит SIGPIPE,
    # пайплайн отдаёт 141, и сенсор через раз молча становится «-1» (аудит флота: на
    # 8 нодах из 8 проверенных, -1 и число чередовались между соседними прогонами).
    local help
    help="$(_to 5 journalctl --help 2>/dev/null)"
    [[ "$help" == *--grep* ]] || return 1
    n="$(_to 15 journalctl -b -k -g '\[na portscan\]' --no-pager -q 2>/dev/null | wc -l | tr -d ' ')"; rc=$?
    # pipefail: timeout, убивший journalctl, отдаёт 124 — счёт неполный, врать не будем
    [[ "$rc" -eq 124 ]] && return 1
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    echo "$n"
}

# cert_retired <path/to/fullchain> — серт acme.sh, снятый с renew. `acme.sh --remove`
# оставляет каталог с сертом на диске, но переименовывает <domain>.conf →
# <domain>.conf.removed: продлеваться он уже не будет, и его notAfter — гарантированная
# ложная тревога по домену, которого в проде нет (issue #39).
cert_retired() {
    local d; d="$(dirname "$1")"
    compgen -G "$d/*.conf" >/dev/null 2>&1 && return 1
    compgen -G "$d/*.conf.removed" >/dev/null 2>&1 && return 0
    return 1
}

# Пути сертов: LE, acme.sh, фасадный selfsteal-каталог (/opt/<стек>/certs/...) и
# NA_CERT_PATHS. Нестандартного /opt-каталога в v4.0 не было, и на selfsteal-ноде
# сенсор отдавал cert_min_days=-1 — молчал ровно там, где серт и надо стеречь (#39).
# v4.2: хранилище Caddy — в docker volume (панель/CDN-origin за Caddy) и у пакетного
# Caddy; плюс ssl_certificate из конфигов nginx (nginx_cert_paths).
NA_CERT_GLOBS='/etc/letsencrypt/live/*/fullchain.pem /root/.acme.sh/*/fullchain.cer /opt/*/certs/*/fullchain.cer /opt/*/certs/*/fullchain.pem /opt/*/certs/fullchain.cer /opt/*/certs/fullchain.pem'
NA_CERT_GLOBS+=' /var/lib/docker/volumes/*/_data/caddy/certificates/*/*/*.crt /var/lib/caddy/.local/share/caddy/certificates/*/*/*.crt'

# tls_listening — на :443/:8443 кто-то слушает? Если сертов при этом не нашли, сенсор
# не «чист», а слеп — это warn, а не info (issue #39).
tls_listening() {
    # awk дочитывает вход до конца (не grep -q: SIGPIPE под pipefail, см. portscan_log_lines)
    ss -tlnH 2>/dev/null | awk '$4 ~ /[:.](443|8443)$/{f=1} END{exit !f}'
}

# reboot_pending — optimize поставил ядро/параметры загрузки, а перезагрузки с тех пор не
# было. Маркер `reboot_needed=1` пишет optimize, и никто его не снимает: после ребута JSON
# продолжал отдавать true (аудит флота: 9 нод уже на XanMod, а мониторинг ждал ребута).
# Сверяем с ТЕКУЩЕЙ загрузкой: boot_id из маркера (v4.1.3+) или, для старых маркеров,
# время загрузки (btime) против installed_at. Не разобрать — как раньше, верим маркеру.
reboot_pending() {
    local f="$STATE_DIR/optimize.installed" bid cur inst inst_s bt
    [[ -f "$f" ]] || return 1
    grep -q '^reboot_needed=1' "$f" 2>/dev/null || return 1
    bid="$(awk -F= '/^boot_id=/{print $2; exit}' "$f" 2>/dev/null)"
    cur="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
    if [[ -n "$bid" && -n "$cur" ]]; then [[ "$bid" == "$cur" ]]; return; fi
    inst="$(awk -F= '/^installed_at=/{print $2; exit}' "$f" 2>/dev/null)"
    [[ -n "$inst" ]] || return 0   # `date -d ""` = сегодняшняя полночь — не дата установки
    inst_s="$(date -d "$inst" +%s 2>/dev/null)" || return 0
    bt="$(awk '/^btime /{print $2; exit}' /proc/stat 2>/dev/null)"
    [[ "$inst_s" =~ ^[0-9]+$ && "$bt" =~ ^[0-9]+$ ]] || return 0
    (( bt < inst_s ))
}

# dynset_fill — заполненность наборов-лимитеров na_filter (SYN/UDP/SSH/ICMP/анти-скан/
# node-port/open). До v4.1.3 они создавались `meter` без timeout: записи не истекали, и на
# полном наборе (65535) новые клиенты на порт отсекались (аудит флота: 22 764 адреса за
# 32 дня). Берём ТОЛЬКО лимитеры по имени: nft помечает dynamic и сеты autoban/suspect
# (в них пишет правило), а timeout у тех — на каждой записи, не в объявлении. Старые
# meter на nft 1.0.6 — анонимные: в `-t list table` они есть только внутри правил
# (`meter NAME size N {`), содержимое отдаёт `nft list meter`.
# stdout: «имя<TAB>элементов<TAB>size<TAB>timeout(1|0)»; набор, который не уложился в
# таймаут (флуд — десятки тысяч записей), пропускается. rc=1 — таблицы нет.
NA_LIMITER_RE='^((syn|udp|osyn|oudp)[46](_[0-9]+)?|ssh[46]|icmp[46]|na[46]|psc?[46])$'
_dyn_count() {   # _dyn_count set|meter <имя> → число записей; rc≠0 — не измерено
    local out
    out="$(_to 5 nft list "$1" inet na_filter "$2" 2>/dev/null)" || return 1
    printf '%s\n' "$out" | sed -n '/elements = {/,/^[[:space:]]*}/p' \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?|[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}(/[0-9]+)?' \
        | sort -u | wc -l | tr -d ' '
}
dynset_fill() {
    local terse kind name size to n
    terse="$(_to 10 nft -t list table inet na_filter 2>/dev/null)" || return 1
    [[ -n "$terse" ]] || return 1
    while IFS=$'\t' read -r kind name size to; do
        [[ "$name" =~ $NA_LIMITER_RE && "$size" =~ ^[0-9]+$ ]] && (( size > 0 )) || continue
        n="$(_dyn_count "$kind" "$name")" && [[ "$n" =~ ^[0-9]+$ ]] || continue
        printf '%s\t%s\t%s\t%s\n' "$name" "$n" "$size" "$to"
    done < <(awk '
        /^[[:space:]]*set [A-Za-z0-9_]+ \{/ { name=$2; size=0; to=0; inset=1; next }
        inset && /^[[:space:]]*size [0-9]+/  { size=$2 }
        inset && /^[[:space:]]*timeout /     { to=1 }
        inset && /^[[:space:]]*}/            { print "set\t" name "\t" size "\t" to; seen[name]=1; inset=0; next }
        { while (match($0, /meter [A-Za-z0-9_]+ size [0-9]+/)) {
              split(substr($0, RSTART, RLENGTH), m, " ")
              if (!(m[2] in meters)) meters[m[2]] = m[4]
              $0 = substr($0, RSTART + RLENGTH)
          } }
        END { for (k in meters) if (!(k in seen)) print "meter\t" k "\t" meters[k] "\t0" }
    ' <<<"$terse")
}

# ─── v4.2: хелперы сенсоров по аудиту флота ──────────────────────────────────

# conf_val <файл> <КЛЮЧ> — значение из сохранённого conf модуля. save_conf пишет
# `: "${KEY:=v}"`, protect v4.2 — `: "${KEY=v}"` (пустое ENV очищает значение): понимаем
# обе идиомы, последняя строка выигрывает (как при source).
conf_val() {
    [[ -r "$1" ]] || return 0
    sed -nE 's/^[[:space:]]*:[[:space:]]+"\$\{'"$2"':?=([^}]*)\}"[[:space:]]*$/\1/p' "$1" 2>/dev/null | tail -1
}
# conf_has <файл> <КЛЮЧ> — ключ вообще записан (пустое значение — тоже значение: UDP_PORTS=)
conf_has() { grep -qE '^[[:space:]]*:[[:space:]]+"\$\{'"$2"':?=' "$1" 2>/dev/null; }
# mark_val <ключ> [файл] — значение из маркера protect (или указанного маркера)
mark_val() {
    awk -F= -v k="$1" '$1 == k { sub(/^[^=]*=/, ""); v = $0 } END { printf "%s", v }' \
        "${2:-$STATE_DIR/protect.installed}" 2>/dev/null
}
# csv_norm <список> — порты через запятую: только числа, по возрастанию, без повторов
csv_norm() { tr ', ' '\n\n' <<<"$1" | grep -E '^[0-9]+$' | sort -un | paste -sd, -; }

# Живая input-цепочка na_filter — читаем ОДИН раз (её смотрят несколько сенсоров).
NA_CHAIN=""; NA_CHAIN_READ=0
chain_load() {
    [[ "$NA_CHAIN_READ" == 1 ]] && return 0
    NA_CHAIN_READ=1
    NA_CHAIN="$(_to 10 nft list chain inet na_filter input 2>/dev/null)"
    return 0
}
# fw_live_ports tcp|udp — сервисные порты из ЖИВЫХ правил (то, что действует сейчас):
# per-port наборы cc4_<порт> (TCP: `meter cc4_443` на nft 1.0.6, `@cc4_443` на 1.1) и
# udp4_<порт> (UDP).
fw_live_ports() {
    local pre=cc4_; [[ "$1" == udp ]] && pre=udp4_
    chain_load
    grep -oE "(^|[^a-z0-9_])${pre}[0-9]+" <<<"$NA_CHAIN" | grep -oE '[0-9]+$' | sort -un | paste -sd, -
}
# fw_ports tcp|udp — порты для сенсоров. Таблица есть → живые правила (истина «сейчас»);
# нет → protect.conf → маркер. tcp_ports= в маркере пишется только прогоном protect и
# устаревает после ручной правки правил/conf (аудит флота: порты «мимо маркера»).
fw_ports() {
    local K=TCP_PORTS mk=tcp_ports
    [[ "$1" == udp ]] && { K=UDP_PORTS; mk=udp_ports; }
    chain_load
    if [[ -n "$NA_CHAIN" ]]; then fw_live_ports "$1"; return 0; fi
    local v; v="$(csv_norm "$(conf_val "$CONF_DIR/protect.conf" "$K")")"
    [[ -n "$v" ]] || v="$(csv_norm "$(mark_val "$mk")")"
    echo "$v"
}

# ─── CPU steal: окно + среднее с загрузки ────────────────────────────────────
# Секундный семпл на флоте прыгал 0↔8% между соседними прогонами: решение принималось по
# шуму. Окно 3 с + среднее с загрузки (/proc/stat копит steal с момента старта).
cpu_stat() { awk '/^cpu /{ t = 0; for (i = 2; i <= 9; i++) t += $i; printf "%.0f %.0f\n", $9, t; exit }' /proc/stat 2>/dev/null; }
cpu_steal_measure() {   # → «окно% с_загрузки%»
    local w="${1:-3}" s1 t1 s2 t2 win=0 boot=0
    read -r s1 t1 <<<"$(cpu_stat)"
    [[ "$s1" =~ ^[0-9]+$ && "$t1" =~ ^[0-9]+$ ]] || { echo "0 0"; return 1; }
    (( t1 > 0 )) && boot=$(( s1 * 100 / t1 ))
    sleep "$w"
    read -r s2 t2 <<<"$(cpu_stat)"
    if [[ "$s2" =~ ^[0-9]+$ && "$t2" =~ ^[0-9]+$ ]] && (( t2 > t1 && s2 >= s1 )); then
        win=$(( (s2 - s1) * 100 / (t2 - t1) ))
    fi
    echo "$win $boot"
}

# ─── Дельты счётчиков между запусками ────────────────────────────────────────
# UDP RcvbufErrors, softnet drop/squeeze, ListenOverflows, steal копятся с загрузки: на
# ноде с аптаймом в месяц одна давняя вспышка горела ▲ вечно, а свежий рост тонул в старом
# итоге (аудит флота: «UDP RcvbufErrors» на всех нодах при нулевом приросте). Каждый запуск
# оставляет снимок, следующий считает разницу, если загрузка та же и прошло ≥30 с; окно
# короче — копим от старого снимка, иначе частый опрос мониторинга не дал бы окна никогда.
# Это ЕДИНСТВЕННОЕ, что diagnose пишет на диск; не вышло (не root) — просто нет дельт.
NA_CNT_FILE="$STATE_DIR/diag-counters.last"
NA_DELTA_MIN_S=30
counters_now() {
    local bid ep u4 u6 sn lo st
    bid="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
    ep="$(date +%s)"
    u4="$(awk '/^Udp:/ { if (!h) { for (i = 2; i <= NF; i++) n[i] = $i; h = 1; next }
                        for (i = 2; i <= NF; i++) { if (n[i] == "RcvbufErrors") e = $i; if (n[i] == "InDatagrams") d = $i } }
               END { printf "%.0f %.0f", e, d }' /proc/net/snmp 2>/dev/null)"
    u6="$(awk '$1 == "Udp6RcvbufErrors" { e = $2 } $1 == "Udp6InDatagrams" { d = $2 }
               END { printf "%.0f %.0f", e, d }' /proc/net/snmp6 2>/dev/null)"
    # softnet_stat: строка на CPU, hex; 2-я колонка — dropped (backlog полон), 3-я — time_squeeze
    sn="$(awk 'function hx(s,  i, c, v) { v = 0; s = tolower(s)
                   for (i = 1; i <= length(s); i++) { c = index("0123456789abcdef", substr(s, i, 1)); if (!c) break; v = v * 16 + c - 1 }
                   return v }
               NF >= 3 { d += hx($2); q += hx($3) } END { printf "%.0f %.0f", d, q }' /proc/net/softnet_stat 2>/dev/null)"
    lo="$(awk '/^TcpExt:/ { if (!h) { for (i = 2; i <= NF; i++) n[i] = $i; h = 1; next }
                           for (i = 2; i <= NF; i++) { if (n[i] == "ListenOverflows") o = $i; if (n[i] == "ListenDrops") d = $i } }
               END { printf "%.0f %.0f", o, d }' /proc/net/netstat 2>/dev/null)"
    st="$(cpu_stat)"
    local ue ui ve vi sd sq lov ldr cs ct
    read -r ue ui <<<"$u4"; read -r ve vi <<<"$u6"; read -r sd sq <<<"$sn"
    read -r lov ldr <<<"$lo"; read -r cs ct <<<"$st"
    printf 'boot_id=%s\nepoch=%s\nudp_err=%s\nudp_in=%s\nsn_drop=%s\nsn_squeeze=%s\nlisten_ovf=%s\nlisten_drops=%s\nsteal=%s\ncpu_total=%s\n' \
        "$bid" "$ep" "$(( ${ue:-0} + ${ve:-0} ))" "$(( ${ui:-0} + ${vi:-0} ))" "${sd:-0}" "${sq:-0}" \
        "${lov:-0}" "${ldr:-0}" "${cs:-0}" "${ct:-0}"
}
# delta_load — глобальные C_* (с загрузки) и D_* (за окно DW секунд; −1 = окна нет).
NA_DELTA_DONE=0
DW=-1; D_UDPERR=-1; D_UDPIN=-1; D_SNDROP=-1; D_SQZ=-1; D_LOVF=-1; D_LDROP=-1; D_STEAL=-1
C_UDPERR=0; C_UDPIN=0; C_SNDROP=0; C_SQZ=0; C_LOVF=0; C_LDROP=0
delta_load() {
    [[ "$NA_DELTA_DONE" == 1 ]] && return 0
    NA_DELTA_DONE=1
    local now k v w keep=0
    local -A cur=() prev=()
    now="$(counters_now)"
    while IFS='=' read -r k v; do [[ -n "$k" ]] && cur[$k]="$v"; done <<<"$now"
    if [[ -r "$NA_CNT_FILE" ]]; then
        while IFS='=' read -r k v; do [[ -n "$k" ]] && prev[$k]="$v"; done < "$NA_CNT_FILE"
    fi
    C_UDPERR="${cur[udp_err]:-0}"; C_UDPIN="${cur[udp_in]:-0}"; C_SNDROP="${cur[sn_drop]:-0}"
    C_SQZ="${cur[sn_squeeze]:-0}"; C_LOVF="${cur[listen_ovf]:-0}"; C_LDROP="${cur[listen_drops]:-0}"
    if [[ -n "${cur[boot_id]:-}" && "${prev[boot_id]:-}" == "${cur[boot_id]}" \
          && "${prev[epoch]:-}" =~ ^[0-9]+$ && "${cur[epoch]:-}" =~ ^[0-9]+$ ]]; then
        w=$(( cur[epoch] - prev[epoch] ))
        if (( w >= NA_DELTA_MIN_S )); then
            DW="$w"
            _dl() { local a="${cur[$1]:-}" b="${prev[$1]:-}"; [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ ]] && (( a >= b )) && echo $(( a - b )) || echo -1; }
            D_UDPERR="$(_dl udp_err)"; D_UDPIN="$(_dl udp_in)"; D_SNDROP="$(_dl sn_drop)"
            D_SQZ="$(_dl sn_squeeze)"; D_LOVF="$(_dl listen_ovf)"; D_LDROP="$(_dl listen_drops)"
            local ds dt; ds="$(_dl steal)"; dt="$(_dl cpu_total)"
            [[ "$ds" -ge 0 && "$dt" -gt 0 ]] && D_STEAL=$(( ds * 100 / dt ))
            unset -f _dl
        elif (( w >= 0 )); then
            keep=1
        fi
    fi
    if [[ "$keep" == 0 ]]; then
        { mkdir -p "$STATE_DIR" && printf '%s\n' "$now" > "$NA_CNT_FILE.tmp.$$" \
            && mv -f "$NA_CNT_FILE.tmp.$$" "$NA_CNT_FILE"; } 2>/dev/null || rm -f "$NA_CNT_FILE.tmp.$$" 2>/dev/null
    fi
    return 0
}

# ─── Слушатели и опубликованные порты ────────────────────────────────────────
NA_LT=""; NA_LU=""; NA_L_READ=0
listen_load() {
    [[ "$NA_L_READ" == 1 ]] && return 0
    NA_L_READ=1
    NA_LT="$(ss -Htlnp 2>/dev/null)"; NA_LU="$(ss -Hulnp 2>/dev/null)"
    return 0
}
# listen_rows tcp|udp — «адрес<TAB>порт<TAB>процесс» (адрес без [] и %iface)
listen_rows() {
    listen_load
    local src="$NA_LT"; [[ "$1" == udp ]] && src="$NA_LU"
    awk '$1 == "LISTEN" || $1 == "UNCONN" {
        la = $4; p = la; sub(/.*:/, "", p); a = substr(la, 1, length(la) - length(p) - 1)
        sub(/%.*/, "", a); gsub(/[][]/, "", a)
        proc = "?"; if (match($0, /users:\(\("[^"]+"/)) proc = substr($0, RSTART + 9, RLENGTH - 10)
        if (p ~ /^[0-9]+$/) print a "\t" p "\t" proc
    }' <<<"$src"
}
# addr_public <адрес> — wildcard или глобальный (не loopback/link-local/частный/CGNAT)
addr_public() {
    case "$1" in
        "*"|0.0.0.0|::) return 0 ;;
        127.*|::1|::ffff:127.*|fe80:*|10.*|192.168.*|169.254.*|fc*|fd*) return 1 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 1 ;;
        100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 1 ;;
    esac
    return 0
}
# dnat_ports — публичные порты, приходящие на ноду через DNAT (Docker `-p`, ручные relay):
# «порт/proto» через запятую. Такой трафик идёт хуком forward, мимо input-цепочки
# na_filter: strict его не закрывает, autoban/блоклисты/лимиты не действуют (аудит флота:
# Caddy панели за Docker, тенант на соседнем контейнере, ручные relay-DNAT).
dnat_ports() {
    {
        if command -v docker >/dev/null 2>&1; then
            docker ps --format '{{.Ports}}' 2>/dev/null | tr ',' '\n' \
              | sed -nE 's#^[[:space:]]*\[?([0-9a-fA-F:.]*)\]?:([0-9]+(-[0-9]+)?)->[0-9]+(-[0-9]+)?/(tcp|udp|sctp).*$#\1 \2/\5#p' \
              | awk '$1 !~ /^(127\.|::1$)/ { print $2 }'
        fi
        # -t: без содержимого наборов (у CrowdSec — десятки тысяч адресов)
        _to 10 nft -t list ruleset 2>/dev/null | awk '
            / dnat / {
                if ($0 ~ /ip6? daddr (127\.|::1)/) next
                if ($0 ~ /tcp dport/) proto = "tcp"; else if ($0 ~ /udp dport/) proto = "udp"; else next
                s = $0; sub(/.*(tcp|udp) dport /, "", s)
                if (s ~ /^\{/) {
                    sub(/^\{ */, "", s); sub(/ *\}.*/, "", s); n = split(s, a, / *, */)
                    for (i = 1; i <= n; i++) if (a[i] ~ /^[0-9]+(-[0-9]+)?$/) print a[i] "/" proto
                } else { sub(/ .*/, "", s); if (s ~ /^[0-9]+(-[0-9]+)?$/) print s "/" proto }
            }'
    } | sort -u | sort -t/ -k1,1n | paste -sd, -
}

# ─── CrowdSec ────────────────────────────────────────────────────────────────
# cs_decisions — «локальные CAPI/списки»: `-a` включает решения центрального API. Без
# него `cscli decisions list` показывает только локальные: на ноде с 25 тыс. адресов
# community-блоклиста отчёт печатал «1», а режет bouncer по всем. rc=1 — не измерено.
cs_decisions() {
    command -v cscli >/dev/null 2>&1 || return 1
    local out
    out="$(_to 30 cscli decisions list -a -o raw 2>/dev/null)" || return 1
    # строки данных начинаются с числового id (заголовок CSV — нет); 2-я колонка — origin
    awk -F, '$1 ~ /^[0-9]+$/ { s = tolower($2); if (s ~ /^(capi|lists)/) c++; else l++ }
             END { printf "%d %d\n", l, c }' <<<"$out"
}
# cs_acquis — источники логов CrowdSec из acquis.yaml / acquis.d: «тип[фильтр/пути]» по строке
cs_acquis() {
    local f
    for f in /etc/crowdsec/acquis.yaml /etc/crowdsec/acquis.d/*.yaml /etc/crowdsec/acquis.d/*.yml; do
        [[ -f "$f" ]] || continue
        awk '
            function flush() { if (src != "" || items != "") { if (src == "") src = "file"; print src "[" items "]" } src = ""; items = ""; lk = 0 }
            function add(v) { gsub(/["'\'']/, "", v); sub(/[[:space:]]+#.*/, "", v); sub(/^[[:space:]]+/, "", v); if (v != "") items = items (items == "" ? "" : ",") v }
            /^---/ { flush(); next }
            /^source:/ { v = $0; sub(/^source:[[:space:]]*/, "", v); gsub(/["'\'']/, "", v); src = v; lk = 0; next }
            # значение в строке (`filename: /var/log/x`, `filenames: [a, b]`) или списком ниже
            /^(filenames?|journalctl_filter|container_name|container_id):/ {
                v = $0; sub(/^[a-z_]+:[[:space:]]*/, "", v); gsub(/[][]/, "", v)
                lk = (v == ""); n = split(v, a, ","); for (i = 1; i <= n; i++) add(a[i]); next }
            /^[^[:space:]-]/ { lk = 0; next }
            lk && /^[[:space:]]*-[[:space:]]*/ { v = $0; sub(/^[[:space:]]*-[[:space:]]*/, "", v); add(v); next }
            END { flush() }' "$f"
    done | sort -u
}
# cs_allowlist — ЭФФЕКТИВНЫЙ allowlist CrowdSec: объединение ip/cidr всех парсеров
# s02-enrich с секцией whitelist (наш na-whitelist.yaml, хабовый whitelists, ручные
# файлы операторов). Сверять только наш файл — значит не видеть, что адрес прикрыт
# соседним, или считать прикрытым то, что из нашего файла выпало.
cs_allowlist() {
    local f
    for f in /etc/crowdsec/parsers/s02-enrich/*.yaml /etc/crowdsec/parsers/s02-enrich/*.yml; do
        [[ -f "$f" ]] || continue
        awk '
            /^[^[:space:]#-]/ { inwl = ($1 == "whitelist:"); mode = 0; next }
            !inwl { next }
            /^[[:space:]]+(ip|cidr):/ {
                mode = 1; v = $0; sub(/^[^:]*:/, "", v)
                if (v ~ /\[/) { gsub(/[][ "'\'']/, "", v); n = split(v, a, ","); for (i = 1; i <= n; i++) if (a[i] != "") print a[i] }
                next }
            /^[[:space:]]+[A-Za-z_]+:/ { mode = 0; next }
            mode && /^[[:space:]]*-[[:space:]]*/ { v = $0; sub(/^[[:space:]]*-[[:space:]]*/, "", v); gsub(/["'\'']/, "", v); sub(/[[:space:]]*#.*/, "", v); if (v != "") print v }
        ' "$f"
    done | sed -E 's#/32$##; s#/128$##' | sort -u
}
# wl_covered <адрес|сеть> <allowlist (по строке)> — прикрыт ли адрес (v4 — с учётом CIDR:
# сеть прикрыта, если её адрес входит в сеть allowlist с префиксом не длиннее; v6 — точно)
wl_covered() {
    local e="$1" a pe pa
    while IFS= read -r a; do
        [[ -n "$a" ]] || continue
        [[ "$a" == "$e" ]] && return 0
        [[ "$e" == *:* || "$a" == *:* || "$a" != */* ]] && continue
        pa="${a##*/}"; pe=32; [[ "$e" == */* ]] && pe="${e##*/}"
        [[ "$pa" =~ ^[0-9]+$ && "$pe" =~ ^[0-9]+$ ]] && (( pa <= pe )) || continue
        ip4_in_cidr "${e%%/*}" "$a" && return 0
    done <<<"$2"
    return 1
}

# ─── Прочее ──────────────────────────────────────────────────────────────────
# fw_counters — ненулевые именованные счётчики na_filter (protect v4.2: c_synflood,
# c_portscan, c_autoban…): «имя=пакетов» через пробел. Лог ограничен по скорости, а
# счётчик — нет: это форензика, когда лог уже молчит.
fw_counters() {
    _to 5 nft list counters table inet na_filter 2>/dev/null | awk '
        /counter c_[A-Za-z0-9_]+ \{/ { n = $2; next }
        n != "" && /packets [0-9]+/ { for (i = 1; i < NF; i++) if ($i == "packets") p = $(i + 1); if (p + 0 > 0) printf "%s%s=%s", (o++ ? " " : ""), n, p; n = "" }'
}
# file_sha256 <файл>
file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" 2>/dev/null | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
    fi
}
# xanmod_update — «пакет кандидат», если apt знает версию мета-пакета XanMod новее
# установленной И она из репозитория XanMod. По кэшу apt: сеть не трогаем. rc=1 — нет.
xanmod_update() {
    command -v apt-cache >/dev/null 2>&1 || return 1
    local pkg pol inst cand
    pkg="$(cat "$STATE_DIR/xanmod.pkg" 2>/dev/null)"
    if [[ -z "$pkg" ]] && command -v dpkg-query >/dev/null 2>&1; then
        pkg="$(dpkg-query -W -f='${Package} ${db:Status-Abbrev}\n' 'linux-xanmod*' 2>/dev/null \
               | awk '$2 ~ /^ii/ && $1 !~ /(image|headers)/ { print $1; exit }')"
    fi
    [[ "$pkg" =~ ^[a-z0-9.+-]+$ ]] || return 1
    pol="$(_to 10 apt-cache policy "$pkg" 2>/dev/null)" || return 1
    inst="$(awk '$1 == "Installed:" { print $2; exit }' <<<"$pol")"
    cand="$(awk '$1 == "Candidate:" { print $2; exit }' <<<"$pol")"
    [[ -n "$inst" && "$inst" != "(none)" && -n "$cand" && "$cand" != "(none)" && "$inst" != "$cand" ]] || return 1
    # источник кандидата: строки репозиториев под строкой его версии в «Version table»
    awk -v c="$cand" '
        /^ +(\*\*\* )?[^ ]+ [0-9]+$/ { v = $1; if (v == "***") v = $2; inv = (v == c); next }
        inv && /xanmod/ { f = 1 }
        END { exit !f }' <<<"$pol" || return 1
    echo "$pkg $cand"
}
# reboot_required_pkgs — /run/reboot-required: «why<TAB>пакеты». why: stock — только
# стоковые ядра при работающем XanMod (ребут ради них ничего не даст), other — иное.
reboot_required_pkgs() {
    [[ -f /run/reboot-required ]] || return 1
    local pk kr why=other
    pk="$(sort -u /run/reboot-required.pkgs 2>/dev/null | paste -sd' ' -)"
    kr="$(uname -r)"
    if [[ "${kr,,}" == *xanmod* && -n "$pk" ]] \
       && ! grep -qvE '^linux-(image|headers|modules|modules-extra)-[0-9].*$|^linux-(image|headers)-(amd64|generic|virtual|cloud-amd64)$' \
            <<<"$(tr ' ' '\n' <<<"$pk")" \
       && ! grep -qi xanmod <<<"$pk"; then
        why=stock
    fi
    printf '%s\t%s\n' "$why" "$pk"
}
# Пути сертов Caddy (docker volume и пакетный) и nginx ssl_certificate: на панели/
# CDN-origin серт живёт именно там, и сенсор сроков молчал (аудит флота).
nginx_cert_paths() {
    [[ -d /etc/nginx ]] || return 0
    local f p
    while IFS= read -r f; do
        while IFS= read -r p; do
            [[ -n "$p" && "$p" != *'$'* ]] || continue
            [[ "$p" == /* ]] || p="/etc/nginx/$p"
            printf '%s\n' "$p"
        done < <(sed -nE "s/^[[:space:]]*ssl_certificate[[:space:]]+[\"']?([^\"'; ]+)[\"']?[[:space:]]*;.*/\1/p" "$f" 2>/dev/null)
    done < <(find -L /etc/nginx -type f \( -path '*/sites-enabled/*' -o \( -name '*.conf' ! -path '*/sites-available/*' \) \) 2>/dev/null)
}
cert_candidates() {
    local cf
    # shellcheck disable=SC2086  # глобы и NA_CERT_PATHS обязаны раскрыться
    for cf in $NA_CERT_GLOBS ${NA_CERT_PATHS:-}; do [[ -f "$cf" ]] && printf '%s\n' "$cf"; done
    nginx_cert_paths
}
# cert_scan — ближайший к истечению серт: CERT_FOUND (0|1), CERT_MIN (дни, ≤0 = истёк или
# истекает в ближайшие сутки), CERT_MIN_F. Раньше −1 значил «не найдено», и просроченный
# серт (−10 дней) терялся: следующий живой (30) его «перекрывал».
CERT_FOUND=0; CERT_MIN=-1; CERT_MIN_F=""
cert_scan() {
    CERT_FOUND=0; CERT_MIN=-1; CERT_MIN_F=""
    command -v openssl >/dev/null 2>&1 || return 1
    local cf cend cends now df d
    now="$(date +%s)"
    while IFS= read -r cf; do
        [[ -f "$cf" ]] || continue
        cert_retired "$cf" && continue
        cend="$(openssl x509 -enddate -noout -in "$cf" 2>/dev/null | cut -d= -f2)"; [[ -n "$cend" ]] || continue
        cends="$(date -d "$cend" +%s 2>/dev/null)" || continue; [[ "$cends" =~ ^[0-9]+$ ]] || continue
        df=$(( cends - now ))
        if (( df >= 0 )); then d=$(( df / 86400 )); else d=$(( -((-df + 86399) / 86400) )); fi
        if [[ "$CERT_FOUND" == 0 ]] || (( d < CERT_MIN )); then CERT_MIN="$d"; CERT_MIN_F="$cf"; fi
        CERT_FOUND=1
    done < <(cert_candidates | awk '!seen[$0]++')
    return 0
}
# docker_nocap — работающие контейнеры с json-file БЕЗ max-size: их лог растёт без предела
# (daemon.json log-opts в inspect уже подмешаны — пусто значит «капа нет»)
docker_nocap() {
    command -v docker >/dev/null 2>&1 || return 0
    local ids; ids="$(docker ps -q 2>/dev/null)"; [[ -n "$ids" ]] || return 0
    # shellcheck disable=SC2086  # список id — нарочно словами
    docker inspect -f '{{.Name}} {{.HostConfig.LogConfig.Type}} {{index .HostConfig.LogConfig.Config "max-size"}}' $ids 2>/dev/null \
        | awk '($2 == "json-file" || $2 == "") && ($3 == "" || $3 == "<no") { sub(/^\//, "", $1); print $1 }'
}
# portscan_24h — «строк [na portscan] всего_строк» в журнале за сутки ПО ВСЕМ загрузкам
# (_TRANSPORT=kernel = `-k` без неявного `-b`: после ребута «за загрузку» — это часы).
# всего = −1, если не уложились в таймаут. rc=1 — не измерено.
portscan_24h() {
    command -v journalctl >/dev/null 2>&1 || return 1
    local help n tot rc
    help="$(_to 5 journalctl --help 2>/dev/null)"
    [[ "$help" == *--grep* ]] || return 1
    n="$(_to 15 journalctl -q --no-pager --since -24h _TRANSPORT=kernel -g '\[na portscan\]' 2>/dev/null | wc -l | tr -d ' ')"; rc=$?
    [[ "$rc" -eq 124 || ! "$n" =~ ^[0-9]+$ ]] && return 1
    tot="$(_to 20 journalctl -q --no-pager --since -24h -o cat 2>/dev/null | wc -l | tr -d ' ')"; rc=$?
    [[ "$rc" -eq 124 || ! "$tot" =~ ^[0-9]+$ ]] && tot=-1
    echo "$n $tot"
}
# journal_volatile — журнал только в RAM (/run/log/journal, нет /var/log/journal)
journal_volatile() { [[ -d /run/log/journal && ! -d /var/log/journal ]]; }
# sock_tier — «sock_max sock_def» от RAM, как ставит optimize (маркер; нет — тот же расчёт):
# tier1 (≤1.2G) получает 16M, и порог 32M давал ложный ▲ на каждой маленькой ноде.
sock_tier() {
    local f="$STATE_DIR/optimize.installed" mx df mb
    mx="$(mark_val sock_max "$f")"; df="$(mark_val sock_def "$f")"
    if [[ "$mx" =~ ^[0-9]+$ && "$df" =~ ^[0-9]+$ ]]; then echo "$mx $df"; return 0; fi
    mb="$(awk '/^MemTotal:/{ printf "%d", $2 / 1024 }' /proc/meminfo 2>/dev/null)"; [[ "$mb" =~ ^[0-9]+$ ]] || mb=4096
    if   (( mb <= 1200 )); then echo "16777216 524288"
    elif (( mb <= 2500 )); then echo "33554432 1048576"
    elif (( mb <= 8500 )); then echo "67108864 2097152"
    else                        echo "134217728 2097152"; fi
}
# port_in_list <порт> <список «a,b-c»> — порт покрыт списком (числом или диапазоном)?
port_in_list() {
    local p="$1" t
    for t in ${2//,/ }; do
        [[ "$t" =~ ^[0-9]+(-[0-9]+)?$ ]] || continue
        if [[ "$t" == *-* ]]; then (( p >= ${t%-*} && p <= ${t#*-} )) && return 0
        elif (( p == t )); then return 0; fi
    done
    return 1
}
# node_eph_unreserved — порты ноды (xray/rw-core/rw-node, включая 127.0.0.1) внутри
# ip_local_port_range и вне ip_local_reserved_ports: «порт(процесс)» через пробел.
node_eph_unreserved() {
    local lo hi resv a p pr out=""
    read -r lo hi <<<"$(val net.ipv4.ip_local_port_range)"
    [[ "$lo" =~ ^[0-9]+$ && "$hi" =~ ^[0-9]+$ ]] || return 0
    resv="$(val net.ipv4.ip_local_reserved_ports)"
    while IFS=$'\t' read -r a p pr; do
        [[ "$pr" == xray || "$pr" == rw-core || "$pr" == rw-node ]] || continue
        (( p >= lo && p <= hi )) || continue
        port_in_list "$p" "$resv" && continue
        [[ " $out " == *" $p($pr) "* ]] || out+="${out:+ }$p($pr)"
    done < <(listen_rows tcp; listen_rows udp)
    echo "$out"
}

# ─── JSON-режим (для флот-мониторинга: Zabbix/Prometheus/SSH-поллинг) ─────────
# `diagnose.sh --json` печатает один машинно-читаемый объект и выходит. Read-only.
emit_json() {
    local kern xanmod virt cc qd ctmax ctcnt ctpct uln minsnd mtuprobe collapsed
    local fw fwm ab4 ab6 susp bl4 bl6 fl4 fl6 crowd ctg syndeg safety rebootn
    local steal out rtx rtxpct
    local nav host up load1 mempct wi wanrx wantx ip6def udperr
    local rnst rnrc rnse fsa bla certd certf nowsec cf npd npfw
    local mcpi jsp psl psist wdc csd tcpp wl_live wl_conf tmpv
    local dsf dsfn dsnt _dn _dc _ds _dt
    local stealb csl csc wdcs wl_all csal dnp dng xmu cfound ps24 pst psh csscope
    kern="$(uname -r)"; [[ "${kern,,}" == *xanmod* ]] && xanmod=true || xanmod=false
    virt="$(detect_virt)"
    cc="$(val net.ipv4.tcp_congestion_control)"; qd="$(val net.core.default_qdisc)"
    ctmax="$(val net.netfilter.nf_conntrack_max)"; ctmax="${ctmax:-0}"
    ctcnt="$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)"
    ctpct=0; [[ "${ctmax:-0}" -gt 0 ]] && ctpct=$(( ctcnt * 100 / ctmax ))
    uln="$(ulimit -n 2>/dev/null || echo 0)"; [[ "$uln" =~ ^[0-9]+$ ]] || uln=0   # RLIMIT=infinity → "unlimited" сломал бы JSON-число
    minsnd="$(val net.ipv4.tcp_min_snd_mss)"; minsnd="${minsnd:-0}"
    mtuprobe="$(val net.ipv4.tcp_mtu_probing)"; mtuprobe="${mtuprobe:-0}"
    # только established: отмирающие сокеты (TIME-WAIT и пр.) давали ложный «коллапс»
    collapsed="$(ss -tin state established 2>/dev/null | grep -oE 'mss:[0-9]+' | awk -F: '$2>0 && $2<256{c++} END{print c+0}')"
    # CPU steal: окно 3 с + среднее с загрузки (секундный семпл был шумом)
    steal=0; stealb=0
    [[ -r /proc/stat ]] && read -r steal stealb <<<"$(cpu_steal_measure 3)"
    [[ "$steal" =~ ^[0-9]+$ ]] || steal=0; [[ "$stealb" =~ ^[0-9]+$ ]] || stealb=0
    # дельты счётчиков к прошлому запуску (diag-counters.last)
    delta_load
    out=0; rtx=0; rtxpct=0
    if [[ -r /proc/net/snmp ]]; then
        eval "$(awk '/^Tcp:/{ if(!h){for(i=2;i<=NF;i++)nm[i]=$i;h=1;next} for(i=2;i<=NF;i++){if(nm[i]=="OutSegs")print "out="$i;if(nm[i]=="RetransSegs")print "rtx="$i} }' /proc/net/snmp 2>/dev/null)"
        out="${out:-0}"; rtx="${rtx:-0}"; [[ "$out" -gt 0 ]] && rtxpct=$(( rtx * 100 / out ))
    fi
    nft -t list table inet na_filter >/dev/null 2>&1 && fw=true || fw=false
    # режим файрвола из маркера protect (strict|open|skip; пусто = protect не гонялся
    # или старая версия без fw_mode) — панель отличает осознанный skip/open от «защиты нет»
    fwm="$(awk -F= '/^fw_mode=/{print $2}' "$STATE_DIR/protect.installed" 2>/dev/null)"; fwm="${fwm:-}"
    # Считаем АДРЕСА, а не строки вывода nft: в заголовке динамического набора всегда
    # есть `flags dynamic,timeout` → `grep -c timeout` давал «1» на пустом наборе и +1
    # (с 'expires' — +2) на непустом, и этот ряд уезжал прямо в Zabbix/Prometheus
    # («autoban > 0» горел вечно). Общий хелпер — в lib/common.sh (issue #32/#36).
    ab4="$(nft_set_count inet na_filter autoban_v4)"
    ab6="$(nft_set_count inet na_filter autoban_v6)"
    susp="$(nft_set_count inet na_filter suspect_v4)"
    bl4="$(nft_set_count inet na_filter blocklist_v4)"
    bl6="$(nft_set_count inet na_filter blocklist_v6)"
    fl4="$(nft_set_count inet na_filter na_fleet_v4)"
    fl6="$(nft_set_count inet na_filter na_fleet_v6)"
    command -v cscli >/dev/null 2>&1 && { systemctl is-active --quiet crowdsec && crowd=true || crowd=false; } || crowd=false
    if nft list table inet na_ctguard >/dev/null 2>&1; then
        local enf; enf="$(awk -F= '/^NA_CTG_ENFORCE/{print $2}' /etc/node-accelerator/ctguard.conf 2>/dev/null)"
        [[ "${enf:-0}" == 1 ]] && ctg=enforce || ctg=observe
    else ctg=off; fi
    [[ -f "$STATE_DIR/.synproxy-degraded" ]] && syndeg=true || syndeg=false
    { systemctl is-active --quiet na-fw-safety.timer 2>/dev/null \
      || { [[ -f "$STATE_DIR/na-fw-safety.pid" ]] && kill -0 "$(cat "$STATE_DIR/na-fw-safety.pid" 2>/dev/null)" 2>/dev/null; }; } \
      && safety=true || safety=false
    rebootn=false; reboot_pending && rebootn=true

    # ── na-panel extras: identity, нагрузка, WAN-счётчики, стек ноды, свежесть, серты ──
    nowsec="$(date +%s)"
    nav="${NA_VERSION:-?}"
    host="$(hostname 2>/dev/null || echo '?')"
    up="$(awk '{printf "%d",$1}' /proc/uptime 2>/dev/null)"; up="${up:-0}"
    load1="$(awk '{print $1+0}' /proc/loadavg 2>/dev/null)"; load1="${load1:-0}"
    mempct="$(awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{if(t>0)printf "%d",(t-a)*100/t; else print 0}' /proc/meminfo 2>/dev/null)"; mempct="${mempct:-0}"
    wi="$(default_iface)"; wi="${wi:-}"
    wanrx=0; wantx=0
    if [[ -n "$wi" ]]; then
        wanrx="$(cat "/sys/class/net/$wi/statistics/rx_bytes" 2>/dev/null || echo 0)"
        wantx="$(cat "/sys/class/net/$wi/statistics/tx_bytes" 2>/dev/null || echo 0)"
    fi
    [[ "$wanrx" =~ ^[0-9]+$ ]] || wanrx=0; [[ "$wantx" =~ ^[0-9]+$ ]] || wantx=0
    [[ -n "$(ip -6 route show default 2>/dev/null)" ]] && ip6def=true || ip6def=false
    udperr="$(awk '/^Udp:/{if(!h){for(i=2;i<=NF;i++)n[i]=$i;h=1;next} for(i=2;i<=NF;i++) if(n[i]=="RcvbufErrors") print $i}' /proc/net/snmp 2>/dev/null)"
    udperr="${udperr:-0}"; [[ "$udperr" =~ ^[0-9]+$ ]] || udperr=0
    # remnanode (Remnawave node-контейнер) — статус/рестарты/SPAWN_ERROR за час. Read-only.
    rnst="no-docker"; rnrc=0; rnse=0
    if command -v docker >/dev/null 2>&1; then
        # `docker inspect -f` по несуществующему контейнеру (29.x) печатает в stdout
        # ПУСТУЮ строку и только потом падает: идиома `… || echo absent` давала
        # "\nabsent" — статус не совпадал с absent, а сырой перевод строки ломал ВЕСЬ
        # JSON-документ (issue #27). Не смешиваем stdout с кодом возврата.
        rnst="$(docker inspect -f '{{.State.Status}}' "$NA_NODE_CONTAINER" 2>/dev/null | tr -d '[:space:]')"
        [[ -n "$rnst" ]] || rnst=absent
        rnrc="$(docker inspect -f '{{.RestartCount}}' "$NA_NODE_CONTAINER" 2>/dev/null | tr -d '[:space:]')"
        [[ "$rnrc" =~ ^[0-9]+$ ]] || rnrc=0
        if [[ "$rnst" != "absent" ]]; then
            rnse="$(docker logs --since 1h "$NA_NODE_CONTAINER" 2>&1 | grep -c 'SPAWN_ERROR' || true)"; [[ "$rnse" =~ ^[0-9]+$ ]] || rnse=0
        fi
    fi
    # порт node-агента: факт (детект с ноды) vs заложенный в файрвол — рассинхрон
    # (миграция агента 2222→3000 при strict) панель видит как «нода недоступна»
    npd="$(detect_node_port || true)"
    npfw="$(awk -F= '/^node_port=/{print $2}' "$STATE_DIR/protect.installed" 2>/dev/null)"; npfw="${npfw:-}"
    # сейфти УЖЕ срабатывал (−1 = не срабатывал): значение ≥0 = таблица снята и
    # автозагрузка выключена, т.е. защиты СЕЙЧАС нет до повторного прогона protect
    sfa=-1
    [[ -f "$STATE_DIR/safety-fired.last" ]] && { cf="$(cat "$STATE_DIR/safety-fired.last" 2>/dev/null)"; [[ "$cf" =~ ^[0-9]+$ ]] && sfa=$(( nowsec - cf )); }
    # переживут ли правила ребут (na-firewall.service в автозагрузке)
    fwboot=0
    systemctl is-enabled --quiet na-firewall.service 2>/dev/null && fwboot=1
    # свежесть последнего УСПЕШНОГО синка (−1 = штампа нет / модуль не активен)
    fsa=-1; bla=-1
    [[ -f "$STATE_DIR/fleet-sync.last" ]] && { cf="$(cat "$STATE_DIR/fleet-sync.last" 2>/dev/null)"; [[ "$cf" =~ ^[0-9]+$ ]] && fsa=$(( nowsec - cf )); }
    [[ -f "$STATE_DIR/blocklist.last" ]] && { cf="$(cat "$STATE_DIR/blocklist.last" 2>/dev/null)"; [[ "$cf" =~ ^[0-9]+$ ]] && bla=$(( nowsec - cf )); }
    # ближайший к истечению серт. cert_min_days = −1 и cert_found=false — не нашли/нет
    # openssl; при cert_found=true значение может быть ≤0 (истёк). NA_CERT_PATHS — доп.
    # пути через пробел; используются только в [ -f ] и openssl (без eval).
    cert_scan || true
    certd="$CERT_MIN"; certf="$CERT_MIN_F"; cfound=false
    [[ "$CERT_FOUND" == 1 ]] && cfound=true || certd=-1

    # ── v4.1: метрики, которых мониторингу не хватало ──────────────────────────
    # max_conn_per_ip: по тому же срезу, что и правило `ct count` (−1 = мерить не по чему)
    mcpi=-1
    # порты — из живых правил (маркер устаревает после ручных правок), затем conf/маркер
    tcpp="$(fw_ports tcp)"
    if [[ -n "${tcpp:-}" ]]; then
        tmpv="$(conn_per_ip_max "$tcpp")" && [[ "$tmpv" =~ ^[0-9]+$ ]] && mcpi="$tmpv"
    fi
    # глубина журнала и объём лога анти-скана (−1 = не измерено)
    jsp=-1; tmpv="$(journal_span_h)" && [[ "$tmpv" =~ ^[0-9]+$ ]] && jsp="$tmpv"
    psl=-1; tmpv="$(portscan_log_lines)" && [[ "$tmpv" =~ ^[0-9]+$ ]] && psl="$tmpv"
    # за сутки по всем загрузкам + доля от всех строк журнала за сутки (−1 = не измерено)
    ps24=-1; psh=-1
    if tmpv="$(portscan_24h)"; then
        read -r ps24 pst <<<"$tmpv"
        [[ "$pst" =~ ^[0-9]+$ ]] && (( pst > 0 )) && psh=$(( ps24 * 100 / pst ))
    fi
    psist="$(psi_state)"; psist="${psist:-unknown}"
    # whitelist_drift_conf: адреса живого whitelist_v4, которых НЕТ в WHITELIST= из
    # protect.conf — они не переживут ре-ран protect (−1 = conf нет, сверять не с чем)
    wdc=-1
    if [[ -f "$CONF_DIR/protect.conf" ]]; then
        wl_live="$(nft_set_elems inet na_filter whitelist_v4 2>/dev/null | sed -E 's#/32$##' | sort -u)"
        wl_conf="$(conf_val "$CONF_DIR/protect.conf" WHITELIST \
                   | tr ',' '\n' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?' | sed -E 's#/32$##' | sort -u)"
        wdc="$(comm -23 <(printf '%s\n' "$wl_live" | grep -v '^$' | sort -u) \
                        <(printf '%s\n' "$wl_conf" | grep -v '^$' | sort -u) 2>/dev/null | grep -c .)"
        [[ "$wdc" =~ ^[0-9]+$ ]] || wdc=-1
    fi
    # сохранённый conf пиннит дефолты той версии, при которой ноду настраивали
    csd="$( { conf_stale_defaults "$CONF_DIR/protect.conf"; conf_stale_defaults "$CONF_DIR/optimize.conf"; } 2>/dev/null | grep -c .)"
    [[ "$csd" =~ ^[0-9]+$ ]] || csd=0

    # Диск, inodes и лог-флуд: в человекочитаемом выводе они были, а во флот-мониторинге —
    # нет, поэтому самая частая авария (диск под завязку от нертотируемого лога) была не
    # видна снаружи вообще, пока нода не замолкала.
    dsp="$(df -P / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5);print $5}')"; [[ "$dsp" =~ ^[0-9]+$ ]] || dsp=0
    din="$(df -Pi / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5);print $5}')"; [[ "$din" =~ ^[0-9]+$ ]] || din=0
    logmax="$(find /var/log -xdev -type f -printf '%s\n' 2>/dev/null | sort -rn | head -1)"; [[ "$logmax" =~ ^[0-9]+$ ]] || logmax=0
    dklogmax="$(find /var/lib/docker/containers -xdev -type f -name '*-json.log' -printf '%s\n' 2>/dev/null | sort -rn | head -1)"
    [[ "$dklogmax" =~ ^[0-9]+$ ]] || dklogmax=0
    lrt=0; systemctl is-active --quiet na-logrotate.timer 2>/dev/null && lrt=1
    # Таймер ≠ станса: маски, отданные чужим стансам, тулкит не ротирует, а таймер при
    # этом активен (issue #40). owned/ceded пишет optimize; пусто = станс/уступок нет.
    lro="$(paste -sd' ' "$STATE_DIR/logrotate.owned" 2>/dev/null || true)"; lro="${lro:-}"
    lrc="$(cut -f1 "$STATE_DIR/logrotate.ceded" 2>/dev/null | paste -sd' ' - || true)"; lrc="${lrc:-}"
    lrcn="$(awk -F'\t' '$3=="none"' "$STATE_DIR/logrotate.ceded" 2>/dev/null | grep -c .)"; [[ "$lrcn" =~ ^[0-9]+$ ]] || lrcn=0
    lro="$(json_escape "$lro")"; lrc="$(json_escape "$lrc")"
    # v4.1.3: заполненность наборов-лимитеров (−1 = таблицы нет) и сколько из них без
    # timeout (наследие ≤4.1.2: такие копят адреса до ребута и на 100% режут новых)
    dsf=-1; dsfn=""; dsnt=0
    while IFS=$'\t' read -r _dn _dc _ds _dt; do
        [[ -n "$_dn" ]] || continue
        [[ "$dsf" -lt 0 ]] && dsf=0
        (( _dc * 100 / _ds > dsf )) && { dsf=$(( _dc * 100 / _ds )); dsfn="$_dn"; }
        [[ "$_dt" == "0" ]] && dsnt=$((dsnt+1))
    done < <(dynset_fill 2>/dev/null)
    dsfn="$(json_escape "$dsfn")"

    # v4.2: CrowdSec по источникам решений (−1 = нет cscli / не ответил) и область действия
    csl=-1; csc=-1
    if tmpv="$(cs_decisions)"; then read -r csl csc <<<"$tmpv"; fi
    [[ "$csl" =~ ^-?[0-9]+$ ]] || csl=-1; [[ "$csc" =~ ^-?[0-9]+$ ]] || csc=-1
    csscope="$(mark_val crowdsec_scope)"
    # живой whitelist, не прикрытый ЭФФЕКТИВНЫМ allowlist CrowdSec (−1 = сверять не с чем):
    # такой адрес CrowdSec может забанить, а bouncer режет раньше na_filter
    wdcs=-1
    if [[ "$fw" == true ]] && { command -v cscli >/dev/null 2>&1 || [[ -d /etc/crowdsec ]]; }; then
        wdcs=0
        wl_all="$( { nft_set_elems inet na_filter whitelist_v4; nft_set_elems inet na_filter whitelist_v6; } 2>/dev/null \
                   | sed -E 's#/32$##; s#/128$##' | sort -u)"
        csal="$(cs_allowlist)"
        while IFS= read -r tmpv; do
            [[ -n "$tmpv" ]] || continue
            wl_covered "$tmpv" "$csal" || wdcs=$((wdcs+1))
        done <<<"$wl_all"
    fi
    # опубликованные через DNAT порты и защищает ли их na_filter (dnat_guard: −1 = нет ключа)
    dnp="$(dnat_ports)"
    dng="$(mark_val dnat_guard)"; [[ "$dng" =~ ^[01]$ ]] || dng=-1
    # доступное обновление XanMod (по кэшу apt; пусто = нет/не знаем)
    xmu=""; tmpv="$(xanmod_update)" && xmu="${tmpv#* }"

    # Каждое строковое значение — через json_escape. Раньше каждое поле полагалось на то,
    # что источник «и так чистый», и одного сырого перевода строки из docker хватило,
    # чтобы уронить парсер на ВСЁМ документе (issue #27).
    kern="$(json_escape "$kern")";   virt="$(json_escape "$virt")"
    cc="$(json_escape "${cc:-}")";   qd="$(json_escape "${qd:-}")"
    fwm="$(json_escape "$fwm")";     ctg="$(json_escape "$ctg")"
    nav="$(json_escape "$nav")";     host="$(json_escape "$host")"
    wi="$(json_escape "$wi")";       rnst="$(json_escape "$rnst")"
    npd="$(json_escape "${npd:-}")"; npfw="$(json_escape "$npfw")"
    psist="$(json_escape "$psist")"; certf="$(json_escape "$certf")"
    dnp="$(json_escape "$dnp")";     xmu="$(json_escape "$xmu")"
    csscope="$(json_escape "$csscope")"

    printf '{'
    printf '"kernel":"%s","xanmod":%s,"virt":"%s","cpu_steal_pct":%s,"tcp_retrans_pct":%s,' "$kern" "$xanmod" "$virt" "$steal" "$rtxpct"
    printf '"congestion_control":"%s","qdisc":"%s","conntrack_max":%s,"conntrack_count":%s,"conntrack_pct":%s,' "${cc:-}" "${qd:-}" "$ctmax" "$ctcnt" "$ctpct"
    printf '"ulimit_n":%s,"min_snd_mss":%s,"mtu_probing":%s,"mss_collapsed_sockets":%s,' "${uln:-0}" "$minsnd" "$mtuprobe" "${collapsed:-0}"
    printf '"firewall":%s,"fw_mode":"%s","autoban_v4":%s,"autoban_v6":%s,"suspect":%s,"blocklist_v4":%s,"blocklist_v6":%s,' "$fw" "$fwm" "$ab4" "$ab6" "$susp" "$bl4" "$bl6"
    printf '"fleet_v4":%s,"fleet_v6":%s,"crowdsec":%s,"ctguard":"%s","synproxy_degraded":%s,' "$fl4" "$fl6" "$crowd" "$ctg" "$syndeg"
    printf '"safety_armed":%s,"safety_fired_age_s":%s,"fw_boot_enabled":%s,"reboot_needed":%s,' "$safety" "$sfa" "$fwboot" "$rebootn"
    printf '"na_version":"%s","hostname":"%s","uptime_s":%s,"load1":%s,"mem_used_pct":%s,' "$nav" "$host" "$up" "$load1" "$mempct"
    printf '"wan_iface":"%s","wan_rx_bytes":%s,"wan_tx_bytes":%s,"ipv6_default":%s,"udp_rcvbuf_errors":%s,' "$wi" "$wanrx" "$wantx" "$ip6def" "$udperr"
    printf '"remnanode_status":"%s","remnanode_restarts":%s,"remnanode_spawn_errors_1h":%s,' "$rnst" "$rnrc" "$rnse"
    printf '"node_port_detected":"%s","node_port_fw":"%s",' "$npd" "$npfw"
    printf '"fleet_sync_age_s":%s,"blocklist_age_s":%s,"cert_min_days":%s,' "$fsa" "$bla" "$certd"
    printf '"disk_pct":%s,"inode_pct":%s,"log_max_bytes":%s,"docker_log_max_bytes":%s,"logrotate_timer":%s,' \
        "$dsp" "$din" "$logmax" "$dklogmax" "$lrt"
    # v4.1 (аудит флота): новые поля ТОЛЬКО в хвост — имена и порядок прежних читает
    # мониторинг. −1 везде = «не измерено», а не «ноль».
    printf '"max_conn_per_ip":%s,"journal_span_h":%s,"portscan_log_lines_boot":%s,"psi":"%s",' \
        "$mcpi" "$jsp" "$psl" "$psist"
    printf '"whitelist_drift_conf":%s,"conf_stale_defaults":%s,"cert_min_file":"%s",' \
        "$wdc" "$csd" "$certf"
    printf '"logrotate_owned_masks":"%s","logrotate_ceded_masks":"%s","logrotate_ceded_nocap":%s,' \
        "$lro" "$lrc" "$lrcn"
    printf '"dynset_fill_max_pct":%s,"dynset_fill_max_set":"%s","dynset_no_timeout":%s,' \
        "$dsf" "$dsfn" "$dsnt"
    # v4.2 (аудит флота): дельты к прошлому запуску (−1 = окна ещё нет: первый запуск,
    # ребут или прошло <30 с), steal с загрузки, CrowdSec по источникам, 4-й слой
    # whitelist, DNAT мимо na_filter, обновление XanMod, флаг «серт найден», лог анти-скана за сутки
    printf '"udp_rcvbuf_errors_delta":%s,"softnet_drops_delta":%s,"time_squeeze_delta":%s,"listen_overflows_delta":%s,"delta_window_s":%s,' \
        "$D_UDPERR" "$D_SNDROP" "$D_SQZ" "$D_LOVF" "$DW"
    printf '"cpu_steal_boot_pct":%s,"crowdsec_decisions_local":%s,"crowdsec_decisions_capi":%s,"crowdsec_scope":"%s",' \
        "$stealb" "$csl" "$csc" "$csscope"
    printf '"whitelist_drift_crowdsec":%s,"dnat_ports":"%s","dnat_guard":%s,"xanmod_update":"%s","cert_found":%s,' \
        "$wdcs" "$dnp" "$dng" "$xmu" "$cfound"
    printf '"portscan_log_lines_24h":%s,"portscan_log_share_pct":%s}\n' "$ps24" "$psh"
}
if [[ "${1:-}" == "--json" ]]; then emit_json; exit 0; fi

# ─── Глубокий разбор retrans (`--retrans [--window N]`) ───────────────────────
# Панель/`--json` показывают tcp_retrans_pct и mss_collapsed — это инструмент
# «докопаться до причины»: TX vs RX, тип retrans, хвост сокетов, CC на проводе,
# дропы qdisc/ring/softirq, accept-queue, TCP-фичи + вердикт. Read-only. Все дельты
# снимаются за ОДНО окно (а не цепочкой sleep'ов).
_snmp()    { awk -v k="$1" '/^Tcp:/{if(!h){for(i=2;i<=NF;i++)n[i]=$i;h=1;next} for(i=2;i<=NF;i++) if(n[i]==k) print $i}' /proc/net/snmp 2>/dev/null; }
_tcpext()  { awk -v k="$1" '/^TcpExt:/{if(!h){for(i=2;i<=NF;i++)n[i]=$i;h=1;next} for(i=2;i<=NF;i++) if(n[i]==k) print $i}' /proc/net/netstat 2>/dev/null; }
_tcq()     { tc -s qdisc show dev "$1" 2>/dev/null | grep -oE "$2 [0-9]+" | head -1 | awk '{print $2+0}'; }
_softirq() { awk -v k="$1" '$1==k":"{s=0;for(i=2;i<=NF;i++)s+=$i;print s}' /proc/softirqs 2>/dev/null; }

retrans_deep() {
    local win=20 IFACE k v d
    [[ "${1:-}" == "--window" && -n "${2:-}" ]] && win="$2"
    [[ "$win" =~ ^[0-9]+$ && "$win" -ge 5 && "$win" -le 300 ]] || win=20
    IFACE="$(default_iface)"; IFACE="${IFACE:-eth0}"

    clear 2>/dev/null || true
    printf "%b" "$BOLD"
    cat <<'B'
  ┌────────────────────────────────────────────┐
  │   🔬  node-accelerator — разбор retrans     │
  └────────────────────────────────────────────┘
B
    printf "%b" "$NC"
    info "iface=$IFACE   окно семплинга=${win}s   (read-only)"

    # ── BEFORE
    local out0 rtx0 in0; out0="$(_snmp OutSegs)"; rtx0="$(_snmp RetransSegs)"; in0="$(_snmp InSegs)"
    local exts="TCPLostRetransmit TCPSlowStartRetrans TCPSynRetrans TCPTimeouts TCPSackRecovery TCPSpuriousRtxHostQueues TCPBacklogDrop TCPRcvQDrop"
    declare -A E0
    for k in $exts; do v="$(_tcpext "$k")"; E0[$k]="${v:-0}"; done
    local qd0 qo0 qr0 rx0 tx0 eth0f=""
    qd0="$(_tcq "$IFACE" dropped)"; qo0="$(_tcq "$IFACE" overlimits)"; qr0="$(_tcq "$IFACE" requeues)"
    rx0="$(_softirq NET_RX)"; tx0="$(_softirq NET_TX)"
    command -v ethtool >/dev/null 2>&1 && { eth0f="$(mktemp)"; ethtool -S "$IFACE" 2>/dev/null > "$eth0f"; }

    sleep "$win"

    # ── AFTER + дельты
    local out1 rtx1 in1 dout drtx din rate ratio
    out1="$(_snmp OutSegs)"; rtx1="$(_snmp RetransSegs)"; in1="$(_snmp InSegs)"
    dout=$(( ${out1:-0} - ${out0:-0} )); drtx=$(( ${rtx1:-0} - ${rtx0:-0} )); din=$(( ${in1:-0} - ${in0:-0} ))

    title "1) Retrans rate (за ${win}s)"
    if [[ "$dout" -gt 0 ]]; then
        rate="$(awk -v r="$drtx" -v o="$dout" 'BEGIN{printf "%.2f", r*100/o}')"
        status_line "$(awk -v x="$rate" 'BEGIN{print (x>=5?"FAIL":(x>=2?"WARN":"OK"))}')" "retrans = ${rate}%   (Retrans Δ=$drtx / OutSegs Δ=$dout)"
    else
        info "трафика за окно почти не было (OutSegs Δ=$dout) — увеличь --window"
    fi
    ratio="$(awk -v i="$din" -v o="$dout" 'BEGIN{if(i>0)printf "%.2f",o/i; else print "?"}')"
    info "InSegs Δ=$din  OutSegs Δ=$dout  out/in=$ratio   (>>1 = download через ноду; <1 = upload)"

    title "2) Тип retrans (Δ за ${win}s — что доминирует)"
    for k in $exts; do
        v="$(_tcpext "$k")"; v="${v:-0}"; d=$(( v - ${E0[$k]:-0} ))
        [[ "$d" -gt 0 ]] && printf "   %-28s +%d\n" "$k" "$d"
    done
    cat <<'I'
   ─ SackRecovery/SlowStartRetrans = реальные потери (SACK/dup-ACK)
   ─ Timeouts = RTO/stall (тяжёлые потери или залипание пути/таргета)
   ─ LostRetransmit = ретрансмит сам потерялся → плохой путь
   ─ SpuriousRtxHostQueues = буферизация в host-очередях (qdisc/ring)
   ─ BacklogDrop = переполнение accept-queue (приложение не успевает)
I

    title "3) Хвост по сокетам (top retrans)"
    if command -v ss >/dev/null 2>&1; then
        ss -tin state established 2>/dev/null \
          | awk '/retrans:/{ if(match($0,/retrans:[0-9]+\/[0-9]+/)){ s=substr($0,RSTART,RLENGTH); split(s,p,"/"); if(p[2]+0>0) print p[2] } }' \
          | sort -rn | head -8 | awk '{printf "   retrans=%s\n",$1}'
        ss -tin state established 2>/dev/null | grep -oE 'retrans:[0-9]+/[0-9]+' | awk -F/ '{print $2}' \
          | awk '{t++; if($1==0)b["0"]++; else if($1<5)b["1-4"]++; else if($1<20)b["5-19"]++; else if($1<100)b["20-99"]++; else b["100+"]++}
                 END{ if(t){printf "   распределение по %d сокетам → ",t; for(x in b) printf "%s:%d  ",x,b[x]; print ""} }'
    else warn "ss недоступен"; fi

    title "4) Congestion control на проводе"
    info "настройка: cc=$(val net.ipv4.tcp_congestion_control)  qdisc=$(val net.core.default_qdisc)"
    if command -v ss >/dev/null 2>&1; then
        local ccdist; ccdist="$(ss -tin state established 2>/dev/null | grep -oE ' (bbr|cubic|reno|htcp|vegas|dctcp) ' | sort | uniq -c | sort -rn | awk '{printf "%s:%s  ",$2,$1}')"
        [[ -n "$ccdist" ]] && info "на сокетах: $ccdist" || info "на сокетах: (нет ESTAB или старый ss)"
        # счёт, а не grep -q: на тысячах сокетов grep -q закрывал пайп раньше ss → SIGPIPE →
        # под pipefail условие было ложным ВСЕГДА, и предупреждение не срабатывало никогда
        if [[ "$(ss -tin state established 2>/dev/null | grep -cE ' cubic ')" -gt 0 ]] && [[ "$(val net.ipv4.tcp_congestion_control)" == "bbr" ]]; then
            warn "часть сокетов на cubic при cc=bbr — это коннекты ДО смены CC (или приложение задаёт своё)"
        fi
    fi

    title "5) Дропы TX-тракта (Δ за ${win}s)"
    local qd1 qo1 qr1 rx1 tx1
    qd1="$(_tcq "$IFACE" dropped)"; qo1="$(_tcq "$IFACE" overlimits)"; qr1="$(_tcq "$IFACE" requeues)"
    printf "   qdisc: dropped +%s  overlimits +%s  requeues +%s\n" "$(( ${qd1:-0}-${qd0:-0} ))" "$(( ${qo1:-0}-${qo0:-0} ))" "$(( ${qr1:-0}-${qr0:-0} ))"
    rx1="$(_softirq NET_RX)"; tx1="$(_softirq NET_TX)"
    printf "   softirq: NET_RX +%s  NET_TX +%s\n" "$(( ${rx1:-0}-${rx0:-0} ))" "$(( ${tx1:-0}-${tx0:-0} ))"
    if [[ -n "$eth0f" ]]; then
        local eth1f; eth1f="$(mktemp)"; ethtool -S "$IFACE" 2>/dev/null > "$eth1f"
        awk 'NR==FNR{a[$1]=$2;next}{if($2+0>a[$1]+0 && (($1) in a)) printf "   nic: %-30s +%d\n",$1,$2-a[$1]}' "$eth0f" "$eth1f" \
          | grep -iE 'drop|err|miss|fifo|nobuf|over' | head -8
        rm -f "$eth0f" "$eth1f"
    fi

    title "6) Очереди и TCP-фичи"
    if command -v ss >/dev/null 2>&1; then
        info "состояния: $(ss -tan 2>/dev/null | awk 'NR>1{c[$1]++}END{for(s in c)printf "%s:%d ",s,c[s]}')"
        local lq; lq="$(ss -tlnH 2>/dev/null | awk '$2+0>0{print $4"(rq="$2")"}' | head -5 | tr '\n' ' ')"
        [[ -n "$lq" ]] && warn "listen-очереди с backlog: $lq" || info "listen-очереди: пусто (accept успевает)"
    fi
    info "sack=$(val net.ipv4.tcp_sack) dsack=$(val net.ipv4.tcp_dsack) ts=$(val net.ipv4.tcp_timestamps) frto=$(val net.ipv4.tcp_frto) recovery=$(val net.ipv4.tcp_recovery)"
    local msnd mtup collapsed
    msnd="$(val net.ipv4.tcp_min_snd_mss)"; mtup="$(val net.ipv4.tcp_mtu_probing)"
    collapsed="$(ss -tin 2>/dev/null | grep -oE 'mss:[0-9]+' | awk -F: '$2>0 && $2<256{c++}END{print c+0}')"
    info "min_snd_mss=${msnd:-?} mtu_probing=${mtup:-?} collapsed_sockets=${collapsed:-0}"

    title "Вердикт"
    local said=0
    [[ "$(( ${qd1:-0}-${qd0:-0} ))" -gt 0 ]] && { warn "qdisc дропает на TX — переполнение исходящей очереди (burst/линия медленнее ядра)"; said=1; }
    [[ "${collapsed:-0}" -gt 0 && "${msnd:-0}" -le 64 ]] && { warn "MSS-коллапс: min_snd_mss=${msnd:-?} + collapsed=${collapsed} → send-MSS схлопывается на лоссовом плече (mtu_probing=${mtup:-?}); floor 512 + mtu_probing=0 лечит"; said=1; }
    [[ "$said" -eq 0 ]] && ok "явных TX-узких мест за окно не видно — смотри тип retrans выше (Timeouts=путь/таргет, SackRecovery=потери к клиенту)"
    echo
}
if [[ "${1:-}" == "--retrans" ]]; then shift; retrans_deep "$@"; exit 0; fi

clear 2>/dev/null || true
printf "%b" "$BOLD"
cat <<'B'
  ┌────────────────────────────────────────────┐
  │   🩺  node-accelerator — диагностика ноды   │
  └────────────────────────────────────────────┘
B
printf "%b" "$NC"

# ─── Система ─────────────────────────────────────────────────────────────────
title "Система"
VIRT="$(detect_virt)"
CORES="$(nproc 2>/dev/null || echo '?')"
MEM="$(free -h 2>/dev/null | awk '/Mem:/{print $2}')"
info "Хост:   $(hostname 2>/dev/null || echo '?')   node-accelerator v${NA_VERSION:-?}"
info "OS:     ${PRETTY_NAME:-$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")}"
info "Kernel: $(uname -r)   Arch: $(arch)"
info "Virt:   $VIRT   CPU: ${CORES} ядер   RAM: ${MEM:-?}"
info "Uptime: $(uptime -p 2>/dev/null || uptime)"
# CPU steal: сколько CPU у нашей VPS отбирает гипервизор — главный скрытый потолок,
# не виден в load/governor. Окно 3 с (секундный семпл на флоте прыгал 0↔8%) + среднее с
# загрузки и с прошлого запуска: всплеск ≠ хронический оверселл.
delta_load
if [[ -r /proc/stat ]]; then
    read -r STEAL STEAL_BOOT <<<"$(cpu_steal_measure 3)"
    [[ "$STEAL" =~ ^[0-9]+$ ]] || STEAL=0; [[ "$STEAL_BOOT" =~ ^[0-9]+$ ]] || STEAL_BOOT=0
    STEAL_LONG="$STEAL_BOOT"; [[ "$D_STEAL" -ge 0 ]] && STEAL_LONG="$D_STEAL"
    STEAL_TXT="CPU steal = ${STEAL}% за 3 с, в среднем с загрузки ${STEAL_BOOT}%"
    [[ "$D_STEAL" -ge 0 ]] && STEAL_TXT+=", за $((DW/60)) мин с прошлого запуска ${D_STEAL}%"
    if   [[ "$STEAL" -ge 10 && "$STEAL_LONG" -ge 5 ]]; then bad "$STEAL_TXT — гипервизор хронически отбирает CPU (оверселл/шумный сосед)"
    elif [[ "$STEAL" -ge 10 ]];  then wrn  "$STEAL_TXT — всплеск: в моменте отбирают заметно, в среднем терпимо"
    elif [[ "$STEAL" -ge 3 || "$STEAL_LONG" -ge 3 ]]; then wrn "$STEAL_TXT (заметный — под пиками может проседать)"
    else                              pass "$STEAL_TXT (CPU ноды не отбирают)"
    fi
fi
# Сохранённый conf ПИННИТ дефолты той версии, при которой ноду настраивали: идиома
# `: "${K:=v}"` из load_conf выигрывает у встроенного дефолта всегда. Когда новая
# мажорная меняет дефолт по безопасности (CROWDSEC_STRICT 0→1 в v4.0), на уже настроенных
# нодах он молча не применяется — ни ре-раном, ни апгрейдом тулкита, и узнать об этом
# можно было только чтением конфига на каждом хосте (issue #34).
CSD_N=0
for _cf in "$CONF_DIR/protect.conf" "$CONF_DIR/optimize.conf"; do
    [[ -f "$_cf" ]] || continue
    while IFS='|' read -r _k _old _new _ver _why; do
        [[ -n "$_k" ]] || continue
        CSD_N=$((CSD_N+1))
        wrn "$(basename "$_cf") пиннит устаревший дефолт: $_k=$_old (дефолт с v$_ver = $_new — $_why). Принять: NA_ADOPT_NEW_DEFAULTS=1 ре-ран $(basename "$_cf" .conf)"
    done < <(conf_stale_defaults "$_cf")
done
[[ "$CSD_N" -eq 0 ]] && pass "conf модулей не пиннит устаревших дефолтов"
unset _cf _k _old _new _ver _why

# ─── Ядро / BBR ──────────────────────────────────────────────────────────────
title "Ядро и congestion control"
KREL="$(uname -r)"
XM_EN="$(conf_val "$CONF_DIR/optimize.conf" ENABLE_XANMOD)"
if [[ "${KREL,,}" == *xanmod* ]]; then
    pass "XanMod-ядро активно ($KREL) → BBRv3 доступен"
    if XMU="$(xanmod_update)"; then
        info "доступно обновление XanMod: ${XMU#* } (пакет ${XMU%% *}, по кэшу apt) — apt-get install --only-upgrade ${XMU%% *} + ребут в окно обслуживания"
    fi
else
    if [[ "$XM_EN" == 0 ]]; then
        # осознанный выбор оператора (ENABLE_XANMOD=0 в optimize.conf), а не недоделка
        info "Стоковое ядро: XanMod выключен осознанно (ENABLE_XANMOD=0 в optimize.conf) — BBR из стокового ядра"
    elif can_install_kernel; then
        wrn "Ядро не XanMod — BBRv3 нет. Поставь оптимизатор (XanMod), будет +скорость."
    else
        [[ "$VIRT" != none && "$VIRT" != kvm && "$VIRT" != unknown ]] \
            && info "Контейнер ($VIRT): кастомное ядро невозможно, BBRv3 недоступен — это норма." \
            || info "Стоковое ядро."
    fi
fi
CC="$(val net.ipv4.tcp_congestion_control)"
AVAIL="$(val net.ipv4.tcp_available_congestion_control)"
[[ "$CC" == "bbr" ]] && pass "congestion_control = bbr$([[ "${KREL,,}" == *xanmod* ]] && echo ' (BBRv3)')" \
                     || wrn "congestion_control = ${CC:-?} (ожидалось bbr). Доступно: ${AVAIL:-?}"
QD="$(val net.core.default_qdisc)"
[[ "$QD" == "fq" || "$QD" == "fq_codel" || "$QD" == "cake" ]] && pass "default_qdisc = $QD" \
                     || wrn "default_qdisc = ${QD:-?} (для BBR-пейсинга лучше fq)"
if [[ "$(arch)" == "x86_64" ]]; then
    LVL="$(cpu_psabi_level)"
    info "CPU psABI: поддерживает до x86-64-v${LVL} (выбор сборки XanMod)"
fi
if reboot_pending; then
    wrn "optimize поставил ядро/параметры загрузки, а перезагрузки с тех пор не было — reboot (XanMod/BBRv3, psi=1 включатся после него)"
fi
# /run/reboot-required на флоте почти всегда — от стоковых ядер, которые ставит apt рядом
# с работающим XanMod: ребут ради них ничего не даст, а вечный ▲ приучает его не читать.
if RR="$(reboot_required_pkgs)"; then
    RR_PK="${RR#*$'\t'}"
    if [[ "${RR%%$'\t'*}" == stock ]]; then
        info "/run/reboot-required — от стоковых ядер ($RR_PK), а работает XanMod: ребут ради них не нужен"
    else
        wrn "система ждёт перезагрузки (/run/reboot-required${RR_PK:+: $RR_PK})"
    fi
fi
# Реальность поверх sysctl: сколько живых TCP-сокетов реально на BBR + доля ретрансмитов.
BBRN="$(ss -tin 2>/dev/null | grep -c bbr || true)"
[[ "${BBRN:-0}" -gt 0 ]] && info "Живых TCP-сокетов на BBR сейчас: $BBRN"
eval "$(awk '
  /^Tcp:/ { if (!h){for(i=2;i<=NF;i++)nm[i]=$i; h=1; next}
            for(i=2;i<=NF;i++){ if(nm[i]=="OutSegs")print "OUT="$i; if(nm[i]=="RetransSegs")print "RTX="$i } }
  ' /proc/net/snmp 2>/dev/null)"
if [[ -n "${OUT:-}" && "${OUT:-0}" -gt 0 ]]; then
    PCT=$(( ${RTX:-0} * 100 / OUT ))
    [[ "$PCT" -ge 5 ]] && wrn  "TCP-ретрансмиты ${PCT}% (${RTX:-0}/${OUT}, с загрузки) — потери/перегруз на аплинке" \
                       || pass "TCP-ретрансмиты ${PCT}% (${RTX:-0}/${OUT}, с загрузки) — линк чистый"
fi

# ─── Sysctl-ключи ────────────────────────────────────────────────────────────
title "Sysctl"
chk() { # chk key min "human"
    local k="$1" want="$2" cur; cur="$(val "$k")"
    if [[ -z "$cur" ]]; then wrn "$k не задан"; return; fi
    if [[ "$cur" -ge "$want" ]] 2>/dev/null; then pass "$k = $cur"; else wrn "$k = $cur (рекоменд. ≥ $want)"; fi
}
# Порог буферов — от RAM-tier, как ставит optimize: tier1 (≤1.2G) получает 16M, и
# фиксированный порог 32M давал ложный ▲ на каждой маленькой ноде. rmem_default — буфер
# сокета, которому приложение размер не задавало (исходящие UDP xray): чужой sysctl.d,
# урезавший его, даёт UDP RcvbufErrors при «правильном» rmem_max.
read -r SOCK_MAX SOCK_DEF <<<"$(sock_tier)"
chk net.core.somaxconn 32768
chk net.core.rmem_max "$SOCK_MAX"
chk net.core.wmem_max "$SOCK_MAX"
chk net.core.rmem_default "$SOCK_DEF"
chk net.core.wmem_default "$SOCK_DEF"
chk net.ipv4.tcp_max_syn_backlog 16384
chk fs.file-max 1000000
chk fs.nr_open 1000000
[[ "$(val net.ipv4.tcp_syncookies)" == "1" ]] && pass "tcp_syncookies = 1 (анти-SYN-flood)" || wrn "tcp_syncookies выкл."
[[ "$(val net.ipv4.tcp_fastopen)" == "3" ]] && pass "tcp_fastopen = 3" || info "tcp_fastopen = $(val net.ipv4.tcp_fastopen)"
RPF="$(val net.ipv4.conf.all.rp_filter)"
[[ "$RPF" == "2" ]] && pass "rp_filter = 2 (loose, ок для host-network)" \
    || { [[ "$RPF" == "1" ]] && wrn "rp_filter = 1 (strict) — может рубить асимметричный трафик VPN" || info "rp_filter = ${RPF:-?}"; }
# Порт ноды внутри эфемерного диапазона и не зарезервирован: исходящее соединение может
# занять его раньше, чем xray забиндит (рестарт контейнера) — inbound/API не поднимется.
EPH_BAD="$(node_eph_unreserved)"
if [[ -n "$EPH_BAD" ]]; then
    wrn "порты ноды в эфемерном диапазоне ($(val net.ipv4.ip_local_port_range | tr -s '[:space:]' '-' | sed 's/-$//')) без резерва: $EPH_BAD — исходящие могут занять их до старта xray (bind: address in use). Ре-ран optimize (v4.2 пишет ip_local_reserved_ports)"
fi

# ─── Лимиты ──────────────────────────────────────────────────────────────────
title "Лимиты"
ULN="$(ulimit -n 2>/dev/null)"
[[ "$ULN" -ge 524288 ]] 2>/dev/null && pass "ulimit -n (текущая сессия) = $ULN" \
    || wrn "ulimit -n = $ULN — для shell-сессий применится после перелогина"
if command -v systemctl >/dev/null; then
    DLN="$(systemctl show -p DefaultLimitNOFILE --value 2>/dev/null)"
    [[ "$DLN" -ge 524288 ]] 2>/dev/null && pass "systemd DefaultLimitNOFILE = $DLN" || wrn "systemd DefaultLimitNOFILE = ${DLN:-?}"
fi

# ─── Conntrack ───────────────────────────────────────────────────────────────
title "Conntrack"
CTMAX="$(val net.netfilter.nf_conntrack_max)"
CTCNT="$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)"
if [[ -n "$CTMAX" ]]; then
    pass "nf_conntrack_max = $CTMAX (сейчас занято: ${CTCNT:-0})"
    if [[ -n "$CTCNT" && "$CTMAX" -gt 0 ]]; then
        PCT=$(( CTCNT * 100 / CTMAX ))
        [[ "$PCT" -ge 80 ]] && wrn "conntrack заполнен на ${PCT}% — близко к потолку!"
    fi
else
    info "nf_conntrack ещё не загружен (появится при первом пакете через firewall)"
fi
# Разбивка дропов (если есть conntrack-tools): early_drop=давление по памяти,
# insert_failed=хеш-коллизии, drop=таблица переполнена. Decimal — mawk-safe.
if command -v conntrack >/dev/null 2>&1; then
    read -r CT_IF CT_DR CT_ED < <(conntrack -S 2>/dev/null | awk '
        {for(i=1;i<=NF;i++){split($i,kv,"="); if(kv[1]=="insert_failed")f+=kv[2]; else if(kv[1]=="drop")d+=kv[2]; else if(kv[1]=="early_drop")e+=kv[2]}}
        END{printf "%d %d %d", f+0, d+0, e+0}')
    if [[ "$(( ${CT_IF:-0} + ${CT_DR:-0} + ${CT_ED:-0} ))" -gt 0 ]]; then
        wrn "conntrack дропы: insert_failed=${CT_IF:-0} drop=${CT_DR:-0} early_drop=${CT_ED:-0} (early_drop=память, insert_failed=хеш, drop=таблица полна)"
    else
        pass "conntrack без дропов (insert_failed/drop/early_drop = 0)"
    fi
fi

# ─── MSS (анти-коллапс) ──────────────────────────────────────────────────────
# Ловит ровно тот прод-инцидент, что чинит v2.4: при mtu_probing=1 на лоссовом плече
# ядро ужимает send-MSS к полу (дефолт 48Б) → throughput коллапсирует. Проверяем пол
# и считаем ЖИВЫЕ сокеты с обрезанным MSS (реальность поверх sysctl).
title "MSS (анти-коллапс на туннелях)"
MINSND="$(val net.ipv4.tcp_min_snd_mss)"
MTUPROBE="$(val net.ipv4.tcp_mtu_probing)"
if [[ "${MINSND:-0}" -ge 512 ]] 2>/dev/null; then pass "tcp_min_snd_mss = $MINSND (пол против коллапса)"
else wrn "tcp_min_snd_mss = ${MINSND:-?} (при mtu_probing=1 рекоменд. ≥512 — иначе MSS-коллапс)"; fi
[[ -n "$MTUPROBE" ]] && info "tcp_mtu_probing = $MTUPROBE"
# Считаем ТОЛЬКО established. Без фильтра состояния сюда попадали отмирающие сокеты
# (TIME-WAIT, FIN-WAIT, LAST-ACK), которых на ноде сотни, и одного такого хватало, чтобы
# объявить коллапс на совершенно здоровой ноде. И смотрим долю: единичный пир с маленьким
# MSS — это его канал, а не наша беда. Настоящий коллапс — это когда пол опущен
# (min_snd_mss мал) или просели сразу многие соединения.
COLLAPSED="$(ss -tin state established 2>/dev/null | grep -oE 'mss:[0-9]+' | awk -F: '$2>0 && $2<256{c++} END{print c+0}')"
EST_TOTAL="$(ss -tn state established 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')"
[[ "${EST_TOTAL:-0}" =~ ^[0-9]+$ ]] || EST_TOTAL=0
if [[ "${COLLAPSED:-0}" -eq 0 ]]; then
    pass "сокетов с обрезанным MSS нет (коллапса не видно)"
elif [[ "${MINSND:-0}" -lt 512 ]]; then
    bad "established с обрезанным MSS (<256): $COLLAPSED из ${EST_TOTAL} при поле min_snd_mss=${MINSND:-?} — ИДЁТ MSS-коллапс (подними пол до 512)"
elif [[ "$EST_TOTAL" -gt 0 && $((COLLAPSED * 100 / EST_TOTAL)) -ge 5 && "$COLLAPSED" -ge 3 ]]; then
    bad "established с обрезанным MSS (<256): $COLLAPSED из ${EST_TOTAL} — просела заметная доля соединений (лоссовое плечо; см. tcp_mtu_probing)"
else
    info "established с обрезанным MSS (<256): $COLLAPSED из ${EST_TOTAL} — единичные пиры с узким каналом, пол 512 держит"
fi

# ─── NIC / RPS ───────────────────────────────────────────────────────────────
title "Сетевая карта"
NIC="$(default_iface || true)"
if [[ -n "$NIC" ]]; then
    DRV="$(ethtool -i "$NIC" 2>/dev/null | awk '/^driver:/{print $2}')"
    info "NIC: $NIC   driver: ${DRV:-?}   txqueuelen: $(cat /sys/class/net/$NIC/tx_queue_len 2>/dev/null || echo '?')"
    RXQ=$(ls -d /sys/class/net/"$NIC"/queues/rx-* 2>/dev/null | wc -l | tr -d " ")
    RPS_ON=0
    for q in /sys/class/net/"$NIC"/queues/rx-*/rps_cpus; do
        [[ -f "$q" ]] && grep -qvE '^0+$' "$q" 2>/dev/null && RPS_ON=1
    done
    [[ "$RXQ" -gt 1 ]] && info "RX-очередей: $RXQ (multi-queue)" || info "RX-очередей: $RXQ (single-queue — RPS критичен)"
    # RX-очередей не меньше, чем ядер: приём уже размазан аппаратно (RSS), RPS поверх
    # только гоняет пакеты между CPU — его отсутствие здесь норма, а не ▲ (optimize v4.2
    # в этом случае RPS и не включает).
    RSS_OK=0; [[ "$CORES" =~ ^[0-9]+$ && "$RXQ" -ge "$CORES" && "$CORES" -gt 1 ]] && RSS_OK=1
    if [[ "$RPS_ON" == "1" ]]; then pass "RPS включён (приём размазан по ядрам)"
    elif [[ "$RSS_OK" == 1 ]]; then info "RPS выключен — и не нужен: RX-очередей ($RXQ) ≥ ядер ($CORES), приём размазывает RSS"
    else
        [[ "$CORES" -gt 1 ]] && wrn "RPS выключен — на $CORES ядрах приём может висеть на cpu0" || info "1 ядро — RPS не нужен"
    fi
    if command -v ethtool >/dev/null; then
        OFF="$(ethtool -k "$NIC" 2>/dev/null | awk '/generic-receive-offload:|tcp-segmentation-offload:|generic-segmentation-offload:/{print $1$2}' | tr '\n' ' ')"
        [[ -n "$OFF" ]] && info "offloads: $OFF"
    fi
    # RX/TX drops/errors (накопительно с загрузки) — индикатор качества линка/ring-буфера
    read -r RXE RXD TXE TXD < <(ip -s link show dev "$NIC" 2>/dev/null | awk '
        /RX:/{getline; e=$3; d=$4} /TX:/{getline; te=$3; td=$4} END{printf "%d %d %d %d", e+0, d+0, te+0, td+0}')
    if [[ "$(( ${RXD:-0} + ${TXD:-0} + ${RXE:-0} + ${TXE:-0} ))" -gt 0 ]]; then
        info "NIC drops/errors (с загрузки): RXdrop=${RXD:-0} RXerr=${RXE:-0} TXdrop=${TXD:-0} TXerr=${TXE:-0}"
    else
        pass "NIC без drop/error счётчиков"
    fi
    # «Юнит активен» ≠ «RPS применён»: na-rps-setup определяет NIC по default route и при
    # его отсутствии молча выходит нулём, а RemainAfterExit=yes фиксирует active (exited)
    # навсегда. На буте это гонка с появлением маршрута, и v4.0 печатал ✔ рядом с ▲ «RPS
    # выключен» — две строки в одной секции утверждали противоположное (issue #30).
    if systemctl is-active --quiet na-rps.service 2>/dev/null; then
        if [[ "$RPS_ON" == "1" ]]; then
            pass "na-rps.service активен"
        elif [[ "$RSS_OK" == 1 ]]; then
            info "na-rps.service активен, RPS сознательно не включён (RSS: очередей ≥ ядер)"
        elif [[ "$CORES" -gt 1 ]] 2>/dev/null; then
            wrn "na-rps.service active, но rps_cpus пуст — юнит отработал до появления default route (гонка на буте) и вышел нулём: systemctl restart na-rps.service; v4.1 optimize чинит юнит"
        else
            info "na-rps.service активен (1 ядро — размазывать нечего)"
        fi
    else
        info "na-rps.service не запущен (ставится оптимизатором)"
    fi
else
    wrn "Основной интерфейс не определён"
fi
# softnet: dropped — пакет не влез в backlog (netdev_max_backlog), time_squeeze — softirq
# исчерпал бюджет и отложил приём. Оба с загрузки — смотрим прирост к прошлому запуску.
if [[ -r /proc/net/softnet_stat ]]; then
    if [[ "$DW" -ge 0 && "$D_SNDROP" -ge 0 && "$D_SQZ" -ge 0 ]]; then
        if [[ "$D_SNDROP" -gt 0 ]]; then
            wrn "softnet: +$D_SNDROP пакетов отброшено за $((DW/60)) мин (backlog полон, netdev_max_backlog=$(val net.core.netdev_max_backlog)) — приём не успевает: RPS/ядра/CPU steal"
        elif [[ $(( D_SQZ / (DW > 0 ? DW : 1) )) -ge 1 ]]; then
            wrn "softnet: time_squeeze +$D_SQZ за $((DW/60)) мин (≥1/с) — softirq упирается в бюджет (netdev_budget=$(val net.core.netdev_budget)); дропов нет"
        else
            pass "softnet: за $((DW/60)) мин дропов нет, time_squeeze +$D_SQZ"
        fi
    else
        info "softnet с загрузки: dropped=$C_SNDROP time_squeeze=$C_SQZ (прирост покажет следующий запуск — снимок сохранён)"
    fi
fi

# ─── Память / прочее ─────────────────────────────────────────────────────────
title "Память, swap, THP, governor"
# MemAvailable — то, что ядро реально может отдать без свопа; «used» из free врёт из-за кэша
read -r MEM_T MEM_A SW_T SW_F <<<"$(awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} /^SwapTotal:/{st=$2} /^SwapFree:/{sf=$2}
                                     END{printf "%d %d %d %d", t, a, st, sf}' /proc/meminfo 2>/dev/null)"
if [[ "${MEM_T:-0}" -gt 0 ]]; then
    MEM_AP=$(( MEM_A * 100 / MEM_T ))
    if [[ "$MEM_AP" -lt 15 ]]; then
        wrn "MemAvailable ${MEM_AP}% ($(( MEM_A / 1024 )) из $(( MEM_T / 1024 )) МБ) — памяти впритык: OOM-killer рядом"
    else
        pass "MemAvailable ${MEM_AP}% ($(( MEM_A / 1024 )) из $(( MEM_T / 1024 )) МБ)"
    fi
fi
[[ "${SW_T:-0}" -gt 0 && $(( SW_T - SW_F )) -gt 0 ]] && info "своп занят: $(( (SW_T - SW_F) / 1024 )) из $(( SW_T / 1024 )) МБ"
# balloon: гипервизор забирает RAM у гостя «на лету» — MemTotal остаётся прежним, а памяти
# фактически меньше (на ноде флота balloon гипервизора держал 2.5 ГБ)
BALLOON=""
for _b in vmw_balloon virtio_balloon; do
    if awk -v m="$_b" '$1 == m { f = 1 } END { exit !f }' /proc/modules 2>/dev/null \
       || [[ -d "/sys/bus/virtio/drivers/$_b" || -d "/sys/bus/pci/drivers/$_b" ]]; then
        BALLOON+="${BALLOON:+, }$_b"
    fi
done
unset _b
[[ -n "$BALLOON" ]] && info "balloon-драйвер: $BALLOON — гипервизор может забирать RAM у ноды (MemTotal этого не покажет)"
if [[ -n "$(swapon --show 2>/dev/null)" ]]; then pass "swap: $(swapon --show=NAME,SIZE --noheadings 2>/dev/null | tr '\n' ' ')"; else wrn "swap отсутствует"; fi
THP="$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null | grep -oE '\[.*\]' | tr -d '[]')"
[[ "$THP" == "never" ]] && pass "THP = never" || wrn "THP = ${THP:-?} (для сетевых нагрузок лучше never)"
GOV="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null)"
[[ -n "$GOV" ]] && { [[ "$GOV" == "performance" ]] && pass "governor = performance" || info "governor = $GOV"; } || info "cpufreq недоступен (VPS) — норма"
systemctl is-active --quiet irqbalance 2>/dev/null && pass "irqbalance активен" || info "irqbalance не запущен"

# ─── Firewall / защита ───────────────────────────────────────────────────────
title "Firewall и защита"
FW_MODE_INST="$(awk -F= '/^fw_mode=/{print $2}' "$STATE_DIR/protect.installed" 2>/dev/null)"
if nft -t list table inet na_filter >/dev/null 2>&1; then
    if [[ "$FW_MODE_INST" == "open" ]]; then
        pass "nftables na_filter активна (FW_MODE=open: лимиты/баны есть, не перечисленные порты открыты)"
    else
        pass "nftables na_filter активна (policy drop на input)"
    fi
    # Считаем АДРЕСА, а не строки вывода nft: `flags dynamic,timeout` в заголовке
    # матчился всегда (пустой набор = «1»), а на непустом `timeout\|expires` давал +2 к
    # элементу. Вечная фантомная единица приучала считать строку шумом — и настоящий
    # первый бан (в т.ч. адреса панели) терялся на её фоне (issue #32/#36).
    AB4="$(nft_set_count inet na_filter autoban_v4)"; [[ "$AB4" =~ ^[0-9]+$ ]] || AB4=0
    AB6="$(nft_set_count inet na_filter autoban_v6)"; [[ "$AB6" =~ ^[0-9]+$ ]] || AB6=0
    if [[ $((AB4+AB6)) -gt 0 ]]; then
        # оператору важно не «сколько», а «кто»: первый же бан может оказаться панелью
        AB_LIST="$( { nft_set_elems inet na_filter autoban_v4; nft_set_elems inet na_filter autoban_v6; } 2>/dev/null | head -10 | paste -sd' ' -)"
        AB_MORE=""; [[ $((AB4+AB6)) -gt 10 ]] && AB_MORE=" …ещё $((AB4+AB6-10))"
        info "autoban: v4=$AB4  v6=$AB6 — $AB_LIST$AB_MORE"
    else
        info "autoban: v4=0  v6=0 (нода никого не банила)"
    fi
    WLN=$(nft list set inet na_filter whitelist_v4 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l | tr -d ' ')
    WL6N=$(nft list set inet na_filter whitelist_v6 2>/dev/null | grep -c ':')
    if [[ "$WLN" -gt 0 || "$WL6N" -gt 0 ]]; then pass "whitelist: v4=$WLN v6=$WL6N адрес(ов)"
    else wrn "whitelist пуст — твой IP не защищён от автобана!"; fi
    # Дрейф живого сета от файла. Адреса, добавленные на ходу через `nft add element`,
    # существуют только в памяти ядра: при загрузке правила берутся из na_filter.nft, и
    # ре-ран protect или ребут молча их выбрасывает. Отсюда классическая авария — нода
    # исправна и доступна, а после перезагрузки панель до неё не достучалась.
    # Сверяем ТРИ источника, потому что переживают они разное:
    #   live == na_filter.nft   → переживёт РЕБУТ (правила грузятся из файла);
    #   live ⊆ WHITELIST= conf  → переживёт РЕ-РАН protect (он перегенерирует .nft).
    # v4.0 сверял только первую пару и объявлял здоровым адрес, который есть в файле и в
    # памяти, но не в protect.conf: авто-whitelist SSH-IP в conf не пишется намеренно, то
    # есть «раскурили ноду из транзитной сессии → адрес осел в .nft → диагностика
    # довольна → первый ре-ран из другой сессии его молча выкинул» (issue #38).
    # Наборы na_fleet_* / na_nodeport_wl_* здесь ни при чём — у них свой жизненный цикл.
    NFT_FILE="$CONF_DIR/na_filter.nft"
    LIVE_WL="$(nft_set_elems inet na_filter whitelist_v4 2>/dev/null | sed -E 's#/32$##' | sort -u)"
    if [[ -r "$NFT_FILE" ]]; then
        FILE_WL="$(awk '/set whitelist_v4/,/}/' "$NFT_FILE" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | sed -E 's#/32$##' | sort -u)"
        DRIFT_L="$(comm -23 <(printf '%s\n' "$LIVE_WL" | grep -v '^$' | sort -u) <(printf '%s\n' "$FILE_WL" | grep -v '^$' | sort -u) 2>/dev/null)"
        DRIFT="$(printf '%s\n' "$DRIFT_L" | grep -c .)"; [[ "$DRIFT" =~ ^[0-9]+$ ]] || DRIFT=0
        if [[ "$DRIFT" -gt 0 ]]; then
            wrn "в живом whitelist_v4 на $DRIFT адрес(ов) больше, чем в $NFT_FILE — они пропадут при ребуте: $(printf '%s\n' "$DRIFT_L" | paste -sd' ' -)"
        else
            pass "whitelist в файле и в памяти совпадают (переживёт ребут)"
        fi
        # обратная сторона: в файле есть, в памяти нет — удалён руками на ходу; вернётся
        # после ребута или reload na-firewall (расхождение, а не авария)
        FBACK="$(comm -13 <(printf '%s\n' "$LIVE_WL" | grep -v '^$' | sort -u) <(printf '%s\n' "$FILE_WL" | grep -v '^$' | sort -u) 2>/dev/null | paste -sd' ' -)"
        [[ -n "$FBACK" ]] && info "в $NFT_FILE, но не в живом whitelist_v4: $FBACK (вернутся после ребута/reload na-firewall)"
    fi
    if [[ -f "$CONF_DIR/protect.conf" ]]; then
        # conf пишется идиомой `: "${WHITELIST:=…}"` (protect v4.2 — `=`) — наивный
        # `^WHITELIST=` не матчит
        CONF_WL="$(conf_val "$CONF_DIR/protect.conf" WHITELIST \
                   | tr ',' '\n' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | sed -E 's#/32$##' | sort -u)"
        CDRIFT_L="$(comm -23 <(printf '%s\n' "$LIVE_WL" | grep -v '^$' | sort -u) <(printf '%s\n' "$CONF_WL" | grep -v '^$' | sort -u) 2>/dev/null)"
        CDRIFT="$(printf '%s\n' "$CDRIFT_L" | grep -c .)"; [[ "$CDRIFT" =~ ^[0-9]+$ ]] || CDRIFT=0
        if [[ "$CDRIFT" -gt 0 ]]; then
            SSH_IP_NOW="$(ssh_client_ip || true)"
            CD_NOTE=""
            [[ -n "$SSH_IP_NOW" ]] && printf '%s\n' "$CDRIFT_L" | grep -qxF "$SSH_IP_NOW" \
                && CD_NOTE=" (среди них $SSH_IP_NOW — это IP текущей сессии)"
            wrn "whitelist НЕ переживёт ре-ран protect: в WHITELIST= из protect.conf нет $CDRIFT адрес(ов) — $(printf '%s\n' "$CDRIFT_L" | paste -sd' ' -)$CD_NOTE. Добавлены транзитно (SSH-IP при прогоне protect) или руками; при ре-ране из другой сессии исчезнут. Закрепить: WHITELIST=…,$(printf '%s\n' "$CDRIFT_L" | head -1) ре-ран protect"
        else
            pass "whitelist ⊆ WHITELIST= в protect.conf (переживёт ре-ран protect)"
        fi
        # обратная сторона: в conf есть, в памяти нет — кто-то удалил элемент руками,
        # ре-ран protect вернёт его (не авария, но расхождение стоит знать)
        CBACK="$(comm -13 <(printf '%s\n' "$LIVE_WL" | grep -v '^$' | sort -u) <(printf '%s\n' "$CONF_WL" | grep -v '^$' | sort -u) 2>/dev/null | paste -sd' ' -)"
        [[ -n "$CBACK" ]] && info "в WHITELIST= из protect.conf, но не в живом whitelist_v4: $CBACK (вернутся ре-раном protect)"
    fi
    # 4-й слой — ЭФФЕКТИВНЫЙ allowlist CrowdSec (все s02-enrich/*.yaml с whitelist:).
    # Bouncer CrowdSec стоит РАНЬШЕ na_filter (priority -10): адрес из whitelist na_filter,
    # которого нет в allowlist CrowdSec, всё равно может быть забанен (аудит флота: адрес
    # hub'а управления был в whitelist, но не в allowlist CrowdSec).
    if command -v cscli >/dev/null 2>&1 || [[ -d /etc/crowdsec/parsers ]]; then
        CS_AL="$(cs_allowlist)"
        WL_ALL="$( { nft_set_elems inet na_filter whitelist_v4; nft_set_elems inet na_filter whitelist_v6; } 2>/dev/null \
                   | sed -E 's#/32$##; s#/128$##' | sort -u)"
        CS_MISS=""
        while IFS= read -r _w; do
            [[ -n "$_w" ]] || continue
            wl_covered "$_w" "$CS_AL" || CS_MISS+="${CS_MISS:+ }$_w"
        done <<<"$WL_ALL"
        CS_EXTRA=""
        while IFS= read -r _w; do
            [[ -n "$_w" ]] || continue
            # хабовый whitelists.yaml прикрывает приватные сети — это не дрейф
            case "$_w" in 127.*|::1|10.0.0.0/8|172.16.0.0/12|192.168.0.0/16|fe80::/10|fc00::/7) continue;; esac
            grep -qxF -- "$_w" <<<"$WL_ALL" || CS_EXTRA+="${CS_EXTRA:+ }$_w"
        done <<<"$CS_AL"
        unset _w
        if [[ -n "$CS_MISS" ]] && nft list table ip crowdsec >/dev/null 2>&1; then
            wrn "whitelist na_filter не прикрыт в CrowdSec: $CS_MISS — CrowdSec может их забанить, а его bouncer режет раньше na_filter. Ре-ран protect перепишет na-whitelist.yaml (или добавь в /etc/crowdsec/parsers/s02-enrich/)"
        elif [[ -n "$CS_MISS" ]]; then
            # без bouncer'а решения CrowdSec ничего не режут — расхождение, но не угроза
            info "whitelist na_filter не прикрыт в CrowdSec: $CS_MISS (bouncer'а nft нет — сейчас это не режет)"
        elif [[ -n "$WL_ALL" ]]; then
            pass "whitelist na_filter целиком прикрыт allowlist CrowdSec"
        fi
        [[ -n "$CS_EXTRA" ]] && info "в allowlist CrowdSec, но не в whitelist na_filter: $CS_EXTRA (CrowdSec их не тронет, а autoban na_filter — может)"
    fi
    # Датчик per-IP потолка. Считаем ТОТ ЖЕ срез, что режет правило `ct count`: только
    # входящие established на порты из tcp_ports=, без loopback и вайтлиста. v4.0 брал
    # весь `ss state established` — loopback-пары nginx↔xray (тысячи, и каждая считалась
    # дважды), исходящие плечи и вайтлист, до которых правило не доходит вовсе, — и
    # предупреждение горело вечно, подталкивая поднять CONN_LIMIT, т.е. ослабить
    # защиту от exhaustion ради несуществующей проблемы (issue #31).
    chain_load
    CLIM="$(grep -oE 'ct count over [0-9]+' <<<"$NA_CHAIN" | head -1 | grep -oE '[0-9]+')"
    if [[ -n "$CLIM" ]]; then
        # порты — из живых правил: маркер tcp_ports= устаревает после ручной правки
        TCPP_INST="$(fw_ports tcp)"
        if [[ -z "${TCPP_INST:-}" ]]; then
            info "per-IP лимит $CLIM есть, но список портов правила неизвестен (ни в правилах, ни в protect.conf/маркере) — датчик пропущен"
        else
            MAXIP="$(conn_per_ip_max "$TCPP_INST")"; [[ "$MAXIP" =~ ^[0-9]+$ ]] || MAXIP=0
            if [[ "$MAXIP" -ge $((CLIM*80/100)) ]]; then
                wrn "макс. входящих конн. с одного IP = $MAXIP при CONN_LIMIT=$CLIM (≥80%, порты $TCPP_INST) — за CGNAT возможны дропы, подними CONN_LIMIT"
            else
                pass "макс. входящих конн. с одного IP = $MAXIP / CONN_LIMIT $CLIM (порты $TCPP_INST, без loopback и вайтлиста — запас есть)"
            fi
        fi
    fi
    # Наборы per-IP лимитеров. До v4.1.3 — без timeout: адреса копятся до ребута, и на
    # полном наборе новые клиенты на порт отсекаются (для ssh4 — новый IP админа в бан).
    # максимум считаем ОТДЕЛЬНО по наборам без timeout: ✘ — про них (режут клиентов),
    # заполненный набор с timeout — другой случай (флуд, лимит отключается)
    DS_MAX=-1; DS_MAXN=""; DS_NT=0; DS_N=0; DS_NTMAX=-1; DS_NTMAXN=""
    while IFS=$'\t' read -r _dn _dc _ds _dt; do
        [[ -n "$_dn" ]] || continue
        DS_N=$((DS_N+1))
        (( _dc * 100 / _ds > DS_MAX )) && { DS_MAX=$(( _dc * 100 / _ds )); DS_MAXN="$_dn ($_dc из $_ds)"; }
        if [[ "$_dt" == "0" ]]; then
            DS_NT=$((DS_NT+1))
            (( _dc * 100 / _ds > DS_NTMAX )) && { DS_NTMAX=$(( _dc * 100 / _ds )); DS_NTMAXN="$_dn ($_dc из $_ds)"; }
        fi
    done < <(dynset_fill 2>/dev/null)
    if [[ "$DS_N" -gt 0 ]]; then
        if [[ "$DS_NT" -gt 0 && "$DS_NTMAX" -ge 80 ]]; then
            bad "наборы-лимитеры без timeout ($DS_NT шт., правила ≤4.1.2) заполнены до ${DS_NTMAX}%: $DS_NTMAXN — на 100% новые клиенты на порт отсекаются. Ре-ран protect (4.1.3+); пожарно: systemctl reload na-firewall (сбросит и баны)"
        elif [[ "$DS_NT" -gt 0 ]]; then
            wrn "наборы-лимитеры без timeout ($DS_NT шт., правила ≤4.1.2): адреса копятся до ребута, сейчас максимум ${DS_NTMAX}% — $DS_NTMAXN. На 100% новые клиенты на порт отсекаются: ре-ран protect (4.1.3+)"
        elif [[ "$DS_MAX" -ge 80 ]]; then
            wrn "набор-лимитер заполнен на ${DS_MAX}%: $DS_MAXN — флуд с множества адресов; на 100% лимит перестаёт действовать для новых адресов (клиентов не режет)"
        else
            pass "наборы-лимитеры с timeout, максимум заполнения ${DS_MAX}% ($DS_MAXN)"
        fi
    fi
    unset _dn _dc _ds _dt DS_NTMAX DS_NTMAXN
    # Порты: живые правила ↔ protect.conf ↔ маркер. Живые — то, что действует; conf — то,
    # что применит ре-ран protect; маркер пишет только прогон protect. Ручная правка правил
    # (порт добавлен `nft add rule`) живёт до ре-рана — и молча исчезает (аудит флота).
    for _pr in tcp udp; do
        _K=TCP_PORTS; _mk=tcp_ports; [[ "$_pr" == udp ]] && { _K=UDP_PORTS; _mk=udp_ports; }
        _live="$(fw_live_ports "$_pr")"
        _conf="$(csv_norm "$(conf_val "$CONF_DIR/protect.conf" "$_K")")"
        _mark="$(csv_norm "$(mark_val "$_mk")")"
        if conf_has "$CONF_DIR/protect.conf" "$_K" && [[ "$_live" != "$_conf" ]]; then
            _gone="$(comm -23 <(tr ',' '\n' <<<"$_live" | grep . | sort) <(tr ',' '\n' <<<"$_conf" | grep . | sort) | paste -sd, -)"
            _new="$(comm -13 <(tr ',' '\n' <<<"$_live" | grep . | sort) <(tr ',' '\n' <<<"$_conf" | grep . | sort) | paste -sd, -)"
            wrn "${_pr^^}-порты в живых правилах (${_live:-нет}) ≠ $_K в protect.conf (${_conf:-нет}): ре-ран protect${_gone:+ закроет $_gone}${_new:+${_gone:+,} откроет $_new}. Ручная правка? Перенеси в $_K"
        elif [[ -n "$_mark" && "$_mark" != "$_live" ]]; then
            info "маркер protect.installed устарел: ${_mk}=$_mark, в правилах ${_live:-нет} — сенсоры берут порты из правил"
        fi
    done
    unset _pr _K _mk _live _conf _mark _gone _new
    # Хэш файла автозагрузки (protect v4.2 пишет nft_sha256 в маркер): несовпадение = файл
    # правили руками, а ре-ран protect его молча перезапишет.
    NFT_SHA_MARK="$(mark_val nft_sha256)"
    if [[ -n "$NFT_SHA_MARK" && -r "$NFT_FILE" ]]; then
        NFT_SHA_NOW="$(file_sha256 "$NFT_FILE")"
        if [[ -n "$NFT_SHA_NOW" && "$NFT_SHA_NOW" != "$NFT_SHA_MARK" ]]; then
            wrn "$NFT_FILE правлен руками после прогона protect (sha256 ≠ маркеру) — ре-ран protect его перезапишет; локальные правила — в $(mark_val include_dir | grep . || echo "$CONF_DIR/na_filter.d")/*.nft"
        else
            [[ -n "$NFT_SHA_NOW" ]] && pass "$NFT_FILE совпадает с записанным protect (ручных правок нет)"
        fi
    fi
    # Именованные счётчики дропов (protect v4.2): лог ограничен по скорости, счётчик — нет
    FW_CNT="$(fw_counters)"
    [[ -n "$FW_CNT" ]] && info "счётчики дропов na_filter (с загрузки правил): $FW_CNT"
    # v3.0 компоненты
    if nft list set inet na_filter suspect_v4 >/dev/null 2>&1; then
        SUSP="$(nft_set_count inet na_filter suspect_v4)"; [[ "$SUSP" =~ ^[0-9]+$ ]] || SUSP=0
        info "ban-once: suspect (наблюдение) v4=$SUSP"
    fi
    if nft list set inet na_filter blocklist_v4 >/dev/null 2>&1; then
        BL4="$(nft_set_count inet na_filter blocklist_v4)"; [[ "$BL4" =~ ^[0-9]+$ ]] || BL4=0
        [[ "$BL4" -gt 0 ]] && pass "threat-блоклисты: v4=$BL4 записей (na-blocklist-update)" \
            || wrn "blocklist_v4 пуст — фиды не подтянулись? journalctl -t na-blocklist"
        if [[ -f "$STATE_DIR/blocklist.last" ]]; then
            _bls="$(cat "$STATE_DIR/blocklist.last" 2>/dev/null)"
            [[ "$_bls" =~ ^[0-9]+$ ]] && info "последнее обновление блоклистов: $(( ($(date +%s) - _bls)/3600 ))ч назад"
        fi
    fi
    if nft list set inet na_filter na_fleet_v4 >/dev/null 2>&1; then
        FL4="$(nft_set_count inet na_filter na_fleet_v4)"; [[ "$FL4" =~ ^[0-9]+$ ]] || FL4=0
        [[ "$FL4" -gt 0 ]] && pass "fleet-sync: $FL4 нод флота в whitelist" \
            || wrn "na_fleet пуст — панель/токен? journalctl -t na-fleet-sync"
        # свежесть: fail-safe last-known-good нем — протухший токен/сменившийся API
        # панели молча заморозил бы сет. Ругаемся, если синка не было > 3× интервала.
        if [[ -f "$STATE_DIR/fleet-sync.last" ]]; then
            _fls="$(cat "$STATE_DIR/fleet-sync.last" 2>/dev/null)"
            if [[ "$_fls" =~ ^[0-9]+$ ]]; then
                _age=$(( $(date +%s) - _fls ))
                # интервал: сперва из самого таймера (ground truth), затем из protect.conf.
                # ВАЖНО: conf пишется идиомой `: "${KEY:=value}"`, поэтому наивный
                # парс `^FLEET_SYNC_INTERVAL=` не матчил НИКОГДА — интервал молча
                # считался 5min и всякий более редкий синк выглядел «протухшим».
                _iv="$(awk -F= '/^OnUnitActiveSec=/{print $2; exit}' /etc/systemd/system/na-fleet-sync.timer 2>/dev/null)"
                [[ -n "$_iv" ]] || _iv="$(conf_val "$CONF_DIR/protect.conf" FLEET_SYNC_INTERVAL)"
                _ivs="$(systime_to_s "${_iv:-5min}")"; [[ "$_ivs" -ge 60 ]] || _ivs=300
                if [[ "$_age" -gt $((_ivs*3)) ]]; then
                    wrn "последний успешный fleet-sync $((_age/60)) мин назад (> 3× интервала) — токен протух/панель сменила API? journalctl -t na-fleet-sync"
                else
                    info "последний fleet-sync: $((_age/60)) мин назад (свежо)"
                fi
            fi
        else
            info "штампа fleet-sync ещё нет (первый синк не завершился успешно)"
        fi
    fi
elif [[ "$FW_MODE_INST" == "skip" ]]; then
    info "na_filter не ставилась осознанно (FW_MODE=skip) — порты не блокируются; закрыть позже: FW_MODE=strict ре-ран protect"
else
    wrn "na_filter не активна — защита не стоит (запусти 🛡 protect)"
fi
# ctguard (отдельная таблица)
if nft list table inet na_ctguard >/dev/null 2>&1; then
    ENF=$(awk -F= '/^NA_CTG_ENFORCE/{print $2}' /etc/node-accelerator/ctguard.conf 2>/dev/null)
    PH4="$(nft_set_count inet na_ctguard phantom_v4)"; [[ "$PH4" =~ ^[0-9]+$ ]] || PH4=0
    [[ "${ENF:-0}" == 1 ]] && pass "ctguard ENFORCE активен (фантомов в блоке: $PH4)" \
        || info "ctguard в observe-режиме (только лог; NA_CTG_ENFORCE=1 для эвикта)"
fi
# synproxy degraded-маркер
if [[ -f "$STATE_DIR/.synproxy-degraded" ]]; then
    bad "SYNPROXY DEGRADED: $(cat "$STATE_DIR/.synproxy-degraded") — защита без synproxy"
fi
# Взведённый сейфти-таймер: protect в неинтерактиве оставляет na-fw-safety активным.
# Если не снять — na_filter САМОУДАЛИТСЯ через SAFETY_DELAY. Ловим это громко.
if systemctl is-active --quiet na-fw-safety.timer 2>/dev/null \
   || { [[ -f "$STATE_DIR/na-fw-safety.pid" ]] && kill -0 "$(cat "$STATE_DIR/na-fw-safety.pid" 2>/dev/null)" 2>/dev/null; } \
   || { [[ -f /tmp/na-fw-safety.pid ]] && kill -0 "$(cat /tmp/na-fw-safety.pid 2>/dev/null)" 2>/dev/null; }; then
    bad "ВЗВЕДЁН сейфти-таймер na-fw-safety — na_filter СКОРО САМОУДАЛИТСЯ! Сними после проверки доступа: systemctl stop na-fw-safety.timer"
fi
# Сейфти УЖЕ сработал: таблица снята И автозагрузка правил выключена (иначе локаут-руллсет
# вернулся бы после ребута уже без подстраховки). Значит защиты сейчас нет — это не шум.
if [[ -f "$STATE_DIR/safety-fired.last" ]]; then
    _sfd="$(cat "$STATE_DIR/safety-fired.last" 2>/dev/null)"
    if [[ "$_sfd" =~ ^[0-9]+$ ]]; then
        bad "СЕЙФТИ СРАБАТЫВАЛ $(( ($(date +%s) - _sfd)/60 )) мин назад: na_filter снята, автозагрузка выключена — защиты НЕТ. Проверь SSH_PORT/WHITELIST и прогони protect заново."
    else
        bad "СЕЙФТИ СРАБАТЫВАЛ: защиты нет до повторного прогона protect"
    fi
fi
# Таблица есть, а автозагрузки нет → после ребута нода останется без правил.
if nft -t list table inet na_filter >/dev/null 2>&1 \
   && [[ -f /etc/systemd/system/na-firewall.service ]] \
   && ! systemctl is-enabled --quiet na-firewall.service 2>/dev/null; then
    wrn "na_filter активна, но na-firewall.service ВЫКЛЮЧЕН — после ребута правила не поднимутся. Лечится повторным прогоном protect."
fi
# Дистрибутивный nftables.service: ExecStop/ExecReload = `flush ruleset`, и его конфиг
# обычно начинается с того же. Включённым его оставили старые версии protect (на флоте —
# enabled+active на части нод): любой restart/reload этого юнита сносит ВСЕ таблицы —
# na_filter, CrowdSec, Docker.
NFTS_ST=""
systemctl is-enabled --quiet nftables.service 2>/dev/null && NFTS_ST="enabled"
systemctl is-active --quiet nftables.service 2>/dev/null && NFTS_ST+="${NFTS_ST:++}active"
if [[ -n "$NFTS_ST" ]] && grep -qE '^[[:space:]]*flush[[:space:]]+ruleset' /etc/nftables.conf 2>/dev/null; then
    wrn "nftables.service $NFTS_ST, а /etc/nftables.conf делает flush ruleset — restart/reload этого юнита снесёт все таблицы (na_filter, CrowdSec, Docker). Если конфиг не ведёшь сам: systemctl disable nftables.service (без stop/--now)"
fi
# Порты, опубликованные через DNAT (Docker -p, ручные relay), идут хуком forward мимо
# input-цепочки na_filter: strict их не закрывает, autoban/блоклисты/лимиты не действуют.
# protect v4.2 умеет их стеречь (dnat_guard=1 в маркере).
DNAT_P="$(dnat_ports)"
if [[ -n "$DNAT_P" ]]; then
    if [[ "$(mark_val dnat_guard)" == 1 ]]; then
        info "опубликованы через DNAT: $DNAT_P — под защитой na_filter (dnat_guard=1)"
    elif nft -t list table inet na_filter >/dev/null 2>&1; then
        wrn "опубликованы через DNAT мимо na_filter: $DNAT_P — трафик идёт хуком forward: strict их не закрывает, autoban/блоклисты/лимиты не действуют (protect v4.2 — dnat_guard)"
    else
        info "опубликованы через DNAT: $DNAT_P"
    fi
fi
# Публичные слушатели вне разрешённых портов и разрешённые порты без слушателя. При strict
# первые отрезаны (сервис доступен только из whitelist/флота — на флоте так «молчал»
# агент мониторинга, а его опросы копились в логе как скан); вне strict — открыты миру.
FW_TCP_OK="$(fw_ports tcp)"; FW_UDP_OK="$(fw_ports udp)"
FW_MODE_NOW="$FW_MODE_INST"; nft -t list table inet na_filter >/dev/null 2>&1 || FW_MODE_NOW=none
SSH_OK="$(csv_norm "$(mark_val ssh_port),$(detect_ssh_port 2>/dev/null)")"
NODE_OK="$(csv_norm "$(mark_val node_port),$(detect_node_port 2>/dev/null)")"
LST_OUT=""
while IFS=$'\t' read -r _a _p _pr; do
    [[ -n "$_p" ]] && addr_public "$_a" || continue
    [[ ",$FW_TCP_OK,$SSH_OK,$NODE_OK," == *",$_p,"* || ",$DNAT_P," == *",$_p/tcp,"* ]] && continue
    [[ " $LST_OUT " == *" tcp/$_p("* ]] || LST_OUT+="${LST_OUT:+ }tcp/$_p($_pr)"
done < <(listen_rows tcp)
while IFS=$'\t' read -r _a _p _pr; do
    [[ -n "$_p" ]] && addr_public "$_a" || continue
    # DHCP/NTP/mDNS-клиенты: ответы им проходят по conntrack, «сервисом» они не являются
    case "$_p" in 67|68|123|546|547|5353) continue;; esac
    [[ ",$FW_UDP_OK," == *",$_p,"* || ",$DNAT_P," == *",$_p/udp,"* ]] && continue
    [[ " $LST_OUT " == *" udp/$_p("* ]] || LST_OUT+="${LST_OUT:+ }udp/$_p($_pr)"
done < <(listen_rows udp)
if [[ -n "$LST_OUT" ]]; then
    case "$FW_MODE_NOW" in
        strict) info "слушают публично, но strict их режет (доступны только whitelist/флоту): $LST_OUT — если сервис нужен всем, добавь порт в TCP_PORTS/UDP_PORTS" ;;
        # open — по замыслу (динамические inbound'ы 3x-ui): открыты, но с per-IP лимитами
        open)   info "слушают вне перечисленных портов (FW_MODE=open — открыты по замыслу, с per-IP лимитами): $LST_OUT" ;;
        *)      wrn "слушают публично вне разрешённых портов и открыты миру (na_filter ${FW_MODE_NOW:-нет} — правил нет): $LST_OUT" ;;
    esac
fi
NOL=""
for _p in ${FW_TCP_OK//,/ }; do
    [[ ",$DNAT_P," == *",$_p/tcp,"* ]] && continue
    awk -F'\t' -v p="$_p" '$2 == p && $1 !~ /^(127\.|::1$)/ { f = 1 } END { exit !f }' <<<"$(listen_rows tcp)" || NOL+="${NOL:+ }tcp/$_p"
done
for _p in ${FW_UDP_OK//,/ }; do
    [[ ",$DNAT_P," == *",$_p/udp,"* ]] && continue
    awk -F'\t' -v p="$_p" '$2 == p && $1 !~ /^(127\.|::1$)/ { f = 1 } END { exit !f }' <<<"$(listen_rows udp)" || NOL+="${NOL:+ }udp/$_p"
done
[[ -n "$NOL" && "$FW_MODE_NOW" != none ]] && info "разрешены в файрволе, но никто не слушает: $NOL (лишняя дыра — убери из TCP_PORTS/UDP_PORTS, если сервиса не будет)"
unset _a _p _pr
if command -v cscli >/dev/null 2>&1; then
    systemctl is-active --quiet crowdsec && pass "CrowdSec агент активен" || wrn "CrowdSec установлен, но не active"
    systemctl is-active --quiet crowdsec-firewall-bouncer && pass "firewall-bouncer активен" || wrn "bouncer не active"
    # `cscli decisions list -o raw` печатает CSV С ЗАГОЛОВКОМ, и он попадал в счёт: на
    # пустом списке выходило «decisions: 1» — читается как «один бан есть» (issue #32).
    # Срезаем первую строку (`-o json` + jq не годится: jq на ноде не обязателен).
    # grep -vc печатает 0 И возвращает rc=1, когда совпадений нет → наивный `|| echo 0`
    # дописывал ВТОРОЙ ноль и строка выходила битой. Берём значение, потом валидируем.
    # С `-a`: без него cscli показывает только локальные решения, а bouncer режет и
    # community-блоклист (CAPI, на флоте ~25 тыс. адресов — «1 решение» в отчёте).
    if DEC="$(cs_decisions)"; then
        read -r DEC_L DEC_C <<<"$DEC"
        info "CrowdSec decisions (активные баны): ${DEC_L:-0} локальных (crowdsec/cscli), ${DEC_C:-0} из CAPI/списков"
    else
        info "CrowdSec decisions: не измерено (cscli не ответил)"; DEC_C=0
    fi
    CS_SCOPE="$(mark_val crowdsec_scope)"
    if nft list table ip crowdsec >/dev/null 2>&1; then
        case "$CS_SCOPE" in
            ssh) info "блок-листы CrowdSec действуют только на SSH-порт (crowdsec_scope=ssh)" ;;
            all) info "блок-листы CrowdSec действуют на ВСЕ порты (crowdsec_scope=all — выбор оператора)" ;;
            *)   if [[ "${DEC_C:-0}" -gt 0 ]]; then
                     wrn "bouncer CrowdSec (priority -10, раньше na_filter) режет ${DEC_C} адресов CAPI/списков на ВСЕХ портах — в т.ч. мобильный CGNAT; protect v4.2 сужает до SSH (CROWDSEC_SCOPE=ssh)"
                 else
                     info "таблица bouncer'а ip crowdsec присутствует (priority -10, раньше na_filter; область — все порты)"
                 fi ;;
        esac
    fi
    # откуда CrowdSec вообще берёт события: на флоте — только journal sshd
    CS_ACQ="$(cs_acquis | paste -sd' ' -)"
    if [[ -n "$CS_ACQ" ]]; then
        if ! grep -qviE 'ssh' <<<"$(tr ' ' '\n' <<<"$CS_ACQ")"; then
            info "CrowdSec читает: $CS_ACQ — только sshd: атаки на сервисные порты он не видит (их держит na_filter)"
        else
            info "CrowdSec читает: $CS_ACQ"
        fi
    fi
else
    info "CrowdSec не установлен (ставится модулем 🛡 protect)"
fi

# ─── Слушающие порты ─────────────────────────────────────────────────────────
title "Слушающие порты"
ss -tulnH 2>/dev/null | awk '{print $1, $5}' | sort -u | sed 's/^/  /' | head -25

# ─── Сеть (быстрый тест) ─────────────────────────────────────────────────────
title "Сеть"
EXTIP="$(curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"
[[ -n "$EXTIP" ]] && info "Внешний IPv4: $EXTIP"
# IPv6 default-route: на нодах где v6 включён осознанно (напр. CDN-origin) его пропажа
# после смены сети/провайдера тихо ломает v6-клиентов. Показываем факт, без warn
# (v4-only ноды — легитимный кейс).
if [[ -n "$(ip -6 route show default 2>/dev/null)" ]]; then
    info "IPv6 default-route: есть ($(ip -6 route show default 2>/dev/null | awk '{print $3; exit}'))"
else
    info "IPv6 default-route: нет (v4-only нода)"
fi
# UDP RcvbufErrors (v4 + v6) — датаграммы, отброшенные до приложения: приёмный буфер
# сокета полон. Счётчик копится с загрузки, и одна давняя вспышка горела ▲ вечно (аудит
# флота: на всех нодах при нулевом приросте). ▲ — только по росту за окно с прошлого
# запуска и по доле от принятых. Чьи это сокеты: при публичном UDP-слушателе — входящий
# QUIC/Hysteria2/TUIC; без него — исходящие UDP xray/DNS с буфером по умолчанию.
UDP_SVC=0
while IFS=$'\t' read -r _a _p _pr; do
    [[ -n "$_p" ]] && addr_public "$_a" || continue
    case "$_p" in 67|68|123|546|547|5353) continue;; esac
    UDP_SVC=1; break
done < <(listen_rows udp)
unset _a _p _pr
if [[ "$UDP_SVC" == 1 ]]; then UDP_CTX="входящий UDP (QUIC/Hysteria2/TUIC): поднять rmem_max/PPS"
else UDP_CTX="UDP-слушателей нет — это исходящие сокеты (xray/DNS) с буфером по умолчанию: net.core.rmem_default=$(val net.core.rmem_default)"; fi
if [[ "$DW" -ge 0 && "$D_UDPERR" -ge 0 ]]; then
    if [[ "$D_UDPERR" -gt 0 ]] && { [[ "$D_UDPIN" -le 0 ]] || [[ $(( D_UDPERR * 1000 / D_UDPIN )) -ge 1 ]]; }; then
        wrn "UDP RcvbufErrors +$D_UDPERR за $((DW/60)) мин ($(awk -v e="$D_UDPERR" -v d="$D_UDPIN" 'BEGIN{ printf "%.2f", (d > 0 ? e * 100 / d : 100) }')% принятых) — $UDP_CTX"
    elif [[ "$D_UDPERR" -gt 0 ]]; then
        info "UDP RcvbufErrors +$D_UDPERR за $((DW/60)) мин (<0.1% принятых — шум)"
    else
        pass "UDP RcvbufErrors не растут (за $((DW/60)) мин +0; с загрузки $C_UDPERR)"
    fi
elif [[ "$C_UDPERR" -gt 0 && "$C_UDPIN" -gt 0 && $(( C_UDPERR * 100 / C_UDPIN )) -ge 1 ]]; then
    wrn "UDP RcvbufErrors = $C_UDPERR с загрузки (≥1% принятых) — $UDP_CTX; рост покажет следующий запуск"
else
    info "UDP RcvbufErrors = $C_UDPERR с загрузки (рост к следующему запуску покажет дельта — снимок сохранён)"
fi
# Переполнение accept-очереди: SYN/ACK отброшен, клиент ждёт ретрансмита (секунды)
if [[ "$DW" -ge 0 && "$D_LOVF" -ge 0 ]]; then
    if [[ "$D_LOVF" -gt 0 ]]; then
        wrn "accept-очередь переполнялась: ListenOverflows +$D_LOVF (ListenDrops +$D_LDROP) за $((DW/60)) мин (somaxconn=$(val net.core.somaxconn)) — приложение не успевает accept'ить"
    else
        pass "accept-очереди не переполнялись за $((DW/60)) мин"
    fi
elif [[ "$C_LOVF" -gt 0 ]]; then
    info "ListenOverflows = $C_LOVF (ListenDrops = $C_LDROP) с загрузки (рост покажет следующий запуск)"
fi
if command -v ping >/dev/null; then
    RTT="$(ping -c2 -W2 1.1.1.1 2>/dev/null | awk -F'/' '/rtt|round-trip/{print $5" ms"}')"
    [[ -n "$RTT" ]] && info "RTT до 1.1.1.1: avg $RTT" || info "ICMP-тест не прошёл (возможно ICMP режется аптайм-провайдером)"
fi

# ─── Стек ноды (remnanode) и сертификаты ─────────────────────────────────────
title "Стек ноды и сертификаты"
if command -v docker >/dev/null 2>&1; then
    # `docker inspect -f` по несуществующему контейнеру (29.x) печатает в stdout ПУСТУЮ
    # строку и только потом падает: `… || echo absent` давал "\nabsent", ветка absent
    # была недостижима, и на панель-боксе/CDN-origin сенсор рапортовал ложный ✘
    # «node-агент лежит» (issue #27/#33). Имя контейнера — ручка NA_NODE_CONTAINER.
    RN_ST="$(docker inspect -f '{{.State.Status}}' "$NA_NODE_CONTAINER" 2>/dev/null | tr -d '[:space:]')"
    [[ -n "$RN_ST" ]] || RN_ST=absent
    if [[ "$RN_ST" == "running" ]]; then
        RN_RC="$(docker inspect -f '{{.RestartCount}}' "$NA_NODE_CONTAINER" 2>/dev/null | tr -d '[:space:]')"
        [[ "$RN_RC" =~ ^[0-9]+$ ]] || RN_RC=0
        RN_SE="$(docker logs --since 1h "$NA_NODE_CONTAINER" 2>&1 | grep -c 'SPAWN_ERROR' || true)"
        if [[ "${RN_SE:-0}" -gt 0 ]]; then
            bad "$NA_NODE_CONTAINER: running, но $RN_SE SPAWN_ERROR за час — xray не стартует (сверь node-address в панели: коллизия IP?)"
        elif [[ "${RN_RC:-0}" -gt 3 ]]; then
            wrn "$NA_NODE_CONTAINER: running, но RestartCount=$RN_RC — контейнер флапает (docker logs $NA_NODE_CONTAINER)"
        else
            pass "$NA_NODE_CONTAINER: running (рестартов $RN_RC, SPAWN_ERROR за час нет)"
        fi
    elif [[ "$RN_ST" == "absent" ]]; then
        info "$NA_NODE_CONTAINER: контейнера нет (бокс без Remnawave node-агента — панель/CDN-origin? иначе задай NA_NODE_CONTAINER=<имя>)"
    else
        bad "$NA_NODE_CONTAINER: статус '$RN_ST' (не running) — node-агент лежит"
    fi
else
    info "docker не установлен — сенсор node-контейнера пропущен"
fi
# порт node-агента vs файрвол: рассинхрон (агент мигрировал 2222→3000, а strict-файрвол
# в правилах держит старый порт) = панель молча теряет ноду. Сверяем ФАКТ (детект с ноды:
# env контейнера → .env → ss) с тем, что заложено в правила (маркер protect).
NP_DET="$(detect_node_port || true)"
if [[ -n "$NP_DET" && -f "$STATE_DIR/protect.installed" ]]; then
    NP_FW="$(awk -F= '/^node_port=/{print $2}' "$STATE_DIR/protect.installed" 2>/dev/null)"
    NP_FWM="$(awk -F= '/^fw_mode=/{print $2}' "$STATE_DIR/protect.installed" 2>/dev/null)"
    NP_TCPP="$(awk -F= '/^tcp_ports=/{print $2}' "$STATE_DIR/protect.installed" 2>/dev/null)"
    if [[ "${NP_FWM:-strict}" == "strict" ]] && nft -t list table inet na_filter >/dev/null 2>&1; then
        NP_MISS=""
        for _np in ${NP_DET//,/ }; do
            [[ ",${NP_FW:-},${NP_TCPP:-}," == *",$_np,"* ]] || NP_MISS+="${NP_MISS:+,}$_np"
        done
        if [[ -n "$NP_MISS" ]]; then
            bad "node-agent слушает :$NP_MISS, а файрвол держит node-port :${NP_FW:-?} — панель, скорее всего, ОТРЕЗАНА. Пожарно: nft add element inet na_filter whitelist_v4 '{ <IP панели> }'; правильно: ре-ран protect (NODE_PORT=auto подхватит)"
        else
            pass "node-agent порт(ы) $NP_DET согласованы с файрволом (node_port=${NP_FW:-?})"
        fi
        unset _np
    else
        info "node-agent порт(ы): $NP_DET (fw_mode=${NP_FWM:-?} — сверка с файрволом делается в strict)"
    fi
elif [[ -n "$NP_DET" ]]; then
    info "node-agent порт(ы): $NP_DET (protect ещё не гонялся — сверять не с чем)"
fi
# сертификаты: ближайший к истечению (LE / acme.sh / Caddy / nginx ssl_certificate /
# NA_CERT_PATHS). «Найден» — отдельный флаг: −1 дней раньше значил «не найдено», и
# просроченный серт терялся за следующим живым.
if command -v openssl >/dev/null 2>&1; then
    cert_scan || true
    if [[ "$CERT_FOUND" != 1 ]]; then
        # «сертов нет» и «сенсор слеп» были неотличимы и оба тихие: на selfsteal-ноде с
        # сертом в /opt/<стек>/certs это молчание означало «о протухании не предупредим
        # вообще» — ровно то, ради чего сенсор и нужен (issue #39).
        if tls_listening; then
            wrn "на :443/:8443 кто-то слушает, а TLS-сертификатов не нашёл — сенсор слеп: задай NA_CERT_PATHS='/путь/к/fullchain.pem …'"
        else
            info "TLS-сертификатов в стандартных путях не найдено (задай NA_CERT_PATHS, если selfsteal-серт лежит иначе)"
        fi
    elif [[ "$CERT_MIN" -lt 0 ]];  then bad  "TLS-серт ИСТЁК $(( -CERT_MIN )) дн назад ($CERT_MIN_F) — клиенты получают ошибку TLS; renewal сломан"
    elif [[ "$CERT_MIN" -eq 0 ]];  then bad  "TLS-серт истекает в ближайшие сутки ($CERT_MIN_F) — renewal сломан?"
    elif [[ "$CERT_MIN" -lt 7 ]];  then bad  "TLS-серт истекает через ${CERT_MIN} дн ($CERT_MIN_F) — renewal сломан?"
    elif [[ "$CERT_MIN" -lt 14 ]]; then wrn  "TLS-серт истекает через ${CERT_MIN} дн ($CERT_MIN_F) — проверь авто-renew"
    else pass "ближайший TLS-серт: ${CERT_MIN} дн до истечения ($CERT_MIN_F)"; fi
else
    info "openssl не установлен — проверка сроков сертификатов пропущена"
fi

# ─── Здоровье: давление, диск, инциденты ─────────────────────────────────────
title "Здоровье: давление, диск, инциденты"
# PSI — стол ядра под нагрузкой ('some'). ▲ по avg60, а не avg10: 10-секундное окно
# ловит единичный всплеск (сборка initrd, logrotate), минутное — устойчивое давление.
if [[ -r /proc/pressure/cpu ]]; then
    for r in cpu memory io; do
        read -r A10 A60 <<<"$(awk '/^some/{ for (i = 1; i <= NF; i++) { if ($i ~ /^avg10=/) { a = $i; sub(/avg10=/, "", a) } if ($i ~ /^avg60=/) { b = $i; sub(/avg60=/, "", b) } } }
                                END { printf "%s %s", (a == "" ? 0 : a), (b == "" ? 0 : b) }' "/proc/pressure/$r" 2>/dev/null)"
        A10="${A10:-0}"; A60="${A60:-0}"
        if awk -v x="$A60" 'BEGIN{exit !(x+0>=10)}'; then wrn "PSI $r some avg60=${A60}% (avg10=${A10}%) — устойчивый стол ядра"
        else info "PSI $r some avg60=${A60}% avg10=${A10}%"; fi
    done
else
    # Три состояния вместо двух: «ядро без CONFIG_PSI» ≠ «PSI собран, но выключен по
    # умолчанию». XanMod (тот, что ставит сам тулкит) — второй случай, и v4.0 объяснял
    # его «старым ядром» на ядре 6.18: сенсор давления молчал на 100% боксов, а строка
    # выглядела как штатное «на этом железе не поддерживается» (issue #37).
    case "$(psi_state)" in
        off-by-default)
            info "PSI выключен в сборке ядра (CONFIG_PSI_DEFAULT_DISABLED=y) — включи ENABLE_PSI=1 ре-раном optimize (допишет psi=1 в GRUB) + ребут" ;;
        absent)
            info "PSI не собран в этом ядре (нет CONFIG_PSI) — давление не измеряется" ;;
        *)
            info "PSI недоступен: /proc/pressure нет, конфиг ядра не прочитать" ;;
    esac
fi
# Диск + inodes (лог-флуд жрёт inodes раньше места)
DSP="$(df -P / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5);print $5}')"
DIN="$(df -Pi / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5);print $5}')"
if [[ "${DSP:-0}" -ge 85 ]] 2>/dev/null; then wrn "/ занят на ${DSP}%"; else info "/ занят на ${DSP:-?}%"; fi
if [[ "${DIN:-0}" -ge 85 ]] 2>/dev/null; then wrn "inodes / заняты на ${DIN}% (лог-флуд?)"; else info "inodes /: ${DIN:-?}%"; fi

# Лог-флуд. Процент диска — слишком поздний сигнал: он спокоен, пока один access.log
# растёт на сотни МБ в сутки, а на маленьком диске это упирается в 100% за недели. Диск
# на 100% выглядит тише, чем есть: контейнеры перестают писать логи (нода становится
# ненаблюдаемой), а acme.sh не может обновить сертификат.
LOGBIG="$(find /var/log -xdev -type f -size +500M -printf '%s %p\n' 2>/dev/null | sort -rn | head -1)"
if [[ -n "$LOGBIG" ]]; then
    wrn "крупный лог: $(awk '{printf "%.1f ГБ  %s", $1/1073741824, $2}' <<<"$LOGBIG") — ротация не поспевает"
else
    pass "файлов >500 МБ в /var/log нет"
fi
# Логи контейнеров живут вне /var/log, и logrotate их не видит вообще: кап задаётся
# только в /etc/docker/daemon.json (log-opts max-size) и лишь для НОВЫХ контейнеров.
DKBIG="$(find /var/lib/docker/containers -xdev -type f -name '*-json.log' -size +200M -printf '%s %p\n' 2>/dev/null | sort -rn | head -1)"
[[ -n "$DKBIG" ]] && wrn "json-лог контейнера: $(awk '{printf "%.1f ГБ", $1/1073741824}' <<<"$DKBIG") — задай log-opts max-size в /etc/docker/daemon.json"
# Кап, заданный в daemon.json, получают только контейнеры, созданные ПОСЛЕ него: старый
# контейнер с json-file без max-size пишет лог без предела (на флоте — сам node-агент)
DK_NOCAP="$(docker_nocap | paste -sd' ' -)"
[[ -n "$DK_NOCAP" ]] && wrn "контейнеры с json-логом без max-size (растёт без предела): $DK_NOCAP — logging.options.max-size в compose (или daemon.json) и пересоздать контейнер"
if ! command -v logrotate >/dev/null 2>&1; then
    wrn "logrotate не установлен — стансы в /etc/logrotate.d не выполняются вообще"
elif systemctl is-active --quiet na-logrotate.timer 2>/dev/null; then
    # «Таймер активен» и «станса существует» — разные факты (issue #40): уступив все маски
    # чужим стансам, optimize свою не создаёт, а таймер включает — и на трёх нодах флота
    # диагностика светила ✔ при ротации, которую держала ручная станса weekly без maxsize.
    LR_EN="$(sed -nE 's/.*\{ENABLE_LOGROTATE:=([^}]*)\}.*/\1/p' "$CONF_DIR/optimize.conf" 2>/dev/null | tail -1)"
    if [[ -s "$STATE_DIR/logrotate.ceded" ]]; then
        LR_CEDED="$(awk -F'\t' '{printf "%s%s → %s%s", (NR>1?", ":""), $1, $2, ($3=="none"?" (БЕЗ maxsize/size!)":($3=="unknown"?" (кап неизвестен)":""))}' "$STATE_DIR/logrotate.ceded" 2>/dev/null)"
        LR_NOCAP="$(awk -F'\t' '$3=="none"' "$STATE_DIR/logrotate.ceded" 2>/dev/null | grep -c .)"
        LR_UNK="$(awk -F'\t' '$3=="unknown"' "$STATE_DIR/logrotate.ceded" 2>/dev/null | grep -c .)"
        if [[ "${LR_NOCAP:-0}" -gt 0 ]]; then
            wrn "ротация: таймер активен, но маски отданы чужим стансам, и у $LR_NOCAP из них НЕТ капа по размеру: $LR_CEDED — добавь maxsize в чужую стансу или сузь NA_LOG_PATHS (ре-ран optimize)"
        elif [[ "${LR_UNK:-0}" -gt 0 ]]; then
            wrn "ротация: таймер активен, часть масок у чужих стансы, и кап у $LR_UNK из них не проверить: $LR_CEDED"
        else
            # кап по размеру у владельцев есть — ротация работает, тревожить нечем
            pass "ротация: часовой таймер активен; часть масок держат чужие стансы с капом: $LR_CEDED"
        fi
        [[ -s "$STATE_DIR/logrotate.owned" ]] && info "наша станса держит: $(paste -sd' ' "$STATE_DIR/logrotate.owned" 2>/dev/null)"
    elif [[ "${LR_EN:-1}" == "1" && ! -s /etc/logrotate.d/na-node-logs ]]; then
        wrn "ротация: таймер активен, а стансы /etc/logrotate.d/na-node-logs нет — тулкит ничего не ротирует (ре-ран optimize)"
    else
        pass "ротация логов: часовой таймер активен, станса на месте$( [[ -s "$STATE_DIR/logrotate.owned" ]] && echo " ($(paste -sd' ' "$STATE_DIR/logrotate.owned" 2>/dev/null))")"
    fi
else
    info "часовой таймер ротации не активен — работает только суточный logrotate.timer (maxsize проверяется раз в сутки)"
fi
# grep -c, а не -q: вывод `logrotate -d` большой, grep -q закрывал пайп на первом совпадении →
# SIGPIPE → под pipefail условие ложно ровно тогда, когда дубликат ЕСТЬ
if command -v logrotate >/dev/null 2>&1 \
   && [[ "$(logrotate -d /etc/logrotate.conf 2>&1 | grep -ci 'duplicate log entry')" -gt 0 ]]; then
    wrn "logrotate: дубликат путей — часть станс пропускается целиком (logrotate -d /etc/logrotate.conf)"
fi
# Ретеншен журнала ВО ВРЕМЕНИ. Датчик по объёму (выше) спокоен, когда логи капнуты, но
# journald при SystemMaxUse=300M и логе анти-скана на 5/сек (~432 000 строк = ~50 МБ в
# сутки) вытесняет всё остальное и живёт меньше суток: разбор вчерашнего инцидента уже
# невозможен, а на Debian 13 minimal journald — единственный источник истории входов
# (issue #35). Меряем возраст самой старой записи, а не размер.
# Лог анти-скана за СУТКИ по всем загрузкам и его доля в журнале. Порог «>100000 строк за
# загрузку» рос с аптаймом (ложные ▲ на долгоживущих нодах) и молчал после ребута; доля
# за сутки — это ровно то, что вытесняет историю из журнала.
PS_N=""; PS_T=""; PS_SH=-1
if PS24="$(portscan_24h)"; then
    read -r PS_N PS_T <<<"$PS24"
    [[ "$PS_T" =~ ^[0-9]+$ ]] && (( PS_T > 0 )) && PS_SH=$(( PS_N * 100 / PS_T ))
fi
JSPAN="$(journal_span_h)" || JSPAN=""
UP_H="$(awk '{printf "%d", $1/3600}' /proc/uptime 2>/dev/null)"; [[ "$UP_H" =~ ^[0-9]+$ ]] || UP_H=-1
if journal_volatile; then
    # журнал в RAM: «мелкий» он из-за ребута, а не из-за вытеснения — PORTSCAN тут ни при чём
    wrn "журнал volatile (только /run/log/journal, нет /var/log/journal): история не переживает ребут${JSPAN:+, сейчас ${JSPAN}ч} — ре-ран optimize (v4.2 включает Storage=persistent) или mkdir -p /var/log/journal"
elif [[ "$JSPAN" =~ ^[0-9]+$ ]]; then
    if [[ "$JSPAN" -lt 48 && "$UP_H" -ge 0 && $(( UP_H - JSPAN )) -le 1 ]]; then
        # самая старая запись ≈ момент загрузки: журнал держит всю текущую загрузку, а
        # прошлых в нём нет (почищен/новый каталог) — это не вытеснение
        info "глубина журнала ${JSPAN}ч ≈ аптайму: журнал держит всю текущую загрузку, прошлых загрузок в нём нет"
    elif [[ "$JSPAN" -lt 48 ]]; then
        PS_HINT="подними SystemMaxUse (NA_JOURNAL_MAX_USE, ре-ран optimize)"
        [[ "$PS_SH" -ge 20 ]] && PS_HINT="главный источник — лог анти-скана (${PS_SH}% строк за сутки): снизь PORTSCAN_LOG_RATE (ре-ран protect) или подними SystemMaxUse"
        wrn "журнал вмещает менее 48ч (самая старая запись ${JSPAN}ч назад) — форензика вчерашнего инцидента уже недоступна: $PS_HINT"
    else
        info "глубина журнала: ${JSPAN}ч (~$((JSPAN/24)) сут)"
    fi
fi
if [[ "$PS_N" =~ ^[0-9]+$ ]]; then
    PS_TXT="строк [na portscan] за 24ч: $PS_N"
    [[ "$PS_SH" -ge 0 ]] && PS_TXT+=" (${PS_SH}% журнала за сутки)"
    if [[ "$PS_SH" -ge 50 ]] || { [[ "$PS_SH" -ge 20 && "$JSPAN" =~ ^[0-9]+$ && "$JSPAN" -lt 48 ]] && ! journal_volatile; }; then
        wrn "$PS_TXT — лог анти-скана вытесняет журнал (бан работает по наборам, а не по строкам лога): снизь PORTSCAN_LOG_RATE (ре-ран protect; v4.2 пишет только переходы в suspect/autoban)"
    else
        info "$PS_TXT"
    fi
else
    info "строк [na portscan] за 24ч: не измерено (journalctl без --grep или не уложился в таймаут)"
fi
# Инциденты ядра/сервисов — за сутки по ВСЕМ загрузкам: `-k` подразумевает `-b` (только
# текущая загрузка), и OOM, из-за которого нода перезагрузилась, был не виден ровно тогда,
# когда важнее всего. _TRANSPORT=kernel — тот же фильтр без неявного `-b`.
OOM="$(journalctl -q --no-pager --since '-24h' _TRANSPORT=kernel 2>/dev/null | grep -ciE 'out of memory|oom-killer|soft lockup|hung task')"
if [[ "${OOM:-0}" -gt 0 ]]; then wrn "kern-лог за 24ч: $OOM строк OOM/lockup/hung — память/перегруз"; else pass "kern-лог чист (OOM/lockup/hung за 24ч нет)"; fi
FAILED="$(systemctl --failed --no-legend 2>/dev/null | grep -c .)"
if [[ "${FAILED:-0}" -gt 0 ]]; then wrn "упавших systemd-юнитов: $FAILED (см. systemctl --failed)"; else pass "упавших systemd-юнитов нет"; fi

# ─── Итог ────────────────────────────────────────────────────────────────────
hr
printf "  Итог:  %b✔ %d%b   %b▲ %d%b   %b✘ %d%b\n" "$GREEN" "$OKC" "$NC" "$YELLOW" "$WARNC" "$NC" "$RED" "$FAILC" "$NC"
if [[ "$FAILC" -gt 0 ]]; then
    echo "  → Есть критические пункты (✘). Запусти ⚡ оптимизатор и 🛡 защиту."
elif [[ "$WARNC" -gt 0 ]]; then
    echo "  → Базово ок, но есть, что докрутить (▲ выше)."
else
    echo "  → Нода затюнена и защищена. 🚀"
fi
hr
