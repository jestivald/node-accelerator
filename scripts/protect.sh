#!/usr/bin/env bash
#
# protect.sh — 🛡 Защита ноды.
#   • nftables (своя таблица inet na_filter, БЕЗ flush ruleset — сосуществует с
#     CrowdSec-bouncer и Docker-NAT):
#       AntiScan (portscan→autoban), flag-drop (XMAS/NULL/SYN+FIN/SYN+RST/FIN+RST/…),
#       anti-spoofing (bogon на WAN), SYN-flood + UDP-flood (per-IP rate-limit),
#       connect-flood SSH (per-IP→бан), per-IP connlimit (ct count), ICMP rate-limit.
#   • CrowdSec + crowdsec-firewall-bouncer-nftables — поведенческий IPS и community-блоклист.
#   • Авто-whitelist IP, с которого ты сейчас по SSH + сейфти-таймер от самоблокировки.
#
# Откат: scripts/rollback.sh protect
#
# ENV (всё опционально):
#   SSH_PORT, TCP_PORTS=443,2087, UDP_PORTS=443,2087, NODE_PORT=2222
#   WHITELIST="1.2.3.4,5.6.7.0/24"     IP/CIDR панели/мониторинга (v4 и v6)
#   SYN_RATE=100  SYN_BURST=200        per-IP лимит новых TCP-конн./сек на сервисный порт
#   UDP_RATE=200  UDP_BURST=400        per-IP лимит UDP пакетов/сек
#   CONN_LIMIT=600                     макс. одновременных конн. с одного IP (ct count)
#   SSH_RATE=6    SSH_BURST=5          per-IP новых SSH/мин до бана
#   SSH_BAN_TIME=24h  PORTSCAN_BAN_TIME=1h
#   ENABLE_PORTSCAN_BAN=1  ENABLE_CROWDSEC=1  ENABLE_SYNPROXY=0
#   CROWDSEC_ENROLL_KEY=...            enroll в CrowdSec Console (опц.)
#   SAFETY_DELAY=300  DRY_RUN=0  REMNAWAVE_NONINTERACTIVE=1

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

require_root
detect_os
BACKUP="$(backup_dir)"

# ─── Параметры ───────────────────────────────────────────────────────────────
SSH_PORT="${SSH_PORT:-$(detect_ssh_port)}"
TCP_PORTS="${TCP_PORTS:-443,2087}"
UDP_PORTS="${UDP_PORTS:-443,2087}"
NODE_PORT="${NODE_PORT:-2222}"
WHITELIST="${WHITELIST:-}"
SYN_RATE="${SYN_RATE:-100}";  SYN_BURST="${SYN_BURST:-200}"
UDP_RATE="${UDP_RATE:-200}";  UDP_BURST="${UDP_BURST:-400}"
CONN_LIMIT="${CONN_LIMIT:-600}"
SSH_RATE="${SSH_RATE:-6}";    SSH_BURST="${SSH_BURST:-5}"
SSH_BAN_TIME="${SSH_BAN_TIME:-24h}"
PORTSCAN_BAN_TIME="${PORTSCAN_BAN_TIME:-1h}"
ENABLE_PORTSCAN_BAN="${ENABLE_PORTSCAN_BAN:-1}"
ENABLE_CROWDSEC="${ENABLE_CROWDSEC:-1}"
ENABLE_SYNPROXY="${ENABLE_SYNPROXY:-0}"
SAFETY_DELAY="${SAFETY_DELAY:-300}"
DRY_RUN="${DRY_RUN:-0}"
WAN="$(default_iface || true)"

if [[ -t 0 && -z "${REMNAWAVE_NONINTERACTIVE:-}" && "$DRY_RUN" != "1" ]]; then
    title "Параметры защиты"
    read -rp "SSH порт                         [$SSH_PORT]: "  _v && SSH_PORT="${_v:-$SSH_PORT}"
    read -rp "TCP порты сервиса (через ,)       [$TCP_PORTS]: " _v && TCP_PORTS="${_v:-$TCP_PORTS}"
    read -rp "UDP порты сервиса (через ,)       [$UDP_PORTS]: " _v && UDP_PORTS="${_v:-$UDP_PORTS}"
    read -rp "Порт node-agent                  [$NODE_PORT]: " _v && NODE_PORT="${_v:-$NODE_PORT}"
    read -rp "Whitelist IP/CIDR (панель, твои)  [пусто]: "     _v && WHITELIST="${_v:-$WHITELIST}"
fi

# ─── Валидация ───────────────────────────────────────────────────────────────
_is_port()  { [[ "$1" =~ ^[0-9]+$ ]] && (( $1>=1 && $1<=65535 )); }
validate_port_list() {
    local v="$1" name="$2" p
    [[ -z "$v" ]] && return 0
    [[ "$v" =~ ^[0-9,]+$ ]] || { err "$name: '$v' — только цифры и запятые"; return 1; }
    for p in ${v//,/ }; do _is_port "$p" || { err "$name: '$p' вне 1..65535"; return 1; }; done
}
_is_port "$SSH_PORT"  || { err "SSH_PORT '$SSH_PORT' невалиден"; exit 1; }
_is_port "$NODE_PORT" || { err "NODE_PORT '$NODE_PORT' невалиден"; exit 1; }
validate_port_list "$TCP_PORTS" TCP_PORTS || exit 1
validate_port_list "$UDP_PORTS" UDP_PORTS || exit 1

# whitelist → v4/v6
WL4=""; WL6=""
add_wl() {
    local x
    for x in ${1//,/ }; do
        [[ -z "$x" ]] && continue
        if [[ "$x" == *:* ]]; then WL6+="${WL6:+, }$x"
        elif [[ "$x" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then WL4+="${WL4:+, }$x"
        else err "WHITELIST: '$x' не IPv4/IPv6/CIDR"; return 1; fi
    done
}
add_wl "$WHITELIST" || exit 1
ADMIN_IP="$(ssh_client_ip || true)"
if [[ -n "$ADMIN_IP" ]]; then
    add_wl "$ADMIN_IP" || true
    info "Авто-whitelist твоего SSH-IP: $ADMIN_IP (защита от самоблокировки)"
fi

# ─── Зависимости ─────────────────────────────────────────────────────────────
title "Зависимости"
apt_install nftables curl ca-certificates iproute2
ok "ok"

# ─── Сейфти-таймер: если потеряем SSH — снести нашу таблицу через N сек ───────
arm_safety() {
    [[ "$DRY_RUN" == "1" ]] && return 0
    title "Подстраховка от блокировки"
    warn "Если SSH отвалится — таблица na_filter удалится через ${SAFETY_DELAY}s (доступ вернётся)."
    if command -v systemd-run >/dev/null 2>&1; then
        systemctl stop na-fw-safety.timer 2>/dev/null || true
        systemd-run --quiet --unit=na-fw-safety --on-active="${SAFETY_DELAY}s" \
            /usr/sbin/nft delete table inet na_filter >/dev/null 2>&1 \
            && { ok "safety: systemd-таймер na-fw-safety на ${SAFETY_DELAY}s"; return 0; }
    fi
    # fallback
    [[ -f /tmp/na-fw-safety.pid ]] && { kill "$(cat /tmp/na-fw-safety.pid)" 2>/dev/null || true; }
    nohup sh -c "sleep ${SAFETY_DELAY}; /usr/sbin/nft delete table inet na_filter 2>/dev/null; rm -f /tmp/na-fw-safety.pid" \
        >/tmp/na-fw-safety.log 2>&1 &
    echo $! > /tmp/na-fw-safety.pid
    ok "safety: nohup pid $(cat /tmp/na-fw-safety.pid)"
}
disarm_safety() {
    systemctl stop na-fw-safety.timer 2>/dev/null || true
    [[ -f /tmp/na-fw-safety.pid ]] && { kill "$(cat /tmp/na-fw-safety.pid)" 2>/dev/null || true; rm -f /tmp/na-fw-safety.pid; }
}

# ─── Сборка per-port правил ──────────────────────────────────────────────────
TCP_RULES=""
for p in ${TCP_PORTS//,/ }; do
    [[ -z "$p" ]] && continue
    TCP_RULES+="
        # порт ${p}: per-IP лимит одновременных коннектов (анти-exhaustion)
        tcp dport ${p} ct state new meter cc4_${p} { ip saddr ct count over ${CONN_LIMIT} } drop
        tcp dport ${p} ct state new meter cc6_${p} { ip6 saddr ct count over ${CONN_LIMIT} } drop
        # порт ${p}: per-IP SYN-rate (масштабируется по числу клиентов, не глобальный потолок)
        tcp dport ${p} ct state new meter syn4_${p} { ip saddr limit rate ${SYN_RATE}/second burst ${SYN_BURST} packets } accept
        tcp dport ${p} ct state new meter syn6_${p} { ip6 saddr limit rate ${SYN_RATE}/second burst ${SYN_BURST} packets } accept
        tcp dport ${p} ct state new limit rate 5/second log prefix \"[na synflood] \" level info
        tcp dport ${p} ct state new drop"
done

UDP_RULES=""
for p in ${UDP_PORTS//,/ }; do
    [[ -z "$p" ]] && continue
    UDP_RULES+="
        # порт ${p}/udp: per-IP rate (QUIC/Hysteria2/TUIC) — анти-UDP-flood
        udp dport ${p} meter udp4_${p} { ip saddr limit rate ${UDP_RATE}/second burst ${UDP_BURST} packets } accept
        udp dport ${p} meter udp6_${p} { ip6 saddr limit rate ${UDP_RATE}/second burst ${UDP_BURST} packets } accept
        udp dport ${p} drop"
done

# anti-spoofing (только на WAN-интерфейсе)
ANTISPOOF=""
if [[ -n "$WAN" ]]; then
    ANTISPOOF="        # anti-spoofing: приватные/bogon источники на WAN = спуф
        udp sport 67 udp dport 68 accept
        iifname \"${WAN}\" ip saddr @bogon_v4 drop
        iifname \"${WAN}\" ip6 saddr @bogon_v6 drop"
fi

# portscan → autoban (включается флагом)
PORTSCAN=""
if [[ "$ENABLE_PORTSCAN_BAN" == "1" ]]; then
    PORTSCAN="        # ANTI-SCAN: новый SYN на несервисный порт = скан → лог(rl) + автобан
        meta nfproto ipv4 tcp flags & (fin|syn|rst|ack) == syn ct state new limit rate 5/second log prefix \"[na portscan] \" level info
        meta nfproto ipv4 tcp flags & (fin|syn|rst|ack) == syn ct state new add @autoban_v4 { ip saddr timeout ${PORTSCAN_BAN_TIME} } drop
        meta nfproto ipv6 tcp flags & (fin|syn|rst|ack) == syn ct state new add @autoban_v6 { ip6 saddr timeout ${PORTSCAN_BAN_TIME} } drop"
fi

# опциональный synproxy (по умолчанию off — требует совпадения mss/wscale)
SYNPROXY_PRE=""; SYNPROXY_IN=""
if [[ "$ENABLE_SYNPROXY" == "1" ]]; then
    SP_PORTS="$(echo "$TCP_PORTS" | tr ',' ' ')"; SP_SET="$(echo "$TCP_PORTS")"
    SYNPROXY_PRE="    chain prerouting {
        type filter hook prerouting priority -300; policy accept;
        tcp dport { ${SP_SET} } tcp flags syn notrack
    }"
    SYNPROXY_IN="        tcp dport { ${SP_SET} } ct state invalid,untracked synproxy mss 1460 wscale 7 timestamp sack-perm"
fi

WL4_LINE=""; [[ -n "$WL4" ]] && WL4_LINE="elements = { $WL4 }"
WL6_LINE=""; [[ -n "$WL6" ]] && WL6_LINE="elements = { $WL6 }"

# ─── Генерация nft-файла ─────────────────────────────────────────────────────
NFT_FILE="$CONF_DIR/na_filter.nft"
[[ "$DRY_RUN" == "1" ]] && NFT_FILE="$(mktemp /tmp/na_filter.XXXXXX.nft)"
mkdir -p "$CONF_DIR"
title "Генерация nftables → $NFT_FILE"

cat > "$NFT_FILE" <<NFT
#!/usr/sbin/nft -f
# node-accelerator / protect.sh @ $(date -Is)
# Управляем ТОЛЬКО своей таблицей — НЕ flush ruleset (живём рядом с CrowdSec/Docker).

table inet na_filter {}
delete table inet na_filter

table inet na_filter {

    set whitelist_v4 { type ipv4_addr; flags interval; auto-merge; $WL4_LINE }
    set whitelist_v6 { type ipv6_addr; flags interval; auto-merge; $WL6_LINE }

    # size — потолок записей: portscan-бан ловит чистый SYN (тривиально спуфится),
    # без лимита спуф-флуд раздул бы set в памяти ядра. При переполнении новые баны
    # просто не добавляются (старые живут по timeout).
    set autoban_v4 { type ipv4_addr; flags timeout; size 65536; }
    set autoban_v6 { type ipv6_addr; flags timeout; size 65536; }

    # bogon/martian источники (RFC1918, CGNAT, loopback, link-local, TEST-NET, multicast)
    set bogon_v4 {
        type ipv4_addr; flags interval; auto-merge
        elements = {
            0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
            169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24,
            192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
            224.0.0.0/3
        }
    }

    # bogon-источники IPv6, которые НЕ могут легитимно прийти как saddr на WAN.
    # СОЗНАТЕЛЬНО без fe80::/10 (NDP/RA — link-local source) и без ff00::/8 (multicast):
    # их дроп убил бы соседство/автоконфиг IPv6. Только однозначно поддельные диапазоны.
    set bogon_v6 {
        type ipv6_addr; flags interval; auto-merge
        elements = {
            ::1/128, ::/128, ::ffff:0:0/96, 100::/64, 2001:db8::/32, fc00::/7
        }
    }

    # битые TCP-флаги / скан-пакеты → лог(rl) + drop
    chain scan_drop {
        limit rate 5/second log prefix "[na badflags] " level info
        counter drop
    }

$SYNPROXY_PRE

    chain input {
        type filter hook input priority filter; policy drop;

        iif lo accept
        ct state established,related accept
        ct state invalid drop

        # whitelist — всегда сверху (в т.ч. твой текущий SSH-IP)
        ip  saddr @whitelist_v4 accept
        ip6 saddr @whitelist_v6 accept

        # уже забаненные
        ip  saddr @autoban_v4 drop
        ip6 saddr @autoban_v6 drop

$ANTISPOOF

        # flag-drop: NULL, XMAS, SYN+FIN, SYN+RST, FIN+RST и прочие невалидные комбинации
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0                       jump scan_drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|syn|rst|psh|ack|urg) jump scan_drop
        tcp flags & (fin|psh|urg) == (fin|psh|urg)                         jump scan_drop
        tcp flags & (syn|fin) == (syn|fin)                                 jump scan_drop
        tcp flags & (syn|rst) == (syn|rst)                                 jump scan_drop
        tcp flags & (fin|rst) == (fin|rst)                                 jump scan_drop
        tcp flags & (fin|ack) == fin                                       jump scan_drop
        tcp flags & (psh|ack) == psh                                       jump scan_drop
        tcp flags & (ack|urg) == urg                                       jump scan_drop

        # ICMP: пинг работает, флуд режется
        ip protocol icmp icmp type echo-request limit rate 10/second burst 20 packets accept
        ip protocol icmp icmp type echo-request drop
        ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
        icmpv6 type echo-request limit rate 10/second burst 20 packets accept
        icmpv6 type echo-request drop
        icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, packet-too-big, time-exceeded, parameter-problem, destination-unreachable, mld-listener-query, mld-listener-report, mld-listener-done } accept

$SYNPROXY_IN

        # SSH connect-flood: >${SSH_RATE}/мин новых с одного IP → бан ${SSH_BAN_TIME}
        tcp dport ${SSH_PORT} ct state new meter ssh4 { ip saddr limit rate ${SSH_RATE}/minute burst ${SSH_BURST} packets } accept
        tcp dport ${SSH_PORT} ct state new meter ssh6 { ip6 saddr limit rate ${SSH_RATE}/minute burst ${SSH_BURST} packets } accept
        tcp dport ${SSH_PORT} ct state new limit rate 5/second log prefix "[na ssh-flood] " level warn
        tcp dport ${SSH_PORT} ct state new meta nfproto ipv4 add @autoban_v4 { ip saddr timeout ${SSH_BAN_TIME} } drop
        tcp dport ${SSH_PORT} ct state new meta nfproto ipv6 add @autoban_v6 { ip6 saddr timeout ${SSH_BAN_TIME} } drop

        # сервисные TCP-порты (per-IP лимиты)
$TCP_RULES

        # сервисные UDP-порты (per-IP лимиты)
$UDP_RULES

        # node-agent: только whitelist (выше) + мягкий per-IP лимит
        tcp dport ${NODE_PORT} ct state new meter na4 { ip saddr limit rate 30/second burst 60 packets } accept
        tcp dport ${NODE_PORT} ct state new meter na6 { ip6 saddr limit rate 30/second burst 60 packets } accept
        tcp dport ${NODE_PORT} ct state new drop

$PORTSCAN

        counter drop
    }

    chain forward { type filter hook forward priority filter; policy accept; }
    chain output  { type filter hook output  priority filter; policy accept; }
}
NFT

# ─── Проверка синтаксиса ДО применения ───────────────────────────────────────
if ! nft -c -f "$NFT_FILE"; then
    err "Сгенерированный ruleset не прошёл nft -c. Файл: $NFT_FILE (ничего не применено)."
    exit 1
fi
ok "nft -c: синтаксис валиден"

if [[ "$DRY_RUN" == "1" ]]; then
    ok "DRY-RUN: файл сгенерирован и проверен. Применение пропущено."
    info "Посмотреть: cat $NFT_FILE"
    exit 0
fi

# ─── Применяем (с сейфти-таймером) ───────────────────────────────────────────
arm_safety
nft -f "$NFT_FILE"
ok "nftables na_filter применён"

# boot-persist через свой сервис (не трогаем /etc/nftables.conf и чужие таблицы)
cat > /etc/systemd/system/na-firewall.service <<EOF
[Unit]
Description=node-accelerator nftables (na_filter)
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $NFT_FILE
ExecReload=/usr/sbin/nft -f $NFT_FILE

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable na-firewall.service >/dev/null 2>&1 || true
systemctl enable nftables >/dev/null 2>&1 || true
ok "na-firewall.service включён (правила переживут reboot)"

# ─── CrowdSec + firewall-bouncer ─────────────────────────────────────────────
if [[ "$ENABLE_CROWDSEC" == "1" ]]; then
    title "CrowdSec + nftables firewall-bouncer"
    if ! command -v cscli >/dev/null 2>&1; then
        info "Подключаю репозиторий CrowdSec..."
        curl -s https://install.crowdsec.net | bash >/dev/null 2>&1 || warn "install.crowdsec.net недоступен"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec >/dev/null 2>&1 || warn "crowdsec не установился"
    fi
    if command -v cscli >/dev/null 2>&1; then
        systemctl enable --now crowdsec >/dev/null 2>&1 || true
        sleep 2
        cscli collections install crowdsecurity/sshd crowdsecurity/linux >/dev/null 2>&1 || true

        # whitelist админа/панели в самом CrowdSec — чтобы IPS их не банил.
        # Ключи ip:/cidr: пишем ТОЛЬКО при наличии записей (пустые ключи валят парсер).
        mkdir -p /etc/crowdsec/parsers/s02-enrich
        IP_ITEMS=""; CIDR_ITEMS=""
        for x in ${WHITELIST//,/ } ${ADMIN_IP:-}; do
            [[ -z "$x" ]] && continue
            if [[ "$x" == */* ]]; then CIDR_ITEMS+="    - \"$x\""$'\n'; else IP_ITEMS+="    - \"$x\""$'\n'; fi
        done
        if [[ -n "$IP_ITEMS$CIDR_ITEMS" ]]; then
            {
                echo "name: node-accelerator/whitelist"
                echo "description: never ban admin/panel"
                echo "whitelist:"
                echo "  reason: node-accelerator trusted"
                [[ -n "$IP_ITEMS"   ]] && { echo "  ip:";   printf "%s" "$IP_ITEMS"; }
                [[ -n "$CIDR_ITEMS" ]] && { echo "  cidr:"; printf "%s" "$CIDR_ITEMS"; }
            } > /etc/crowdsec/parsers/s02-enrich/na-whitelist.yaml
        else
            rm -f /etc/crowdsec/parsers/s02-enrich/na-whitelist.yaml
        fi

        # источник логов sshd через journald (на системах без /var/log/auth.log)
        mkdir -p /etc/crowdsec/acquis.d
        cat > /etc/crowdsec/acquis.d/na-sshd.yaml <<'ACQ'
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=ssh.service"
labels:
  type: syslog
---
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=sshd.service"
labels:
  type: syslog
ACQ
        systemctl reload crowdsec >/dev/null 2>&1 || systemctl restart crowdsec >/dev/null 2>&1 || true

        # firewall-bouncer (nftables-режим): своя таблица crowdsec/crowdsec6, priority -10
        if ! dpkg -s crowdsec-firewall-bouncer-nftables >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec-firewall-bouncer-nftables >/dev/null 2>&1 \
                || warn "bouncer не установился"
        fi
        systemctl enable --now crowdsec-firewall-bouncer >/dev/null 2>&1 || true

        # опциональный enroll в Console
        if [[ -n "${CROWDSEC_ENROLL_KEY:-}" ]]; then
            cscli console enroll "$CROWDSEC_ENROLL_KEY" >/dev/null 2>&1 \
                && { systemctl reload crowdsec >/dev/null 2>&1 || true; ok "enroll в CrowdSec Console отправлен"; } \
                || warn "enroll не прошёл (проверь ключ)"
        fi

        if systemctl is-active --quiet crowdsec && systemctl is-active --quiet crowdsec-firewall-bouncer; then
            ok "CrowdSec + bouncer активны (community-блоклист + поведенческий бан)"
        else
            warn "CrowdSec/bouncer установлены, но сервис не active — проверь: cscli metrics"
        fi
    fi
else
    info "ENABLE_CROWDSEC=0 — CrowdSec пропущен"
fi

# ─── fw-status хелпер ────────────────────────────────────────────────────────
cat > /usr/local/sbin/na-fw-status <<'STAT'
#!/usr/bin/env bash
echo "── nft table inet na_filter ──"
nft list table inet na_filter 2>/dev/null | grep -E 'policy|counter|elements' | head -40
echo
echo "── autoban (живые баны) ──"
echo "v4: $(nft list set inet na_filter autoban_v4 2>/dev/null | grep -oE '[0-9.]+ timeout' | wc -l)   v6: $(nft list set inet na_filter autoban_v6 2>/dev/null | grep -c timeout)"
nft list set inet na_filter autoban_v4 2>/dev/null | grep -oE '[0-9.]+ (timeout|expires)[^,]*' | head -15
echo
if command -v cscli >/dev/null 2>&1; then
    echo "── CrowdSec ──"
    cscli decisions list 2>/dev/null | head -20
    echo
    cscli metrics 2>/dev/null | sed -n '1,25p'
fi
STAT
chmod +x /usr/local/sbin/na-fw-status

# ─── top-talkers хелпер ──────────────────────────────────────────────────────
# Если нода за реверс-прокси/балансировщиком/CDN — трафик идёт с горстки upstream-IP,
# и per-IP лимиты их режут. Хелпер показывает топ источников → кандидаты в WHITELIST=.
cat > /usr/local/sbin/na-fw-top-talkers <<'TT'
#!/usr/bin/env bash
# Топ удалённых IP по числу установленных TCP-соединений на сервисных портах.
# Если нода за реверс-прокси/балансировщиком/CDN — легитимный трафик приходит с
# небольшого набора upstream-адресов; их стоит занести в WHITELIST=, чтобы per-IP
# лимиты (CONN_LIMIT/SYN_RATE) их не резали. Хелпер показывает кандидатов.
#   na-fw-top-talkers [порт[,порт...]] [N]   (по умолчанию порты из protect, N=25)
set -u
DEF=443
if [ -r /var/lib/node-accelerator/protect.installed ]; then
    DEF="$(awk -F= '/^tcp_ports=/{print $2}' /var/lib/node-accelerator/protect.installed)"
fi
PORTS="${1:-${DEF:-443}}"
N="${2:-25}"
filt=""
for p in ${PORTS//,/ }; do
    [ -n "$p" ] || continue
    filt="${filt:+$filt or }sport = :$p"
done
[ -n "$filt" ] || { echo "нет портов для анализа"; exit 1; }
echo "── Топ-$N удалённых IP по established TCP на портах: $PORTS ──"
ss -Hnt state established "( $filt )" 2>/dev/null \
    | awk '{print $5}' \
    | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//' \
    | sort | uniq -c | sort -rn | head -n "$N"
TT
chmod +x /usr/local/sbin/na-fw-top-talkers

# ─── Маркер ──────────────────────────────────────────────────────────────────
mkdir -p "$STATE_DIR"
cat > "$STATE_DIR/protect.installed" <<EOF
installed_at=$(date -Is)
backup=$BACKUP
ssh_port=$SSH_PORT
tcp_ports=$TCP_PORTS
udp_ports=$UDP_PORTS
node_port=$NODE_PORT
crowdsec=$ENABLE_CROWDSEC
nft_file=$NFT_FILE
EOF

# ─── Подтверждение работы ────────────────────────────────────────────────────
title "Подтверждение (защита от самоблокировки)"
echo "  Открой НОВОЕ окно и проверь: ssh root@<этот сервер>"
echo "  (твой текущий IP $ADMIN_IP уже в whitelist, но лучше убедиться.)"
echo
if [[ -t 0 && -z "${REMNAWAVE_NONINTERACTIVE:-}" ]]; then
    read -r -p "Соединение работает? [y/N]: " c
    if [[ "$c" =~ ^[yYдД] ]]; then
        disarm_safety; ok "Сейфти-таймер снят. Защита активна."
    else
        warn "Сейфти оставлен: через ${SAFETY_DELAY}s na_filter удалится сам."
        warn "Если всё ок — сними: systemctl stop na-fw-safety.timer  (или kill из /tmp/na-fw-safety.pid)"
    fi
else
    warn "Неинтерактивно: сейфти-таймер на ${SAFETY_DELAY}s АКТИВЕН."
    warn "Подтверди доступ и сними: systemctl stop na-fw-safety.timer"
fi
echo
ok "Готово. Статус: na-fw-status | топ источников (для WHITELIST за CDN/LB): na-fw-top-talkers"
