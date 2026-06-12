#!/usr/bin/env bash
#
# optimize.sh — ⚡ Оптимизатор ноды.
#   • XanMod-ядро (BBRv3) — авто-выбор сборки по psABI, пропуск на контейнерах/ARM
#   • sysctl: BBR + fq, большие буферы, conntrack, anti-spoof, syncookies
#   • RPS/RFS/XPS — размазывает обработку пакетов по всем ядрам (главное на virtio-VPS)
#   • лимиты nofile/nproc, swap, journald cap, THP off, CPU governor=performance, NIC tune
#
# Идемпотентно. Откат: scripts/rollback.sh optimize
#
# ENV-флаги:
#   ENABLE_XANMOD=1   поставить XanMod-ядро (по умолч. 1; авто-skip на контейнере/не-x86_64)
#   XANMOD_FLAVOR=lts сборка: lts (стабильная, по умолч.) | main | edge | rt
#   XANMOD_PKG=...     полностью переопределить имя пакета
#   REMNAWAVE_SWAP_SIZE=2G

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

# Прячем курсор для прогресс-бара установки ядра ниже; гарантированно возвращаем его
# при любом выходе, включая Ctrl-C, чтобы не оставить терминал с невидимым курсором.
trap 'tput cnorm 2>/dev/null || true' EXIT
trap 'tput cnorm 2>/dev/null || true; exit 130' INT

require_root
detect_os

# Подчищаем ТОЛЬКО XanMod-репозитории с мёртвыми suite (focal/jammy/releases выпилены
# из репо) — их 404 роняет 'apt-get update' на повторном прогоне через set -e. Рабочий
# list НЕ трогаем: иначе на уже настроенной ноде молча отключатся обновления ядра.
for _l in /etc/apt/sources.list.d/xanmod*.list; do
    [[ -e "$_l" ]] || continue
    if grep -qE 'deb\.xanmod\.org[[:space:]]+(focal|jammy|releases)([[:space:]]|$)' "$_l" 2>/dev/null; then
        rm -f "$_l"
    fi
done
unset _l

ENABLE_XANMOD="${ENABLE_XANMOD:-1}"
XANMOD_FLAVOR="${XANMOD_FLAVOR:-lts}"
BACKUP="$(backup_dir)"
REBOOT_NEEDED=0
info "Бэкап изменяемых файлов: $BACKUP"

# Прогресс-бар установки ядра (рисуется по APT::Status-Fd в install_xanmod).
draw_progress_bar() {
    local percent=$1 desc=$2 width=30 i bar=""
    local filled=$((percent * width / 100)) empty=$((width - filled))
    for ((i=0; i<filled; i++)); do bar+="#"; done
    for ((i=0; i<empty;  i++)); do bar+="-"; done
    local maxlen=35
    [[ ${#desc} -gt $maxlen ]] && desc="${desc:0:$((maxlen-3))}..."
    printf "\r[*] [%s] %3d%% (%s)\033[K" "$bar" "$percent" "$desc"
}

# ─── 1. Зависимости ──────────────────────────────────────────────────────────
title "Зависимости"
apt_install ca-certificates curl gnupg irqbalance ethtool
ok "ok"

# ─── 2. XanMod-ядро (BBRv3) ──────────────────────────────────────────────────
title "XanMod-ядро (BBRv3)"
# Полный отпечаток ключа подписи XanMod (keyid 86F7D09EE734E623 — последние 16 hex).
# Проверяем именно его: 64-битный keyid подделать дёшево, полный fingerprint — нет.
XANMOD_FP="D38D7D1DA1349567ADED882D86F7D09EE734E623"

# Импорт ключа: 1) напрямую с XanMod; 2) при блокировке (CF-403 типичен для Hetzner/GCP)
# — с Ubuntu keyserver. Что бы ни сработало — сверяем полный отпечаток.
xanmod_import_key() {
    local keyring="$1"
    mkdir -p /etc/apt/keyrings
    if ! curl -fsSL --connect-timeout 5 --max-time 20 https://dl.xanmod.org/archive.key \
            | gpg --yes --dearmor -o "$keyring" 2>/dev/null; then
        warn "dl.xanmod.org недоступен (обычно CF-403 на хостингах) — пробую Ubuntu keyserver…"
        curl -fsSL --connect-timeout 5 --max-time 20 \
                "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${XANMOD_FP: -16}" \
            | gpg --yes --dearmor -o "$keyring" 2>/dev/null \
            || { warn "Ключ XanMod недоступен ни напрямую, ни с keyserver"; return 1; }
    fi
    if ! gpg --show-keys --with-colons "$keyring" 2>/dev/null \
            | awk -F: '/^fpr:/{print $10}' | grep -qx "$XANMOD_FP"; then
        warn "Отпечаток ключа XanMod не совпал с $XANMOD_FP — отказываюсь использовать"
        rm -f "$keyring"; return 1
    fi
    chmod 0644 "$keyring"
}

# Готовим репозиторий XanMod (ключ + sources.list + apt update). Идемпотентно;
# вызывается и при установке, и для уже стоящего ядра (чтобы не заморозить обновления).
setup_xanmod_repo() {
    local keyring=/etc/apt/keyrings/xanmod-archive-keyring.gpg
    local list=/etc/apt/sources.list.d/xanmod-release.list
    local codename; codename="$(os_codename)"

    # focal/jammy выпилены из XanMod-репо → совместимый Debian 'bookworm' (LTS-ветка ядра).
    case "$codename" in
        focal|jammy)
            info "Ubuntu $codename: suite выпилен из XanMod-репо → беру 'bookworm' + lts-сборку"
            codename="bookworm"; XANMOD_FLAVOR="lts" ;;
        "") codename="bookworm" ;;   # релиз не определён — берём универсальный LTS-suite
    esac

    xanmod_import_key "$keyring" || return 1

    echo "deb [signed-by=$keyring] http://deb.xanmod.org $codename main" > "$list"
    if ! apt-get update -qq 2>/dev/null; then
        if [[ "$codename" != "bookworm" ]]; then
            warn "Suite '$codename' не поднялся — откатываюсь на 'bookworm' (LTS)"
            codename="bookworm"; XANMOD_FLAVOR="lts"
            echo "deb [signed-by=$keyring] http://deb.xanmod.org $codename main" > "$list"
            apt-get update -qq 2>/dev/null || { warn "XanMod-репо недоступен"; rm -f "$list"; return 1; }
        else
            warn "XanMod-репо ('bookworm') недоступен"; rm -f "$list"; return 1
        fi
    fi
    return 0
}

# Список пакетов-кандидатов по psABI-уровню (деградация v3→v2→v1). Вынесено отдельно,
# чтобы install_xanmod и XANMOD_PROBE брали кандидатов из одного источника.
xanmod_candidates() {
    local flv="$XANMOD_FLAVOR" pref="" lvl
    case "$flv" in lts) pref="lts-";; edge) pref="edge-";; rt) pref="rt-";; *) pref="";; esac
    lvl="$(cpu_psabi_level)"; [[ "$lvl" =~ ^[1-4]$ ]] || lvl=2
    if [[ -n "${XANMOD_PKG:-}" ]]; then echo "$XANMOD_PKG"; return; fi
    case "$lvl" in
        4|3) echo "linux-xanmod-${pref}x64v3 linux-xanmod-${pref}x64v2 linux-xanmod-lts-x64v2";;
        2)   echo "linux-xanmod-${pref}x64v2 linux-xanmod-lts-x64v2";;
        *)   echo "linux-xanmod-lts-x64v1";;
    esac
}

install_xanmod() {
    setup_xanmod_repo || return 1
    info "psABI уровень CPU: x86-64-v$(cpu_psabi_level), сборка: $XANMOD_FLAVOR"

    local p pkg="" err_log candidates
    read -ra candidates <<< "$(xanmod_candidates)"
    for p in "${candidates[@]}"; do
        apt-cache show "$p" >/dev/null 2>&1 || continue
        info "Ставлю $p (это надолго — компилит initramfs)…"
        err_log="$(mktemp)"
        tput civis 2>/dev/null || true
        # APT::Status-Fd=1 → машинный прогресс в stdout; stdbuf -oL снимает буферизацию пайпа.
        # pkg НЕ трогаем в subshell справа от пайпа (там только отрисовка) — ставим в родителе.
        if DEBIAN_FRONTEND=noninteractive stdbuf -oL \
                apt-get -o APT::Status-Fd=1 install -y "$p" 2>"$err_log" \
                | while IFS=: read -r f1 f2 f3 f4 _r; do
                    case "$f1" in
                        pmstatus|dlstatus)
                            pct="$f3"; dsc="$f4"
                            if ! [[ "$pct" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                                if [[ "$f2" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then pct="$f2"; dsc="$f3"; else continue; fi
                            fi
                            pct="${pct%%.*}"
                            [[ "$pct" =~ ^[0-9]+$ ]] || continue
                            [[ "$pct" -gt 100 ]] && pct=100
                            [[ "$f1" == "dlstatus" ]] && act="Загрузка" || act="Установка"
                            draw_progress_bar "$pct" "$act: $dsc"
                            ;;
                    esac
                done
        then
            printf "\r\033[K"; tput cnorm 2>/dev/null || true
            rm -f "$err_log"; pkg="$p"; break
        else
            printf "\r\033[K"; tput cnorm 2>/dev/null || true
            warn "Сборка $p не установилась — пробую следующую. Хвост ошибки:"
            tail -n 3 "$err_log" >&2; rm -f "$err_log"
        fi
    done
    [[ -z "$pkg" ]] && { warn "Ни одна сборка XanMod не поставилась"; return 1; }

    mkdir -p "$STATE_DIR"; echo "$pkg" > "$STATE_DIR/xanmod.pkg"
    update-grub >/dev/null 2>&1 || true
    ok "XanMod установлен: $pkg (активируется ПОСЛЕ перезагрузки)"
    REBOOT_NEEDED=1
    return 0
}

# PROBE: проверить, что репозиторий+ключ+кандидат резолвятся на этой ОС, БЕЗ установки.
# Используется в CI (матрица дистрибутивов) и как ops-проба. Обходит гейт «контейнер».
if [[ "${XANMOD_PROBE:-0}" == "1" ]]; then
    setup_xanmod_repo || { err "XANMOD_PROBE: репозиторий не поднялся"; exit 1; }
    cand="$(xanmod_candidates)"; info "кандидаты: $cand"
    for p in $cand; do
        if apt-cache show "$p" >/dev/null 2>&1; then
            ok "XANMOD_PROBE: '$p' доступен в репозитории"
            DEBIAN_FRONTEND=noninteractive apt-get install --download-only -y "$p" >/dev/null 2>&1 \
                && ok "XANMOD_PROBE: '$p' скачивается" \
                || warn "XANMOD_PROBE: '$p' в индексе есть, но download-only не прошёл (зависимости дистрибутива)"
            exit 0
        fi
    done
    err "XANMOD_PROBE: ни один кандидат не доступен"; exit 1
fi

if [[ "$ENABLE_XANMOD" == "1" ]]; then
    if ! can_install_kernel; then
        if is_container; then
            warn "Виртуализация: $(detect_virt) — это контейнер, делит ядро хоста."
            warn "XanMod поставить нельзя. BBR возьмётся из стокового ядра (если поддерживается)."
        else
            warn "Архитектура $(arch) — XanMod только под x86_64. Пропускаю ядро."
        fi
    elif uname -r | grep -q xanmod; then
        ok "XanMod уже стоит ($(uname -r)) — обновляю только репозиторий (чтобы шли апдейты ядра)"
        setup_xanmod_repo || warn "репозиторий XanMod не обновлён (само ядро не тронуто)"
    else
        install_xanmod || warn "XanMod не установлен — продолжаю с текущим ядром"
    fi
else
    info "ENABLE_XANMOD=0 — установка ядра пропущена"
fi

# ─── 3. Sysctl ───────────────────────────────────────────────────────────────
title "Sysctl: BBR, буферы, conntrack, anti-spoof, syncookies"
backup_file /etc/sysctl.d/99-node-accelerator.conf "$BACKUP"
cat > /etc/sysctl.d/99-node-accelerator.conf <<'SYSCTL'
# === node-accelerator / optimize ===

# --- Network core ---
net.core.default_qdisc            = fq
net.core.netdev_max_backlog       = 250000
net.core.somaxconn                = 65535
net.core.rmem_default             = 2097152
net.core.wmem_default             = 2097152
net.core.rmem_max                 = 67108864
net.core.wmem_max                 = 67108864
net.core.optmem_max               = 65536
# RPS: глобальная таблица flow-привязок (дополняет per-queue настройку из na-rps)
net.core.rps_sock_flow_entries    = 32768

# --- TCP (под XanMod congestion=bbr == BBRv3) ---
net.ipv4.tcp_congestion_control   = bbr
net.ipv4.tcp_fastopen             = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse             = 1
net.ipv4.tcp_fin_timeout          = 15
# keepalive 1200с: 300с резало клиентов за NAT/мобилой раньше, чем доходила проба.
net.ipv4.tcp_keepalive_time       = 1200
net.ipv4.tcp_keepalive_intvl      = 30
net.ipv4.tcp_keepalive_probes     = 5
net.ipv4.tcp_max_syn_backlog      = 65535
net.ipv4.tcp_max_tw_buckets       = 2000000
net.ipv4.tcp_mtu_probing          = 1
# Floor the probe MSS well above the kernel default of 48: with mtu_probing on,
# repeated RTOs on a lossy link make the kernel suspect a PMTU black hole and
# ratchet the send MSS down toward this floor. At 48B a segment is ~97% header
# overhead and throughput collapses with no recovery. 512 keeps probing useful
# for genuine black holes while never destroying goodput (and stays above the
# CVE-2019-11479 mitigation minimum).
net.ipv4.tcp_min_snd_mss          = 512
net.ipv4.tcp_no_metrics_save      = 1
net.ipv4.tcp_rfc1337              = 1
net.ipv4.tcp_sack                 = 1
net.ipv4.tcp_window_scaling       = 1
net.ipv4.tcp_rmem                 = 4096 87380 67108864
net.ipv4.tcp_wmem                 = 4096 65536 67108864
net.ipv4.tcp_notsent_lowat        = 131072
net.ipv4.tcp_ecn                  = 1
net.ipv4.ip_local_port_range      = 10000 65535

# --- UDP (QUIC/Hysteria2/TUIC). Потолок буфера берётся из rmem_max выше. ---
net.ipv4.udp_rmem_min             = 16384
net.ipv4.udp_wmem_min             = 16384

# --- IP forwarding (XRay/VLESS в network_mode: host + Docker) ---
net.ipv4.ip_forward               = 1
net.ipv4.conf.all.forwarding      = 1
net.ipv6.conf.all.forwarding      = 1

# --- Conntrack: timeout здесь; ёмкость (max/buckets) — отдельным drop-in ниже,
# масштабируется от RAM (99-node-accelerator-conntrack.conf), чтобы мелкая VPS под
# флудом не словила OOM в ядре ---
net.netfilter.nf_conntrack_tcp_timeout_established = 7440

# --- SYN flood (ядро) ---
net.ipv4.tcp_syncookies           = 1
net.ipv4.tcp_synack_retries       = 2
net.ipv4.tcp_syn_retries          = 2

# --- Anti-spoof / ICMP ---
# rp_filter=2 (loose): на VPN-нодах с host-network часто асимметричный роутинг,
# strict (1) рубит легитимные пакеты.
net.ipv4.conf.all.rp_filter                = 2
net.ipv4.conf.default.rp_filter            = 2
net.ipv4.conf.all.accept_source_route      = 0
net.ipv4.conf.default.accept_source_route  = 0
net.ipv4.conf.all.send_redirects           = 0
net.ipv4.conf.default.send_redirects       = 0
net.ipv4.conf.all.accept_redirects         = 0
net.ipv4.conf.default.accept_redirects     = 0
net.ipv4.conf.all.secure_redirects         = 0
net.ipv4.icmp_echo_ignore_broadcasts       = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv6.conf.all.accept_redirects         = 0
net.ipv6.conf.all.accept_source_route      = 0

# --- Память ---
vm.swappiness                = 10
vm.dirty_ratio               = 10
vm.dirty_background_ratio    = 5
vm.overcommit_memory         = 1
vm.max_map_count             = 262144

# --- Файловые дескрипторы ---
fs.file-max                   = 2097152
fs.nr_open                    = 2097152
fs.inotify.max_user_watches   = 524288
fs.inotify.max_user_instances = 8192
SYSCTL

# Ёмкость conntrack под RAM ноды: ~320 B на запись, держим таблицу ≤ ~1/8 RAM, чтобы
# под флудом мелкая VPS не упёрлась в OOM ядра. Потолок 2M, пол 262144 (как было).
_mem_kb="$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo 1048576)"
CT_MAX=$(( _mem_kb * 1024 / 8 / 320 ))
[[ "$CT_MAX" -gt 2000000 ]] && CT_MAX=2000000
[[ "$CT_MAX" -lt 262144  ]] && CT_MAX=262144
CT_BUCKETS=$(( CT_MAX / 4 ))
cat > /etc/sysctl.d/99-node-accelerator-conntrack.conf <<CT
# node-accelerator: ёмкость conntrack под RAM этой ноды (~$(( _mem_kb / 1024 )) MB)
net.netfilter.nf_conntrack_max     = $CT_MAX
net.netfilter.nf_conntrack_buckets = $CT_BUCKETS
CT
info "conntrack: max=$CT_MAX buckets=$CT_BUCKETS (под ~$(( _mem_kb / 1024 )) MB RAM)"

modprobe tcp_bbr 2>/dev/null || true
modprobe nf_conntrack 2>/dev/null || true
echo "tcp_bbr"      > /etc/modules-load.d/na-bbr.conf
echo "nf_conntrack" > /etc/modules-load.d/na-conntrack.conf
sysctl --system >/dev/null 2>&1 || true

if sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -qx bbr; then
    ok "BBR активен (под XanMod это BBRv3)"
else
    warn "BBR пока не активен — модуль/ядро подхватятся после reboot"
fi

# ─── 4. Лимиты ───────────────────────────────────────────────────────────────
title "Лимиты nofile/nproc"
backup_file /etc/security/limits.conf "$BACKUP"
sed -i '/# === node-accelerator ===/,/# === \/node-accelerator ===/d' /etc/security/limits.conf
cat >> /etc/security/limits.conf <<'LIMITS'
# === node-accelerator ===
*       soft    nofile  1048576
*       hard    nofile  1048576
*       soft    nproc   1048576
*       hard    nproc   1048576
root    soft    nofile  1048576
root    hard    nofile  1048576
# === /node-accelerator ===
LIMITS

mkdir -p /etc/systemd/system.conf.d /etc/systemd/user.conf.d
cat > /etc/systemd/system.conf.d/na-limits.conf <<'L'
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=1048576
L
cp /etc/systemd/system.conf.d/na-limits.conf /etc/systemd/user.conf.d/na-limits.conf

for pam in common-session common-session-noninteractive; do
    f="/etc/pam.d/$pam"
    [[ -f "$f" ]] && ! grep -q '^session.*pam_limits.so' "$f" && echo "session required pam_limits.so" >> "$f"
done
ok "nofile/nproc → 1048576 (shell-сессии подхватят после перелогина)"

# ─── 5. RPS/RFS/XPS — раскидываем softirq по ядрам ───────────────────────────
title "RPS/RFS/XPS (масштабирование приёма пакетов по ядрам)"
cat > /usr/local/sbin/na-rps-setup <<'RPS'
#!/usr/bin/env bash
# Включает Receive/Transmit Packet Steering на основном интерфейсе.
# На virtio/single-queue VPS весь RX-softirq иначе висит на cpu0 — это потолок PPS.
set -e
NIC="${1:-$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')}"
[ -z "$NIC" ] && exit 0
ncpu="$(nproc)"
# Битовая маска всех CPU в формате rps_cpus (группы по 32 бита, старшая первой).
mask="$(awk -v n="$ncpu" 'BEGIN{
    s=""; while(n>0){ b=(n>=32?32:n); n-=32;
        v=(b>=32?4294967295:(2^b)-1);
        s=(s==""?sprintf("%x",v):sprintf("%x,%s",v,s)); } print (s==""?"0":s) }')"
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true
for q in /sys/class/net/"$NIC"/queues/rx-*; do
    [ -e "$q/rps_cpus" ] && echo "$mask" > "$q/rps_cpus" 2>/dev/null || true
    [ -e "$q/rps_flow_cnt" ] && echo 4096 > "$q/rps_flow_cnt" 2>/dev/null || true
done
for q in /sys/class/net/"$NIC"/queues/tx-*; do
    [ -e "$q/xps_cpus" ] && echo "$mask" > "$q/xps_cpus" 2>/dev/null || true
done
echo "na-rps: NIC=$NIC mask=$mask cpus=$ncpu"
RPS
chmod +x /usr/local/sbin/na-rps-setup

cat > /etc/systemd/system/na-rps.service <<'EOF'
[Unit]
Description=node-accelerator RPS/RFS/XPS tuning
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/na-rps-setup

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now na-rps.service >/dev/null 2>&1 || true
ok "RPS/RFS/XPS включены ($(nproc) ядер)"

# ─── 6. NIC tuning ───────────────────────────────────────────────────────────
title "NIC tuning (ring buffer, offloads)"
NIC="$(default_iface || true)"
if [[ -n "${NIC:-}" ]]; then
    cat > /etc/systemd/system/na-nic-tune.service <<EOF
[Unit]
Description=node-accelerator NIC tuning ($NIC)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '\
    ethtool -G $NIC rx 4096 tx 4096 2>/dev/null || true; \
    ethtool -K $NIC gro on gso on tso on 2>/dev/null || true; \
    ip link set $NIC txqueuelen 10000 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now na-nic-tune.service >/dev/null 2>&1 || true
    ok "NIC=$NIC: ring 4096, GRO/GSO/TSO on, txqueuelen 10000"
else
    warn "Основной интерфейс не определён — NIC tuning пропущен"
fi

# ─── 7. Swap ─────────────────────────────────────────────────────────────────
title "Swap"
if [[ ! -f /swapfile ]] && ! swapon --show | grep -q .; then
    SWAP_SIZE="${REMNAWAVE_SWAP_SIZE:-2G}"
    fallocate -l "$SWAP_SIZE" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    ok "Создан /swapfile $SWAP_SIZE"
else
    info "Swap уже есть — пропускаю"
fi

# ─── 8. journald cap ─────────────────────────────────────────────────────────
title "journald (ограничение логов)"
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/na-size.conf <<'J'
[Journal]
SystemMaxUse=300M
SystemKeepFree=500M
SystemMaxFileSize=50M
Compress=yes
J
systemctl restart systemd-journald
ok "journald ≤ 300M"

# ─── 9. THP off ──────────────────────────────────────────────────────────────
title "Transparent Huge Pages → never"
cat > /etc/systemd/system/na-thp-off.service <<'EOF'
[Unit]
Description=node-accelerator disable THP
After=multi-user.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true; echo never > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now na-thp-off.service >/dev/null 2>&1 || true
ok "THP отключён"

# ─── 10. CPU governor ────────────────────────────────────────────────────────
title "CPU governor → performance"
if [[ -d /sys/devices/system/cpu/cpu0/cpufreq ]]; then
    cat > /etc/systemd/system/na-cpu-perf.service <<'EOF'
[Unit]
Description=node-accelerator CPU governor performance
After=multi-user.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'for c in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$c" 2>/dev/null || true; done'

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now na-cpu-perf.service >/dev/null 2>&1 || true
    ok "governor → performance"
else
    info "cpufreq недоступен (обычная VPS) — пропуск"
fi

# ─── 11. irqbalance ──────────────────────────────────────────────────────────
title "irqbalance"
systemctl enable --now irqbalance >/dev/null 2>&1 || true
ok "irqbalance запущен"

# ─── 12. Маркер ──────────────────────────────────────────────────────────────
mkdir -p "$STATE_DIR"
cat > "$STATE_DIR/optimize.installed" <<EOF
installed_at=$(date -Is)
backup=$BACKUP
nic=${NIC:-none}
xanmod=$([[ -f "$STATE_DIR/xanmod.pkg" ]] && cat "$STATE_DIR/xanmod.pkg" || echo none)
reboot_needed=$REBOOT_NEEDED
EOF

title "ГОТОВО"
ok "Оптимизатор применён."
echo
printf "    %-32s %s\n" "congestion_control:" "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo n/a)"
printf "    %-32s %s\n" "default_qdisc:"      "$(sysctl -n net.core.default_qdisc 2>/dev/null || echo n/a)"
printf "    %-32s %s\n" "somaxconn:"          "$(sysctl -n net.core.somaxconn 2>/dev/null || echo n/a)"
printf "    %-32s %s\n" "nf_conntrack_max:"   "$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo n/a)"
printf "    %-32s %s\n" "file-max:"           "$(sysctl -n fs.file-max 2>/dev/null || echo n/a)"
echo
if [[ "$REBOOT_NEEDED" == "1" ]]; then
    warn "УСТАНОВЛЕНО НОВОЕ ЯДРО XanMod — нужна ПЕРЕЗАГРУЗКА (reboot), чтобы BBRv3 заработал."
    warn "После reboot проверь: uname -r  (должно содержать 'xanmod')."
fi
warn "Часть лимитов применится после перелогина/reboot (DefaultLimit* для systemd-сервисов)."
