#!/usr/bin/env bash
#
# optimize.sh — ⚡ Оптимизатор ноды.
#   • XanMod-ядро (BBRv3) — авто-выбор сборки по psABI, пропуск на контейнерах/ARM (с поддержкой Ubuntu 22)
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

require_root
detect_os

# ─── Очистка старых битых репозиториев ───────────────────────────────────────
# Удаляем файлы прошлых неудачных попыток установки, чтобы они не блокировали apt в начале скрипта
rm -f /etc/apt/sources.list.d/xanmod*.list

ENABLE_XANMOD="${ENABLE_XANMOD:-1}"
XANMOD_FLAVOR="${XANMOD_FLAVOR:-lts}"
BACKUP="$(backup_dir)"
REBOOT_NEEDED=0
info "Бэкап изменяемых файлов: $BACKUP"

# ─── Вспомогательные функции прогресс-бара ──────────────────────────────────
# Отрисовка графического прогресс-бара в реальном времени
draw_progress_bar() {
    local percent=$1
    local desc=$2
    local width=30
    local filled=$((percent * width / 100))
    local empty=$((width - filled))
    
    # Создаем заполненную часть шкалы (символ #)
    local filled_bar=""
    for ((i=0; i<filled; i++)); do filled_bar="${filled_bar}#"; done
    
    # Создаем пустую часть шкалы (символ -)
    local empty_bar=""
    for ((i=0; i<empty; i++)); do empty_bar="${empty_bar}-"; done
    
    # Обрезаем описание, чтобы шкала не съезжала на узких экранах
    local max_desc_len=35
    if [ ${#desc} -gt $max_desc_len ]; then
        desc="${desc:0:$((max_desc_len - 3))}..."
    fi
    
    # Печатаем прогресс-бар и очищаем остаток консольной строки (ANSI \033[K)
    printf "\r[*] [%s%s] %3d%% (%s)\033[K" "$filled_bar" "$empty_bar" "$percent" "$desc"
}

# ─── 1. Зависимости ──────────────────────────────────────────────────────────
title "Зависимости"
apt_install ca-certificates curl gnupg irqbalance ethtool
ok "ok"

# ─── 2. XanMod-ядро (BBRv3) ──────────────────────────────────────────────────
title "XanMod-ядро (BBRv3)"
install_xanmod() {
    local codename keyring=/etc/apt/keyrings/xanmod-archive-keyring.gpg
    local list=/etc/apt/sources.list.d/xanmod-release.list
    codename="$(os_codename)"
    local is_jammy=false

    # Если мы на Ubuntu 22.04 (jammy), используем совместимый репозиторий 'bookworm' и только LTS-версию ядра
    if [[ "$codename" == "jammy" ]]; then
        info "Обнаружена Ubuntu 22.04 (jammy). Подменяем репозиторий на 'bookworm' и переводим сборку в режим LTS..."
        codename="bookworm"
        XANMOD_FLAVOR="lts"
        is_jammy=true
    fi

    mkdir -p /etc/apt/keyrings
    
    # --- ДВУХКАНАЛЬНЫЙ ИМПОРТ КЛЮЧА ---
    # 1. Сначала пробуем скачать ключ напрямую с официального сайта XanMod
    if ! curl -fsSL https://dl.xanmod.org/archive.key | gpg --yes --dearmor -o "$keyring" 2>/dev/null; then
        warn "Прямая ссылка dl.xanmod.org заблокирована Cloudflare (стандартно для Hetzner/GCP). Пробую резервный Keyserver..."
        
        # 2. Если прямой запрос заблокирован, скачиваем ключ с официального Ubuntu Keyserver по сигнатуре 86F7D09EE734E623
        if ! curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x86F7D09EE734E623" | gpg --yes --dearmor -o "$keyring" 2>/dev/null; then
            warn "Резервный Keyserver также недоступен. Пропускаю установку ядра"; return 1
        else
            ok "Ключ XanMod успешно импортирован через резервный Keyserver!"
        fi
    fi
    chmod 0644 "$keyring"

    # Сначала пробуем по codename (новый формат репо), при неудаче — releases (старый).
    echo "deb [signed-by=$keyring] http://deb.xanmod.org ${codename:-releases} main" > "$list"
    if ! apt-get update -qq 2>/dev/null; then
        if [[ "$is_jammy" == "true" ]]; then
            warn "Репозиторий bookworm не поднялся"
            return 1
        else
            warn "Репозиторий по '$codename' не поднялся, пробую 'releases'"
            echo "deb [signed-by=$keyring] http://deb.xanmod.org releases main" > "$list"
            apt-get update -qq 2>/dev/null || { warn "XanMod-репо недоступен"; return 1; }
        fi
    fi

    # Выбор сборки: явный XANMOD_PKG > по psABI-уровню. Деградация v3→v2→v1.
    local lvl pkg flv="$XANMOD_FLAVOR" pref=""
    [[ "$flv" == "lts" ]] && pref="lts-"
    [[ "$flv" == "main" ]] && pref=""
    [[ "$flv" == "edge" ]] && pref="edge-"
    [[ "$flv" == "rt"  ]] && pref="rt-"
    
    # Пытаемся получить уровень процессора. Если функция из lib/common.sh пуста/ошибочна, используем awk-тест
    lvl="$(cpu_psabi_level 2>/dev/null || echo "")"
    if [[ -z "$lvl" || ! "$lvl" =~ ^[1-4]$ ]]; then
        lvl=$(curl -fsSL https://dl.xanmod.org/check_x86-64_psabi.sh | awk -f - 2>/dev/null | grep -oP 'x86-64-v\K\d' || echo "2")
    fi
    info "psABI уровень CPU: x86-64-v$lvl, сборка: ${flv}"

    local candidates=()
    if [[ -n "${XANMOD_PKG:-}" ]]; then
        candidates=("$XANMOD_PKG")
    else
        case "$lvl" in
            4|3) candidates=("linux-xanmod-${pref}x64v3" "linux-xanmod-${pref}x64v2" "linux-xanmod-lts-x64v2");;
            2)   candidates=("linux-xanmod-${pref}x64v2" "linux-xanmod-lts-x64v2");;
            *)   candidates=("linux-xanmod-lts-x64v1");;
        esac
    fi

    local p
    for p in "${candidates[@]}"; do
        if apt-cache show "$p" >/dev/null 2>&1; then
            info "Ставлю $p (это надолго — компилит initramfs)..."
            
            local err_log
            err_log=$(mktemp)
            
            tput civis 2>/dev/null || true  # Временно скрываем курсор
            
            # Используем stdbuf -oL для отключения буферизации вывода в pipe,
            # и выводим статус-лог прямо в stdout (FD 1). Лишний текстовый вывод отсекается в цикле.
            if ! DEBIAN_FRONTEND=noninteractive stdbuf -oL apt-get -o APT::Status-Fd=1 install -y "$p" 2>"$err_log" | while IFS=: read -r f1 f2 f3 f4 rest; do
                case "$f1" in
                    pmstatus|dlstatus)
                        percent_raw="$f3"
                        desc_raw="$f4"
                        
                        # Если в f3 нет числа, пробуем взять его из f2 (защита от плавающего формата)
                        if [[ ! "$percent_raw" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                            if [[ "$f2" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                                percent_raw="$f2"
                                desc_raw="$f3"
                            else
                                continue
                            fi
                        fi
                        
                        # Превращаем float во integer (например, 14.2500 -> 14)
                        percent="${percent_raw%%.*}"
                        
                        # Финальная валидация и отрисовка
                        if [[ "$percent" =~ ^[0-9]+$ ]]; then
                            [[ $percent -gt 100 ]] && percent=100
                            
                            action_prefix=""
                            if [[ "$f1" == "dlstatus" ]]; then
                                action_prefix="Загрузка: "
                            else
                                action_prefix="Установка: "
                            fi
                            
                            draw_progress_bar "$percent" "${action_prefix}${desc_raw}"
                        fi
                        ;;
                esac
            done; then
                # Если произошла ошибка при установке ядра
                printf "\r\033[K"  # Стираем строку прогресса
                tput cnorm 2>/dev/null || true # Возвращаем курсор
                warn "Ошибка при установке пакета $p:"
                cat "$err_log" >&2
                rm -f "$err_log"
                return 1
            fi
            
            # Успешное завершение установки
            printf "\r\033[K"  # Стираем строку прогресса
            tput cnorm 2>/dev/null || true # Возвращаем курсор
            rm -f "$err_log"
            pkg="$p"
            break
        fi
    done
    [[ -z "${pkg:-}" ]] && { warn "Ни одна сборка XanMod не поставилась"; return 1; }

    echo "$pkg" > "$STATE_DIR/xanmod.pkg" 2>/dev/null || { mkdir -p "$STATE_DIR"; echo "$pkg" > "$STATE_DIR/xanmod.pkg"; }
    update-grub >/dev/null 2>&1 || true
    ok "XanMod установлен: $pkg (активируется ПОСЛЕ перезагрузки)"
    REBOOT_NEEDED=1
    return 0
}

if [[ "$ENABLE_XANMOD" == "1" ]]; then
    if ! can_install_kernel; then
        if is_container; then
            warn "Виртуализация: $(detect_virt) — это контейнер, делит ядро хоста."
            warn "XanMod поставить нельзя. BBR возьмётся из стокового ядра (если поддерживается)."
        else
            warn "Архитектура $(arch) — XanMod только под x86_64. Пропускаю ядро."
        fi
    elif uname -r | grep -q xanmod; then
        ok "XanMod уже стоит ($(uname -r)) — пропускаю установку"
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

# --- Conntrack: тысячи одновременных соединений ---
net.netfilter.nf_conntrack_max                     = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 7440
net.netfilter.nf_conntrack_buckets                 = 500000

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
