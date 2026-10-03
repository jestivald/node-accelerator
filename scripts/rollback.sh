#!/usr/bin/env bash
#
# rollback.sh — откат optimize / protect.
# Бэкапы оригиналов остаются в /var/backups/node-accelerator/.
#
# ENV:
#   NA_REMOVE_XANMOD=1   попытаться удалить пакет XanMod (только если сейчас грузимся НЕ с него)
#   NA_PURGE_CROWDSEC=1  удалить CrowdSec и bouncer (по умолчанию оставляем — это отдельный IPS)

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

require_root
WHAT="${1:-all}"

rollback_optimize() {
    title "Откат: ⚡ optimize"
    rm -f /etc/sysctl.d/99-node-accelerator.conf /etc/sysctl.d/99-node-accelerator-conntrack.conf
    rm -f /etc/modules-load.d/na-bbr.conf /etc/modules-load.d/na-conntrack.conf
    rm -f /etc/systemd/system.conf.d/na-limits.conf /etc/systemd/user.conf.d/na-limits.conf
    # journald: имя drop-in'а до v4.2 — na-size.conf, с v4.2 — 10-na-size.conf
    rm -f /etc/systemd/journald.conf.d/10-na-size.conf /etc/systemd/journald.conf.d/na-size.conf
    sed -i '/# === node-accelerator ===/,/# === \/node-accelerator ===/d' /etc/security/limits.conf 2>/dev/null || true

    # pam_limits: строку дописывал optimize (её нет в стоке Debian/Ubuntu common-session)
    for pam in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
        [[ -f "$pam" ]] || continue
        sed -i '/^session required pam_limits.so$/d' "$pam" 2>/dev/null || true
    done

    for svc in na-rps na-nic-tune na-cpu-perf na-thp-off na-zram na-mss-clamp; do
        systemctl disable --now "$svc.service" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/$svc.service"
    done
    rm -f /usr/local/sbin/na-rps-setup /usr/local/sbin/na-zram-setup

    # Ротация логов: свой таймер и своя станса. Уже сжатые/повёрнутые файлы не трогаем —
    # это данные оператора, а не наш артефакт.
    systemctl disable --now na-logrotate.timer   >/dev/null 2>&1 || true
    systemctl disable --now na-logrotate.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/na-logrotate.timer /etc/systemd/system/na-logrotate.service
    rm -f /etc/logrotate.d/na-node-logs

    # /swapfile снимаем ТОЛЬКО если его создали мы (метка swapfile.created) — чужой swap
    # трогать нельзя, а снятие живого swap'а на нагруженной ноде это прямой путь к OOM.
    if [[ -f "$STATE_DIR/swapfile.created" ]]; then
        if swapoff /swapfile 2>/dev/null; then
            rm -f /swapfile
            sed -i '\#^/swapfile[[:space:]]#d' /etc/fstab 2>/dev/null || true
            rm -f "$STATE_DIR/swapfile.created"
            ok "/swapfile снят и удалён (запись из fstab убрана)"
        else
            warn "/swapfile занят — не снял. Вручную: swapoff /swapfile && rm -f /swapfile (и строка в /etc/fstab)"
        fi
    fi
    # MSS-clamp: снять свою таблицу
    nft delete table inet na_mss 2>/dev/null || true
    rm -f "$CONF_DIR/na_mss.nft"

    systemctl daemon-reload

    # ── Runtime без ребута ───────────────────────────────────────────────────
    # Удалить файлы мало: `sysctl --system` вернёт только ключи, которые задаёт другой
    # файл, а остальные держат наши значения до перезагрузки; маски очередей и THP тоже.
    # Возвращаем то, что было ДО первого применения (снимки optimize v4.2+), затем
    # `sysctl --system` — чужие файлы по-прежнему главнее снимка.
    local rt="" n line k v p
    if [[ -s "$STATE_DIR/sysctl.orig" ]]; then
        n=0
        while IFS= read -r line; do
            k="${line%%$'\t'*}"; v="${line#*$'\t'}"
            [[ "$k" =~ ^[a-z0-9_.-]+$ ]] || continue
            # Форвардинг НЕ возвращаем: снимок снят до Docker (штатный порядок раскатки), там
            # 0, а `conf.all.forwarding=0` выключил бы его на всех интерфейсах — bridge-
            # контейнеры (Caddy панели, второй тенант) потеряли бы сеть до рестарта Docker.
            case "$k" in
                net.ipv4.ip_forward|net.ipv4.conf.*.forwarding|net.ipv6.conf.*.forwarding) continue ;;
            esac
            # потолок conntrack ниже текущего числа записей — «table full», дроп новых соединений
            if [[ "$k" == net.netfilter.nf_conntrack_max && "$v" =~ ^[0-9]+$ ]]; then
                local cnt; cnt="$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)"
                [[ "$cnt" =~ ^[0-9]+$ ]] && (( v < cnt * 2 )) && v=$(( cnt * 2 ))
            fi
            p="/proc/sys/${k//.//}"
            [[ -w "$p" ]] || continue
            printf '%s\n' "$v" > "$p" 2>/dev/null && n=$((n+1))
        done < "$STATE_DIR/sysctl.orig"
        rt+="sysctl — $n ключ(ей) возвращены к значениям до первого прогона; "
    else
        rt+="sysctl — снимка нет (optimize ставился до v4.2): ключи, которых не задаёт другой файл, держат наши значения до ребута; "
    fi
    sysctl --system >/dev/null 2>&1 || true
    systemctl restart systemd-journald 2>/dev/null || true

    if [[ -s "$STATE_DIR/rps-orig.tsv" ]]; then
        while IFS=$'\t' read -r p v; do
            [[ "$p" == /sys/class/net/*/queues/* && -e "$p" ]] || continue
            printf '%s\n' "$v" > "$p" 2>/dev/null || true
        done < "$STATE_DIR/rps-orig.tsv"
        rt+="маски RPS/XPS — из снимка; "
    else
        # RPS включал тулкит, дефолт ядра — 0; раскладку XPS драйвер восстановит на ребуте
        local nic; nic="$(awk -F= '/^nic=/{print $2; exit}' "$STATE_DIR/optimize.installed" 2>/dev/null)"
        if [[ -n "$nic" && "$nic" != none && -d "/sys/class/net/$nic" ]]; then
            for p in /sys/class/net/"$nic"/queues/rx-*/rps_cpus; do
                [[ -e "$p" ]] && { printf '0\n' > "$p" 2>/dev/null || true; }
            done
        fi
        rt+="RPS выключен (снимка масок нет), XPS — к раскладке драйвера после ребута; "
    fi
    if [[ -s "$STATE_DIR/thp.orig" ]]; then
        while IFS=$'\t' read -r k v; do
            [[ "$k" == enabled || "$k" == defrag ]] || continue
            printf '%s\n' "$v" > "/sys/kernel/mm/transparent_hugepage/$k" 2>/dev/null || true
        done < "$STATE_DIR/thp.orig"
        rt+="THP — из снимка; "
    else
        rt+="THP — never до ребута (снимка нет); "
    fi
    if [[ -f "$STATE_DIR/journald.persistent" ]]; then
        info "журнал остаётся постоянным: /var/log/journal создал optimize, в нём история (удалить: rm -rf /var/log/journal — история пропадёт)"
    fi
    rm -f "$STATE_DIR/sysctl.orig" "$STATE_DIR/rps-orig.tsv" "$STATE_DIR/thp.orig" \
          "$STATE_DIR/reserved-ports.na" "$STATE_DIR/journald.persistent"

    # psi=1 в GRUB_CMDLINE_LINUX_DEFAULT снимаем ТОЛЬКО если дописывали его МЫ: ровно
    # в этом случае в маркере есть строка psi=1. Оператор мог включить учёт давления
    # сам (или он приехал из образа хостера) — чужой параметр загрузки не наш артефакт.
    if [[ -f /etc/default/grub ]] \
       && grep -qx 'psi=1' "$STATE_DIR/optimize.installed" 2>/dev/null \
       && grep -qE '^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=.*psi=1' /etc/default/grub; then
        # Правим ТОЛЬКО строку GRUB_CMDLINE_LINUX_DEFAULT: остальной cmdline (и чужие
        # psi= в других переменных) не наше дело. Хвостовые пробелы подчищаем, иначе
        # ре-ран optimize увидит «не в ожидаемом виде».
        sed -i -E '/^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=/{
            s/psi=1//g
            s/="[[:space:]]+/="/
            s/[[:space:]]+"[[:space:]]*$/"/
            s/[[:space:]][[:space:]]+/ /g
        }' /etc/default/grub 2>/dev/null || warn "не смог убрать psi=1 из /etc/default/grub — проверь вручную"
        update-grub >/dev/null 2>&1 || true
        info "psi=1 убран из GRUB_CMDLINE_LINUX_DEFAULT (/proc/pressure исчезнет после reboot)"
    fi

    # XanMod-ядро: удаляем ТОЛЬКО если сейчас работаем не на нём (иначе оставим как есть)
    if [[ -f "$STATE_DIR/xanmod.pkg" ]]; then
        local pkg; pkg="$(cat "$STATE_DIR/xanmod.pkg")"
        if [[ "${NA_REMOVE_XANMOD:-0}" == "1" ]] && [[ "$(uname -r)" != *xanmod* ]]; then
            info "Удаляю XanMod-пакет $pkg ..."
            DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "$pkg" >/dev/null 2>&1 || warn "не удалил $pkg"
            update-grub >/dev/null 2>&1 || true
            # репозиторий и ключ больше не нужны — чистим, чтобы apt не ругался на suite
            rm -f /etc/apt/sources.list.d/xanmod*.list /etc/apt/keyrings/xanmod-archive-keyring.gpg
            apt-get update -qq 2>/dev/null || true
        else
            warn "XanMod ($pkg) оставлен. Сейчас грузимся: $(uname -r)."
            warn "Чтобы убрать: загрузись со стокового ядра и запусти NA_REMOVE_XANMOD=1 rollback optimize."
        fi
    fi
    rm -f "$STATE_DIR/optimize.installed" "$CONF_DIR/optimize.conf"
    ok "optimize откатан. Runtime: ${rt%; }. Лимиты nofile для сервисов — после ребута; XanMod — по флагу"
}

rollback_protect() {
    title "Откат: 🛡 protect"
    systemctl stop na-fw-safety.timer 2>/dev/null || true
    [[ -f "$STATE_DIR/na-fw-safety.pid" ]] && { kill "$(cat "$STATE_DIR/na-fw-safety.pid")" 2>/dev/null || true; }
    [[ -f /tmp/na-fw-safety.pid ]] && { kill "$(cat /tmp/na-fw-safety.pid)" 2>/dev/null || true; }
    rm -f "$STATE_DIR/na-fw-safety.pid" "$STATE_DIR/na-fw-safety.log" /tmp/na-fw-safety.pid /tmp/na-fw-safety.log 2>/dev/null || true

    # v3.0 модули: fleet-sync / blocklists / ctguard — снимаем таймеры/сервисы
    for unit in na-firewall na-fleet-sync na-blocklist na-ctguard; do
        systemctl disable --now "$unit.service" >/dev/null 2>&1 || true
        systemctl disable --now "$unit.timer"   >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/$unit.service" "/etc/systemd/system/$unit.timer"
    done
    systemctl daemon-reload

    # удаляем ТОЛЬКО свои таблицы — CrowdSec/Docker не трогаем
    nft delete table inet na_filter  2>/dev/null || true
    nft delete table inet na_ctguard 2>/dev/null || true
    # + отвергнутый ruleset и недописанные кандидаты (protect v4.1.3+ генерирует рядом и
    # переименовывает в na_filter.nft только после успешного nft -f)
    rm -f "$CONF_DIR/na_filter.nft" "$CONF_DIR/na_filter.nft.rejected" "$CONF_DIR"/.na_filter.nft.*
    rm -f /usr/local/sbin/na-fw-status /usr/local/sbin/na-fw-top-talkers /usr/local/sbin/na-fw \
          /usr/local/sbin/na-fleet-sync /usr/local/sbin/na-blocklist-update /usr/local/sbin/na-ctguard \
          /usr/local/sbin/na-fw-safety-revert
    rm -f "$STATE_DIR"/.bans.* 2>/dev/null || true
    [[ -d "$CONF_DIR/na_filter.d" ]] && info "оставлен $CONF_DIR/na_filter.d (локальные правила оператора)"
    # SYNPROXY: свой sysctl снимаем и возвращаем дефолт ядра
    if [[ -f /etc/sysctl.d/99-na-synproxy.conf ]]; then
        rm -f /etc/sysctl.d/99-na-synproxy.conf
        sysctl -q -w net.netfilter.nf_conntrack_tcp_loose=1 2>/dev/null || true
    fi
    # CROWDSEC_SCOPE=ssh: наш юнит/правила снимаем. Порядок как в protect: bouncer в set-only
    # таблицу на остановке не трогает — stop → режим/таблицы → start. Если protect выключал
    # ручной crowdsec-nft-scope.service оператора (флаг) — возвращаем его вместе с set-only:
    # откат не должен снова включить community-лист на всех портах, который оператор сузил сам.
    if [[ -f /etc/systemd/system/na-crowdsec-scope.service ]]; then
        local _by=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml _legacy=crowdsec-nft-scope.service
        systemctl stop crowdsec-firewall-bouncer >/dev/null 2>&1 || true
        systemctl disable na-crowdsec-scope.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/na-crowdsec-scope.service "$CONF_DIR/na-crowdsec-scope.nft"
        systemctl daemon-reload 2>/dev/null || true
        if [[ -f "$STATE_DIR/crowdsec-legacy-scope.disabled" ]] && systemctl cat "$_legacy" >/dev/null 2>&1; then
            systemctl enable "$_legacy" >/dev/null 2>&1 || true
            systemctl restart "$_legacy" >/dev/null 2>&1 || true
            info "CrowdSec scope: возвращён ручной $_legacy (как было до protect)"
        else
            if [[ -f "$_by" ]]; then
                sed -i.na-tmp -E 's/^([[:space:]]+set-only:)[[:space:]]*true[[:space:]]*$/\1 false/' "$_by" && rm -f "$_by.na-tmp"
            fi
            local _t
            for _t in "ip $(awk '/^nftables:/{n=1} n && $1=="ipv4:"{f=1} f && $1=="table:"{print $2; exit}' "$_by" 2>/dev/null)" \
                      "ip6 $(awk '/^nftables:/{n=1} n && $1=="ipv6:"{f=1} f && $1=="table:"{print $2; exit}' "$_by" 2>/dev/null)"; do
                [[ "$_t" == *" " ]] && continue
                nft delete table $_t 2>/dev/null || true
            done
            info "CrowdSec scope снят: bouncer снова ставит свои правила (на всех портах)"
        fi
        rm -f "$STATE_DIR/crowdsec-legacy-scope.disabled"
        systemctl start crowdsec-firewall-bouncer >/dev/null 2>&1 || true
    fi
    rm -f "$STATE_DIR/safety-fired.last" "$STATE_DIR/protect.lock"
    # nftables.service до v4.1.2 включал сам protect (boot-persist), но выключать не будем: он
    # лишь грузит /etc/nftables.conf, который тулкит никогда не писал — трогать чужой конфиг нельзя.
    systemctl is-enabled --quiet nftables 2>/dev/null && info "nftables.service оставлен включённым (грузит ваш /etc/nftables.conf, наших правил там нет)"
    rm -f /etc/modules-load.d/na-synproxy.conf "$STATE_DIR/.synproxy-degraded"
    # конфиги: persisted protect.conf, ctguard.conf, токен панели fleet.env (custom-blocklist.txt — данные оператора, оставляем)
    rm -f "$STATE_DIR/protect.installed" "$CONF_DIR/protect.conf" "$CONF_DIR/ctguard.conf" "$CONF_DIR/fleet.env"
    rm -f "$STATE_DIR/fleet-sync.last" "$STATE_DIR/blocklist.last"
    [[ -f "$CONF_DIR/custom-blocklist.txt" ]] && info "оставлен $CONF_DIR/custom-blocklist.txt (данные оператора)"
    ok "na_filter/na_ctguard удалены, сервисы и таймеры сняты"

    if [[ "${NA_PURGE_CROWDSEC:-0}" == "1" ]]; then
        warn "Удаляю CrowdSec и bouncer..."
        systemctl disable --now crowdsec-firewall-bouncer crowdsec >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq crowdsec-firewall-bouncer-nftables crowdsec >/dev/null 2>&1 || true
        nft delete table ip crowdsec 2>/dev/null || true
        nft delete table ip6 crowdsec6 2>/dev/null || true
        rm -f /etc/crowdsec/parsers/s02-enrich/na-whitelist.yaml /etc/crowdsec/acquis.d/na-sshd.yaml
        # пиннингованный APT-репо CrowdSec (создаёт setup_crowdsec_repo в protect.sh)
        rm -f /etc/apt/sources.list.d/crowdsec.list /etc/apt/keyrings/crowdsec-archive-keyring.gpg
        apt-get update -qq 2>/dev/null || true
        ok "CrowdSec удалён"
    else
        info "CrowdSec оставлен работать (NA_PURGE_CROWDSEC=1 чтобы удалить)."
        rm -f /etc/crowdsec/parsers/s02-enrich/na-whitelist.yaml /etc/crowdsec/acquis.d/na-sshd.yaml 2>/dev/null || true
        systemctl reload crowdsec >/dev/null 2>&1 || true
    fi
}

# CLI-обёртки (na-diagnose/na-report) и персист скриптов снимаем ТОЛЬКО когда не
# осталось ни одного установленного модуля — иначе частичный откат (напр. protect
# при живом optimize) убил бы команду, которая ещё нужна для мониторинга.
remove_cli_if_orphaned() {
    [[ -f "$STATE_DIR/optimize.installed" || -f "$STATE_DIR/protect.installed" ]] && return 0
    rm -f /usr/local/sbin/na-diagnose /usr/local/sbin/na-report
    rm -rf "$NA_LIB_DIR"
    ok "CLI na-diagnose/na-report сняты (модулей не осталось)"
}

case "$WHAT" in
    optimize) rollback_optimize ;;
    protect)  rollback_protect ;;
    all)      rollback_protect; rollback_optimize ;;
    *) err "Использование: $0 [optimize|protect|all]"; exit 1 ;;
esac
remove_cli_if_orphaned
ok "Бэкапы остаются в /var/backups/node-accelerator/"
