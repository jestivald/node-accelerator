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
    rm -f /etc/systemd/journald.conf.d/na-size.conf
    sed -i '/# === node-accelerator ===/,/# === \/node-accelerator ===/d' /etc/security/limits.conf 2>/dev/null || true

    for svc in na-rps na-nic-tune na-cpu-perf na-thp-off na-zram na-mss-clamp; do
        systemctl disable --now "$svc.service" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/$svc.service"
    done
    rm -f /usr/local/sbin/na-rps-setup /usr/local/sbin/na-zram-setup
    # MSS-clamp: снять свою таблицу
    nft delete table inet na_mss 2>/dev/null || true
    rm -f "$CONF_DIR/na_mss.nft"

    systemctl daemon-reload
    sysctl --system >/dev/null 2>&1 || true
    systemctl restart systemd-journald 2>/dev/null || true

    # XanMod-ядро: удаляем ТОЛЬКО если сейчас работаем не на нём (иначе оставим как есть)
    if [[ -f "$STATE_DIR/xanmod.pkg" ]]; then
        local pkg; pkg="$(cat "$STATE_DIR/xanmod.pkg")"
        if [[ "${NA_REMOVE_XANMOD:-0}" == "1" ]] && ! uname -r | grep -qi xanmod; then
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
    ok "optimize откатан (значения sysctl вернутся к дефолтам; XanMod — по флагу)"
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
    rm -f "$CONF_DIR/na_filter.nft"
    rm -f /usr/local/sbin/na-fw-status /usr/local/sbin/na-fw-top-talkers \
          /usr/local/sbin/na-fleet-sync /usr/local/sbin/na-blocklist-update /usr/local/sbin/na-ctguard
    rm -f /etc/modules-load.d/na-synproxy.conf "$STATE_DIR/.synproxy-degraded"
    # конфиги: persisted protect.conf, ctguard.conf, токен панели fleet.env (custom-blocklist.txt — данные оператора, оставляем)
    rm -f "$STATE_DIR/protect.installed" "$CONF_DIR/protect.conf" "$CONF_DIR/ctguard.conf" "$CONF_DIR/fleet.env"
    [[ -f "$CONF_DIR/custom-blocklist.txt" ]] && info "оставлен $CONF_DIR/custom-blocklist.txt (данные оператора)"
    ok "na_filter/na_ctguard удалены, сервисы и таймеры сняты"

    if [[ "${NA_PURGE_CROWDSEC:-0}" == "1" ]]; then
        warn "Удаляю CrowdSec и bouncer..."
        systemctl disable --now crowdsec-firewall-bouncer crowdsec >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq crowdsec-firewall-bouncer-nftables crowdsec >/dev/null 2>&1 || true
        nft delete table ip crowdsec 2>/dev/null || true
        nft delete table ip6 crowdsec6 2>/dev/null || true
        rm -f /etc/crowdsec/parsers/s02-enrich/na-whitelist.yaml /etc/crowdsec/acquis.d/na-sshd.yaml
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
