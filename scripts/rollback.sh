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
    rm -f /etc/sysctl.d/99-node-accelerator.conf
    rm -f /etc/modules-load.d/na-bbr.conf /etc/modules-load.d/na-conntrack.conf
    rm -f /etc/systemd/system.conf.d/na-limits.conf /etc/systemd/user.conf.d/na-limits.conf
    rm -f /etc/systemd/journald.conf.d/na-size.conf
    sed -i '/# === node-accelerator ===/,/# === \/node-accelerator ===/d' /etc/security/limits.conf 2>/dev/null || true

    for svc in na-rps na-nic-tune na-cpu-perf na-thp-off; do
        systemctl disable --now "$svc.service" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/$svc.service"
    done
    rm -f /usr/local/sbin/na-rps-setup

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
            
            # НОВОЕ: Очищаем репозитории и GPG-ключи XanMod при полном удалении ядра
            info "Удаляю репозиторий и GPG-ключ XanMod из системы..."
            rm -f /etc/apt/sources.list.d/xanmod*.list
            rm -f /etc/apt/keyrings/xanmod-archive-keyring.gpg
            apt-get update -qq 2>/dev/null || true
        else
            warn "XanMod ($pkg) оставлен. Сейчас грузимся: $(uname -r)."
            warn "Чтобы убрать: загрузись со стокового ядра и запусти NA_REMOVE_XANMOD=1 rollback optimize."
        fi
    fi
    rm -f "$STATE_DIR/optimize.installed"
    ok "optimize откатан (значения sysctl вернутся к дефолтам; XanMod — по флагу)"
}

rollback_protect() {
    title "Откат: 🛡 protect"
    systemctl stop na-fw-safety.timer 2>/dev/null || true
    [[ -f /tmp/na-fw-safety.pid ]] && { kill "$(cat /tmp/na-fw-safety.pid)" 2>/dev/null || true; rm -f /tmp/na-fw-safety.pid; }

    systemctl disable --now na-firewall.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/na-firewall.service
    systemctl daemon-reload

    # удаляем ТОЛЬКО свою таблицу — CrowdSec/Docker не трогаем
    nft delete table inet na_filter 2>/dev/null || true
    rm -f "$CONF_DIR/na_filter.nft"
    rm -f /usr/local/sbin/na-fw-status
    rm -f "$STATE_DIR/protect.installed"
    ok "na_filter удалена, сервис снят"

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

case "$WHAT" in
    optimize) rollback_optimize ;;
    protect)  rollback_protect ;;
    all)      rollback_protect; rollback_optimize ;;
    *) err "Использование: $0 [optimize|protect|all]"; exit 1 ;;
esac
ok "Бэкапы остаются in /var/backups/node-accelerator/"
