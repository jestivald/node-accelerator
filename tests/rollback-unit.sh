#!/usr/bin/env bash
#
# rollback-unit.sh — ИСПОЛНЯЕТ scripts/rollback.sh целиком в песочнице: системные пути
# (/etc, /usr/local, /var, /sys, /proc, /swapfile) подменяются sed'ом на каталог песочницы,
# systemctl/nft/sysctl/apt-get/... — стабы, пишущие журнал вызовов. Что стережём (v4.3):
#   1. после `rollback all` не остаётся наших артефактов: юниты/таймеры, хелперы, маркеры
#      и снимки состояния (в т.ч. logrotate.ceded / logrotate.owned), а чужое — на месте;
#   2. таймеры снимаются раньше сервисов и раньше удаления таблиц (иначе таймер успевает
#      перезапустить сервис, который вернёт правила/наборы в уже удаляемую таблицу);
#   3. повторный откат и откат на пустом хосте — rc 0 и ничего не ломают;
#   4. частичный откат (protect при живом optimize) не снимает CLI; после успешного
#      удаления XanMod метка xanmod.pkg снимается (иначе повторный откат врёт «оставлен»).
#
# Не требует root/сети/systemd. Запуск: bash tests/rollback-unit.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
S="$T/root"                # «корень» песочницы
BIN="$T/bin"; mkdir -p "$BIN" "$T/scripts/lib"
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

# sed: на BSD (macOS) у -i суффикс обязателен — заворачиваем `-i` в `-i ''`
REAL_SED="$(command -v sed)"
if "$REAL_SED" --version 2>/dev/null | grep -q GNU; then
    printf '#!/bin/sh\nexec %s "$@"\n' "$REAL_SED" > "$BIN/sed"
else
    cat > "$BIN/sed" <<SEDW
#!/usr/bin/env bash
args=()
for a in "\$@"; do
    if [ "\$a" = "-i" ]; then args+=( -i '' ); else args+=( "\$a" ); fi
done
exec "$REAL_SED" "\${args[@]}"
SEDW
fi

# стабы: каждый вызов — строка в $T/calls
for c in systemctl nft sysctl apt-get update-grub swapoff logger; do
    cat > "$BIN/$c" <<'STUB'
#!/bin/sh
echo "$(basename "$0") $*" >> "$NA_T/calls"
case "$(basename "$0"):$*" in
    "systemctl:is-enabled"*|"systemctl:cat"*|"swapoff:"*) exit 1 ;;
esac
exit 0
STUB
done
printf '#!/bin/sh\nif [ "$1" = -r ]; then echo "${NA_T_UNAME:-6.1.0-stock}"; else echo "${NA_T_UNAME:-6.1.0-stock}"; fi\n' > "$BIN/uname"
chmod +x "$BIN"/*
export PATH="$BIN:$PATH"

# ── Копия скриптов с подменой системных путей ──────────────────────────────────
sandbox() {   # двухшаговая подмена: $S сам лежит под /var/…, повторная подмена его бы испортила
    "$REAL_SED" -e 's#/etc/#@S@/etc/#g' -e 's#/usr/local/#@S@/usr/local/#g' \
                -e 's#/var/#@S@/var/#g' -e 's#/tmp/na-#@S@/tmp/na-#g' \
                -e 's#/swapfile#@S@/swapfile#g' -e 's#/sys/#@S@/sys/#g' -e 's#/proc/#@S@/proc/#g' \
        | "$REAL_SED" -e "s#@S@#$S#g"
}
sandbox < "$REPO_ROOT/scripts/lib/common.sh" \
    | "$REAL_SED" 's/-ne 0 /-lt 0 /' > "$T/scripts/lib/common.sh"
sandbox < "$REPO_ROOT/scripts/rollback.sh" > "$T/scripts/rollback.sh"
if [[ -n "${NA_DEBUG:-}" ]]; then cp "$T/scripts/rollback.sh" /tmp/rb-dbg.sh; fi
grep -q "$S/var/lib/node-accelerator" "$T/scripts/lib/common.sh" || { echo "[x] подмена STATE_DIR не сработала"; exit 1; }
STATE="$S/var/lib/node-accelerator"; CONF="$S/etc/node-accelerator"
RB() { rc=0; : > "$T/calls"; "$WBASH" "$T/scripts/rollback.sh" "$@" > "$T/out" 2>&1 < /dev/null || rc=$?; [[ -z "${NA_DEBUG:-}" ]] || cp "$T/out" /tmp/rb-out.txt; }

PASS=0; FAIL=0
check() { if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); echo "  ok   $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1: ожидалось [$2], получено [$3]"; fi; }
gone() { if [[ ! -e "$2" ]]; then PASS=$((PASS+1)); echo "  ok   $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1: остался $2"; fi; }
kept() { if [[ -e "$2" ]]; then PASS=$((PASS+1)); echo "  ok   $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1: пропал $2"; fi; }
line_of() { grep -nF -- "$1" "$T/calls" | head -n1 | cut -d: -f1; }

# ── «Полная установка» ─────────────────────────────────────────────────────────
install_all() {
    rm -rf "$S"
    mkdir -p "$S/etc/systemd/system" "$S/etc/systemd/system.conf.d" "$S/etc/systemd/user.conf.d" \
             "$S/etc/systemd/journald.conf.d" "$S/etc/sysctl.d" "$S/etc/modules-load.d" "$S/etc/logrotate.d" \
             "$S/etc/security" "$S/etc/pam.d" "$S/usr/local/sbin" "$S/usr/local/lib/node-accelerator/lib" \
             "$STATE" "$CONF/na_filter.d" "$S/tmp"
    local f u
    for f in 99-node-accelerator.conf 99-node-accelerator-conntrack.conf 99-na-synproxy.conf; do : > "$S/etc/sysctl.d/$f"; done
    for f in na-bbr.conf na-conntrack.conf na-synproxy.conf; do : > "$S/etc/modules-load.d/$f"; done
    : > "$S/etc/systemd/system.conf.d/na-limits.conf"; : > "$S/etc/systemd/user.conf.d/na-limits.conf"
    : > "$S/etc/systemd/journald.conf.d/10-na-size.conf"; : > "$S/etc/logrotate.d/na-node-logs"
    for u in na-rps na-nic-tune na-cpu-perf na-thp-off na-zram na-mss-clamp na-logrotate na-firewall na-fleet-sync na-blocklist na-ctguard; do
        : > "$S/etc/systemd/system/$u.service"
    done
    for u in na-logrotate na-fleet-sync na-blocklist na-ctguard; do : > "$S/etc/systemd/system/$u.timer"; done
    for f in na-rps-setup na-zram-setup na-fw-status na-fw-top-talkers na-fw na-fleet-sync na-blocklist-update \
             na-ctguard na-fw-safety-revert na-diagnose na-report; do : > "$S/usr/local/sbin/$f"; done
    : > "$S/usr/local/lib/node-accelerator/na-report.sh"
    : > "$CONF/na_filter.nft"; : > "$CONF/na_mss.nft"; : > "$CONF/optimize.conf"; : > "$CONF/protect.conf"
    : > "$CONF/ctguard.conf"; : > "$CONF/fleet.env"
    for f in optimize.installed protect.installed sysctl.orig rps-orig.tsv thp.orig reserved-ports.na journald.persistent \
             logrotate.ceded logrotate.owned na-fw-safety.pid safety-fired.last protect.lock fleet-sync.last blocklist.last; do
        : > "$STATE/$f"
    done
    printf 'nic=none\n' > "$STATE/optimize.installed"
    : > "$S/etc/fstab"
    printf '# stock\n* soft core 0\n# === node-accelerator ===\n* soft nofile 1048576\n# === /node-accelerator ===\n# tail\n' > "$S/etc/security/limits.conf"
    printf 'session required pam_unix.so\nsession required pam_limits.so\n' > "$S/etc/pam.d/common-session"
    # чужое — должно пережить откат
    echo "198.51.100.1" > "$CONF/custom-blocklist.txt"; : > "$CONF/na_filter.d/local.nft"
    : > "$S/etc/logrotate.d/nginx"; : > "$S/etc/sysctl.d/99-operator.conf"
}

echo "== 1. полный откат: артефакты сняты, чужое на месте =="
install_all
RB all
check "rc 0" 0 "$rc"
for f in etc/sysctl.d/99-node-accelerator.conf etc/sysctl.d/99-na-synproxy.conf etc/logrotate.d/na-node-logs \
         etc/systemd/system/na-zram.service etc/systemd/system/na-fleet-sync.timer etc/systemd/system/na-ctguard.timer \
         usr/local/sbin/na-fw usr/local/sbin/na-rps-setup usr/local/sbin/na-report usr/local/sbin/na-diagnose \
         usr/local/lib/node-accelerator etc/node-accelerator/na_filter.nft etc/node-accelerator/protect.conf \
         var/lib/node-accelerator/optimize.installed var/lib/node-accelerator/protect.installed; do
    gone "снято: $f" "$S/$f"
done
gone "снято: logrotate.ceded (снимок чужих станс)" "$STATE/logrotate.ceded"
gone "снято: logrotate.owned"                       "$STATE/logrotate.owned"
for f in na-fw-safety.pid safety-fired.last protect.lock fleet-sync.last blocklist.last sysctl.orig rps-orig.tsv thp.orig; do
    gone "снят маркер: $f" "$STATE/$f"
done
kept "оставлен custom-blocklist.txt"       "$CONF/custom-blocklist.txt"
kept "оставлен na_filter.d/local.nft"      "$CONF/na_filter.d/local.nft"
kept "оставлен чужой logrotate nginx"      "$S/etc/logrotate.d/nginx"
kept "оставлен чужой sysctl оператора"     "$S/etc/sysctl.d/99-operator.conf"
check "limits.conf: наш блок вырезан, остальное цело" "# stock|* soft core 0|# tail" "$(paste -sd'|' "$S/etc/security/limits.conf")"
check "pam: убран только pam_limits"        "session required pam_unix.so" "$(cat "$S/etc/pam.d/common-session")"

echo "== 2. порядок: таймеры раньше сервисов, всё — раньше удаления таблиц =="
t_safety="$(line_of 'stop na-fw-safety.timer')"; t_tab="$(line_of 'delete table inet na_filter')"
check "сейфти-таймер остановлен до удаления na_filter" yes "$([[ -n "$t_safety" && -n "$t_tab" && "$t_safety" -lt "$t_tab" ]] && echo yes || echo no)"
for u in na-fleet-sync na-blocklist na-ctguard; do
    a="$(line_of "disable --now $u.timer")"; b="$(line_of "disable --now $u.service")"
    check "$u: таймер снят раньше сервиса" yes "$([[ -n "$a" && -n "$b" && "$a" -lt "$b" ]] && echo yes || echo no)"
    check "$u: таймер снят до удаления таблиц" yes "$([[ -n "$a" && "$a" -lt "$t_tab" ]] && echo yes || echo no)"
done

echo "== 3. повторный откат и откат на пустом хосте =="
RB all
check "повторный откат: rc 0" 0 "$rc"
kept "повторный откат не тронул чужое" "$CONF/custom-blocklist.txt"
rm -rf "$S"; mkdir -p "$S/etc" "$S/var/lib"
for w in all optimize protect; do RB "$w"; check "пустой хост, $w: rc 0" 0 "$rc"; done
RB bogus; check "неизвестный режим: rc 1" 1 "$rc"

echo "== 4. частичный откат: protect при живом optimize =="
install_all
RB protect
check "rc 0" 0 "$rc"
kept "CLI na-diagnose остался (optimize жив)" "$S/usr/local/sbin/na-diagnose"
kept "маркер optimize.installed остался"      "$STATE/optimize.installed"
gone "маркер protect.installed снят"          "$STATE/protect.installed"

echo "== 5. XanMod: purge → метка снимается =="
install_all
echo "linux-xanmod-x64v3" > "$STATE/xanmod.pkg"
NA_REMOVE_XANMOD=1 RB optimize
grep -q 'apt-get purge.*linux-xanmod-x64v3' "$T/calls" && x=yes || x=no
check "apt-get purge вызван" yes "$x"
gone "xanmod.pkg снят после удаления пакета" "$STATE/xanmod.pkg"
install_all
echo "linux-xanmod-x64v3" > "$STATE/xanmod.pkg"
RB optimize
kept "без NA_REMOVE_XANMOD метка остаётся (удалить можно позже)" "$STATE/xanmod.pkg"
NA_T_UNAME=6.1.0-xanmod1 NA_REMOVE_XANMOD=1 RB optimize
kept "грузимся с XanMod — метка остаётся" "$STATE/xanmod.pkg"
grep -q 'apt-get purge' "$T/calls" && x=yes || x=no
check "с XanMod-ядра purge не зовётся" no "$x"

echo
echo "  прогон: $PASS ok, $FAIL fail"
if [[ "$FAIL" -ne 0 ]]; then echo "ROLLBACK-UNIT: FAIL"; exit 1; fi
echo "ROLLBACK-UNIT: OK (полнота, порядок, идемпотентность, чужое не тронуто)"
