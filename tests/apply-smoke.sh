#!/usr/bin/env bash
#
# apply-smoke.sh — гоняет ПОЛНЫЙ apply-path protect.sh (DRY_RUN=0) под `set -u`
# со стабами вместо реальных nft/systemctl/apt/curl и с перенаправлением системных
# путей в /tmp. Ловит класс багов, который НЕ виден ни в `bash -n`, ни в shellcheck,
# ни в DRY_RUN-смоуке: unbound-переменные (set -u) в ветках, исполняемых только при
# реальном применении (установка модулей fleet/blocklists/ctguard, маркер, save_conf).
# Пример пойманного: $LIVE_FLOOR вместо $NA_CTG_LIVE_FLOOR в ctguard-сообщении.
#
# Не требует root/nft/systemd — переносим (CI и локально). Запуск: bash tests/apply-smoke.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/sys" "$T/sbin" "$T/modload" "$T/conf" "$T/state" "$T/backup"
cp -r "$REPO_ROOT/scripts" "$T/scripts"

# Перенаправляем хардкод-системные пути на писабельные /tmp (portable sed: без -i).
P="$T/scripts/protect.sh"
sed -e "s#/etc/systemd/system/#$T/sys/#g" \
    -e "s#/usr/local/sbin/#$T/sbin/#g" \
    -e "s#/etc/modules-load.d/#$T/modload/#g" \
    "$P" > "$P.tmp" && mv "$P.tmp" "$P"

# Стаб-бинари (no-op) в PATH.
for c in systemctl modprobe nft systemd-run sysctl ss conntrack; do
    printf '#!/bin/sh\nexit 0\n' > "$T/bin/$c"; chmod +x "$T/bin/$c"
done
# curl падает → сетевые fetch (crowdsec/blocklist/fleet) деградируют мягко, не висят.
printf '#!/bin/sh\nexit 1\n' > "$T/bin/curl"; chmod +x "$T/bin/curl"
# cscli намеренно НЕ стабим → CrowdSec-тело пропускается (его хардкод-пути не трогаем).

# Глушим root/os/iface-детекты и переносим CONF_DIR/STATE_DIR.
cat >> "$T/scripts/lib/common.sh" <<STUB
require_root(){ :; }
detect_os(){ OS_ID=debian; OS_VER=12; OS_CODENAME=bookworm; }
default_iface(){ echo eth0; }
detect_ssh_port(){ echo 22; }
ssh_client_ip(){ echo "203.0.113.9"; }
apt_install(){ :; }
backup_dir(){ echo "$T/backup"; }
CONF_DIR="$T/conf"
STATE_DIR="$T/state"
STUB

export PATH="$T/bin:$PATH"
LOG="$T/apply.log"

# Полный apply со ВСЕМИ v3.0-модулями включёнными (CrowdSec off — его пути хардкод).
set +e
ENABLE_BLOCKLISTS=1 BLOCK_TOR=1 ENABLE_BANONCE=1 ENABLE_CTGUARD=1 NA_CTG_ENFORCE=0 \
  FLEET_SYNC=1 REMNAWAVE_URL=https://panel.example.com REMNAWAVE_TOKEN=tok \
  WHITELIST="1.2.3.4,2001:db8::1" NODE_PORT_WHITELIST_ONLY=1 ENABLE_CROWDSEC=0 \
  ENABLE_SYNPROXY=1 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 \
  bash "$T/scripts/protect.sh" >"$LOG" 2>&1
rc=$?
set -e

fail=0
if [ "$rc" -ne 0 ]; then echo "[x] apply упал (exit $rc)"; fail=1; fi
if grep -qiE 'unbound variable|bad substitution' "$LOG"; then echo "[x] найдена unbound-переменная:"; grep -iE 'unbound variable|bad substitution' "$LOG"; fail=1; fi
# ключевые блоки должны были отработать
for marker in 'fleet-sync включён' 'блоклисты включены' 'ctguard в OBSERVE' 'Готово'; do
    grep -qF "$marker" "$LOG" || { echo "[x] не достигнут блок: '$marker'"; fail=1; }
done
# артефакты на месте
for f in conf/protect.conf conf/ctguard.conf conf/fleet.env sbin/na-fleet-sync sbin/na-blocklist-update sbin/na-ctguard; do
    [ -e "$T/$f" ] || { echo "[x] не создан артефакт: $f"; fail=1; }
done
# strict (дефолт): policy drop, анти-скан и node-port правила на месте, fw_mode в маркере
NFTF="$T/conf/na_filter.nft"
grep -q 'hook input priority filter; policy drop;' "$NFTF" || { echo "[x] strict: нет policy drop на input"; fail=1; }
grep -q 'ANTI-SCAN' "$NFTF" || { echo "[x] strict: нет анти-скан правил"; fail=1; }
grep -q 'dport 2222' "$NFTF" || { echo "[x] strict: нет node-port правил"; fail=1; }
grep -q '^fw_mode=strict$' "$T/state/protect.installed" || { echo "[x] strict: fw_mode=strict не в маркере"; fail=1; }
grep -qE 'meter (osyn|occ|oudp)' "$NFTF" && { echo "[x] strict: generic open-лимитеры не должны ставиться (ruleset должен быть идентичен прежнему)"; fail=1; }

# Сброс окружения между прогонами режимов
reset_t() {
    rm -rf "$T/sys" "$T/sbin" "$T/modload" "$T/conf" "$T/state"
    mkdir -p "$T/sys" "$T/sbin" "$T/modload" "$T/conf" "$T/state"
}

# ── FW_MODE=open: policy accept, без анти-скана/node-port, остальная защита на месте ──
reset_t
LOG2="$T/apply-open.log"
set +e
FW_MODE=open ENABLE_BANONCE=1 ENABLE_CROWDSEC=0 \
  REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 \
  bash "$T/scripts/protect.sh" >"$LOG2" 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ]; then echo "[x] FW_MODE=open: apply упал (exit $rc)"; tail -25 "$LOG2"; fail=1; fi
grep -qiE 'unbound variable|bad substitution' "$LOG2" && { echo "[x] open: unbound-переменная:"; grep -iE 'unbound variable|bad substitution' "$LOG2"; fail=1; }
grep -q 'hook input priority filter; policy accept;' "$NFTF" || { echo "[x] open: нет policy accept на input"; fail=1; }
grep -q 'counter accept' "$NFTF" || { echo "[x] open: нет catch-all accept"; fail=1; }
grep -q 'meter osyn4' "$NFTF" || { echo "[x] open: нет generic per-IP SYN-rate для неперечисленных портов"; fail=1; }
grep -q 'meter occ4'  "$NFTF" || { echo "[x] open: нет generic per-IP conn-limit для неперечисленных портов"; fail=1; }
grep -q 'meter oudp4' "$NFTF" || { echo "[x] open: нет generic per-IP UDP-rate для неперечисленных портов"; fail=1; }
grep -q 'ANTI-SCAN' "$NFTF" && { echo "[x] open: анти-скан автобан не должен ставиться"; fail=1; }
grep -q 'dport 2222' "$NFTF" && { echo "[x] open: node-port правила не должны ставиться"; fail=1; }
grep -q 'ssh-flood' "$NFTF" || { echo "[x] open: SSH-защита должна оставаться"; fail=1; }
grep -q 'bogon_v4' "$NFTF" || { echo "[x] open: анти-спуф должен оставаться"; fail=1; }
grep -q '^fw_mode=open$' "$T/state/protect.installed" || { echo "[x] open: fw_mode=open не в маркере"; fail=1; }

# ── FW_MODE=skip: файрвол не генерится, fleet/blocklists пропущены, ctguard работает ──
reset_t
LOG3="$T/apply-skip.log"
set +e
FW_MODE=skip ENABLE_BLOCKLISTS=1 ENABLE_CTGUARD=1 NA_CTG_ENFORCE=0 \
  FLEET_SYNC=1 REMNAWAVE_URL=https://panel.example.com REMNAWAVE_TOKEN=tok \
  ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 \
  bash "$T/scripts/protect.sh" >"$LOG3" 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ]; then echo "[x] FW_MODE=skip: прогон упал (exit $rc)"; tail -25 "$LOG3"; fail=1; fi
grep -qiE 'unbound variable|bad substitution' "$LOG3" && { echo "[x] skip: unbound-переменная:"; grep -iE 'unbound variable|bad substitution' "$LOG3"; fail=1; }
[ ! -e "$NFTF" ] || { echo "[x] skip: na_filter.nft не должен создаваться"; fail=1; }
[ ! -e "$T/sys/na-firewall.service" ] || { echo "[x] skip: na-firewall.service не должен создаваться"; fail=1; }
[ ! -e "$T/sbin/na-fleet-sync" ] || { echo "[x] skip: fleet-sync должен быть пропущен"; fail=1; }
[ ! -e "$T/sbin/na-blocklist-update" ] || { echo "[x] skip: блоклисты должны быть пропущены"; fail=1; }
[ -e "$T/sbin/na-ctguard" ] || { echo "[x] skip: ctguard независим от na_filter — должен ставиться"; fail=1; }
grep -qF 'Как закрыть порты самому' "$LOG3" || { echo "[x] skip: не напечатана инструкция по ручной блокировке"; fail=1; }
grep -qF 'Готово' "$LOG3" || { echo "[x] skip: прогон не дошёл до конца"; fail=1; }
grep -q '^fw_mode=skip$' "$T/state/protect.installed" || { echo "[x] skip: fw_mode=skip не в маркере"; fail=1; }

if [ "$fail" -ne 0 ]; then
    echo "=== ХВОСТ ЛОГА (strict) ==="; tail -25 "$LOG"
    echo "APPLY-SMOKE: FAIL"; exit 1
fi
echo "APPLY-SMOKE: OK (apply-path protect.sh чист под set -u в режимах strict/open/skip, модули и артефакты на месте)"
