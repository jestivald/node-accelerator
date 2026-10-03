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
for c in systemctl modprobe nft systemd-run sysctl conntrack; do
    printf '#!/bin/sh\nexit 0\n' > "$T/bin/$c"; chmod +x "$T/bin/$c"
done
# Стаб systemctl пишет журнал вызовов: protect включает СВОЙ na-firewall.service и не
# трогает дистрибутивный nftables.service (его stop/restart/reload = flush ruleset).
export NA_TEST_SYSTEMCTL_LOG="$T/systemctl.log"
cat > "$T/bin/systemctl" <<'SYSTEMCTL'
#!/bin/sh
printf '%s\n' "$*" >> "$NA_TEST_SYSTEMCTL_LOG"
# сейфти прошлого прогона «взведён» только по просьбе теста (иначе — нет)
case "$*" in
    "is-active --quiet na-fw-safety.timer") [ "${NA_TEST_SAFETY_ACTIVE:-0}" = 1 ] && exit 0; exit 3 ;;
esac
exit 0
SYSTEMCTL
# curl падает → сетевые fetch (crowdsec/blocklist/fleet) деградируют мягко, не висят.
printf '#!/bin/sh\nexit 1\n' > "$T/bin/curl"; chmod +x "$T/bin/curl"
# docker падает → детект node-порта детерминированно идёт по .env/ss-веткам
# (на CI-раннере/маке живой docker дал бы недетерминизм).
printf '#!/bin/sh\nexit 1\n' > "$T/bin/docker"; chmod +x "$T/bin/docker"
# ss: harvest established-пиров node-порта видит «панель» 198.51.100.7 (TEST-NET-2),
# остальные вызовы (детект listening и т.п.) — пусто.
cat > "$T/bin/ss" <<'SS'
#!/bin/sh
case "$*" in
    *established*) echo 'ESTAB 0 0 10.0.0.5:3000 198.51.100.7:41234';;
esac
exit 0
SS
chmod +x "$T/bin/ss"
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
grep -qx 'enable na-firewall.service' "$NA_TEST_SYSTEMCTL_LOG" \
    || { echo "[x] protect не включил свой na-firewall.service"; fail=1; }
if grep -Eq '^(enable|start|restart|reload|stop|disable|mask)( [^ ]+)* nftables(\.service)?( |$)' "$NA_TEST_SYSTEMCTL_LOG"; then
    echo "[x] protect тронул чужой nftables.service (риск flush ruleset)"
    fail=1
fi
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
# NODE_PORT не задан, детект пуст (docker/ss стабы) → фолбэк на ОБА известных дефолта
grep -q 'tcp dport { 2222, 3000 } ct state new drop' "$NFTF" || { echo "[x] strict: нет node-port правил на фолбэк 2222,3000"; fail=1; }
grep -q 'set na_nodeport_wl_v4' "$NFTF" || { echo "[x] strict: нет сета na_nodeport_wl_v4 (пожарный допуск панели)"; fail=1; }
grep -q '^node_port=2222,3000$' "$T/state/protect.installed" || { echo "[x] strict: node_port=2222,3000 не в маркере"; fail=1; }
# wl-only задан ЯВНО → авто-допуск пиров выключен: warn с их списком, элементов в сете нет
grep -q '198.51.100.7' "$NFTF" && { echo "[x] strict: пир НЕ должен попадать в сет при явном NODE_PORT_WHITELIST_ONLY=1"; fail=1; }
grep -qF 'node-port сейчас держат коннект: 198.51.100.7' "$LOG" || { echo "[x] strict: нет warn со списком established-пиров node-порта"; fail=1; }
grep -q '^fw_mode=strict$' "$T/state/protect.installed" || { echo "[x] strict: fw_mode=strict не в маркере"; fail=1; }
grep -qE '(@osyn|meter occ|@oudp)' "$NFTF" && { echo "[x] strict: generic open-лимитеры не должны ставиться (ruleset должен быть идентичен прежнему)"; fail=1; }
# v4.1.3: per-IP лимитеры — объявленные наборы С timeout, правило «превысил → drop»
grep -q 'set syn4_443 { type ipv4_addr; size 65535; flags dynamic,timeout; timeout 60s; }' "$NFTF" \
    || { echo "[x] strict: набор syn4_443 без timeout (записи копятся до ребута → полный набор режет новых клиентов)"; fail=1; }
grep -q 'set ssh4 { type ipv4_addr; size 65535; flags dynamic,timeout; timeout 600s; }' "$NFTF" \
    || { echo "[x] strict: набор ssh4 без timeout 600s (пол 10m)"; fail=1; }
# SSH на полном ssh4 НЕ открывается: известный адрес — accept, прочим — общий потолок
grep -q 'tcp dport { 22 } ct state new ip  saddr @ssh4 accept' "$NFTF" \
    || { echo "[x] strict: нет accept для адресов из ssh4"; fail=1; }
grep -q 'tcp dport { 22 } ct state new limit rate 30/minute burst 30 packets accept' "$NFTF" \
    || { echo "[x] strict: нет общего потолка SSH на полном наборе"; fail=1; }
# медленный rate → timeout растёт вместе с временем восстановления корзины
grep -q 'set ps4 { type ipv4_addr; size 65535; flags dynamic,timeout; timeout 600s; }' "$NFTF" \
    || { echo "[x] strict: набор ps4 — ожидался timeout 600s (пол 10m)"; fail=1; }
grep -q 'update @syn4_443 { ip saddr limit rate over 200/second burst 400 packets } jump synflood_drop' "$NFTF" \
    || { echo "[x] strict: SYN-лимит не по схеме «превысил → drop»"; fail=1; }
if grep -qE 'meter [A-Za-z0-9_]+ \{ ip6? saddr limit' "$NFTF"; then
    echo "[x] strict: остался meter с limit без timeout:"; grep -nE 'meter [A-Za-z0-9_]+ \{ ip6? saddr limit' "$NFTF"; fail=1
fi
for st in ps4 psc4 icmp4 udp4_443; do
    grep -q "set $st { type ipv4_addr; size 65535; flags dynamic,timeout;" "$NFTF" || { echo "[x] strict: нет набора $st с timeout"; fail=1; }
done
grep -q 'chain ssh_flood {' "$NFTF" || { echo "[x] strict: нет цепочки ssh_flood"; fail=1; }

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
grep -q 'update @osyn4 { ip saddr limit rate over' "$NFTF" || { echo "[x] open: нет generic per-IP SYN-rate для неперечисленных портов"; fail=1; }
grep -q 'meter occ4'  "$NFTF" || { echo "[x] open: нет generic per-IP conn-limit для неперечисленных портов"; fail=1; }
grep -q 'update @oudp4 { ip saddr limit rate over' "$NFTF" || { echo "[x] open: нет generic per-IP UDP-rate для неперечисленных портов"; fail=1; }
grep -q 'set osyn4 { type ipv4_addr; size 65535; flags dynamic,timeout; timeout 60s; }' "$NFTF" || { echo "[x] open: набор osyn4 без timeout"; fail=1; }
grep -q 'ANTI-SCAN' "$NFTF" && { echo "[x] open: анти-скан автобан не должен ставиться"; fail=1; }
grep -qE 'tcp dport \{ 2222|na_nodeport_wl' "$NFTF" && { echo "[x] open: node-port правила/сеты не должны ставиться"; fail=1; }
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

# ── NODE_PORT=auto: детект из .env node-агента + авто-допуск пиров панели ──────
# WHITELIST задан, wl-only НЕ задан явно → авто-вывод → NODE_PORT_AUTOWL=auto включается.
reset_t
printf 'NODE_PORT=3000\n' > "$T/remnanode.env"
LOG4="$T/apply-autodetect.log"
set +e
NA_REMNANODE_ENV="$T/remnanode.env" WHITELIST="1.2.3.4" ENABLE_CROWDSEC=0 \
  REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 \
  bash "$T/scripts/protect.sh" >"$LOG4" 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ]; then echo "[x] autodetect: apply упал (exit $rc)"; tail -25 "$LOG4"; fail=1; fi
grep -qiE 'unbound variable|bad substitution' "$LOG4" && { echo "[x] autodetect: unbound-переменная:"; grep -iE 'unbound variable|bad substitution' "$LOG4"; fail=1; }
grep -qF 'автодетект порта → 3000' "$LOG4" || { echo "[x] autodetect: нет лога про автодетект 3000"; fail=1; }
grep -q 'tcp dport { 3000 } ct state new drop' "$NFTF" || { echo "[x] autodetect: нет wl-only правил на детект-порт 3000"; fail=1; }
grep -q 'dport { 2222' "$NFTF" && { echo "[x] autodetect: фолбэк 2222 не должен ставиться при удачном детекте"; fail=1; }
grep -q '198.51.100.7' "$NFTF" || { echo "[x] autodetect: established-пир панели не попал в na_nodeport_wl (авто-допуск)"; fail=1; }
grep -q '^node_port=3000$' "$T/state/protect.installed" || { echo "[x] autodetect: node_port=3000 не в маркере"; fail=1; }
grep -q 'NODE_PORT:=auto' "$T/conf/protect.conf" || { echo "[x] autodetect: intent NODE_PORT=auto не персистится"; fail=1; }
grep -q 'NODE_PORT_LAST:=3000' "$T/conf/protect.conf" || { echo "[x] autodetect: кэш NODE_PORT_LAST=3000 не персистится"; fail=1; }
grep -q 'NODE_PORT_PEERS:=198.51.100.7' "$T/conf/protect.conf" || { echo "[x] autodetect: пиры панели не персистятся"; fail=1; }

# ── Явный NODE_PORT=2222, а агент фактически на :3000 → правила на ОБА + warn ──
reset_t
LOG5="$T/apply-mismatch.log"
set +e
NA_REMNANODE_ENV="$T/remnanode.env" NODE_PORT=2222 ENABLE_CROWDSEC=0 \
  REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 \
  bash "$T/scripts/protect.sh" >"$LOG5" 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ]; then echo "[x] mismatch: apply упал (exit $rc)"; tail -25 "$LOG5"; fail=1; fi
grep -qF 'node-agent фактически слушает :3000' "$LOG5" || { echo "[x] mismatch: нет warn про расхождение явного порта с детектом"; fail=1; }
grep -q 'tcp dport { 2222, 3000 }' "$NFTF" || { echo "[x] mismatch: правила должны крыть ОБА порта (явный + детект)"; fail=1; }
grep -q '^node_port=2222,3000$' "$T/state/protect.installed" || { echo "[x] mismatch: node_port=2222,3000 не в маркере"; fail=1; }
grep -q 'NODE_PORT:=2222}' "$T/conf/protect.conf" || { echo "[x] mismatch: явный intent NODE_PORT=2222 не персистится"; fail=1; }

# ── CADDY_AUTH_API_TOKEN → fleet.env + X-Api-Key в na-fleet-sync ─────────────
reset_t
LOG6="$T/apply-caddy.log"
set +e
FLEET_SYNC=1 REMNAWAVE_URL=https://panel.example.com REMNAWAVE_TOKEN=tok \
  CADDY_AUTH_API_TOKEN=caddy-secret ENABLE_CROWDSEC=0 \
  REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 \
  bash "$T/scripts/protect.sh" >"$LOG6" 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ]; then echo "[x] caddy: apply упал (exit $rc)"; tail -25 "$LOG6"; fail=1; fi
grep -qF 'CADDY_AUTH_API_TOKEN=caddy-secret' "$T/conf/fleet.env" \
  || { echo "[x] caddy: токен не сохранён в fleet.env"; fail=1; }
grep -qF 'X-Api-Key: %s' "$T/sbin/na-fleet-sync" \
  || { echo "[x] caddy: na-fleet-sync не шлёт X-Api-Key"; fail=1; }
# секрет должен уходить файлом заголовков, а не в argv (виден в /proc/<pid>/cmdline)
grep -qF -- '-H @"$HDRF"' "$T/sbin/na-fleet-sync" \
  || { echo "[x] caddy: заголовки с секретом не передаются через файл (-H @…)"; fail=1; }
grep -qF 'redact_url "$SRC"' "$T/sbin/na-fleet-sync" \
  || { echo "[x] caddy: URL уходит в лог без зачистки userinfo"; fail=1; }
# поведенческая проверка того же хелпера — отдельным тестом
bash "$REPO_ROOT/tests/fleet-sync-unit.sh" >/dev/null 2>&1 \
  || { echo "[x] fleet-sync-unit.sh не прошёл (детали: bash tests/fleet-sync-unit.sh)"; fail=1; }

# ── Сейфти-откат снимает И автозагрузку правил (иначе локаут вернулся бы ребутом) ──
grep -qF 'systemctl disable na-firewall.service' "$T/sbin/na-fw-safety-revert" \
  || { echo "[x] safety: аварийный откат не выключает na-firewall.service"; fail=1; }
grep -qF 'nft delete table inet na_filter' "$T/sbin/na-fw-safety-revert" \
  || { echo "[x] safety: аварийный откат не удаляет na_filter"; fail=1; }

# ── Порт текущей SSH-сессии не должен потеряться (ground truth из SSH_CONNECTION) ──
reset_t
LOG7="$T/apply-sshport.log"
set +e
SSH_CONNECTION='203.0.113.9 55000 10.0.0.5 56777' SSH_PORT=22 ENABLE_CROWDSEC=0 \
  REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 \
  bash "$T/scripts/protect.sh" >"$LOG7" 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ]; then echo "[x] ssh-port: apply упал (exit $rc)"; tail -25 "$LOG7"; fail=1; fi
grep -qF 'SSH-сессия пришла на :56777' "$LOG7" \
  || { echo "[x] ssh-port: нет warn про расхождение SSH_PORT с портом сессии"; fail=1; }
grep -q 'tcp dport { 22, 56777 }' "$NFTF" \
  || { echo "[x] ssh-port: в ruleset должны быть ОБА порта (заданный + порт сессии)"; fail=1; }
grep -q '^ssh_port=22,56777$' "$T/state/protect.installed" \
  || { echo "[x] ssh-port: эффективный список портов не в маркере"; fail=1; }
grep -q 'SSH_PORT:=22}' "$T/conf/protect.conf" \
  || { echo "[x] ssh-port: в protect.conf должен персиститься intent (22), а не транзитный порт сессии"; fail=1; }

# ── timeout набора растёт с медленным rate; NA_RATE_TO_*=0 (вечные записи) отвергается ──
reset_t
set +e
PORTSCAN_RATE=1 PORTSCAN_BURST=30 ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 \
  bash "$T/scripts/protect.sh" >"$T/apply-slow.log" 2>&1
rc=$?
NA_RATE_TO_MIN=0 ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 \
  bash "$T/scripts/protect.sh" >"$T/apply-to0.log" 2>&1
rc0=$?
set -e
[ "$rc" -eq 0 ] || { echo "[x] slow-rate: прогон упал"; fail=1; }
# 30 пакетов при 1/мин = 30 мин восстановления → timeout 2×30 мин = 3600s (выше пола 10m)
grep -q 'set ps4 { type ipv4_addr; size 65535; flags dynamic,timeout; timeout 3600s; }' "$NFTF" \
    || { echo "[x] slow-rate: timeout ps4 не вырос до 2× восстановления корзины"; fail=1; }
[ "$rc0" -ne 0 ] && grep -q 'NA_RATE_TO_MIN' "$T/apply-to0.log" || { echo "[x] NA_RATE_TO_MIN=0 должен отвергаться"; fail=1; }

# ── Файл автозагрузки меняется только после nft -c И успешного nft -f (v4.1.3) ──
# До v4.1.3 ruleset генерился прямо в na_filter.nft: провал проверки печатал «ничего не
# применено», а битый файл уже стоял на месте рабочего и поднимался первым же ребутом.
nft_fail_on() {   # nft_fail_on <check|apply> — стаб nft, падающий на nft -c или на nft -f
    if [ "$1" = check ]; then
        printf '#!/bin/sh\ncase "$*" in *-c*) exit 1;; esac\nexit 0\n' > "$T/bin/nft"
    else
        printf '#!/bin/sh\ncase "$*" in *-c*) exit 0;; "-f "*) exit 1;; esac\nexit 0\n' > "$T/bin/nft"
    fi
    chmod +x "$T/bin/nft"
}
for mode in check apply; do
    reset_t
    echo '# OLD-WORKING-RULESET' > "$NFTF"
    : > "$NA_TEST_SYSTEMCTL_LOG"
    nft_fail_on "$mode"
    LOG8="$T/apply-nftfail-$mode.log"
    set +e
    ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 bash "$T/scripts/protect.sh" >"$LOG8" 2>&1
    rc=$?
    set -e
    [ "$rc" -ne 0 ] || { echo "[x] nft-$mode-fail: protect должен завершиться ошибкой"; fail=1; }
    grep -qx '# OLD-WORKING-RULESET' "$NFTF" || { echo "[x] nft-$mode-fail: файл автозагрузки подменён отвергнутым ruleset"; fail=1; }
    [ -s "$T/conf/na_filter.nft.rejected" ] || { echo "[x] nft-$mode-fail: отвергнутый ruleset не сохранён рядом (.rejected)"; fail=1; }
    ls "$T/conf"/.na_filter.nft.* >/dev/null 2>&1 && { echo "[x] nft-$mode-fail: остался временный кандидат"; fail=1; }
    [ -e "$T/state/protect.installed" ] && { echo "[x] nft-$mode-fail: маркер не должен писаться при отказе"; fail=1; }
    if [ "$mode" = apply ]; then
        # nft -f отвергнут → живая таблица прежняя → сейфти обязан быть снят, иначе он
        # через SAFETY_DELAY снёс бы рабочую таблицу и автозагрузку
        # arm_safety сам гасит прошлый таймер перед взводом → ждём ДВА stop: взвод + снятие
        [ "$(grep -c 'stop na-fw-safety.timer' "$NA_TEST_SYSTEMCTL_LOG")" -ge 2 ] \
            || { echo "[x] nft-apply-fail: сейфти не снят после отказа nft -f"; fail=1; }
    fi
done
# сейфти прошлого неинтерактивного прогона ещё взведён → при отказе nft -f его НЕ снимаем
reset_t
echo '# OLD-WORKING-RULESET' > "$NFTF"
: > "$NA_TEST_SYSTEMCTL_LOG"
nft_fail_on apply
set +e
NA_TEST_SAFETY_ACTIVE=1 ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 bash "$T/scripts/protect.sh" >"$T/apply-nftfail-pre.log" 2>&1
set -e
[ "$(grep -c 'stop na-fw-safety.timer' "$NA_TEST_SYSTEMCTL_LOG")" -eq 1 ] \
    || { echo "[x] nft-apply-fail: сейфти прошлого прогона снят (а должен остаться взведённым)"; fail=1; }
printf '#!/bin/sh\nexit 0\n' > "$T/bin/nft"; chmod +x "$T/bin/nft"
# успешный прогон: кандидат переименован в файл автозагрузки, прошлый — в бэкапе
reset_t
echo '# OLD-WORKING-RULESET' > "$NFTF"
set +e
ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 bash "$T/scripts/protect.sh" >"$T/apply-ok.log" 2>&1
rc=$?
set -e
[ "$rc" -eq 0 ] || { echo "[x] nft-ok: прогон упал (exit $rc)"; tail -15 "$T/apply-ok.log"; fail=1; }
grep -q 'table inet na_filter {' "$NFTF" || { echo "[x] nft-ok: новый ruleset не стал файлом автозагрузки"; fail=1; }
grep -qx '# OLD-WORKING-RULESET' "$T/backup/na_filter.nft" 2>/dev/null || { echo "[x] nft-ok: прошлый ruleset не попал в бэкап"; fail=1; }
ls "$T/conf"/.na_filter.nft.* >/dev/null 2>&1 && { echo "[x] nft-ok: остался временный кандидат"; fail=1; }

if [ "$fail" -ne 0 ]; then
    echo "=== ХВОСТ ЛОГА (strict) ==="; tail -25 "$LOG"
    echo "APPLY-SMOKE: FAIL"; exit 1
fi
echo "APPLY-SMOKE: OK (apply-path protect.sh чист под set -u в режимах strict/open/skip + node-port детект/фолбэк/mismatch/caddy-auth, модули и артефакты на месте)"
