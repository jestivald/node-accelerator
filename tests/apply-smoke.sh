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
mkdir -p "$T/bin" "$T/sys" "$T/sbin" "$T/modload" "$T/conf" "$T/state" "$T/backup" "$T/sysctl.d"
cp -r "$REPO_ROOT/scripts" "$T/scripts"

# Перенаправляем хардкод-системные пути на писабельные /tmp (portable sed: без -i).
P="$T/scripts/protect.sh"
sed -e "s#/etc/systemd/system/#$T/sys/#g" \
    -e "s#/usr/local/sbin/#$T/sbin/#g" \
    -e "s#/etc/modules-load.d/#$T/modload/#g" \
    -e "s#/etc/sysctl.d/#$T/sysctl.d/#g" \
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
grep -q 'tcp dport { 2222, 3000 } ct state new counter name c_nodeport drop' "$NFTF" || { echo "[x] strict: нет node-port правил на фолбэк 2222,3000"; fail=1; }
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
# ── v4.2 ──
for c in c_synflood c_udpflood c_udp_amp c_portscan c_autoban c_blocklist c_bogon c_badflags c_nodeport c_catchall c_dnat_guard c_sshflood; do
    grep -q "counter $c { packets 0 bytes 0 }" "$NFTF" || { echo "[x] v4.2: не объявлен счётчик $c"; fail=1; }
done
grep -q 'ct status dnat ct state new jump dnat_guard' "$NFTF" || { echo "[x] v4.2: forward не ведёт новые DNAT-соединения в dnat_guard"; fail=1; }
grep -q 'chain dnat_guard {' "$NFTF" || { echo "[x] v4.2: нет цепочки dnat_guard"; fail=1; }
grep -q 'udp sport { 17, 19, 53, 123, 389, 1900, 11211 } udp dport' "$NFTF" || { echo "[x] v4.2: нет анти-амплификации UDP"; fail=1; }
grep -q 'ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept' "$NFTF" || { echo "[x] v4.2: DHCPv6-ответы не пропускаются"; fail=1; }
grep -q '::1/128, ::ffff:0:0/96' "$NFTF" || { echo "[x] v4.2: :: (DAD) всё ещё в bogon_v6"; fail=1; }
grep -q 'update @sshs4 {' "$NFTF" || { echo "[x] v4.2: SSH ban-once без порога эскалации sshs4"; fail=1; }
# SYNPROXY — ДО invalid-drop (иначе третий ACK рукопожатия съедается раньше synproxy)
_sp=$(grep -n 'synproxy mss' "$NFTF" | head -1 | cut -d: -f1); _inv=$(grep -n 'ct state invalid drop' "$NFTF" | head -1 | cut -d: -f1)
[ -n "$_sp" ] && [ -n "$_inv" ] && [ "$_sp" -lt "$_inv" ] || { echo "[x] v4.2: synproxy стоит не до ct state invalid drop ($_sp vs $_inv)"; fail=1; }
grep -q 'net.netfilter.nf_conntrack_tcp_loose = 0' "$T/sysctl.d/99-na-synproxy.conf" 2>/dev/null || { echo "[x] v4.2: SYNPROXY без nf_conntrack_tcp_loose=0"; fail=1; }
grep -qE '^nft_sha256=[0-9a-f]{64}$' "$T/state/protect.installed" || { echo "[x] v4.2: нет nft_sha256 в маркере"; fail=1; }
[ "$(grep -E '^nft_sha256=' "$T/state/protect.installed" | cut -d= -f2)" = "$(sha256sum "$NFTF" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$NFTF" | awk '{print $1}')" ] \
    || { echo "[x] v4.2: nft_sha256 не совпадает с файлом"; fail=1; }
grep -q '^dnat_guard=1$' "$T/state/protect.installed" || { echo "[x] v4.2: dnat_guard=1 не в маркере"; fail=1; }
[ -x "$T/sbin/na-fw" ] || { echo "[x] v4.2: не создан na-fw"; fail=1; }
# SSH_PORT из автодетекта (стаб: 22) в conf НЕ пишется — следующий прогон детектит заново
grep -q 'SSH_PORT' "$T/conf/protect.conf" && { echo "[x] v4.2: автодетект SSH_PORT персистится"; fail=1; }

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
grep -q 'tcp dport { 3000 } ct state new counter name c_nodeport drop' "$NFTF" || { echo "[x] autodetect: нет wl-only правил на детект-порт 3000"; fail=1; }
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

# ── v4.2: none, явный SSH_PORT, локальные правила, DNAT_GUARD=0, снятие ctguard ──
reset_t
mkdir -p "$T/conf/na_filter.d/table" "$T/conf/na_filter.d/input"
echo '    set frontlist_v4 { type ipv4_addr; elements = { 192.0.2.10 } }' > "$T/conf/na_filter.d/table/front.nft"
echo '        ip saddr @frontlist_v4 tcp dport { 80, 443 } accept' > "$T/conf/na_filter.d/input/front.nft"
set +e
WHITELIST=203.0.113.50 UDP_PORTS=none NODE_PORT=none SSH_PORT=2222 DNAT_GUARD=0 ENABLE_CTGUARD=1 \
  ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 bash "$T/scripts/protect.sh" >"$T/apply-v42.log" 2>&1
rc=$?
set -e
[ "$rc" -eq 0 ] || { echo "[x] v4.2: прогон упал"; tail -15 "$T/apply-v42.log"; fail=1; }
grep -q 'udp dport' "$NFTF" && grep -q 'udp dport 443 update' "$NFTF" && { echo "[x] v4.2: UDP_PORTS=none — UDP-правила всё ещё ставятся"; fail=1; }
grep -q 'counter name c_nodeport drop' "$NFTF" && { echo "[x] v4.2: NODE_PORT=none — правила node-порта есть"; fail=1; }
grep -q '^node_port=none$' "$T/state/protect.installed" || { echo "[x] v4.2: node_port=none не в маркере"; fail=1; }
grep -q 'UDP_PORTS:=none' "$T/conf/protect.conf" || { echo "[x] v4.2: UDP_PORTS=none не персистится словом none"; fail=1; }
grep -q 'NODE_PORT:=none' "$T/conf/protect.conf" || { echo "[x] v4.2: NODE_PORT=none не персистится"; fail=1; }
grep -q 'SSH_PORT:=2222' "$T/conf/protect.conf" && grep -qx '# explicit: SSH_PORT' "$T/conf/protect.conf" || { echo "[x] v4.2: явный SSH_PORT не персистится с меткой explicit"; fail=1; }
grep -q 'set frontlist_v4' "$NFTF" && grep -q 'ip saddr @frontlist_v4 tcp dport { 80, 443 } accept' "$NFTF" || { echo "[x] v4.2: локальные правила na_filter.d не вклеены"; fail=1; }
grep -q '^include_files=2$' "$T/state/protect.installed" || { echo "[x] v4.2: include_files=2 не в маркере"; fail=1; }
grep -q 'jump dnat_guard' "$NFTF" && { echo "[x] v4.2: DNAT_GUARD=0 — forward всё ещё ведёт в dnat_guard"; fail=1; }
[ -e "$T/sbin/na-ctguard" ] || { echo "[x] v4.2: ctguard не поставился (подготовка проверки снятия)"; fail=1; }
# второй прогон БЕЗ ENV: none держится, явный SSH_PORT держится; ctguard выключаем — снимается
set +e
ENABLE_CTGUARD=0 ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 bash "$T/scripts/protect.sh" >"$T/apply-v42b.log" 2>&1
rc=$?
set -e
[ "$rc" -eq 0 ] || { echo "[x] v4.2: ре-ран упал"; tail -15 "$T/apply-v42b.log"; fail=1; }
grep -q 'udp dport 443 update' "$NFTF" && { echo "[x] v4.2: ре-ран без ENV вернул UDP_PORTS по умолчанию"; fail=1; }
grep -q 'tcp dport { 2222 } ct state new update @ssh4' "$NFTF" || { echo "[x] v4.2: ре-ран потерял явный SSH_PORT=2222"; fail=1; }
[ -e "$T/sbin/na-ctguard" ] && { echo "[x] v4.2: ENABLE_CTGUARD=0 не снял ctguard"; fail=1; }
[ -e "$T/conf/ctguard.conf" ] && { echo "[x] v4.2: ENABLE_CTGUARD=0 оставил ctguard.conf"; fail=1; }
# WHITELIST=none — явная очистка (пустой ENV значит «как в conf»)
set +e
WHITELIST=none ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 bash "$T/scripts/protect.sh" >"$T/apply-v42c.log" 2>&1
WHITELIST= ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 bash "$T/scripts/protect.sh" >"$T/apply-v42d.log" 2>&1
set -e
grep -q '203.0.113.50' "$NFTF" && { echo "[x] v4.2: WHITELIST=none не очистил whitelist"; fail=1; }
grep -q 'WHITELIST:=none' "$T/conf/protect.conf" || { echo "[x] v4.2: WHITELIST=none не персистится"; fail=1; }
# валидация новых ручек
for bad in 'SAFETY_DELAY=10' 'CROWDSEC_SCOPE=ports' 'DNAT_GUARD=2' 'REMNAWAVE_URL=https://p.example.com REMNAWAVE_TOKEN=abc;id FLEET_SYNC=1'; do
    set +e
    env $bad ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 bash "$T/scripts/protect.sh" >"$T/apply-bad.log" 2>&1
    rcb=$?
    set -e
    [ "$rcb" -ne 0 ] || { echo "[x] v4.2: не отвергнуто: $bad"; fail=1; }
done
# устаревший conf: SSH_PORT сохранён старой версией (без explicit), sshd на 22 → оба порта + warn
reset_t
printf ': "${SSH_PORT:=2200}"\n' > "$T/conf/protect.conf"
set +e
ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 bash "$T/scripts/protect.sh" >"$T/apply-v42e.log" 2>&1
set -e
grep -q 'tcp dport { 2200, 22 } ct state new update @ssh4' "$NFTF" || { echo "[x] v4.2: устаревший SSH_PORT из conf + детект — не оба порта"; fail=1; }
grep -qF 'сохранён старой версией (автодетект)' "$T/apply-v42e.log" || { echo "[x] v4.2: нет warn про устаревший SSH_PORT"; fail=1; }
# в conf остаётся исходный порт БЕЗ метки explicit — сверка (и warn) повторится на ре-ране,
# а не «оба порта навсегда»
grep -q 'SSH_PORT:=2200}' "$T/conf/protect.conf" && ! grep -qx '# explicit: SSH_PORT' "$T/conf/protect.conf" \
    || { echo "[x] v4.2: устаревший SSH_PORT закреплён (ждём :=2200 без explicit)"; fail=1; }

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

# ── v4.3: интерактивный прогон на НАСТОЯЩЕМ pty (stdin — терминал, как из меню) ──
# В v4.3 меню install.sh запускает модули со stdin = терминал даже при `curl | bash`, и
# интерактивная ветка становится основной. Здесь она исполняется как есть: -t 0 истинно,
# read читает с терминала, Ctrl+D — настоящий EOF терминала. pty даёт python3 (он уже нужен
# diagnose-unit/na-report-unit); 6 пустых ответов — режим, SSH, TCP, UDP, node-agent,
# whitelist по умолчанию, дальше — ответ на «Соединение работает?».
cat > "$T/pty-run.py" <<'PY'
import os, pty, select, signal, sys, time
# pty-run.py <файл с вводом> <таймаут, с> <команда> [аргументы…] — вывод ребёнка в stdout, его код
inp = open(sys.argv[1], 'rb').read()
limit = float(sys.argv[2])
pid, fd = pty.fork()
if pid == 0:
    try:
        os.execvp(sys.argv[3], sys.argv[3:])
    finally:
        os._exit(127)
os.write(fd, inp)   # строки ждут в очереди терминала; ^D в начале строки — EOF для read
out = bytearray()
end = time.time() + limit
while True:
    left = end - time.time()
    if left <= 0:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        sys.stdout.buffer.write(bytes(out) + b'\n[pty-run] timeout\n')
        sys.exit(124)
    r, _, _ = select.select([fd], [], [], left)
    if not r:
        continue
    try:
        chunk = os.read(fd, 65536)
    except OSError:   # Linux: EIO, когда ребёнок закрыл терминал
        break
    if not chunk:     # macOS: EOF
        break
    out += chunk
_, st = os.waitpid(pid, 0)
sys.stdout.buffer.write(bytes(out))
sys.exit(os.WEXITSTATUS(st) if os.WIFEXITED(st) else 128 + os.WTERMSIG(st))
PY
pty_protect() {   # pty_protect <ответ на «Соединение работает?» (байты)> <лог> [VAR=знач…]
    local ans="$1" log="$2"; shift 2
    printf '\n\n\n\n\n\n%s' "$ans" > "$T/pty.in"
    : > "$NA_TEST_SYSTEMCTL_LOG"
    python3 "$T/pty-run.py" "$T/pty.in" 120 \
        env -u REMNAWAVE_NONINTERACTIVE ENABLE_CROWDSEC=0 DRY_RUN=0 "$@" bash "$T/scripts/protect.sh" >"$log" 2>&1
}
if ! command -v python3 >/dev/null 2>&1; then
    echo "[x] нужен python3 (pty для интерактивного прогона)"; fail=1
else
    # C-локаль: LC_CTYPE=UTF-8, который macOS передаёт по SSH, на Linux не существует → bash
    # в C, а там скобочное выражение — набор БАЙТОВ: «д» = D0 B4, «н» = D0 BD, и ответ
    # «нет» (или «н» — клавиша Y в русской раскладке) снимал сейфти, хотя вход НЕ работает.
    # EOF (Ctrl+D): под set -e голый read ронял скрипт молча — с ВЗВЕДЁННЫМ сейфти.
    i=0
    for ans in $'нет\n' $'н\n' $'\x04' $'y\n' $'д\n' $'Да\n'; do
        i=$((i+1)); reset_t; L="$T/apply-pty-$i.log"
        set +e; pty_protect "$ans" "$L" LC_ALL=C; rc=$?; set -e
        case "$ans" in $'\x04') what='EOF (Ctrl+D)';; *) what="«${ans%$'\n'}»";; esac
        grep -qF 'Режим файрвола' "$L" || { echo "[x] pty $what: интерактивная ветка не исполнялась"; tail -5 "$L"; fail=1; }
        [ "$rc" -eq 0 ] || { echo "[x] pty $what: прогон упал (exit $rc) — без слова о взведённом сейфти"; tail -5 "$L"; fail=1; }
        grep -qF 'Готово' "$L" || { echo "[x] pty $what: прогон не дошёл до «Готово»"; fail=1; }
        n="$(grep -c 'stop na-fw-safety.timer' "$NA_TEST_SYSTEMCTL_LOG" || true)"
        case "$ans" in
            $'нет\n'|$'н\n'|$'\x04')
                # взвод гасит прошлый таймер (1 stop); второй stop — это снятие сейфти
                [ "$n" -eq 1 ] || { echo "[x] pty LC_ALL=C $what: сейфти СНЯТ, хотя вход не подтверждён"; fail=1; }
                grep -qF 'Сейфти оставлен' "$L" || { echo "[x] pty LC_ALL=C $what: нет сообщения, что сейфти остался взведённым"; fail=1; } ;;
            *)
                [ "$n" -eq 2 ] || { echo "[x] pty LC_ALL=C $what: подтверждение не сняло сейфти"; fail=1; }
                grep -qF 'Сейфти-таймер снят' "$L" || { echo "[x] pty LC_ALL=C $what: нет сообщения о снятии сейфти"; fail=1; } ;;
        esac
    done
    # Ре-ран на настроенной ноде: вопрос про whitelist показывал «[пусто]», а Enter оставлял
    # список из protect.conf. Поверив подсказке, оператор вписывал «свой» адрес — и ЗАМЕНЯЛ им
    # весь список (адрес панели выпадал из whitelist).
    reset_t
    printf ': "${WHITELIST:=198.51.100.50,203.0.113.60}"\n' > "$T/conf/protect.conf"
    L="$T/apply-pty-wl.log"
    set +e; pty_protect $'y\n' "$L"; rc=$?; set -e
    [ "$rc" -eq 0 ] || { echo "[x] pty whitelist: прогон упал (exit $rc)"; tail -5 "$L"; fail=1; }
    grep -qF 'Whitelist IP/CIDR (панель, твои)  [198.51.100.50,203.0.113.60]' "$L" \
        || { echo "[x] pty whitelist: подсказка не показывает сохранённый список (Enter его оставляет)"; { grep -a 'Whitelist IP' "$L" || true; }; fail=1; }
    grep -q 'elements = { 198.51.100.50, 203.0.113.60' "$NFTF" || { echo "[x] pty whitelist: Enter не сохранил список из conf"; fail=1; }
fi

# ── Сейфти сработал, пока шли установки после взвода (apt jq/conntrack, фиды блок-листов,
# fleet-sync; SAFETY_DELAY бывает и 30 с) ──
# Неинтерактивный финал печатал «сейфти-таймер АКТИВЕН — подтверди доступ и сними», хотя
# таблицы уже нет и автозагрузка выключена: вход «работает» (файрвола-то нет), оператор
# снимал уже сработавший таймер и уходил с нодой без защиты. Ветка «y» это проверяет с v4.2.
grep -qF 'сейфти-таймер на 300s АКТИВЕН' "$LOG" || { echo "[x] safety: в обычном неинтерактивном прогоне нет «таймер АКТИВЕН»"; fail=1; }
reset_t
# таблицы na_filter нет — ровно то, что оставляет сработавший сейфти
printf '#!/bin/sh\ncase "$*" in "-t list table inet na_filter") exit 1;; esac\nexit 0\n' > "$T/bin/nft"; chmod +x "$T/bin/nft"
set +e
ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 bash "$T/scripts/protect.sh" >"$T/apply-fired.log" 2>&1
rc=$?
set -e
printf '#!/bin/sh\nexit 0\n' > "$T/bin/nft"; chmod +x "$T/bin/nft"
[ "$rc" -eq 0 ] || { echo "[x] safety-fired: прогон упал (exit $rc)"; tail -5 "$T/apply-fired.log"; fail=1; }
grep -qF 'АКТИВЕН' "$T/apply-fired.log" && { echo "[x] safety-fired: «таймер АКТИВЕН» при уже сработавшем сейфти"; fail=1; }
grep -qF 'Сейфти-таймер УЖЕ сработал' "$T/apply-fired.log" || { echo "[x] safety-fired: не сказано, что сейфти уже сработал и защиты нет"; fail=1; }

# ── Кривой токен fleet-sync отвергается ДО применения ──
# Проверка набора символов токенов стояла в блоке fleet-sync — ПОСЛЕ nft -f и взвода сейфти:
# прогон падал «недопустимые символы» с уже применённым ruleset и взведённым сейфти, а тот
# через SAFETY_DELAY снимал таблицу И автозагрузку — нода оставалась без файрвола (и после
# ребута), хотя оператор видел лишь ошибку валидации.
reset_t; : > "$NA_TEST_SYSTEMCTL_LOG"
set +e
FLEET_SYNC=1 REMNAWAVE_URL=https://panel.example.com REMNAWAVE_TOKEN=tok CADDY_AUTH_API_TOKEN='s3cr3t!#x' \
  ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 bash "$T/scripts/protect.sh" >"$T/apply-badtok.log" 2>&1
rc=$?
set -e
{ [ "$rc" -ne 0 ] && grep -qF 'CADDY_AUTH_API_TOKEN: недопустимые символы' "$T/apply-badtok.log"; } \
    || { echo "[x] bad-token: кривой токен не отвергнут"; tail -5 "$T/apply-badtok.log"; fail=1; }
grep -q 'stop na-fw-safety.timer' "$NA_TEST_SYSTEMCTL_LOG" && { echo "[x] bad-token: сейфти взведён до отказа (через SAFETY_DELAY снял бы таблицу и автозагрузку)"; fail=1; }
[ -e "$NFTF" ] && { echo "[x] bad-token: ruleset применён до отказа"; fail=1; }
# FW_MODE=skip: fleet-sync не ставится, токен не используется — отказа нет, как и раньше
reset_t
set +e
FW_MODE=skip FLEET_SYNC=1 REMNAWAVE_URL=https://panel.example.com REMNAWAVE_TOKEN=tok CADDY_AUTH_API_TOKEN='s3cr3t!#x' \
  ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 bash "$T/scripts/protect.sh" >"$T/apply-badtok-skip.log" 2>&1
rc=$?
set -e
[ "$rc" -eq 0 ] || { echo "[x] bad-token: FW_MODE=skip (fleet не ставится) теперь отвергает неиспользуемый токен"; fail=1; }

# ── v4.3: списки портов с пробелами и пустыми элементами ─────────────────────────
# «443, 8443» — естественный ответ в интерактиве (из меню install.sh) — ронял прогон после
# всех вопросов; «,22»/хвостовая запятая уходили в ruleset как `{ , 22 }`. Теперь пробелы и
# пустые элементы убираются до проверки, а список из одних запятых — ошибка до применения.
reset_t
set +e
TCP_PORTS="443 8443" UDP_PORTS=",443,," SSH_PORT=" 22 " ENABLE_CROWDSEC=0 \
  REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 bash "$T/scripts/protect.sh" >"$T/apply-ports.log" 2>&1
rc=$?
set -e
[ "$rc" -eq 0 ] || { echo "[x] ports: «443 8443» уронил прогон (exit $rc)"; tail -5 "$T/apply-ports.log"; fail=1; }
grep -q 'tcp dport 4438443 ' "$NFTF" && { echo "[x] ports: «443 8443» склеен в один порт"; fail=1; }
{ grep -q 'tcp dport 443 ct state new accept' "$NFTF" && grep -q 'tcp dport 8443 ct state new accept' "$NFTF"; } \
    || { echo "[x] ports: в ruleset нет правил на 443 и 8443"; { grep -a 'ct state new accept' "$NFTF" 2>/dev/null | head -5 || true; }; fail=1; }
grep -q 'tcp dport { 22 } ct state new ip  saddr @ssh4 accept' "$NFTF" || { echo "[x] ports: SSH_PORT « 22 » не нормализован"; fail=1; }
grep -qE 'dport \{ *,|, *\}' "$NFTF" && { echo "[x] ports: пустой элемент дошёл до ruleset"; fail=1; }
grep -q '^: "${TCP_PORTS:=443,8443}"$' "$T/conf/protect.conf" || { echo "[x] ports: в protect.conf не нормализованный список"; fail=1; }
reset_t
set +e
TCP_PORTS="," ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 bash "$T/scripts/protect.sh" >"$T/apply-ports2.log" 2>&1
rc=$?
set -e
{ [ "$rc" -ne 0 ] && grep -qF "TCP_PORTS=',' — ни одного порта" "$T/apply-ports2.log"; } \
    || { echo "[x] ports: список из одних запятых не отвергнут"; tail -3 "$T/apply-ports2.log"; fail=1; }
[ -e "$NFTF" ] && { echo "[x] ports: ruleset применён при отвергнутом списке"; fail=1; }
reset_t
set +e
SSH_PORT=" , " ENABLE_CROWDSEC=0 REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 bash "$T/scripts/protect.sh" >"$T/apply-ports3.log" 2>&1
rc=$?
set -e
{ [ "$rc" -ne 0 ] && grep -qF "SSH_PORT=' , ' — ни одного порта" "$T/apply-ports3.log"; } \
    || { echo "[x] ports: пустой SSH_PORT не отвергнут"; tail -3 "$T/apply-ports3.log"; fail=1; }
grep -q 'словом none' "$T/apply-ports3.log" && { echo "[x] ports: для SSH_PORT предложено none (его SSH_PORT не принимает)"; fail=1; }

if [ "$fail" -ne 0 ]; then
    echo "=== ХВОСТ ЛОГА (strict) ==="; tail -25 "$LOG"
    echo "APPLY-SMOKE: FAIL"; exit 1
fi
echo "APPLY-SMOKE: OK (apply-path protect.sh чист под set -u в режимах strict/open/skip + node-port детект/фолбэк/mismatch/caddy-auth, модули и артефакты на месте)"
