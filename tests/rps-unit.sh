#!/usr/bin/env bash
#
# rps-unit.sh — ИСПОЛНЯЕТ сгенерированный /usr/local/sbin/na-rps-setup из optimize.sh
# в песочнице против стабов ip/nproc/sleep + статические проверки юнита и «курсорного»
# вывода. Оба бага раскатки v4.0.1 живут именно тут и в CI не ловились ничем.
#
# Что стережём:
#   1. RPS применяется к NIC, вшитому в ExecStart (имя с момента optimize) — без
#      обращения к таблице маршрутов вообще;
#   2. интерфейс переименовался после смены ядра (eth0→ens18) → фолбэк на автодетект;
#   3. default route появляется ПОЗЖЕ network-online.target — скрипт ждёт его, а не
#      выходит нулём с неприменённым RPS (issue #30: юнит зелёный, rps_cpus=0);
#   4. маршрута нет вовсе → RPS ко ВСЕМ физическим интерфейсам (lo/veth/docker/br- мимо);
#   5. кандидатов нет → exit 1 и «giving up» в stderr (юнит уходит в failed, а не в
#      вечное active (exited) с невыполненной работой);
#   6. юнит несёт Restart=on-failure/RestartSec и ExecStart с именем NIC;
#   7. ничего «курсорного» (tput/\033[K) не уезжает в stdout, когда это не терминал
#      (issue #28: escape-коды в логах раскатки под nohup … > log);
#   8. v4.2: RPS не включается на 1 vCPU и при RX-очередей ≥ ядер (аппаратный RSS) —
#      маски прошлых версий возвращаются к снимку optimize или к 0; XPS не трогается
#      без NA_XPS=1 (раскладку TX-очередей задаёт драйвер); `default dev venet0 scope
#      link` (OpenVZ) даёт venet0, а не «scope».
#
# Не требует root/сети/systemd. Запуск: bash tests/rps-unit.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
SYS="$T/sys/class/net"
REC="$T/rec"
export REC
mkdir -p "$T/bin" "$SYS" "$REC" "$T/proc/sys/net/core" "$T/state"

# Секции/скрипту нужен bash ≥ 4.4 — системный bash macOS древний, берём первый годный.
pick_bash() {
    local c
    for c in bash /opt/homebrew/bin/bash /usr/local/bin/bash; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" -c 'set -u; a=(); : "${a[@]}"' 2>/dev/null; then command -v "$c"; return 0; fi
    done
    return 1
}
WBASH="$(pick_bash)" || { echo "[x] не нашёл bash ≥ 4.4"; exit 1; }

fail=0
expect()     { local d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  ✔ $d"; else echo "  ✘ $d"; fail=1; fi; }
expect_not() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  ✘ $d"; fail=1; else echo "  ✔ $d"; fi; }

# ── Стабы ───────────────────────────────────────────────────────────────────────
# ip: маршрут появляется только с ROUTE_AFTER-го вызова (0 = не появляется никогда) —
# так воспроизводится гонка «network-online.target раньше default route».
cat > "$T/bin/ip" <<'IP'
#!/bin/sh
n=$(( $(cat "$REC/ip.calls" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$REC/ip.calls"
[ "${ROUTE_AFTER:-0}" -gt 0 ] || exit 0
[ "$n" -ge "${ROUTE_AFTER:-0}" ] || exit 0
if [ -n "${ROUTE_LINE:-}" ]; then echo "$ROUTE_LINE"; exit 0; fi
echo "default via 10.0.0.1 dev ${ROUTE_IFACE:-ens18} proto static metric 100"
IP
printf '#!/bin/sh\necho "${NA_TEST_NCPU:-3}"\n' > "$T/bin/nproc"
cat > "$T/bin/sleep" <<'SL'
#!/bin/sh
echo "$*" >> "$REC/sleep.calls"
exit 0
SL
chmod +x "$T/bin/ip" "$T/bin/nproc" "$T/bin/sleep"
export PATH="$T/bin:$PATH"

# ── Достаём тело na-rps-setup из heredoc optimize.sh ────────────────────────────
extract_rps() {   # extract_rps <исходник optimize.sh> <куда>
    awk "/^cat > \/usr\/local\/sbin\/na-rps-setup <<'RPS'\$/{f=1;next} /^RPS\$/{f=0} f" "$1" \
        | sed -e "s#/sys/class/net#$SYS#g" -e "s#/proc/sys/net/core#$T/proc/sys/net/core#g" \
              -e "s#/var/lib/node-accelerator#$T/state#g" > "$2"
    [ -s "$2" ] || return 1
    chmod +x "$2"
}
RPS="$T/na-rps-setup"
extract_rps "$REPO_ROOT/scripts/optimize.sh" "$RPS" \
    || { echo "[x] не смог извлечь na-rps-setup из optimize.sh"; exit 1; }

mk_net() {   # mk_net <iface> [phys] — очереди rx/tx; phys=1 → есть /device (не veth)
    local n="$1" phys="${2:-}"
    mkdir -p "$SYS/$n/queues/rx-0" "$SYS/$n/queues/tx-0"
    : > "$SYS/$n/queues/rx-0/rps_cpus"
    : > "$SYS/$n/queues/rx-0/rps_flow_cnt"
    : > "$SYS/$n/queues/tx-0/xps_cpus"
    [ -n "$phys" ] && : > "$SYS/$n/device"
    return 0
}
reset_net() { rm -rf "$SYS"; mkdir -p "$SYS"; : > "$REC/ip.calls"; : > "$REC/sleep.calls"; rm -f "$T/state/rps-orig.tsv"; }
mk_queues() {   # mk_queues <iface> <rx-очередей> — multi-queue NIC (RSS), маски заранее «наши»
    local n="$1" i
    mkdir -p "$SYS/$n"; : > "$SYS/$n/device"
    for ((i = 0; i < $2; i++)); do
        mkdir -p "$SYS/$n/queues/rx-$i" "$SYS/$n/queues/tx-$i"
        echo 7 > "$SYS/$n/queues/rx-$i/rps_cpus"; echo 4096 > "$SYS/$n/queues/rx-$i/rps_flow_cnt"
        echo 7 > "$SYS/$n/queues/tx-$i/xps_cpus"
    done
}
q_of() { cat "$SYS/$1/queues/$2" 2>/dev/null || echo ""; }
run_rps() {  # run_rps <скрипт> [аргумент-NIC] → rc в $rc, вывод в $T/out/$T/err
    rc=0
    "$WBASH" "$@" > "$T/out" 2> "$T/err" || rc=$?
    return 0
}
ip_calls()  { local n; n="$(cat "$REC/ip.calls" 2>/dev/null || true)"; echo "${n:-0}"; }
# Голый `tput` в КОДЕ (комментарии не в счёт — в них слово встречается по делу).
bare_tput() { sed 's/#.*//' "$1" | grep -nE '(^|[^_[:alnum:]])tput '; }
mask_of()   { cat "$SYS/$1/queues/rx-0/rps_cpus" 2>/dev/null || echo ""; }

# ── Кейс (a): NIC вшит в ExecStart и существует ─────────────────────────────────
echo "== (a) NIC из ExecStart существует =="
reset_net; mk_net ens18 1
ROUTE_AFTER=0 run_rps "$RPS" ens18
expect "rc=0" test "$rc" -eq 0
expect "rps_cpus = маска 3 ядер (7)" test "$(mask_of ens18)" = "7"
expect "rps_flow_cnt проставлен" grep -qx 4096 "$SYS/ens18/queues/rx-0/rps_flow_cnt"
expect "xps_cpus НЕ тронут без NA_XPS=1 (раскладка драйвера)" test -z "$(q_of ens18 tx-0/xps_cpus)"
expect "итоговая строка-маркер напечатана" grep -q '^na-rps: NIC=ens18 mask=7 cpus=3$' "$T/out"
expect "таблица маршрутов не опрашивалась вовсе" test "$(ip_calls)" -eq 0
reset_net; mk_net ens18 1
NA_XPS=1 ROUTE_AFTER=0 run_rps "$RPS" ens18
expect "NA_XPS=1 → xps_cpus проставлен" test "$(q_of ens18 tx-0/xps_cpus)" = 7
expect "NA_XPS=1 → маркер XPS" grep -q '^na-rps: NIC=ens18 xps=7$' "$T/out"

# ── Кейс (b): интерфейс переименовался после смены ядра ─────────────────────────
echo "== (b) вшитого интерфейса нет → автодетект =="
reset_net; mk_net ens18 1
ROUTE_AFTER=1 ROUTE_IFACE=ens18 run_rps "$RPS" eth0
expect "rc=0" test "$rc" -eq 0
expect "применён к найденному по маршруту ens18" test "$(mask_of ens18)" = "7"
expect "в stderr сказано, что имени нет" grep -q "не найден" "$T/err"

# ── Кейс (c): маршрут появляется на 3-м опросе (гонка на буте, issue #30) ───────
echo "== (c) default route появляется на 3-м опросе =="
reset_net; mk_net ens18 1
ROUTE_AFTER=3 ROUTE_IFACE=ens18 run_rps "$RPS"
expect "rc=0" test "$rc" -eq 0
expect "RPS всё-таки применён (не молчаливый exit 0)" test "$(mask_of ens18)" = "7"
expect "маршрут опрашивался ≥3 раз" test "$(ip_calls)" -ge 3
expect "между опросами был sleep" test -s "$REC/sleep.calls"
expect "строка-маркер в stdout" grep -q 'na-rps: NIC=ens18' "$T/out"

# ── Кейс (d): маршрута нет никогда → все физические интерфейсы ──────────────────
echo "== (d) маршрута нет → все физические NIC =="
reset_net
mk_net eth0 1; mk_net eth1 1
mk_net lo 1; mk_net docker0 1; mk_net veth1a2b 1; mk_net br-abc 1
ROUTE_AFTER=0 run_rps "$RPS"
expect "rc=0" test "$rc" -eq 0
expect "eth0 затюнен" test "$(mask_of eth0)" = "7"
expect "eth1 затюнен" test "$(mask_of eth1)" = "7"
expect "lo не тронут" test -z "$(mask_of lo)"
expect "docker0 не тронут" test -z "$(mask_of docker0)"
expect "veth не тронут" test -z "$(mask_of veth1a2b)"
expect "br- не тронут" test -z "$(mask_of br-abc)"
expect "маркер на каждый NIC" test "$(grep -c '^na-rps: NIC=' "$T/out")" -eq 2
expect "ожидание маршрута выработано полностью (20 опросов)" test "$(ip_calls)" -ge 20

# ── Кейс (e): кандидатов нет вообще → честный отказ ─────────────────────────────
echo "== (e) ни маршрута, ни физических NIC =="
reset_net
mk_net veth9z9z   # только виртуальный, без /device
ROUTE_AFTER=0 run_rps "$RPS"
expect "rc≠0 (юнит уйдёт в failed, а не в active/exited)" test "$rc" -ne 0
expect "«giving up» в stderr" grep -q "giving up" "$T/err"
expect_not "маркера успеха нет" grep -q '^na-rps: NIC=' "$T/out"

# ── Кейс (f): RX-очередей ≥ ядер — RSS уже размазывает, RPS не нужен (v4.2) ──────
echo "== (f) RX-очередей ≥ ядер: RPS не включаем, маски прошлых версий снимаем =="
reset_net; mk_queues ens18 3
ROUTE_AFTER=0 run_rps "$RPS" ens18
expect "rc=0 (это успех, а не отказ)" test "$rc" -eq 0
expect "rps_cpus снят в 0 на всех очередях" test "$(q_of ens18 rx-0/rps_cpus)$(q_of ens18 rx-2/rps_cpus)" = 00
expect "rps_flow_cnt снят в 0" test "$(q_of ens18 rx-1/rps_flow_cnt)" = 0
expect "маркер «rps=off» с причиной" grep -q '^na-rps: NIC=ens18 rps=off rxq=3 cpus=3' "$T/out"
expect "XPS прошлых версий без снимка не трогаем" test "$(q_of ens18 tx-0/xps_cpus)" = 7
# снимок optimize (первое применение) — возвращаем исходные маски, а не 0
reset_net; mk_queues ens18 3
printf '%s\t%s\n' "$SYS/ens18/queues/rx-0/rps_cpus" 5 "$SYS/ens18/queues/rx-0/rps_flow_cnt" 2048 \
    "$SYS/ens18/queues/tx-0/xps_cpus" 1 "$SYS/ens18/queues/tx-1/xps_cpus" 2 > "$T/state/rps-orig.tsv"
ROUTE_AFTER=0 run_rps "$RPS" ens18
expect "rps_cpus из снимка (5), а не 0" test "$(q_of ens18 rx-0/rps_cpus)" = 5
expect "rps_flow_cnt из снимка (2048)" test "$(q_of ens18 rx-0/rps_flow_cnt)" = 2048
expect "очередь без записи в снимке → 0" test "$(q_of ens18 rx-1/rps_cpus)" = 0
expect "XPS без NA_XPS=1 → исходная раскладка из снимка (1, 2)" test "$(q_of ens18 tx-0/xps_cpus)$(q_of ens18 tx-1/xps_cpus)" = 12
expect "очередь XPS без записи в снимке не тронута" test "$(q_of ens18 tx-2/xps_cpus)" = 7

echo "== (g) 1 vCPU: размазывать нечего =="
reset_net; mk_net ens18 1; echo 1 > "$SYS/ens18/queues/rx-0/rps_cpus"
NA_TEST_NCPU=1 ROUTE_AFTER=0 run_rps "$RPS" ens18
expect "rc=0" test "$rc" -eq 0
expect "rps_cpus=0" test "$(q_of ens18 rx-0/rps_cpus)" = 0
expect "маркер «rps=off … cpus=1»" grep -q 'rps=off rxq=1 cpus=1' "$T/out"

echo "== (h) OpenVZ: default dev venet0 scope link =="
reset_net; mk_net venet0 1
ROUTE_AFTER=1 ROUTE_LINE="default dev venet0 scope link" run_rps "$RPS"
expect "интерфейс venet0 (токен после dev, а не \$5=scope)" test "$(mask_of venet0)" = "7"
expect_not "в stderr нет «scope»" grep -q "scope" "$T/err"

# ── Юнит na-rps.service (статически по генератору) ──────────────────────────────
echo "== юнит na-rps.service =="
awk "/^cat > \/etc\/systemd\/system\/na-rps.service <<EOF\$/{f=1;next} /^EOF\$/{f=0} f" \
    "$REPO_ROOT/scripts/optimize.sh" > "$T/unit"
expect "юнит извлечён" test -s "$T/unit"
expect "ExecStart передаёт имя NIC" grep -qF 'ExecStart=/usr/local/sbin/na-rps-setup ${NIC:-}' "$T/unit"
expect "NA_XPS доезжает до юнита (Environment=)" grep -qF 'Environment=NA_XPS=${NA_XPS}' "$T/unit"
expect "Restart=on-failure" grep -qx 'Restart=on-failure' "$T/unit"
expect "RestartSec задан" grep -qx 'RestartSec=5' "$T/unit"
expect "Type=oneshot + RemainAfterExit (is-active остаётся правдой)" grep -qx 'RemainAfterExit=yes' "$T/unit"
expect "перезапуск ограничен (не долбёжка вечно)" grep -q '^StartLimitBurst=' "$T/unit"
expect "NIC детектится ДО генерации юнита" \
    test "$(grep -n 'NIC="\$(default_iface || true)"' "$REPO_ROOT/scripts/optimize.sh" | cut -d: -f1)" \
       -lt "$(grep -n 'ExecStart=/usr/local/sbin/na-rps-setup' "$REPO_ROOT/scripts/optimize.sh" | cut -d: -f1)"

# Активный oneshot `enable --now` повторно не исполняет. Гоняем саму секцию активации
# optimize.sh в этом состоянии, а не хелпер напрямую.
echo "== ре-ран при уже активном na-rps.service =="
extract_activation() {
    awk '
        /^cat > \/etc\/systemd\/system\/na-rps.service <<EOF$/ { unit=1; next }
        unit && /^EOF$/ { unit=0; activation=1; next }
        activation && /^# .* NIC tuning/ { exit }
        activation { print }
    ' "$1" > "$2"
}
extract_activation "$REPO_ROOT/scripts/optimize.sh" "$T/activation.sh"
cat > "$T/activation-driver.sh" <<'DRIVER'
. "$REPO_ROOT/scripts/lib/common.sh"
systemctl() {
    case "$1" in
        enable)
            # oneshot с RemainAfterExit=yes уже активен: enable (с --now или без)
            # ExecStart повторно не запускает.
            return 0;;
        restart)
            [ "${RPS_FORCE_FAILURE:-0}" = 1 ] && return 1
            "$WBASH" "$RPS" "$NIC";;
        *) return 0;;
    esac
}
. "$ACTIVATION"
DRIVER
run_activation() {
    REPO_ROOT="$REPO_ROOT" WBASH="$WBASH" RPS="$RPS" NIC=ens18 NA_XPS=0 \
        ACTIVATION="$1" "$WBASH" "$T/activation-driver.sh" > "$T/activation.out" 2>&1
}
reset_net; mk_net ens18 1
run_activation "$T/activation.sh"
expect "ре-ран применяет RPS даже при активном старом oneshot" test "$(mask_of ens18)" = 7
reset_net; mk_net ens18 1
RPS_FORCE_FAILURE=1 run_activation "$T/activation.sh"
expect "отказ применения — warn" grep -q 'не удалось применить RPS' "$T/activation.out"
expect_not "при отказе нет рапорта об успехе" grep -q 'na-rps применён' "$T/activation.out"
if git -C "$REPO_ROOT" show v4.1.1:scripts/optimize.sh > "$T/v411-optimize.sh" 2>/dev/null; then
    extract_activation "$T/v411-optimize.sh" "$T/v411-activation.sh"
    reset_net; mk_net ens18 1
    run_activation "$T/v411-activation.sh"
    expect "регрессия v4.1.1: активный oneshot не применён (маска пуста)" test -z "$(mask_of ens18)"
    expect "регрессия v4.1.1: при этом рапортовал успех" grep -q 'RPS/RFS/XPS включены' "$T/activation.out"
fi

# ── #28: ничего «курсорного» в не-терминал ──────────────────────────────────────
echo "== курсорный вывод только в терминал (#28) =="
expect_not "голых 'tput ' в коде optimize.sh не осталось" bare_tput "$REPO_ROOT/scripts/optimize.sh"
expect "прогресс-бар гейтится is_tty" grep -q 'is_tty || return 0' "$REPO_ROOT/scripts/optimize.sh"

{
    echo '. "$REPO_ROOT/scripts/lib/common.sh"'
    awk '/^draw_progress_bar\(\) \{/,/^\}/' "$REPO_ROOT/scripts/optimize.sh"
    awk '/^progress_end\(\) \{/,/^\}/'      "$REPO_ROOT/scripts/optimize.sh"
    echo 'tty_tput civis'
    echo 'draw_progress_bar 42 "Загрузка: linux-xanmod-lts-x64v2"'
    echo 'progress_end'
} > "$T/tty.sh"
REPO_ROOT="$REPO_ROOT" TERM=xterm "$WBASH" "$T/tty.sh" > "$T/tty.out" 2>&1
expect_not "ESC-последовательностей в перенаправленном stdout нет" \
    grep -q $'\033' "$T/tty.out"
expect "и мусорных \\r тоже нет" test ! -s "$T/tty.out"

# ── Регрессия: на коде v4.0.1 те же кейсы обязаны падать ───────────────────────
# Не в каждом чекауте есть ветка main (shallow-клон CI) — тогда просто пропускаем.
echo "== код v4.0.1 (регрессия; пропускается без тега v4.0.1) =="
if git -C "$REPO_ROOT" show v4.0.1:scripts/optimize.sh > "$T/old-optimize.sh" 2>/dev/null \
   && extract_rps "$T/old-optimize.sh" "$T/na-rps-old"; then
    reset_net; mk_net ens18 1
    ROUTE_AFTER=3 ROUTE_IFACE=ens18 run_rps "$T/na-rps-old"
    expect "(c) старый код НЕ применял RPS при опоздавшем маршруте" test -z "$(mask_of ens18)"
    expect "(c) …и рапортовал успех (rc=0) — тот самый зелёный юнит" test "$rc" -eq 0
    reset_net
    ROUTE_AFTER=0 run_rps "$T/na-rps-old"
    expect "(e) старый код выходил нулём вместо отказа" test "$rc" -eq 0
    expect "старый optimize.sh писал голый tput" bare_tput "$T/old-optimize.sh"
else
    echo "  • ветка main недоступна — сравнение с v4.0.1 пропущено"
fi

if [ "$fail" -ne 0 ]; then echo "RPS-UNIT: FAIL"; exit 1; fi
echo "RPS-UNIT: OK (NIC из ExecStart, ожидание маршрута, фолбэк на физические, честный отказ, юнит с Restart=, без escape-кодов в логах)"
