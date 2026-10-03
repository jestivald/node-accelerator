#!/usr/bin/env bash
#
# optimize-unit.sh — ИСПОЛНЯЕТ секции optimize.sh (sysctl, journald, снимки RPS/THP,
# проверки ядра XanMod), блок отката runtime из rollback.sh и хелперы common.sh
# (default_iface, apt_install) в песочнице против стабов sysctl/ss/systemctl/mokutil/df.
# Секции — top-level код, целиком optimize в CI не гоняется: тот же приём, что в
# logrotate-unit.sh / psi-unit.sh.
#
# Что стережём (v4.2, аудит флота):
#   1. sysctl: чужой файл, сортирующийся позже нашего (99-tuning.conf), перебивает ключ —
#      optimize называет виновника, а не печатает «применено»; ключ, который ядро не дало
#      записать, — отдельное предупреждение; работает и через `systemd-analyze cat-config`;
#   2. ip_local_reserved_ports: LISTEN-порты xray (включая 127.0.0.1:10085) внутри
#      эфемерного диапазона резервируются, резерв оператора не затирается, а порт, с которого
#      xray ушёл, на ре-ране снимается;
#   3. net.ipv6.conf.all.forwarding больше не ставится (RA на ядерном SLAAC);
#   4. снимок исходных значений sysctl — только при ПЕРВОМ применении, ре-ран его не портит;
#      откат возвращает runtime (sysctl, маски RPS/XPS, THP) без ребута;
#   5. journald: drop-in 10-na-size.conf (операторский 99-* главнее), старый na-size.conf
#      снимается; volatile-журнал → Storage=persistent, но явный Storage= оператора не трогаем;
#   6. XanMod: Secure Boot и тесный /boot — отказ от ядра; после установки — initrd и драйвер
#      текущего NIC в /lib/modules/<версия> до рапорта «нужна перезагрузка»;
#   7. common: default_iface берёт токен после `dev` (OpenVZ venet0, multipath);
#      apt_install ждёт чужой dpkg-лок (DPkg::Lock::Timeout), а не падает сразу.
#
# Не требует root/сети/systemd. Запуск: bash tests/optimize-unit.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap '[ -n "${KEEP:-}" ] || rm -rf "$T"' EXIT
export NA_T="$T"
OPT="$REPO_ROOT/scripts/optimize.sh"

pick_bash() {
    local c
    for c in bash /opt/homebrew/bin/bash /usr/local/bin/bash; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" -c 'set -u; a=(); : "${a[@]}"; [[ -v HOME ]]' 2>/dev/null; then command -v "$c"; return 0; fi
    done
    return 1
}
WBASH="$(pick_bash)" || { echo "[x] не нашёл bash ≥ 4.4"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "[x] нужен python3 (стаб sysctl)"; exit 1; }

fail=0
# tsv_has <файл> <ключ> <значение> — строка «ключ<TAB>значение» (grep -P есть не везде)
tsv_has() { awk -F'\t' -v k="$2" -v v="$3" '$1 == k && substr($0, length(k) + 2) == v { f = 1 } END { exit !f }' "$1"; }
expect()     { local d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  ✔ $d"; else echo "  ✘ $d"; fail=1; fi; }
expect_not() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  ✘ $d"; fail=1; else echo "  ✔ $d"; fi; }

BIN="$T/bin"; REC="$T/rec"; export REC
mkdir -p "$BIN" "$REC" "$T/state" "$T/backup" "$T/etc/sysctl.d" "$T/etc/modules-load.d" \
         "$T/usr/lib/sysctl.d" "$T/proc/sys" "$T/conf"

# ── Стабы ───────────────────────────────────────────────────────────────────────
# sysctl: `-n` читает песочный /proc/sys; `--system` применяет файлы в порядке procps/
# systemd-sysctl (по ИМЕНИ через каталоги, /etc главнее, /etc/sysctl.conf последним).
# NA_TEST_RO — ключи, которые «ядро» записать не даёт (контейнер).
cat > "$BIN/sysctl" <<'SY'
#!/usr/bin/env python3
import glob, os, sys
T = os.environ["NA_T"]
def path(k): return os.path.join(T, "proc/sys", k.replace(".", "/"))
a = sys.argv[1:]
if a[:1] == ["-n"]:
    p = path(a[1])
    if not os.path.exists(p): sys.exit(1)
    print(open(p).read().rstrip("\n")); sys.exit(0)
if a[:1] == ["--system"]:
    ro = set(filter(None, os.environ.get("NA_TEST_RO", "").split(",")))
    seen = {}
    for d in ["etc/sysctl.d", "run/sysctl.d", "usr/local/lib/sysctl.d", "usr/lib/sysctl.d", "lib/sysctl.d"]:
        for f in glob.glob(os.path.join(T, d, "*.conf")):
            seen.setdefault(os.path.basename(f), f)
    files = [seen[b] for b in sorted(seen)]
    if os.path.exists(os.path.join(T, "etc/sysctl.conf")): files.append(os.path.join(T, "etc/sysctl.conf"))
    with open(os.path.join(T, "rec/sysctl-order"), "w") as o: o.write("\n".join(files) + "\n")
    for f in files:
        for line in open(f):
            line = line.strip()
            if not line or line[0] in "#;" or "=" not in line: continue
            k, v = line.split("=", 1)
            k = k.strip().lstrip("-").replace("/", "."); v = " ".join(v.split())
            p = path(k)
            if k in ro or not os.path.exists(p): continue
            open(p, "w").write(v.replace(" ", "\t") + "\n")
    sys.exit(0)
sys.exit(1)
SY
# systemd-analyze: по умолчанию «нет» (фолбэк на перебор каталогов); NA_TEST_SA=1 —
# печатает cat-config как настоящий: заголовок «# <путь>» + содержимое, в порядке применения
cat > "$BIN/systemd-analyze" <<'SA'
#!/bin/sh
[ "${NA_TEST_SA:-0}" = 1 ] || exit 1
[ "$1 $2" = "cat-config sysctl.d" ] || exit 1
for f in $(cat "$NA_T/rec/sa-order"); do printf '# %s\n' "$f"; cat "$f"; echo; done
SA
cat > "$BIN/ss" <<'SS'
#!/bin/sh
case "$*" in
  "-Htlnp") [ -f "$NA_T/ss-t" ] && cat "$NA_T/ss-t" ;;
  "-Hulnp") [ -f "$NA_T/ss-u" ] && cat "$NA_T/ss-u" ;;
esac
exit 0
SS
printf '#!/bin/sh\nexit 1\n' > "$BIN/docker"
printf '#!/bin/sh\nexit 0\n' > "$BIN/modprobe"
cat > "$BIN/systemctl" <<'SC'
#!/bin/sh
echo "systemctl $*" >> "$REC/calls"
exit 0
SC
cat > "$BIN/journalctl" <<'JC'
#!/bin/sh
echo "journalctl $*" >> "$REC/calls"
exit 0
JC
printf '#!/bin/sh\nexit 0\n' > "$BIN/systemd-tmpfiles"
# date -Is (GNU) — для маркеров; на BSD date его нет
cat > "$BIN/date" <<'DT'
#!/bin/sh
[ "$1" = "-Is" ] && { /bin/date -u +%Y-%m-%dT%H:%M:%S+00:00; exit 0; }
exec /bin/date "$@"
DT
chmod +x "$BIN"/*
export PATH="$BIN:$PATH"

# GNU/BSD sed: секции пишут `sed -i` без суффикса — на macOS заворачиваем
REAL_SED="$(command -v sed)"

# ════════════════════════════════════════════════════════════════════════════
echo "== 1. sysctl: снимок, резерв портов, сверка с перебивающим файлом =="
# ════════════════════════════════════════════════════════════════════════════
awk '/^# ─── 3\. Sysctl/{f=1} /^# ─── 4\. Лимиты/{f=0} f' "$OPT" \
  | "$REAL_SED" -e "s#/etc/sysctl\.d#$T/etc/sysctl.d#g" \
                -e "s#/etc/sysctl\.conf#$T/etc/sysctl.conf#g" \
                -e "s#/run/sysctl\.d#$T/run/sysctl.d#g" \
                -e "s#/usr/local/lib/sysctl\.d#$T/usr/local/lib/sysctl.d#g" \
                -e "s#/usr/lib/sysctl\.d#$T/usr/lib/sysctl.d#g" \
                -e "s# /lib/sysctl\.d# $T/lib/sysctl.d#g" \
                -e "s#/etc/modules-load\.d#$T/etc/modules-load.d#g" \
                -e "s#/proc/sys/#$T/proc/sys/#g" \
                -e "s#/proc/meminfo#$T/proc/meminfo#g" > "$T/sysctl-section.sh"
[ -s "$T/sysctl-section.sh" ] || { echo "[x] не смог извлечь секцию 3 из optimize.sh"; exit 1; }
cat > "$T/wrap-sysctl.sh" <<WRAP
#!/usr/bin/env bash
set -euo pipefail
. "$REPO_ROOT/scripts/lib/common.sh"
STATE_DIR="$T/state"; CONF_DIR="$T/conf"; BACKUP="$T/backup"
NA_REMNANODE_ENV="$T/no-such.env"
. "$T/sysctl-section.sh"
WRAP
printf 'MemTotal:  2048000 kB\n' > "$T/proc/meminfo"
# «ядро»: ключи, которые есть в этом ядре, со стоковыми значениями
kset() { mkdir -p "$T/proc/sys/$(dirname "${1//.//}")"; printf '%s\n' "$2" > "$T/proc/sys/${1//.//}"; }
kget() { cat "$T/proc/sys/${1//.//}" 2>/dev/null; }
kset net.core.rmem_max 212992
kset net.core.wmem_max 212992
kset net.core.rmem_default 212992
kset net.ipv4.tcp_congestion_control cubic
kset net.ipv4.tcp_rmem $'4096\t131072\t6291456'
kset net.ipv4.ip_local_port_range $'32768\t60999'
kset net.ipv4.ip_local_reserved_ports "20000-20010"
kset net.ipv6.conf.all.forwarding 0
kset vm.swappiness 60
kset net.netfilter.nf_conntrack_max 65536
# xray слушает 0.0.0.0:443 и API на 127.0.0.1:10085, node-агент — 2222 (ниже диапазона)
cat > "$T/ss-t" <<'L'
LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=10,fd=7))
LISTEN 0 4096 127.0.0.1:10085 0.0.0.0:* users:(("xray",pid=10,fd=8))
LISTEN 0 511 0.0.0.0:2222 0.0.0.0:* users:(("rw-node",pid=11,fd=3))
LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
L
# + исходящие UDP-сокеты xray на эфемерных портах — резервировать их нельзя
{ printf 'UNCONN 0 0 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=10,fd=9))\n'
  printf 'UNCONN 0 0 *:40404 *:* users:(("rw-core",pid=10,fd=31))\n'; } > "$T/ss-u"
# чужой файл сортируется ПОЗЖЕ нашего (t > n) и урезает буфер
printf 'net.core.rmem_max = 16777216\n' > "$T/etc/sysctl.d/99-tuning.conf"
run_sysctl() { rc=0; "$WBASH" "$T/wrap-sysctl.sh" > "$T/out" 2>&1 || rc=$?; return 0; }
NA_TEST_RO=vm.swappiness run_sysctl
F="$T/etc/sysctl.d/99-node-accelerator.conf"
expect "секция отработала (rc=0)" test "$rc" -eq 0
expect "файл записан" test -s "$F"
expect_not "временный кандидат не остался" compgen -G "$T/etc/sysctl.d/.na-sysctl*"
expect_not "net.ipv6.conf.all.forwarding больше не ставится" grep -qE '^[[:space:]]*net\.ipv6\.conf\.all\.forwarding' "$F"
expect "net.ipv4.ip_forward на месте" grep -qE '^net.ipv4.ip_forward[[:space:]]+= 1' "$F"
expect "резерв: порт xray 10085 (127.0.0.1) + резерв оператора" grep -qE '^net.ipv4.ip_local_reserved_ports = 10085,20000-20010$' "$F"
expect_not "резерв: 443 и 2222 ниже диапазона — не резервируются" grep -qE 'reserved_ports = .*(443|2222)' "$F"
expect_not "резерв: исходящий UDP-сокет xray (40404) не резервируется" grep -qE 'reserved_ports = .*40404' "$F"
expect "состояние: наши порты = 10085" grep -qx 10085 "$T/state/reserved-ports.na"
expect "снимок исходных значений создан" test -s "$T/state/sysctl.orig"
expect "снимок: rmem_max = сток 212992" tsv_has "$T/state/sysctl.orig" net.core.rmem_max 212992
expect "снимок: cc = cubic" tsv_has "$T/state/sysctl.orig" net.ipv4.tcp_congestion_control cubic
expect "снимок: многозначный tcp_rmem целиком" tsv_has "$T/state/sysctl.orig" net.ipv4.tcp_rmem $'4096\t131072\t6291456'
expect "снимок: резерв оператора" tsv_has "$T/state/sysctl.orig" net.ipv4.ip_local_reserved_ports 20000-20010
expect_not "снимок: ключа, которого нет в ядре, нет" grep -q 'tcp_notsent_lowat' "$T/state/sysctl.orig"
expect "сверка: виновник назван (99-tuning.conf)" grep -q 'net.core.rmem_max = 16777216, а .*99-node-accelerator.conf ставит 33554432 — перебивает .*99-tuning.conf' "$T/out"
expect "сверка: незаписанный ключ — отдельный warn" grep -q 'не применились (ядро/контейнер не дал записать?): vm.swappiness=60' "$T/out"
expect_not "сверка: «действуют» не печатается при расхождении" grep -q 'значения наших файлов действуют' "$T/out"
expect "в ядре наш резерв" test "$(kget net.ipv4.ip_local_reserved_ports)" = "10085,20000-20010"

echo "== 1b. ре-ран: снимок не портится, ушедший порт xray снимается =="
cp "$T/state/sysctl.orig" "$T/orig.first" 2>/dev/null || : > "$T/orig.first"
"$REAL_SED" -e 's/:10085 /:10086 /' "$T/ss-t" > "$T/ss-t.new" && mv "$T/ss-t.new" "$T/ss-t"
rm -f "$T/etc/sysctl.d/99-tuning.conf"
run_sysctl
expect "rc=0" test "$rc" -eq 0
expect "снимок не перезаписан ре-раном" cmp -s "$T/orig.first" "$T/state/sysctl.orig"
expect "резерв: 10085 снят, 10086 добавлен, оператор сохранён" grep -qE '^net.ipv4.ip_local_reserved_ports = 10086,20000-20010$' "$F"
expect "без перебивающего файла и RO-ключей — «действуют»" grep -q 'значения наших файлов действуют' "$T/out"

echo "== 1c. сверка через systemd-analyze cat-config =="
printf 'net.core.wmem_max = 4194304\n' > "$T/etc/sysctl.d/99-zz-ops.conf"
printf '#\n# /etc/sysctl.conf - Configuration file for setting system variables\n' > "$T/etc/sysctl.conf"
printf '%s\n' "$T/etc/sysctl.d/99-node-accelerator-conntrack.conf" "$T/etc/sysctl.d/99-node-accelerator.conf" \
              "$T/etc/sysctl.d/99-zz-ops.conf" "$T/etc/sysctl.conf" > "$REC/sa-order"
NA_TEST_SA=1 run_sysctl
expect "виновник найден по cat-config" grep -q 'net.core.wmem_max = 4194304, а .* — перебивает .*99-zz-ops.conf' "$T/out"
expect_not "шапка /etc/sysctl.conf не принята за файл" grep -q 'Configuration file for' "$T/out"
rm -f "$T/etc/sysctl.d/99-zz-ops.conf" "$T/etc/sysctl.conf"

echo "== 1d. снимок НЕ снимается, если наш файл уже стоял (апгрейд с ≤4.1) =="
rm -f "$T/state/sysctl.orig"
run_sysctl
expect_not "наш файл есть, снимка не было → не создаём (в ядре уже наши значения)" test -e "$T/state/sysctl.orig"

# ════════════════════════════════════════════════════════════════════════════
echo "== 2. journald: 10-na-size.conf, volatile → persistent, явный Storage оператора =="
# ════════════════════════════════════════════════════════════════════════════
JD="$T/etc/systemd/journald.conf.d"
awk '/^# ─── 8\. journald cap/{f=1} /^# ─── 8b\./{f=0} f' "$OPT" \
  | "$REAL_SED" -e "s#/etc/systemd/journald\.conf#$T/etc/systemd/journald.conf#g" \
                -e "s#/run/systemd/journald\.conf\.d#$T/run/systemd/journald.conf.d#g" \
                -e "s#/usr/local/lib/systemd/journald\.conf\.d#$T/usr/local/lib/systemd/journald.conf.d#g" \
                -e "s#/usr/lib/systemd/journald\.conf\.d#$T/usr/lib/systemd/journald.conf.d#g" \
                -e "s#/run/log/journal#$T/run/log/journal#g" \
                -e "s#/var/log/journal#$T/var/log/journal#g" > "$T/jd-section.sh"
[ -s "$T/jd-section.sh" ] || { echo "[x] не смог извлечь секцию 8 из optimize.sh"; exit 1; }
cat > "$T/wrap-jd.sh" <<WRAP
#!/usr/bin/env bash
set -euo pipefail
. "$REPO_ROOT/scripts/lib/common.sh"
STATE_DIR="$T/state"; BACKUP="$T/backup"
. "$T/jd-section.sh"
WRAP
run_jd() { rc=0; : > "$REC/calls"; "$WBASH" "$T/wrap-jd.sh" > "$T/out" 2>&1 || rc=$?; return 0; }
mkdir -p "$JD" "$T/run/log/journal"
printf '[Journal]\nSystemMaxUse=300M\n' > "$JD/na-size.conf"
printf '[Journal]\nSystemMaxUse=2G\n' > "$JD/99-ops.conf"
run_jd
expect "rc=0" test "$rc" -eq 0
expect "новый drop-in 10-na-size.conf" test -s "$JD/10-na-size.conf"
expect "старый na-size.conf снят" test ! -e "$JD/na-size.conf"
expect "старый — в бэкапе" test -f "$T/backup/na-size.conf"
expect "операторский 99-ops.conf сортируется ПОСЛЕ нашего (он главнее)" \
    test "$(printf '%s\n' "$JD"/*.conf | LC_ALL=C sort | tail -1)" = "$JD/99-ops.conf"
expect "volatile → Storage=persistent" grep -qx 'Storage=persistent' "$JD/10-na-size.conf"
expect "каталог /var/log/journal создан" test -d "$T/var/log/journal"
expect "накопленное в RAM перенесено (journalctl --flush)" grep -q 'journalctl --flush' "$REC/calls"
expect "маркер «persistent включили мы»" test -f "$T/state/journald.persistent"
run_jd
expect "ре-ран: Storage=persistent сохраняется (маркер)" grep -qx 'Storage=persistent' "$JD/10-na-size.conf"
rm -rf "$T/var/log/journal" "$T/state/journald.persistent"
mkdir -p "$T/etc/systemd"; printf '[Journal]\nStorage=volatile\n' > "$T/etc/systemd/journald.conf"
run_jd
expect "явный Storage=volatile оператора — не трогаем" test ! -d "$T/var/log/journal"
expect_not "…и Storage в нашем drop-in нет" grep -q '^Storage=' "$JD/10-na-size.conf"
expect "…с пояснением" grep -q 'Storage= задан явно' "$T/out"
# явный Storage= оператора при уже постоянном журнале — тоже не трогаем и не падаем
mkdir -p "$T/var/log/journal"
run_jd
expect "явный Storage + persistent-журнал: rc=0" test "$rc" -eq 0
rm -f "$T/etc/systemd/journald.conf"; rm -rf "$T/run/log/journal"
run_jd
expect_not "журнал уже persistent — Storage не пишем" grep -q '^Storage=' "$JD/10-na-size.conf"

# ════════════════════════════════════════════════════════════════════════════
echo "== 3. снимки RPS/XPS и THP при первом применении =="
# ════════════════════════════════════════════════════════════════════════════
SYSN="$T/sys/class/net"
for n in ens18 lo veth1 zz0; do
    mkdir -p "$SYSN/$n/queues/rx-0" "$SYSN/$n/queues/tx-0"
    echo 0 > "$SYSN/$n/queues/rx-0/rps_cpus"; echo 0 > "$SYSN/$n/queues/rx-0/rps_flow_cnt"
    echo 3 > "$SYSN/$n/queues/tx-0/xps_cpus"
done
# у последнего по глобу интерфейса xps_cpus пустой (так бывает у одноочередных драйверов)
: > "$SYSN/zz0/queues/tx-0/xps_cpus"
mkdir -p "$T/sys/kernel/mm/transparent_hugepage" "$T/sbin"
echo 'always [madvise] never' > "$T/sys/kernel/mm/transparent_hugepage/enabled"
echo 'always defer [defer+madvise] madvise never' > "$T/sys/kernel/mm/transparent_hugepage/defrag"
{ awk '/^RPS_ORIG=/{f=1} f{print} f && /^fi$/{exit}' "$OPT"
  awk '/^THP_ORIG=/{f=1} f{print} f && /^fi$/{exit}' "$OPT"; } \
  | "$REAL_SED" -e "s#/sys/class/net#$SYSN#g" -e "s#/sys/kernel/mm#$T/sys/kernel/mm#g" \
                -e "s#/usr/local/sbin/na-rps-setup#$T/sbin/na-rps-setup#g" \
                -e "s#/etc/systemd/system/#$T/sbin/#g" > "$T/snap-section.sh"
cat > "$T/wrap-snap.sh" <<WRAP
#!/usr/bin/env bash
set -euo pipefail
. "$REPO_ROOT/scripts/lib/common.sh"
STATE_DIR="$T/state"
. "$T/snap-section.sh"
WRAP
rc=0; "$WBASH" "$T/wrap-snap.sh" > "$T/out" 2>&1 || rc=$?
expect "rc=0" test "$rc" -eq 0
expect "снимок масок: ens18 rx/tx" tsv_has "$T/state/rps-orig.tsv" "$SYSN/ens18/queues/tx-0/xps_cpus" 3
expect_not "снимок масок: lo/veth мимо" grep -qE '/(lo|veth1)/' "$T/state/rps-orig.tsv"
expect "снимок не выброшен из-за пустой маски последней очереди" tsv_has "$T/state/rps-orig.tsv" "$SYSN/zz0/queues/rx-0/rps_cpus" 0
expect "снимок THP: enabled=madvise" tsv_has "$T/state/thp.orig" enabled madvise
expect "снимок THP: defrag=defer+madvise" tsv_has "$T/state/thp.orig" defrag defer+madvise
{ cp "$T/state/rps-orig.tsv" "$T/rps.first" 2>/dev/null || : > "$T/rps.first"; }; echo 7 > "$SYSN/ens18/queues/tx-0/xps_cpus"
: > "$T/sbin/na-rps-setup"; rm -f "$T/state/rps-orig.tsv"
"$WBASH" "$T/wrap-snap.sh" > "$T/out" 2>&1 || true
expect_not "хелпер уже стоял (ре-ран/апгрейд) — снимок не снимаем" test -e "$T/state/rps-orig.tsv"

# ════════════════════════════════════════════════════════════════════════════
echo "== 4. rollback optimize: runtime возвращается без ребута =="
# ════════════════════════════════════════════════════════════════════════════
awk '/^    # ── Runtime без ребута/{f=1} f{print} f && /reserved-ports\.na" "\$STATE_DIR\/journald\.persistent"$/{exit}' \
    "$REPO_ROOT/scripts/rollback.sh" \
  | "$REAL_SED" -e "s#/proc/sys/#$T/proc/sys/#g" -e "s#/sys/class/net#$SYSN#g" \
                -e "s#/sys/kernel/mm#$T/sys/kernel/mm#g" > "$T/rb-section.sh"
[ -s "$T/rb-section.sh" ] || { echo "  ✘ не смог извлечь блок runtime из rollback.sh"; fail=1; }
cat > "$T/wrap-rb.sh" <<WRAP
#!/usr/bin/env bash
set -uo pipefail
. "$REPO_ROOT/scripts/lib/common.sh"
STATE_DIR="$T/state"
rb() {
. "$T/rb-section.sh"
echo "RT=\$rt"
}
rb
WRAP
# rollback сначала удаляет наши файлы (как в rollback_optimize), в ядре — наши значения,
# в снимках — исходные
rm -f "$T/etc/sysctl.d/99-node-accelerator.conf" "$T/etc/sysctl.d/99-node-accelerator-conntrack.conf"
kset net.ipv4.tcp_congestion_control bbr
kset net.ipv4.tcp_rmem $'4096\t87380\t33554432'
cp "$T/orig.first" "$T/state/sysctl.orig"
cp "$T/rps.first" "$T/state/rps-orig.tsv"
echo never > "$T/sys/kernel/mm/transparent_hugepage/enabled"
printf 'nic=ens18\n' > "$T/state/optimize.installed"
"$WBASH" "$T/wrap-rb.sh" > "$T/out" 2>&1 || true
expect "sysctl: cc вернулся к cubic" test "$(kget net.ipv4.tcp_congestion_control)" = cubic
expect "sysctl: многозначный tcp_rmem вернулся" test "$(kget net.ipv4.tcp_rmem | tr '\t' ' ')" = "4096 131072 6291456"
expect "sysctl: резерв оператора вернулся" test "$(kget net.ipv4.ip_local_reserved_ports)" = "20000-20010"
expect "XPS: маска из снимка (3)" test "$(cat "$SYSN/ens18/queues/tx-0/xps_cpus")" = 3
expect "THP: madvise из снимка" grep -qx madvise "$T/sys/kernel/mm/transparent_hugepage/enabled"
expect "честное сообщение: ключи из снимка" grep -q 'RT=sysctl — .* ключ(ей) возвращены к значениям до первого прогона' "$T/out"
expect "снимки убраны" test ! -e "$T/state/sysctl.orig" -a ! -e "$T/state/rps-orig.tsv" -a ! -e "$T/state/thp.orig"
# без снимков (optimize ставился до v4.2): RPS — в 0 по nic из маркера, честно про остальное
echo f > "$SYSN/ens18/queues/rx-0/rps_cpus"
"$WBASH" "$T/wrap-rb.sh" > "$T/out" 2>&1 || true
expect "без снимка: rps_cpus в 0 (дефолт ядра)" test "$(cat "$SYSN/ens18/queues/rx-0/rps_cpus")" = 0
expect "без снимка: сказано, что sysctl держит наши значения до ребута" grep -q 'снимка нет (optimize ставился до v4.2)' "$T/out"
expect "без снимка: про THP — до ребута" grep -q 'THP — never до ребута' "$T/out"
expect "rollback снимает оба имени journald drop-in" \
    grep -q 'rm -f /etc/systemd/journald.conf.d/10-na-size.conf /etc/systemd/journald.conf.d/na-size.conf' "$REPO_ROOT/scripts/rollback.sh"

# ════════════════════════════════════════════════════════════════════════════
echo "== 5. XanMod: Secure Boot, место в /boot, готовность нового ядра =="
# ════════════════════════════════════════════════════════════════════════════
awk '/^NA_SB_EFIVAR=/{f=1} /^install_xanmod\(\) \{/{f=0} f' "$OPT" \
  | "$REAL_SED" -e "s#/sys/firmware#$T/sys/firmware#g" -e "s#/boot/#$T/boot/#g" \
                -e "s#/lib/modules#$T/lib/modules#g" -e "s#/sys/class/net#$SYSN#g" > "$T/xm-section.sh"
[ -s "$T/xm-section.sh" ] || { echo "  ✘ не смог извлечь проверки XanMod из optimize.sh"; fail=1; }
cat > "$BIN/df" <<'DF'
#!/bin/sh
echo "Filesystem 1M-blocks Used Available Capacity Mounted on"
echo "/dev/vda1 1000 100 ${NA_TEST_BOOT_FREE:-900} 10% /boot"
DF
cat > "$BIN/dpkg-query" <<'DQ'
#!/bin/sh
echo "linux-image-6.18.52-x64v3-xanmod1, linux-headers-6.18.52-x64v3-xanmod1"
DQ
cat > "$BIN/update-initramfs" <<'UI'
#!/bin/sh
echo "update-initramfs $*" >> "$REC/calls"
[ "${NA_TEST_INITRD_FIX:-0}" = 1 ] && echo x > "$NA_T/boot/initrd.img-$3"
exit 0
UI
chmod +x "$BIN/df" "$BIN/dpkg-query" "$BIN/update-initramfs"
cat > "$T/wrap-xm.sh" <<WRAP
#!/usr/bin/env bash
set -euo pipefail
. "$REPO_ROOT/scripts/lib/common.sh"
. "$T/xm-section.sh"
case "\$1" in
  pre)  xanmod_preflight ;;
  post) v="\$(xanmod_kver linux-xanmod-x64v3)"; echo "KVER=\$v"; why="\$(xanmod_postcheck "\$v" ens18)" && echo READY || echo "RISK=\$why" ;;
esac
WRAP
xm() { rc=0; : > "$REC/calls"; "$WBASH" "$T/wrap-xm.sh" "$@" > "$T/out" 2>&1 || rc=$?; return 0; }
mkdir -p "$T/sys/firmware/efi/efivars" "$T/boot"
printf '#!/bin/sh\necho "SecureBoot enabled"\n' > "$BIN/mokutil"; chmod +x "$BIN/mokutil"
xm pre
expect "Secure Boot (mokutil) → отказ от ядра" test "$rc" -ne 0
expect "…с причиной" grep -q 'UEFI Secure Boot включён' "$T/out"
# mokutil «не знает» (как на BIOS/без efivars) — решает efivar. Не удаляем стаб: на
# CI-раннере может стоять настоящий mokutil со своим ответом про Secure Boot.
printf '#!/bin/sh\necho "EFI variables are not supported on this system"\nexit 1\n' > "$BIN/mokutil"
EV="$T/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
printf '\007\000\000\000\001' > "$EV"
xm pre
expect "Secure Boot (efivar, без mokutil) → отказ" test "$rc" -ne 0
printf '\007\000\000\000\000' > "$EV"
xm pre
expect "Secure Boot выключен, места хватает → можно" test "$rc" -eq 0
NA_TEST_BOOT_FREE=150 xm pre
expect "/boot: 150 МБ → отказ" test "$rc" -ne 0
expect "…с причиной и подсказкой" grep -q 'свободно 150 МБ (нужно ≥ 200)' "$T/out"
# новое ядро: initrd + драйвер NIC текущего интерфейса
KV=6.18.52-x64v3-xanmod1
mkdir -p "$SYSN/ens18/device" "$T/lib/modules/$KV/kernel/drivers/net"
ln -sfn ../../../bus/virtio/drivers/virtio_net "$SYSN/ens18/device/driver"
echo x > "$T/boot/initrd.img-$KV"
: > "$T/lib/modules/$KV/kernel/drivers/net/virtio_net.ko.zst"
xm post
expect "версия ядра из Depends мета-пакета" grep -qx "KVER=$KV" "$T/out"
expect "initrd + virtio_net на месте → READY" grep -qx READY "$T/out"
rm -f "$T/lib/modules/$KV/kernel/drivers/net/virtio_net.ko.zst"
xm post
expect "драйвера NIC нет → риск назван" grep -q 'RISK=драйвера NIC ens18 (virtio_net) нет' "$T/out"
printf 'kernel/drivers/net/virtio_net.ko\n' > "$T/lib/modules/$KV/modules.builtin"
xm post
expect "драйвер встроен (modules.builtin) → READY" grep -qx READY "$T/out"
rm -f "$T/boot/initrd.img-$KV"
xm post
expect "нет initrd → пробуем пересобрать (update-initramfs -c -k)" grep -q "update-initramfs -c -k $KV" "$REC/calls"
expect "…не вышло → риск назван" grep -q "RISK=нет $T/boot/initrd.img-$KV" "$T/out"
NA_TEST_INITRD_FIX=1 xm post
expect "пересборка initrd удалась → READY" grep -qx READY "$T/out"
expect "установка ядра идёт только после предполётной проверки" grep -q 'elif xanmod_preflight; then' "$OPT"
expect "риск печатается до рапорта «нужна перезагрузка»" grep -q 'НЕ ПЕРЕЗАГРУЖАЙСЯ, пока не исправлено' "$OPT"

# ════════════════════════════════════════════════════════════════════════════
echo "== 6. common: default_iface и apt_install =="
# ════════════════════════════════════════════════════════════════════════════
cat > "$T/wrap-common.sh" <<WRAP
#!/usr/bin/env bash
set -euo pipefail
. "$REPO_ROOT/scripts/lib/common.sh"
ip() { printf '%s\n' "\$NA_ROUTE"; }
case "\$1" in
  iface) default_iface ;;
  apt)   apt_install foo bar ;;
esac
WRAP
iface() { NA_ROUTE="$1" "$WBASH" "$T/wrap-common.sh" iface 2>/dev/null; }
expect "обычный маршрут → eth0"      test "$(iface 'default via 10.0.0.1 dev eth0 proto static metric 100')" = eth0
expect "OpenVZ: default dev venet0 scope link → venet0" test "$(iface 'default dev venet0 scope link')" = venet0
expect "multipath → первый nexthop dev" \
    test "$(iface 'default proto static metric 100 nexthop via 10.0.0.1 dev ens3 weight 1 nexthop via 10.0.1.1 dev ens4 weight 1')" = ens3
expect "маршрута нет → пусто" test -z "$(iface '')"
cat > "$BIN/apt-get" <<'AG'
#!/bin/sh
echo "apt-get $*" >> "$REC/apt"
case "$*" in *" install "*) [ "${NA_TEST_APT_FAIL_ONCE:-0}" = 1 ] && [ ! -e "$REC/apt.failed" ] && { : > "$REC/apt.failed"; exit 100; } ;; esac
exit 0
AG
printf '#!/bin/sh\nexit 0\n' > "$BIN/dpkg"; chmod +x "$BIN/apt-get" "$BIN/dpkg"
: > "$REC/apt"
rc=0; "$WBASH" "$T/wrap-common.sh" apt > "$T/out" 2>&1 || rc=$?
expect "apt_install rc=0" test "$rc" -eq 0
expect "install ждёт чужой dpkg-лок (DPkg::Lock::Timeout=120)" grep -q 'apt-get -o DPkg::Lock::Timeout=120 install -y -qq --no-install-recommends foo bar' "$REC/apt"
expect "update — тоже с таймаутом лока" grep -q 'apt-get -o DPkg::Lock::Timeout=120 update' "$REC/apt"
: > "$REC/apt"; rm -f "$REC/apt.failed"
rc=0; NA_TEST_APT_FAIL_ONCE=1 "$WBASH" "$T/wrap-common.sh" apt > "$T/out" 2>&1 || rc=$?
expect "ретрай после неудачи тоже с таймаутом лока" test "$(grep -c 'DPkg::Lock::Timeout=120 install -y -qq --no-install-recommends foo bar' "$REC/apt")" -eq 2
expect_not "ни одного вызова apt-get без таймаута лока" grep -qv 'DPkg::Lock::Timeout=120' "$REC/apt"

if [ "$fail" -ne 0 ]; then echo "OPTIMIZE-UNIT: FAIL"; exit 1; fi
echo "OPTIMIZE-UNIT: OK (sysctl: виновник назван, резерв портов, снимок только при первом прогоне; journald 10-*, persistent; откат runtime; XanMod: Secure Boot//boot/initrd/драйвер NIC; default_iface после dev; apt ждёт лок)"
