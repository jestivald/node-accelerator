#!/usr/bin/env bash
#
# diagnose-unit.sh — ИСПОЛНЯЕТ scripts/diagnose.sh (обе ветки: --json и человекочитаемую)
# в песочнице против стабов docker/nft/ss/cscli/journalctl/systemctl. diagnose read-only,
# но целиком в CI не гонялся никогда — поэтому весь урожай аудита боевого флота v4.0.1
# (11 нод + панель) собран именно здесь.
#
# Что стережём (issue → проверка):
#   #27 docker inspect по несуществующему контейнеру печатает "\n" ДО ошибки → статус
#       должен быть absent (а не "\nabsent"), --json обязан парситься, ✘ «node-агент
#       лежит» не печататься; NA_NODE_CONTAINER переключает имя контейнера;
#   #30 юнит na-rps active при пустом rps_cpus — это ▲ «гонка на буте», а не ✔;
#   #31 датчик CONN_LIMIT считает ТОЛЬКО входящие на порты правила, без loopback и
#       вайтлиста (иначе вечная ложная тревога на любой ноде с nginx↔xray);
#   #32 счётчики autoban/suspect считают АДРЕСА, а не строки вывода nft (пустой набор =
#       0, не 1), при ненулевом autoban печатаются сами адреса; CrowdSec decisions без
#       строки-заголовка CSV;
#   #34 conf, пиннящий устаревший дефолт (CROWDSEC_STRICT=0), виден как ▲;
#   #35 глубина журнала во времени + объём лога анти-скана;
#   #37 PSI: «собран, но выключен по умолчанию» ≠ «старое ядро»;
#   #38 whitelist сверяется с ТРЕМЯ источниками: дрейф относительно protect.conf назван
#       по адресу и опознан как IP текущей сессии;
#   #39 серт в /opt/<стек>/certs/*/ находится, серт acme.sh, снятый с renew, — нет.
#
# Не требует root/сети/nft/docker. Запуск: bash tests/diagnose-unit.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

# diagnose и хелперам нужен bash ≥ 4.2 ([[ -v ]], пустые массивы под set -u) — на нодах и
# в CI он есть всегда, системный bash macOS древний: берём первый подходящий.
pick_bash() {
    local c
    for c in bash /opt/homebrew/bin/bash /usr/local/bin/bash; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" -c 'set -u; a=(); : "${a[@]}"; [[ -v HOME ]]' 2>/dev/null; then command -v "$c"; return 0; fi
    done
    return 1
}
WBASH="$(pick_bash)" || { echo "[x] не нашёл bash ≥ 4.2"; exit 1; }

BIN="$T/bin"; NFTD="$T/nft"; SSD="$T/ssdata"; export NFTD SSD
mkdir -p "$BIN" "$NFTD" "$SSD" \
         "$T/var/lib/node-accelerator" "$T/etc/node-accelerator" "$T/var/log" \
         "$T/var/lib/docker/containers" "$T/proc" "$T/boot" "$T/systemd" \
         "$T/sys/class/net/eth0/queues/rx-0" "$T/sys/class/net/eth0/statistics" \
         "$T/sys/kernel/mm/transparent_hugepage" \
         "$T/opt/selfsteal/certs/node.example.test" \
         "$T/proc/net" "$T/proc/sys/net/netfilter" "$T/proc/sys/kernel/random" \
         "$T/root/.acme.sh/retired.example.test"

KREL="6.18.47-x64v3-xanmod1"
JSTART=$(( $(date +%s) - 10*3600 ))   # журнал вмещает 10ч → «менее 48ч»
export JSTART

# ── Копия скриптов с системными путями, уведёнными в песочницу ────────────────
# STATE_DIR/CONF_DIR живут в lib/common.sh, менять его нельзя — правим КОПИЮ (тот же
# приём, что в logrotate-unit.sh). Заодно уводим /proc, /sys, /boot и пути сертов:
# без этого тест читал бы живой /proc/pressure раннера и результат зависел бы от того,
# с каким ядром собран CI.
cp -R "$REPO_ROOT/scripts" "$T/scripts"
# /proc/sys/… уводим через метку: иначе правило для /sys/ срабатывало ВНУТРИ уже
# подставленного $T/proc/sys/… и ломало путь (до v4.1.3 так молча не читались
# nf_conntrack_count и boot_id песочницы).
sandbox_paths() {
    sed -i.bak \
        -e "s#/var/lib/node-accelerator#$T/var/lib/node-accelerator#g" \
        -e "s#/etc/node-accelerator#$T/etc/node-accelerator#g" \
        -e "s#/proc/sys/#@@PROCSYS@@#g" \
        -e "s#/proc/#$T/proc/#g" \
        -e "s#/sys/#$T/sys/#g" \
        -e "s#@@PROCSYS@@#$T/proc/sys/#g" \
        -e "s#/boot/config-#$T/boot/config-#g" \
        -e "s#/var/log#$T/var/log#g" \
        -e "s#/var/lib/docker#$T/var/lib/docker#g" \
        -e "s#/etc/systemd/system/#$T/systemd/#g" \
        -e "s#/etc/logrotate.conf#$T/etc/logrotate.conf#g" \
        -e "s#/etc/logrotate.d#$T/etc/logrotate.d#g" \
        -e "s#/etc/os-release#$T/etc/os-release#g" \
        -e "s#/tmp/na-fw-safety.pid#$T/na-fw-safety.pid#g" \
        -e "s#/etc/letsencrypt#$T/etc/letsencrypt#g" \
        -e "s#/root/.acme.sh#$T/root/.acme.sh#g" \
        -e "s#/opt/\*/certs#$T/opt/*/certs#g" \
        "$1"
    rm -f "$1.bak"
}
sandbox_paths "$T/scripts/diagnose.sh"
sandbox_paths "$T/scripts/lib/common.sh"
DIAG="$T/scripts/diagnose.sh"
: > "$T/etc/logrotate.conf"
# os-release тоже в песочницу: иначе отчёт зависел бы от ОС раннера
printf 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\n' > "$T/etc/os-release"

# ── Фикстуры /proc, /sys, /boot ───────────────────────────────────────────────
# btime = 2026-09-02 00:00 UTC — загрузка ПОЗЖЕ installed_at старого маркера optimize
printf 'cpu  100 0 50 900 0 0 0 0 0 0\nbtime 1788307200\n' > "$T/proc/stat"
printf 'boot-current\n' > "$T/proc/sys/kernel/random/boot_id"
printf '99999.00 88888.00\n'             > "$T/proc/uptime"
printf '0.05 0.10 0.15 1/200 1234\n'     > "$T/proc/loadavg"
printf 'MemTotal:  2048000 kB\nMemAvailable: 1024000 kB\n' > "$T/proc/meminfo"
# PSI собран, но выключен по умолчанию, и psi=1 в cmdline нет (ровно XanMod, #37)
printf 'CONFIG_PSI=y\nCONFIG_PSI_DEFAULT_DISABLED=y\n' > "$T/boot/config-$KREL"
printf 'BOOT_IMAGE=/boot/vmlinuz-%s root=PARTUUID=x ro console=tty0\n' "$KREL" > "$T/proc/cmdline"
printf '100\n' > "$T/proc/sys/net/netfilter/nf_conntrack_count"
cat > "$T/proc/net/snmp" <<'SNMP'
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts
Tcp: 1 200 120000 -1 100 200 0 0 10 5000 10000 100 0 0
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors
Udp: 1000 0 0 900 0 0
SNMP
printf '0\n'    > "$T/sys/class/net/eth0/queues/rx-0/rps_cpus"   # RPS НЕ применён (#30)
printf '1000\n' > "$T/sys/class/net/eth0/tx_queue_len"
printf '1234\n' > "$T/sys/class/net/eth0/statistics/rx_bytes"
printf '4321\n' > "$T/sys/class/net/eth0/statistics/tx_bytes"
printf 'always madvise [never]\n' > "$T/sys/kernel/mm/transparent_hugepage/enabled"

# ── Маркеры и конфиги тулкита ─────────────────────────────────────────────────
cat > "$T/var/lib/node-accelerator/protect.installed" <<'MARK'
installed_at=2026-09-01T00:00:00+00:00
na_version=4.0.1
fw_mode=strict
ssh_port=22
tcp_ports=443,8445
udp_ports=443
node_port=2222
crowdsec=1
MARK
# WHITELIST в conf НЕ содержит 198.51.100.7 — он осел в .nft транзитно (SSH-IP), и
# ре-ран protect из другой сессии его выкинет (#38)
cat > "$T/etc/node-accelerator/protect.conf" <<'CONF'
: "${FW_MODE:=strict}"
: "${WHITELIST:=203.0.113.5,192.0.2.0/24}"
: "${CROWDSEC_STRICT:=0}"
CONF
cat > "$T/etc/node-accelerator/na_filter.nft" <<'NFTF'
table inet na_filter {
	set whitelist_v4 {
		type ipv4_addr
		flags interval
		elements = { 192.0.2.0/24, 198.51.100.7, 203.0.113.5 }
	}
}
NFTF

# ── Фикстуры nft ──────────────────────────────────────────────────────────────
set_fixture() { # set_fixture <имя> <элементы|"">
    if [[ -z "${2:-}" ]]; then
        printf 'table inet na_filter {\n\tset %s {\n\t\ttype ipv4_addr\n\t\tsize 65536\n\t\tflags dynamic,timeout\n\t\ttimeout 30m\n\t}\n}\n' "$1" > "$NFTD/set-$1"
    else
        printf 'table inet na_filter {\n\tset %s {\n\t\ttype ipv4_addr\n\t\tsize 65536\n\t\tflags dynamic,timeout\n\t\telements = { %s }\n\t}\n}\n' "$1" "$2" > "$NFTD/set-$1"
    fi
}
set_fixture autoban_v4 '203.0.113.10 timeout 1d expires 1h11m50s608ms, 203.0.113.11 timeout 1d expires 2h'
set_fixture autoban_v6 ''
set_fixture suspect_v4 ''
printf 'table inet na_filter {\n\tset whitelist_v4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { 192.0.2.0/24, 198.51.100.7, 203.0.113.5 }\n\t}\n}\n' > "$NFTD/set-whitelist_v4"
printf 'table inet na_filter {\n\tset whitelist_v6 {\n\t\ttype ipv6_addr\n\t\telements = { 2001:db8::1 }\n\t}\n}\n' > "$NFTD/set-whitelist_v6"
cat > "$NFTD/chain-input" <<'CH'
table inet na_filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iif "lo" accept
		ct state established,related accept
		ip saddr @whitelist_v4 accept
		tcp dport 443 ct state new meter cc4_443 { ip saddr ct count over 8192 } drop
	}
}
CH

# ── Фикстуры ss ───────────────────────────────────────────────────────────────
# Срез правила `ct count`: loopback-пары nginx↔xray (их правило не видит вовсе), пир из
# вайтлиста (accept раньше лимита) и два внешних. Ожидаемый максимум = 3 (#31).
{
  for i in $(seq 1 12); do printf '0      0      127.0.0.1:8445    127.0.0.1:%d\n' $((40000+i)); done
  for i in $(seq 1 5);  do printf '0      0      10.0.0.5:443      198.51.100.7:%d\n' $((50000+i)); done
  for i in $(seq 1 3);  do printf '0      0      10.0.0.5:443      203.0.113.99:%d\n' $((60000+i)); done
  for i in $(seq 1 2);  do printf '0      0      10.0.0.5:443      [2001:db8::99]:%d\n' $((61000+i)); done
} > "$SSD/estab-ports"
cat > "$SSD/estab-mss" <<'EST'
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port
ESTAB  0      0      10.0.0.5:443        203.0.113.99:60001
	 bbr wscale:7,7 rto:204 mss:1400 cwnd:10
ESTAB  0      0      10.0.0.5:443        203.0.113.99:60002
	 bbr wscale:7,7 rto:204 mss:1400 cwnd:10
EST
cat > "$SSD/listen-t" <<'LT'
LISTEN 0      511    0.0.0.0:443        0.0.0.0:*
LISTEN 0      128    0.0.0.0:22         0.0.0.0:*
LT
cat > "$SSD/listen-tu" <<'LTU'
tcp   LISTEN 0      511    0.0.0.0:443        0.0.0.0:*
tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*
udp   UNCONN 0      0      0.0.0.0:443        0.0.0.0:*
LTU

# ── Серты: живой в /opt/<стек>/certs/<sni>/ и снятый с renew в acme.sh (#39) ───
printf 'x\n' > "$T/opt/selfsteal/certs/node.example.test/fullchain.cer"
printf 'x\n' > "$T/root/.acme.sh/retired.example.test/fullchain.cer"
# acme.sh --remove переименовал <domain>.conf → .conf.removed: продлевать перестали
printf 'Le_Domain=retired.example.test\n' > "$T/root/.acme.sh/retired.example.test/retired.example.test.conf.removed"

# ── Стабы ─────────────────────────────────────────────────────────────────────
cat > "$BIN/docker" <<'DOC'
#!/bin/sh
# Docker 29.x: `inspect -f` по НЕСУЩЕСТВУЮЩЕМУ объекту печатает в stdout пустую строку
# и только потом падает — ровно это и ломало сенсор (#27).
case "$1" in
  inspect)
    name=""
    for a in "$@"; do name="$a"; done
    if [ -n "${NA_TEST_CONTAINER:-}" ] && [ "$name" = "$NA_TEST_CONTAINER" ]; then
        case "$*" in
          *State.Status*)  echo running ;;
          *RestartCount*)  echo 0 ;;
          *)               echo '{}' ;;
        esac
        exit 0
    fi
    printf '\n'
    exit 1 ;;
  logs) exit 0 ;;
  ps)   exit 0 ;;
esac
exit 1
DOC

cat > "$BIN/nft" <<'NFTS'
#!/bin/sh
case "$*" in
  "-t list table inet na_filter") [ -f "$NFTD/terse" ] && cat "$NFTD/terse"; exit 0 ;;
  "list table inet na_filter")   exit 0 ;;
  "list table inet na_ctguard")  exit 1 ;;
  "list table ip crowdsec")      exit 1 ;;
  "list chain inet na_filter input") cat "$NFTD/chain-input"; exit 0 ;;
  "list set inet "*)
      # ${*##* } раскрывается по КАЖДОМУ параметру, а не по склейке — берём имя набора
      # через промежуточную переменную
      all="$*"; s=${all##* }
      if [ -f "$NFTD/set-$s" ]; then cat "$NFTD/set-$s"; exit 0; fi
      echo "Error: No such file or directory" >&2; exit 1 ;;
esac
exit 1
NFTS

cat > "$BIN/ss" <<'SSS'
#!/bin/sh
case "$*" in
  *"sport = :"*)        cat "$SSD/estab-ports" ;;
  "-tulnH")             cat "$SSD/listen-tu" ;;
  "-tlnH")              cat "$SSD/listen-t" ;;
  "-Htlnp")             : ;;
  *)                    cat "$SSD/estab-mss" ;;
esac
exit 0
SSS

cat > "$BIN/cscli" <<'CS'
#!/bin/sh
# `decisions list -o raw` печатает CSV С ЗАГОЛОВКОМ — он и завышал счёт на 1 (#32)
case "$*" in
  "decisions list -o raw")
    echo "id,source,ip,reason,action,country,as,duration,scenario"
    i=0
    while [ "$i" -lt "${NA_TEST_DECISIONS:-0}" ]; do
        i=$((i+1))
        echo "$i,crowdsec,203.0.113.$i,ban,ban,--,--,3h,ssh-bf"
    done ;;
esac
exit 0
CS

cat > "$BIN/journalctl" <<'JC'
#!/bin/sh
case "$*" in
  *--help*)
      echo "  -g --grep=PATTERN     Show entries with MESSAGE matching PATTERN"
      # NA_TEST_BIG_HELP: справка больше буфера пайпа — `| grep -q` закрыл бы пайп на
      # первой строке, и следующая запись словила бы SIGPIPE (141 под pipefail)
      if [ "${NA_TEST_BIG_HELP:-0}" = 1 ]; then
          i=0; while [ "$i" -lt 6000 ]; do echo "  --filler-option-$i   long help text line to overflow the pipe buffer"; i=$((i+1)); done
      fi
      exit 0 ;;
  *short-unix*)      printf '%s.000000 node kernel: Linux version\n' "$JSTART"; exit 0 ;;
  *"na portscan"*)   printf 'a\nb\nc\n'; exit 0 ;;
esac
exit 0
JC

cat > "$BIN/systemctl" <<'SC'
#!/bin/sh
case "$*" in
  "is-active --quiet na-rps.service")                exit 0 ;;   # active (exited)
  "is-active --quiet na-logrotate.timer")            exit 0 ;;   # таймер активен — станса отдельно (#40)
  "is-active --quiet crowdsec")                      exit 0 ;;
  "is-active --quiet crowdsec-firewall-bouncer")     exit 0 ;;
  "is-enabled --quiet na-firewall.service")          exit 0 ;;
  "show -p DefaultLimitNOFILE --value")              echo 524288; exit 0 ;;
  "--failed --no-legend")                            exit 0 ;;
esac
exit 1
SC

# logrotate — только чтобы diagnose не ушёл в ветку «не установлен» раньше сенсора стансы (#40);
# `-d` по пустому conf в песочнице → тишина, дубликатов нет.
cat > "$BIN/logrotate" <<'LR'
#!/bin/sh
# NA_TEST_LR_DUP: дубликат в НАЧАЛЕ большого вывода `logrotate -d` — ровно тот случай,
# когда grep -q закрывал пайп раньше, чем logrotate дописывал (SIGPIPE → «дублей нет»)
if [ "$1" = "-d" ] && [ "${NA_TEST_LR_DUP:-0}" = 1 ]; then
    echo "error: na-node-logs:1 duplicate log entry for /var/log/nginx/access.log"
    i=0; while [ "$i" -lt 6000 ]; do echo "considering log /var/log/filler-$i.log"; i=$((i+1)); done
fi
exit 0
LR

cat > "$BIN/uname" <<'UN'
#!/bin/sh
[ "$1" = "-r" ] && { echo "6.18.47-x64v3-xanmod1"; exit 0; }
exec /usr/bin/uname "$@"
UN

cat > "$BIN/sysctl" <<'SY'
#!/bin/sh
[ "$1" = "-n" ] || exit 1
case "$2" in
  net.ipv4.tcp_congestion_control)            echo bbr ;;
  net.ipv4.tcp_available_congestion_control)  echo "reno cubic bbr" ;;
  net.core.default_qdisc)                     echo fq ;;
  net.netfilter.nf_conntrack_max)             echo 262144 ;;
  net.ipv4.tcp_min_snd_mss)                   echo 512 ;;
  net.ipv4.tcp_mtu_probing)                   echo 0 ;;
  net.core.somaxconn)                         echo 65535 ;;
  net.core.rmem_max|net.core.wmem_max)        echo 33554432 ;;
  net.ipv4.tcp_max_syn_backlog)               echo 16384 ;;
  fs.file-max|fs.nr_open)                     echo 2000000 ;;
  net.ipv4.tcp_syncookies)                    echo 1 ;;
  net.ipv4.tcp_fastopen)                      echo 3 ;;
  net.ipv4.conf.all.rp_filter)                echo 2 ;;
  *) exit 1 ;;
esac
exit 0
SY

cat > "$BIN/ip" <<'IPS'
#!/bin/sh
case "$*" in
  "-o -4 route show default") echo "default via 10.0.0.1 dev eth0 proto static metric 100" ;;
  "-6 route show default")    : ;;
  "-s link show dev eth0")    printf '2: eth0\n    RX: bytes packets errors dropped\n    100 10 0 0\n    TX: bytes packets errors dropped\n    200 20 0 0\n' ;;
esac
exit 0
IPS

cat > "$BIN/openssl" <<'SSL'
#!/bin/sh
# Снятый с renew серт истекает РАНЬШЕ живого: если сенсор его учтёт — увидим ✘ (#39)
for a in "$@"; do last="$a"; done
case "$last" in
  *retired*) echo "notAfter=RETIRED" ;;
  *)         echo "notAfter=GOOD" ;;
esac
exit 0
SSL

cat > "$BIN/date" <<'DT'
#!/bin/sh
if [ "$1" = "-d" ]; then
    now=$(/bin/date +%s)
    case "$2" in
      *GOOD*)    echo $(( now + 60*86400 )) ;;
      *RETIRED*) echo $(( now + 3*86400 )) ;;
      2026-09-01T00:00:00+00:00) echo 1788220800 ;;   # installed_at старого маркера optimize
      *) exit 1 ;;
    esac
    exit 0
fi
exec /bin/date "$@"
DT

printf '#!/bin/sh\necho 4\n'                > "$BIN/nproc"
printf '#!/bin/sh\necho aarch64\n'          > "$BIN/arch"
printf '#!/bin/sh\necho kvm\n'              > "$BIN/systemd-detect-virt"
printf '#!/bin/sh\nexit 1\n'                > "$BIN/curl"
printf '#!/bin/sh\nexit 1\n'                > "$BIN/ping"
printf '#!/bin/sh\nexit 1\n'                > "$BIN/swapon"
printf '#!/bin/sh\necho "up 2 days"\n'      > "$BIN/uptime"
printf '#!/bin/sh\necho "Mem: 2.0Gi 1.0Gi"\n' > "$BIN/free"
cat > "$BIN/df" <<'DF'
#!/bin/sh
echo "Filesystem 1024-blocks Used Available Capacity Mounted on"
echo "/dev/x 100 12 88 12% /"
DF
chmod +x "$BIN"/*
export PATH="$BIN:$PATH"

# ── Прогоны ───────────────────────────────────────────────────────────────────
PASS=0; FAIL=0
check() { # check "описание" <ожидание> <факт>
    if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); echo "  ok   $1"
    else FAIL=$((FAIL+1)); echo "  FAIL $1: ожидалось [$2], получено [$3]"; fi
}
grep_ok()  { local d="$1" p="$2" f="$3"; if grep -qF -- "$p" "$f"; then PASS=$((PASS+1)); echo "  ok   $d"; else FAIL=$((FAIL+1)); echo "  FAIL $d: нет строки [$p]"; fi; }
grep_not() { local d="$1" p="$2" f="$3"; if grep -qF -- "$p" "$f"; then FAIL=$((FAIL+1)); echo "  FAIL $d: строка [$p] есть, а быть не должно"; else PASS=$((PASS+1)); echo "  ok   $d"; fi; }

# 198.51.100.7 — «IP текущей сессии»: он есть в живом сете и в .nft, но не в WHITELIST=
SSHENV='SSH_CONNECTION=198.51.100.7 51234 10.0.0.5 22'

jget() { # jget <файл> <поле> — без jq: он на ноде не обязателен, а в CI не гарантирован
    python3 - "$1" "$2" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
v=d.get(sys.argv[2], "<НЕТ ПОЛЯ>")
print("true" if v is True else "false" if v is False else v)
PY
}

command -v python3 >/dev/null 2>&1 || { echo "[x] нужен python3 для валидации JSON"; exit 1; }

echo "== 1. --json: контракт мониторинга (#27 #31 #32 #34 #35 #37 #38 #39) =="
env "$SSHENV" TERM=dumb "$WBASH" "$DIAG" --json > "$T/out.json" 2>"$T/err.json" || true
if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$T/out.json" 2>/dev/null; then
    PASS=$((PASS+1)); echo "  ok   --json парсится как валидный JSON (#27)"
else
    FAIL=$((FAIL+1)); echo "  FAIL --json НЕ парсится: $(head -c 400 "$T/out.json")"
fi
check "одна строка на выходе"                       1 "$(wc -l < "$T/out.json" | tr -d ' ')"
check "remnanode_status=absent (не '\\nabsent')"     absent "$(jget "$T/out.json" remnanode_status)"
check "autoban_v4=2 (адреса, а не строки nft)"      2 "$(jget "$T/out.json" autoban_v4)"
check "autoban_v6=0 на пустом наборе"               0 "$(jget "$T/out.json" autoban_v6)"
check "suspect=0 на пустом наборе"                  0 "$(jget "$T/out.json" suspect)"
check "psi=off-by-default (CONFIG_PSI_DEFAULT_DISABLED)" off-by-default "$(jget "$T/out.json" psi)"
check "max_conn_per_ip=3 (внешний пир, без loopback/вайтлиста)" 3 "$(jget "$T/out.json" max_conn_per_ip)"
check "journal_span_h=10"                           10 "$(jget "$T/out.json" journal_span_h)"
check "portscan_log_lines_boot=3"                   3 "$(jget "$T/out.json" portscan_log_lines_boot)"
check "whitelist_drift_conf=1"                      1 "$(jget "$T/out.json" whitelist_drift_conf)"
check "conf_stale_defaults=1 (CROWDSEC_STRICT=0)"   1 "$(jget "$T/out.json" conf_stale_defaults)"
check "cert_min_days=60 (снятый с renew не считается)" 60 "$(jget "$T/out.json" cert_min_days)"
check "cert_min_file — серт из /opt/<стек>/certs"   "$T/opt/selfsteal/certs/node.example.test/fullchain.cer" "$(jget "$T/out.json" cert_min_file)"
check "старые поля на месте: firewall"              true "$(jget "$T/out.json" firewall)"
check "старые поля на месте: fw_mode"               strict "$(jget "$T/out.json" fw_mode)"

echo "== 2. --json: пустой autoban не даёт фантомную единицу (#32) =="
set_fixture autoban_v4 ''
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/out2.json" 2>/dev/null || true
check "autoban_v4=0 на пустом динамическом наборе"  0 "$(jget "$T/out2.json" autoban_v4)"
set_fixture autoban_v4 '203.0.113.10 timeout 1d expires 1h11m50s608ms, 203.0.113.11 timeout 1d expires 2h'

echo "== 3. текстовый отчёт =="
env "$SSHENV" TERM=dumb "$WBASH" "$DIAG" > "$T/out.txt" 2>"$T/err.txt" || true
grep_ok  "контейнера нет — info, а не ✘ (#27)"            "remnanode: контейнера нет" "$T/out.txt"
if grep -F 'remnanode' "$T/out.txt" | grep -qF '✘'; then
    FAIL=$((FAIL+1)); echo "  FAIL ✘ про remnanode есть, а быть не должно (#27)"
else PASS=$((PASS+1)); echo "  ok   ✘ «node-агент лежит» не печатается (#27)"; fi
grep_ok  "autoban печатает адреса, а не только счёт (#32)" "autoban: v4=2  v6=0 — 203.0.113.10 203.0.113.11" "$T/out.txt"
grep_ok  "suspect=0 (пустой набор — не «1») (#32)"         "suspect (наблюдение) v4=0" "$T/out.txt"
grep_ok  "CrowdSec decisions без строки-заголовка CSV (#32)" "CrowdSec decisions (активные баны): 0" "$T/out.txt"
grep_ok  "CONN_LIMIT: считаем внешнего пира, не loopback (#31)" "с одного IP = 3 / CONN_LIMIT 8192" "$T/out.txt"
grep_not "loopback-максимум (12) в датчик не попал (#31)"  "с одного IP = 12" "$T/out.txt"
grep_ok  "whitelist переживёт ребут (live == .nft) (#38)"  "переживёт ребут" "$T/out.txt"
grep_ok  "дрейф относительно protect.conf найден (#38)"    "НЕ переживёт ре-ран protect" "$T/out.txt"
grep_ok  "дрейфующий адрес назван (#38)"                   "198.51.100.7" "$T/out.txt"
grep_ok  "опознан IP текущей сессии (#38)"                 "это IP текущей сессии" "$T/out.txt"
grep_ok  "PSI: выключен в сборке ядра (#37)"               "CONFIG_PSI_DEFAULT_DISABLED=y" "$T/out.txt"
grep_not "PSI: слов про «старое ядро» больше нет (#37)"    "старое ядро" "$T/out.txt"
grep_ok  "na-rps: гонка на буте — ▲, а не ✔ (#30)"        "na-rps.service active, но rps_cpus пуст" "$T/out.txt"
grep_not "✔ «na-rps.service активен» при пустом rps_cpus (#30)" "✔  na-rps.service активен" "$T/out.txt"
grep_ok  "conf пиннит устаревший дефолт (#34)"             "пиннит устаревший дефолт: CROWDSEC_STRICT=0" "$T/out.txt"
grep_ok  "глубина журнала меньше 48ч (#35)"                "журнал вмещает менее 48ч" "$T/out.txt"
grep_ok  "строки лога анти-скана посчитаны (#35)"          "строк [na portscan] за текущую загрузку: 3" "$T/out.txt"
grep_ok  "серт из /opt/<стек>/certs найден (#39)"          "ближайший TLS-серт: 60 дн" "$T/out.txt"
grep_not "снятый с renew серт не тревожит (#39)"           "retired.example.test" "$T/out.txt"

echo "== 4. NA_NODE_CONTAINER: бокс с иначе названным контейнером (#27) =="
env TERM=dumb NA_NODE_CONTAINER=nodeagent NA_TEST_CONTAINER=nodeagent "$WBASH" "$DIAG" > "$T/out4.txt" 2>/dev/null || true
grep_ok "контейнер под своим именем виден как running" "nodeagent: running" "$T/out4.txt"
env TERM=dumb NA_NODE_CONTAINER=nodeagent NA_TEST_CONTAINER=nodeagent "$WBASH" "$DIAG" --json > "$T/out4.json" 2>/dev/null || true
check "json: remnanode_status=running для NA_NODE_CONTAINER" running "$(jget "$T/out4.json" remnanode_status)"

echo "== 5. сертов нет, а :443 слушает — сенсор слеп, это ▲ (#39) =="
mv "$T/opt" "$T/opt.off"; mv "$T/root" "$T/root.off"
env TERM=dumb "$WBASH" "$DIAG" > "$T/out5.txt" 2>/dev/null || true
grep_ok "warn «сенсор слеп: задай NA_CERT_PATHS»" "сенсор слеп: задай NA_CERT_PATHS" "$T/out5.txt"
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/out5.json" 2>/dev/null || true
check "json: cert_min_file пуст, когда сертов нет" "" "$(jget "$T/out5.json" cert_min_file)"
mv "$T/opt.off" "$T/opt"; mv "$T/root.off" "$T/root"

echo "== 6. CrowdSec: 3 решения = 3, а не 4 (#32) =="
env TERM=dumb NA_TEST_DECISIONS=3 "$WBASH" "$DIAG" > "$T/out6.txt" 2>/dev/null || true
grep_ok "три решения считаются как 3" "CrowdSec decisions (активные баны): 3" "$T/out6.txt"

echo "== 7. ротация: «таймер активен» ≠ «станса есть» (#40) =="
LRSTATE="$T/var/lib/node-accelerator"; mkdir -p "$T/etc/logrotate.d"
printf '/var/log/nginx/*.log\t/etc/logrotate.d/vpn-node-logs\tnone\n' > "$LRSTATE/logrotate.ceded"
printf '/var/log/remnanode/*.log\n' > "$LRSTATE/logrotate.owned"
printf '/var/log/remnanode/*.log {\n    daily\n}\n' > "$T/etc/logrotate.d/na-node-logs"
env "$SSHENV" TERM=dumb "$WBASH" "$DIAG" --json > "$T/out7.json" 2>/dev/null || true
check "json: logrotate_ceded_nocap=1"                 1 "$(jget "$T/out7.json" logrotate_ceded_nocap)"
check "json: logrotate_ceded_masks — отданная маска"  "/var/log/nginx/*.log" "$(jget "$T/out7.json" logrotate_ceded_masks)"
check "json: logrotate_owned_masks — наша маска"      "/var/log/remnanode/*.log" "$(jget "$T/out7.json" logrotate_owned_masks)"
env "$SSHENV" TERM=dumb "$WBASH" "$DIAG" > "$T/out7.txt" 2>/dev/null || true
grep_ok  "текст: ▲ уступка, владелец без капа назван" "vpn-node-logs (БЕЗ maxsize/size!)" "$T/out7.txt"
grep_not "текст: зелёного «станса на месте» при уступке нет" "часовой таймер активен, станса на месте" "$T/out7.txt"
# уступок нет, но стансы тоже нет (пустая) — таймер крутится вхолостую
rm -f "$LRSTATE/logrotate.ceded" "$LRSTATE/logrotate.owned"; : > "$T/etc/logrotate.d/na-node-logs"
env "$SSHENV" TERM=dumb "$WBASH" "$DIAG" > "$T/out7b.txt" 2>/dev/null || true
grep_ok  "текст: таймер активен, стансы нет → ▲"     "na-node-logs нет" "$T/out7b.txt"
check    "json: без уступок ceded_nocap=0"            0 "$(env "$SSHENV" TERM=dumb "$WBASH" "$DIAG" --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["logrotate_ceded_nocap"])')"
# станса есть, уступок нет — ✔
printf '/var/log/remnanode/*.log {\n    daily\n}\n' > "$T/etc/logrotate.d/na-node-logs"
printf '/var/log/remnanode/*.log\n' > "$LRSTATE/logrotate.owned"
env "$SSHENV" TERM=dumb "$WBASH" "$DIAG" > "$T/out7c.txt" 2>/dev/null || true
grep_ok  "текст: станса на месте → ✔ с перечнем масок" "часовой таймер активен, станса на месте (/var/log/remnanode/*.log)" "$T/out7c.txt"
rm -f "$LRSTATE/logrotate.owned"

echo "== 8. SIGPIPE под pipefail: большой вывод не гасит сенсоры (v4.1.3) =="
for i in 1 2 3; do
    env TERM=dumb NA_TEST_BIG_HELP=1 "$WBASH" "$DIAG" --json > "$T/out8.json" 2>/dev/null || true
    check "portscan_log_lines_boot=3 при справке journalctl > буфера пайпа (прогон $i)" 3 "$(jget "$T/out8.json" portscan_log_lines_boot)"
done
env TERM=dumb NA_TEST_LR_DUP=1 "$WBASH" "$DIAG" > "$T/out8.txt" 2>/dev/null || true
grep_ok "дубликат в большом выводе logrotate -d найден" "logrotate: дубликат путей" "$T/out8.txt"

echo "== 9. наборы-лимитеры: без timeout копят адреса, на 100% режут клиентов (v4.1.3) =="
# legacy (≤4.1.2): syn4_443 без timeout, 85 из 100; cc4_443 — ct count, ядро чистит само
cat > "$NFTD/terse" <<'TERSE'
table inet na_filter {
	set whitelist_v4 {
		type ipv4_addr
		flags interval
	}
	set syn4_443 {
		type ipv4_addr
		size 100
		flags dynamic
	}
	set cc4_443 {
		type ipv4_addr
		size 65535
		flags dynamic
	}
}
TERSE
mk_elems() { local n="$1" i out=""; for ((i=1; i<=n; i++)); do out+="${out:+, }198.18.$((i/250)).$((i%250+1))"; done; printf '%s' "$out"; }
printf 'table inet na_filter {\n\tset syn4_443 {\n\t\ttype ipv4_addr\n\t\tsize 100\n\t\tflags dynamic\n\t\telements = { %s }\n\t}\n}\n' "$(mk_elems 85)" > "$NFTD/set-syn4_443"
printf 'table inet na_filter {\n\tset cc4_443 {\n\t\ttype ipv4_addr\n\t\tsize 65535\n\t\tflags dynamic\n\t\telements = { %s }\n\t}\n}\n' "$(mk_elems 99)" > "$NFTD/set-cc4_443"
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/out9.json" 2>/dev/null || true
check "json: dynset_fill_max_pct=85"        85 "$(jget "$T/out9.json" dynset_fill_max_pct)"
check "json: dynset_fill_max_set=syn4_443"  syn4_443 "$(jget "$T/out9.json" dynset_fill_max_set)"
check "json: dynset_no_timeout=1 (cc4 не в счёт)" 1 "$(jget "$T/out9.json" dynset_no_timeout)"
env TERM=dumb "$WBASH" "$DIAG" > "$T/out9.txt" 2>/dev/null || true
grep_ok "текст: ✘ legacy-набор почти полон"  "наборы-лимитеры без timeout (1 шт., правила ≤4.1.2) заполнены до 85%" "$T/out9.txt"
# v4.1.3: тот же набор с timeout, 10 из 100 → ✔
printf 'table inet na_filter {\n\tset syn4_443 {\n\t\ttype ipv4_addr\n\t\tsize 100\n\t\tflags dynamic,timeout\n\t\ttimeout 1m\n\t\telements = { %s }\n\t}\n}\n' "$(mk_elems 10)" > "$NFTD/set-syn4_443"
awk '{ if ($0 ~ /flags dynamic$/) { print "\t\tflags dynamic,timeout"; print "\t\ttimeout 1m" } else print }' "$NFTD/terse" > "$NFTD/terse.new" && mv "$NFTD/terse.new" "$NFTD/terse"
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/out9b.json" 2>/dev/null || true
check "json: с timeout dynset_no_timeout=0"  0 "$(jget "$T/out9b.json" dynset_no_timeout)"
check "json: заполнение 10%"                 10 "$(jget "$T/out9b.json" dynset_fill_max_pct)"
env TERM=dumb "$WBASH" "$DIAG" > "$T/out9b.txt" 2>/dev/null || true
grep_ok "текст: ✔ лимитеры с timeout"         "наборы-лимитеры с timeout, максимум заполнения 10%" "$T/out9b.txt"
rm -f "$NFTD/terse" "$NFTD/set-syn4_443" "$NFTD/set-cc4_443"
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/out9c.json" 2>/dev/null || true
check "json: наборов нет → dynset_fill_max_pct=-1" -1 "$(jget "$T/out9c.json" dynset_fill_max_pct)"

echo "== 10. reboot_needed — по факту загрузки, а не вечный маркер (v4.1.3) =="
OPTM="$T/var/lib/node-accelerator/optimize.installed"
printf 'installed_at=2026-10-03T10:00:00+00:00\nreboot_needed=1\nboot_id=boot-current\n' > "$OPTM"
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/out10.json" 2>/dev/null || true
check "тот же boot_id → ребута не было → true" true "$(jget "$T/out10.json" reboot_needed)"
env TERM=dumb "$WBASH" "$DIAG" > "$T/out10.txt" 2>/dev/null || true
grep_ok "текст: ▲ ждёт перезагрузки" "а перезагрузки с тех пор не было" "$T/out10.txt"
printf 'installed_at=2026-10-03T10:00:00+00:00\nreboot_needed=1\nboot_id=boot-before\n' > "$OPTM"
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/out10b.json" 2>/dev/null || true
check "другой boot_id → ребут был → false" false "$(jget "$T/out10b.json" reboot_needed)"
# маркер ≤4.1.2 без boot_id: установка 01.09, загрузка (btime) 02.09 → ребут был
printf 'installed_at=2026-09-01T00:00:00+00:00\nreboot_needed=1\n' > "$OPTM"
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/out10c.json" 2>/dev/null || true
check "старый маркер, btime > installed_at → false" false "$(jget "$T/out10c.json" reboot_needed)"
rm -f "$OPTM"

echo
echo "  прогон: $PASS ok, $FAIL fail"
if [[ "$FAIL" -ne 0 ]]; then echo "DIAGNOSE-UNIT: FAIL"; exit 1; fi
echo "DIAGNOSE-UNIT: OK (--json валиден и честен, датчики меряют тот же срез, что и правила)"
