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
#   v4.2 (аудит флота): дельты счётчиков между запусками вместо накопленного с загрузки
#       (UDP RcvbufErrors v4+v6, softnet, ListenOverflows); steal окном 3 с + с загрузки;
#       PSI по avg60; ложные ▲ (ENABLE_XANMOD=0, logrotate с капом, volatile-журнал,
#       журнал ≈ аптайму, лог анти-скана — доля за сутки); порты из живых правил/conf;
#       CrowdSec по источникам решений + scope + acquisition; 4-й слой whitelist (allowlist
#       CrowdSec); DNAT мимо na_filter; слушатели вне файрвола; память/balloon;
#       nftables.service с flush; хэш na_filter.nft; c_*-счётчики; буферы от tier;
#       порт xray в эфемерном диапазоне; обновление XanMod и reboot-required; просроченный
#       серт и серты Caddy/nginx; docker без max-size; OOM за сутки по всем загрузкам;
#       RPS при RX-очередей ≥ ядер.
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
NA_TEST_PROC="$T/proc"; export NA_TEST_PROC
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
        -e "s#/run/log/journal#$T/run/log/journal#g" \
        -e "s#/run/reboot-required#$T/run/reboot-required#g" \
        -e "s#/etc/crowdsec#$T/etc/crowdsec#g" \
        -e "s#/etc/nginx#$T/etc/nginx#g" \
        -e "s#/etc/nftables.conf#$T/etc/nftables.conf#g" \
        -e "s#/var/lib/caddy#$T/var/lib/caddy#g" \
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
    case "$*" in
      *LogConfig*) echo "/remnanode json-file "; exit 0 ;;
    esac
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
  ps)
    # опубликованные порты (v4.2: сенсор DNAT мимо na_filter) и id для LogConfig
    case "$*" in
      *"{{.Ports}}"*) [ -f "$NFTD/docker-ports" ] && cat "$NFTD/docker-ports" ;;
      "ps -q")        [ "${NA_TEST_DK_NOCAP:-0}" = 1 ] && echo abc123 ;;
    esac
    exit 0 ;;
esac
exit 1
DOC

cat > "$BIN/nft" <<'NFTS'
#!/bin/sh
case "$*" in
  "-t list table inet na_filter") [ -f "$NFTD/terse" ] && cat "$NFTD/terse"; exit 0 ;;
  "list table inet na_filter")   exit 0 ;;
  "list table inet na_ctguard")  exit 1 ;;
  "list table ip crowdsec")      [ "${NA_TEST_CS_TABLE:-0}" = 1 ] && exit 0; exit 1 ;;
  "list counters table inet na_filter") [ -f "$NFTD/counters" ] && cat "$NFTD/counters"; exit 0 ;;
  "-t list ruleset")             [ -f "$NFTD/ruleset" ] && cat "$NFTD/ruleset"; exit 0 ;;
  "list chain inet na_filter input") cat "$NFTD/chain-input"; exit 0 ;;
  "list meter inet "*)
      all="$*"; s=${all##* }
      if [ -f "$NFTD/meter-$s" ]; then cat "$NFTD/meter-$s"; exit 0; fi
      echo "Error: No such file or directory" >&2; exit 1 ;;
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
  "-Htlnp")             [ -f "$SSD/listen-tp" ] && cat "$SSD/listen-tp" ;;
  "-Hulnp")             [ -f "$SSD/listen-up" ] && cat "$SSD/listen-up" ;;
  *)                    cat "$SSD/estab-mss" ;;
esac
exit 0
SSS

cat > "$BIN/cscli" <<'CS'
#!/bin/sh
# `decisions list -o raw` печатает CSV С ЗАГОЛОВКОМ — он и завышал счёт на 1 (#32)
# `-a` — вместе с CAPI/списками: NA_TEST_CAPI решений origin=CAPI и NA_TEST_LISTS — lists
case "$*" in
  "decisions list -o raw"|"decisions list -a -o raw")
    echo "id,source,ip,reason,action,country,as,events_count,expiration,simulated,alert_id"
    i=0
    while [ "$i" -lt "${NA_TEST_DECISIONS:-0}" ]; do
        i=$((i+1))
        echo "$i,crowdsec,Ip:203.0.113.$i,crowdsecurity/ssh-bf,ban,,\"64500 EXAMPLE, Inc\",3,3h,false,$i"
    done
    if [ "$*" = "decisions list -a -o raw" ]; then
        j=0
        while [ "$j" -lt "${NA_TEST_CAPI:-0}" ]; do
            j=$((j+1)); echo "$((1000+j)),CAPI,Ip:198.18.0.$j,crowdsecurity/http-probing,ban,,,0,160h,false,0"
        done
        j=0
        while [ "$j" -lt "${NA_TEST_LISTS:-0}" ]; do
            j=$((j+1)); echo "$((2000+j)),lists,Ip:198.18.1.$j,firehol_level1,ban,,,0,24h,false,0"
        done
    fi ;;
esac
exit 0
CS

cat > "$BIN/journalctl" <<'JC'
#!/bin/sh
case "$*" in
  *--help*)
      [ "${NA_TEST_NO_GREP:-0}" = 1 ] && { echo "  -k --dmesg  Show kernel message log from the current boot"; exit 0; }
      echo "  -g --grep=PATTERN     Show entries with MESSAGE matching PATTERN"
      # NA_TEST_BIG_HELP: справка больше буфера пайпа — `| grep -q` закрыл бы пайп на
      # первой строке, и следующая запись словила бы SIGPIPE (141 под pipefail)
      if [ "${NA_TEST_BIG_HELP:-0}" = 1 ]; then
          i=0; while [ "$i" -lt 6000 ]; do echo "  --filler-option-$i   long help text line to overflow the pipe buffer"; i=$((i+1)); done
      fi
      exit 0 ;;
  *short-unix*)      printf '%s.000000 node kernel: Linux version\n' "$JSTART"; exit 0 ;;
  *"na portscan"*)   printf 'a\nb\nc\n'; exit 0 ;;
  # все строки журнала за сутки (знаменатель доли лога анти-скана)
  *"-o cat"*)
      i=0; while [ "$i" -lt "${NA_TEST_JTOTAL:-0}" ]; do echo "line $i"; i=$((i+1)); done; exit 0 ;;
  # журнал ядра за сутки по всем загрузкам (OOM прошлой загрузки)
  *_TRANSPORT=kernel*)
      [ "${NA_TEST_OOM:-0}" = 1 ] && echo "Oct 02 03:00:00 node kernel: Out of memory: Killed process 1234 (xray)"
      exit 0 ;;
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
  "is-enabled --quiet nftables.service")             [ "${NA_TEST_NFTS:-0}" = 1 ] && exit 0; exit 1 ;;
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
[ "$1" = "-r" ] && { echo "${NA_TEST_KREL:-6.18.47-x64v3-xanmod1}"; exit 0; }
[ "$1" = "-m" ] && [ -n "${NA_TEST_ARCH:-}" ] && { echo "$NA_TEST_ARCH"; exit 0; }
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
  net.core.rmem_max|net.core.wmem_max)        echo "${NA_TEST_RMEM_MAX:-33554432}" ;;
  net.core.rmem_default|net.core.wmem_default) echo "${NA_TEST_RMEM_DEF:-1048576}" ;;
  net.ipv4.ip_local_port_range)               printf '10000\t65535\n' ;;
  net.ipv4.ip_local_reserved_ports)           echo "${NA_TEST_RESV:-}" ;;
  net.core.netdev_max_backlog)                echo 250000 ;;
  net.core.netdev_budget)                     echo 600 ;;
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
  *expired*) echo "notAfter=EXPIRED" ;;
  *nginx*)   echo "notAfter=NGINX" ;;
  *caddy*)   echo "notAfter=CADDY" ;;
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
      *EXPIRED*) echo $(( now - 10*86400 + 3600 )) ;;
      *NGINX*)   echo $(( now + 20*86400 + 3600 )) ;;
      *CADDY*)   echo $(( now + 15*86400 + 3600 )) ;;
      2026-09-01T00:00:00+00:00) echo 1788220800 ;;   # installed_at старого маркера optimize
      *) exit 1 ;;
    esac
    exit 0
fi
exec /bin/date "$@"
DT

# sleep: steal меряется окном 3 с — в тесте ждать нечего. NA_TEST_STAT_AFTER — подменить
# /proc/stat «после окна» (steal за окно считается из разницы двух чтений).
cat > "$BIN/sleep" <<'SLP'
#!/bin/sh
[ -n "${NA_TEST_STAT_AFTER:-}" ] && cp "$NA_TEST_STAT_AFTER" "$NA_TEST_PROC/stat"
exit 0
SLP
printf '#!/bin/sh\necho 4\n'                > "$BIN/nproc"
printf '#!/bin/sh\necho "${NA_TEST_ARCH:-aarch64}"\n' > "$BIN/arch"
# apt-cache policy для сенсора обновления XanMod (NA_TEST_APTPOL — файл с выводом)
cat > "$BIN/apt-cache" <<'AC'
#!/bin/sh
[ "$1" = policy ] && [ -n "${NA_TEST_APTPOL:-}" ] && { cat "$NA_TEST_APTPOL"; exit 0; }
exit 1
AC
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
# Сверяем текст БЕЗ цветовых escape-кодов: status_line красит значок, и «▲  текст» в
# файле разорван кодом сброса цвета — иначе проверка значка молча не работала бы.
plain()    { sed $'s/\033\\[[0-9;]*m//g' "$1"; }
grep_ok()  { local d="$1" p="$2" c; c="$(plain "$3")"; if grep -qF -- "$p" <<<"$c"; then PASS=$((PASS+1)); echo "  ok   $d"; else FAIL=$((FAIL+1)); echo "  FAIL $d: нет строки [$p]"; fi; }
grep_not() { local d="$1" p="$2" c; c="$(plain "$3")"; if grep -qF -- "$p" <<<"$c"; then FAIL=$((FAIL+1)); echo "  FAIL $d: строка [$p] есть, а быть не должно"; else PASS=$((PASS+1)); echo "  ok   $d"; fi; }

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
grep_ok  "строки лога анти-скана посчитаны за сутки (#35, v4.2)" "строк [na portscan] за 24ч: 3" "$T/out.txt"
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
grep_ok "три решения считаются как 3 (заголовок CSV и запятая в имени AS не в счёт)" "CrowdSec decisions (активные баны): 3 локальных" "$T/out6.txt"

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
mk_elems() { local n="$1" i out=""; for ((i=1; i<=n; i++)); do out+="${out:+, }198.18.$((i/250)).$((i%250+1))"; done; printf '%s' "$out"; }
mk_set() {   # mk_set <имя> <size> <flags> <timeout|""> <число элементов> <set|meter>
    local to_line=""; [[ -n "$4" ]] && to_line="\t\ttimeout $4\n"
    printf "table inet na_filter {\n\t%s %s {\n\t\ttype ipv4_addr\n\t\tsize %s\n\t\tflags %s\n${to_line}\t\telements = { %s }\n\t}\n}\n" \
        "$6" "$1" "$2" "$3" "$(mk_elems "$5")" > "$NFTD/$6-$1"
}
# nft 1.1.3, правила ≤4.1.2: syn4_443 — бывший meter, виден как набор БЕЗ timeout (85 из 100);
# autoban_v4 — dynamic,timeout БЕЗ строки timeout (срок на каждой записи) и почти полон:
# это НЕ лимитер, его считать нельзя; cc4_443 — ct count, ядро чистит само.
cat > "$NFTD/terse" <<'TERSE'
table inet na_filter {
	set whitelist_v4 {
		type ipv4_addr
		flags interval
	}
	set autoban_v4 {
		type ipv4_addr
		size 100
		flags dynamic,timeout
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
mk_set syn4_443 100 dynamic "" 85 set
mk_set autoban_v4 100 dynamic,timeout "" 95 set
mk_set cc4_443 65535 dynamic "" 99 set
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/out9.json" 2>/dev/null || true
check "json: dynset_fill_max_pct=85 (autoban не лимитер)" 85 "$(jget "$T/out9.json" dynset_fill_max_pct)"
check "json: dynset_fill_max_set=syn4_443"  syn4_443 "$(jget "$T/out9.json" dynset_fill_max_set)"
check "json: dynset_no_timeout=1 (autoban и cc4 не в счёт)" 1 "$(jget "$T/out9.json" dynset_no_timeout)"
env TERM=dumb "$WBASH" "$DIAG" > "$T/out9.txt" 2>/dev/null || true
grep_ok "текст: ✘ legacy-набор почти полон"  "наборы-лимитеры без timeout (1 шт., правила ≤4.1.2) заполнены до 85%" "$T/out9.txt"

# nft 1.0.6, правила ≤4.1.2: meter анонимный — в -t есть только внутри правила
cat > "$NFTD/terse" <<'TERSE'
table inet na_filter {
	set autoban_v4 {
		type ipv4_addr
		size 65536
		flags dynamic,timeout
	}
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 443 ct state new meter cc4_443 size 65535 { ip saddr ct count over 2048 } drop
		tcp dport 443 ct state new meter syn4_443 size 100 { ip saddr limit rate 200/second burst 400 packets } accept
		tcp dport 443 ct state new drop
	}
}
TERSE
rm -f "$NFTD/set-syn4_443"
mk_set syn4_443 100 dynamic "" 90 meter
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/out9n.json" 2>/dev/null || true
check "nft 1.0.6: meter из правила виден, 90%"   90 "$(jget "$T/out9n.json" dynset_fill_max_pct)"
check "nft 1.0.6: meter считается без timeout"   1 "$(jget "$T/out9n.json" dynset_no_timeout)"
rm -f "$NFTD/meter-syn4_443"

# v4.1.3: лимитер с timeout (10 из 100) → ✔, autoban на 95% тревоги не поднимает
cat > "$NFTD/terse" <<'TERSE'
table inet na_filter {
	set autoban_v4 {
		type ipv4_addr
		size 100
		flags dynamic,timeout
	}
	set syn4_443 {
		type ipv4_addr
		size 100
		flags dynamic,timeout
		timeout 60s
	}
}
TERSE
mk_set syn4_443 100 dynamic,timeout 60s 10 set
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/out9b.json" 2>/dev/null || true
check "json: с timeout dynset_no_timeout=0"  0 "$(jget "$T/out9b.json" dynset_no_timeout)"
check "json: заполнение 10%"                 10 "$(jget "$T/out9b.json" dynset_fill_max_pct)"
env TERM=dumb "$WBASH" "$DIAG" > "$T/out9b.txt" 2>/dev/null || true
grep_ok "текст: ✔ лимитеры с timeout"         "наборы-лимитеры с timeout, максимум заполнения 10%" "$T/out9b.txt"
rm -f "$NFTD/terse" "$NFTD/set-syn4_443" "$NFTD/set-cc4_443"
mk_set autoban_v4 65536 dynamic,timeout "" 0 set; rm -f "$NFTD/set-autoban_v4"
set_fixture autoban_v4 '203.0.113.10 timeout 1d expires 1h11m50s608ms, 203.0.113.11 timeout 1d expires 2h'
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
printf 'reboot_needed=1\n' > "$OPTM"   # без boot_id и installed_at — верим маркеру, как раньше
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/out10d.json" 2>/dev/null || true
check "маркер без дат → как раньше, true" true "$(jget "$T/out10d.json" reboot_needed)"
rm -f "$OPTM"

# ════════════════════════════════════════════════════════════════════════════
#  v4.2 — сенсоры по аудиту флота
# ════════════════════════════════════════════════════════════════════════════
STATE="$T/var/lib/node-accelerator"
PROT="$STATE/protect.installed"
cp "$PROT" "$T/protect.installed.orig"
cp "$T/proc/net/snmp" "$T/snmp.orig"
NOW_S="$(/bin/date +%s)"

echo "== 11. дельты счётчиков между запусками вместо накопленного с загрузки (v4.2) =="
# С загрузки ошибок много (накопились давно), за окно — ни одной: ▲ быть не должно.
cat > "$T/proc/net/snmp" <<'SNMP'
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts
Tcp: 1 200 120000 -1 100 200 0 0 10 5000 10000 100 0 0
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors
Udp: 100000 0 0 900 5000 0
SNMP
printf 'Udp6InDatagrams                 2000\nUdp6RcvbufErrors                100\n' > "$T/proc/net/snmp6"
printf '00000100 00000002 00000003 0 0 0 0 0 0 0 0\n00000200 00000002 0000000a 0 0 0 0 0 0 0 0\n' > "$T/proc/net/softnet_stat"
printf 'TcpExt: SyncookiesSent ListenOverflows ListenDrops\nTcpExt: 0 7 9\n' > "$T/proc/net/netstat"
mk_snap() { # mk_snap <boot_id> <возраст, с> <udp_err> <udp_in> <sn_drop> <squeeze> <listen_ovf>
    printf 'boot_id=%s\nepoch=%s\nudp_err=%s\nudp_in=%s\nsn_drop=%s\nsn_squeeze=%s\nlisten_ovf=%s\nlisten_drops=0\nsteal=0\ncpu_total=1050\n' \
        "$1" "$(( NOW_S - $2 ))" "$3" "$4" "$5" "$6" "$7" > "$STATE/diag-counters.last"
}
mk_snap boot-current 600 5100 102000 4 13 7
env TERM=dumb "$WBASH" "$DIAG" > "$T/o11.txt" 2>/dev/null || true
grep_ok  "текст: рост за окно 0 → ✔ «не растут»"                "UDP RcvbufErrors не растут" "$T/o11.txt"
grep_not "текст: накопленные с загрузки 5100 не дают ▲"          "UDP RcvbufErrors = 5100" "$T/o11.txt"
# окно ≥30 с → снимок перезаписан текущими значениями
check "снимок перезаписан (udp_err = v4+v6 = 5100)" "udp_err=5100" "$(grep '^udp_err=' "$STATE/diag-counters.last")"
# рост за окно: +60 ошибок на 1500 датаграмм (4%) — ▲, без UDP-слушателя — без «QUIC»
mk_snap boot-current 120 5040 100600 0 0 0
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/o11.json" 2>/dev/null || true
check "json: udp_rcvbuf_errors_delta=60 (v4 + Udp6)" 60 "$(jget "$T/o11.json" udp_rcvbuf_errors_delta)"
check "json: softnet_drops_delta=4"   4 "$(jget "$T/o11.json" softnet_drops_delta)"
check "json: time_squeeze_delta=13"  13 "$(jget "$T/o11.json" time_squeeze_delta)"
check "json: listen_overflows_delta=7" 7 "$(jget "$T/o11.json" listen_overflows_delta)"
W11="$(jget "$T/o11.json" delta_window_s)"
if [[ "$W11" =~ ^[0-9]+$ && "$W11" -ge 119 && "$W11" -le 140 ]]; then PASS=$((PASS+1)); echo "  ok   json: delta_window_s≈120 ($W11)"
else FAIL=$((FAIL+1)); echo "  FAIL json: delta_window_s ожидалось ≈120, получено [$W11]"; fi
check "json: старое поле udp_rcvbuf_errors не тронуто (v4, с загрузки)" 5000 "$(jget "$T/o11.json" udp_rcvbuf_errors)"
mk_snap boot-current 120 5040 100600 0 0 0
env TERM=dumb "$WBASH" "$DIAG" > "$T/o11b.txt" 2>/dev/null || true
grep_ok  "текст: ▲ рост RcvbufErrors за окно"          "UDP RcvbufErrors +60 за 2 мин" "$T/o11b.txt"
grep_ok  "текст: без UDP-слушателя — исходящие сокеты" "UDP-слушателей нет — это исходящие сокеты" "$T/o11b.txt"
grep_not "текст: про QUIC/Hysteria2 без UDP-слушателя ни слова" "QUIC" "$T/o11b.txt"
grep_ok  "текст: softnet-дропы за окно — ▲"            "softnet: +4 пакетов отброшено" "$T/o11b.txt"
grep_ok  "текст: ListenOverflows за окно — ▲"          "ListenOverflows +7" "$T/o11b.txt"
# окно <30 с: дельты нет, а старый снимок НЕ затирается (копим окно — частый опрос)
mk_snap boot-current 10 5040 100600 0 0 0
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/o11c.json" 2>/dev/null || true
check "json: окно <30 с → delta_window_s=-1" -1 "$(jget "$T/o11c.json" delta_window_s)"
check "окно <30 с → старый снимок сохранён" "udp_err=5040" "$(grep '^udp_err=' "$STATE/diag-counters.last")"
# другая загрузка: дельт нет, снимок переписан
mk_snap boot-other 600 1 1 0 0 0
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/o11d.json" 2>/dev/null || true
check "json: другой boot_id → udp_rcvbuf_errors_delta=-1" -1 "$(jget "$T/o11d.json" udp_rcvbuf_errors_delta)"
check "другой boot_id → снимок текущей загрузки" "boot_id=boot-current" "$(grep '^boot_id=' "$STATE/diag-counters.last")"
# публичный UDP-слушатель → контекст QUIC/Hysteria2
printf 'UNCONN 0 0 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=10,fd=9))\n' > "$SSD/listen-up"
mk_snap boot-current 120 5040 100600 0 0 0
env TERM=dumb "$WBASH" "$DIAG" > "$T/o11e.txt" 2>/dev/null || true
grep_ok  "текст: есть UDP-слушатель → входящий QUIC/Hysteria2" "входящий UDP (QUIC/Hysteria2/TUIC)" "$T/o11e.txt"
rm -f "$SSD/listen-up" "$STATE/diag-counters.last" "$T/proc/net/snmp6" "$T/proc/net/softnet_stat" "$T/proc/net/netstat"
cp "$T/snmp.orig" "$T/proc/net/snmp"

echo "== 12. CPU steal: окно 3 с + среднее с загрузки; PSI — по avg60 (v4.2) =="
printf 'cpu  4000 0 500 5000 0 0 0 500 0 0\nbtime 1788307200\n' > "$T/proc/stat"
printf 'cpu  4200 0 520 5030 0 0 0 530 0 0\nbtime 1788307200\n' > "$T/stat.after"
env TERM=dumb NA_TEST_STAT_AFTER="$T/stat.after" "$WBASH" "$DIAG" --json > "$T/o12.json" 2>/dev/null || true
check "json: cpu_steal_pct=10 (за окно)"       10 "$(jget "$T/o12.json" cpu_steal_pct)"
check "json: cpu_steal_boot_pct=5 (с загрузки)" 5 "$(jget "$T/o12.json" cpu_steal_boot_pct)"
rm -f "$STATE/diag-counters.last"
printf 'cpu  4000 0 500 5000 0 0 0 500 0 0\nbtime 1788307200\n' > "$T/proc/stat"
env TERM=dumb NA_TEST_STAT_AFTER="$T/stat.after" "$WBASH" "$DIAG" > "$T/o12.txt" 2>/dev/null || true
grep_ok "текст: окно и среднее с загрузки в одной строке" "CPU steal = 10% за 3 с, в среднем с загрузки 5%" "$T/o12.txt"
printf 'cpu  100 0 50 900 0 0 0 0 0 0\nbtime 1788307200\n' > "$T/proc/stat"
rm -f "$STATE/diag-counters.last"
mkdir -p "$T/proc/pressure"
printf 'some avg10=55.00 avg60=2.00 avg300=1.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n' > "$T/proc/pressure/cpu"
printf 'some avg10=0.00 avg60=12.50 avg300=3.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n' > "$T/proc/pressure/memory"
printf 'some avg10=0.00 avg60=0.00 avg300=0.00 total=1\n' > "$T/proc/pressure/io"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o12b.txt" 2>/dev/null || true
grep_not "PSI: всплеск avg10=55 при avg60=2 — не ▲" "PSI cpu some avg10=55.00% — заметный" "$T/o12b.txt"
grep_ok  "PSI: всплеск avg10 виден как info с avg60"  "PSI cpu some avg60=2.00% avg10=55.00%" "$T/o12b.txt"
grep_ok  "PSI: устойчивое давление avg60=12.5 — ▲"     "PSI memory some avg60=12.50% (avg10=0.00%) — устойчивый" "$T/o12b.txt"
rm -rf "$T/proc/pressure"

echo "== 13. ложные ▲: XanMod выключен осознанно, logrotate с капом, журнал (v4.2) =="
printf ': "${ENABLE_XANMOD:=0}"\n' > "$T/etc/node-accelerator/optimize.conf"
env TERM=dumb NA_TEST_KREL=6.12.48+deb13-amd64 NA_TEST_ARCH=x86_64 "$WBASH" "$DIAG" > "$T/o13.txt" 2>/dev/null || true
grep_ok  "ENABLE_XANMOD=0 → info, а не ▲"           "XanMod выключен осознанно (ENABLE_XANMOD=0" "$T/o13.txt"
grep_not "ENABLE_XANMOD=0 → нет «Ядро не XanMod»"   "Ядро не XanMod" "$T/o13.txt"
printf ': "${ENABLE_XANMOD=1}"\n' > "$T/etc/node-accelerator/optimize.conf"
env TERM=dumb NA_TEST_KREL=6.12.48+deb13-amd64 NA_TEST_ARCH=x86_64 "$WBASH" "$DIAG" > "$T/o13b.txt" 2>/dev/null || true
grep_ok  "ENABLE_XANMOD=1 (идиома protect v4.2 «=») → ▲ как раньше" "Ядро не XanMod" "$T/o13b.txt"
rm -f "$T/etc/node-accelerator/optimize.conf"
# все уступленные маски — у стансы с капом: ✔, без ▲
printf '/var/log/nginx/*.log\t/etc/logrotate.d/nginx\tcapped\n' > "$STATE/logrotate.ceded"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o13c.txt" 2>/dev/null || true
grep_ok  "logrotate: уступка стансе с капом — ✔"    "✔  ротация: часовой таймер активен; часть масок держат чужие стансы с капом" "$T/o13c.txt"
grep_not "logrotate: ▲ про чужие стансы нет"        "▲  ротация: таймер активен, но часть масок" "$T/o13c.txt"
rm -f "$STATE/logrotate.ceded"
# volatile-журнал: свой текст, без совета про PORTSCAN_LOG_RATE
mkdir -p "$T/run/log/journal"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o13d.txt" 2>/dev/null || true
grep_ok  "журнал volatile — свой ▲"                 "▲  журнал volatile (только" "$T/o13d.txt"
grep_not "volatile: «вмещает менее 48ч» не печатается" "журнал вмещает менее 48ч" "$T/o13d.txt"
rm -rf "$T/run/log/journal"
# глубина ≈ аптайму (одна загрузка): info, PORTSCAN не советуем
printf '36500.00 88888.00\n' > "$T/proc/uptime"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o13e.txt" 2>/dev/null || true
grep_ok  "span ≈ uptime — info «держит всю текущую загрузку»" "≈ аптайму: журнал держит всю текущую загрузку" "$T/o13e.txt"
grep_not "span ≈ uptime — PORTSCAN_LOG_RATE не советуем"    "PORTSCAN_LOG_RATE" "$T/o13e.txt"
printf '99999.00 88888.00\n' > "$T/proc/uptime"
# лог анти-скана: доля за сутки 75% — ▲; 0.3% — info; без --grep — «не измерено»
env TERM=dumb NA_TEST_JTOTAL=4 "$WBASH" "$DIAG" > "$T/o13f.txt" 2>/dev/null || true
grep_ok  "portscan: 75% журнала за сутки → ▲"        "▲  строк [na portscan] за 24ч: 3 (75% журнала за сутки)" "$T/o13f.txt"
env TERM=dumb NA_TEST_JTOTAL=1000 "$WBASH" "$DIAG" --json > "$T/o13g.json" 2>/dev/null || true
check "json: portscan_log_lines_24h=3"   3 "$(jget "$T/o13g.json" portscan_log_lines_24h)"
check "json: portscan_log_share_pct=0"   0 "$(jget "$T/o13g.json" portscan_log_share_pct)"
env TERM=dumb NA_TEST_NO_GREP=1 "$WBASH" "$DIAG" > "$T/o13h.txt" 2>/dev/null || true
grep_ok  "portscan: journalctl без --grep → info «не измерено»" "строк [na portscan] за 24ч: не измерено" "$T/o13h.txt"
# OOM прошлой загрузки виден (журнал ядра за сутки по ВСЕМ загрузкам)
env TERM=dumb NA_TEST_OOM=1 "$WBASH" "$DIAG" > "$T/o13i.txt" 2>/dev/null || true
grep_ok  "OOM за 24ч по всем загрузкам → ▲"          "kern-лог за 24ч: 1 строк OOM" "$T/o13i.txt"

echo "== 14. порты — из живых правил и conf, а не из маркера (v4.2) =="
grep -v '^tcp_ports=' "$T/protect.installed.orig" > "$PROT"
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/o14.json" 2>/dev/null || true
check "json: маркер без tcp_ports= → max_conn_per_ip по живым правилам" 3 "$(jget "$T/o14.json" max_conn_per_ip)"
env "$SSHENV" TERM=dumb "$WBASH" "$DIAG" > "$T/o14.txt" 2>/dev/null || true
grep_ok  "текст: датчик CONN_LIMIT работает без tcp_ports= в маркере" "с одного IP = 3 / CONN_LIMIT 8192 (порты 443," "$T/o14.txt"
cp "$T/protect.installed.orig" "$PROT"
cp "$T/etc/node-accelerator/protect.conf" "$T/protect.conf.orig"
printf ': "${TCP_PORTS=443,8443}"\n' >> "$T/etc/node-accelerator/protect.conf"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o14b.txt" 2>/dev/null || true
grep_ok  "conf (идиома «=») ≠ живым правилам → ▲ с последствием ре-рана" "TCP-порты в живых правилах (443) ≠ TCP_PORTS в protect.conf (443,8443): ре-ран protect откроет 8443" "$T/o14b.txt"
cp "$T/protect.conf.orig" "$T/etc/node-accelerator/protect.conf"
printf ': "${TCP_PORTS:=443}"\n' >> "$T/etc/node-accelerator/protect.conf"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o14c.txt" 2>/dev/null || true
grep_not "conf = живым → ▲ нет"           "TCP-порты в живых правилах" "$T/o14c.txt"
grep_ok  "маркер tcp_ports=443,8445 устарел → info" "маркер protect.installed устарел: tcp_ports=443,8445, в правилах 443" "$T/o14c.txt"
cp "$T/protect.conf.orig" "$T/etc/node-accelerator/protect.conf"

echo "== 15. CrowdSec: решения по источникам, scope, acquisition (v4.2) =="
env TERM=dumb NA_TEST_DECISIONS=2 NA_TEST_CAPI=33 NA_TEST_LISTS=2 "$WBASH" "$DIAG" --json > "$T/o15.json" 2>/dev/null || true
check "json: crowdsec_decisions_local=2"  2 "$(jget "$T/o15.json" crowdsec_decisions_local)"
check "json: crowdsec_decisions_capi=35 (CAPI + lists)" 35 "$(jget "$T/o15.json" crowdsec_decisions_capi)"
mkdir -p "$T/etc/crowdsec/acquis.d"
cat > "$T/etc/crowdsec/acquis.d/na-sshd.yaml" <<'ACQ'
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=ssh.service"
labels:
  type: syslog
---
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=sshd.service"
labels:
  type: syslog
ACQ
env TERM=dumb NA_TEST_CS_TABLE=1 NA_TEST_DECISIONS=2 NA_TEST_CAPI=33 "$WBASH" "$DIAG" > "$T/o15.txt" 2>/dev/null || true
grep_ok "текст: локальные и CAPI раздельно" "2 локальных (crowdsec/cscli), 33 из CAPI/списков" "$T/o15.txt"
grep_ok "текст: scope неизвестен (≤4.1) + CAPI → ▲ «на ВСЕХ портах»" "режет 33 адресов CAPI/списков на ВСЕХ портах" "$T/o15.txt"
grep_ok "текст: acquisition — только sshd" "CrowdSec читает: journalctl[_SYSTEMD_UNIT=ssh.service] journalctl[_SYSTEMD_UNIT=sshd.service] — только sshd" "$T/o15.txt"
printf 'crowdsec_scope=ssh\n' >> "$PROT"
env TERM=dumb NA_TEST_CS_TABLE=1 NA_TEST_CAPI=33 "$WBASH" "$DIAG" > "$T/o15b.txt" 2>/dev/null || true
grep_ok  "scope=ssh из маркера → info" "блок-листы CrowdSec действуют только на SSH-порт" "$T/o15b.txt"
grep_not "scope=ssh → ▲ «на ВСЕХ портах» нет" "на ВСЕХ портах" "$T/o15b.txt"
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/o15c.json" 2>/dev/null || true
check "json: crowdsec_scope из маркера" ssh "$(jget "$T/o15c.json" crowdsec_scope)"
cp "$T/protect.installed.orig" "$PROT"

echo "== 16. whitelist: 4-й слой — эффективный allowlist CrowdSec (v4.2) =="
S2="$T/etc/crowdsec/parsers/s02-enrich"; mkdir -p "$S2"
cat > "$S2/na-whitelist.yaml" <<'YML'
name: node-accelerator/whitelist
description: never ban admin/panel
whitelist:
  reason: node-accelerator trusted
  ip:
    - "203.0.113.5"
  cidr:
    - "192.0.2.0/24"
YML
# ручной файл оператора — прикрывает v6-адрес; и парсер без секции whitelist — мимо
printf 'name: ops/extra\nwhitelist:\n  reason: ops\n  ip: ["2001:db8::1", "198.18.9.9"]\n' > "$S2/ops-extra.yaml"
printf 'name: crowdsecurity/geoip-enrich\nfilter: "1==1"\nip:\n  - "198.51.100.7"\n' > "$S2/geoip-enrich.yaml"
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/o16.json" 2>/dev/null || true
check "json: whitelist_drift_crowdsec=1 (198.51.100.7 не прикрыт)" 1 "$(jget "$T/o16.json" whitelist_drift_crowdsec)"
env TERM=dumb NA_TEST_CS_TABLE=1 "$WBASH" "$DIAG" > "$T/o16.txt" 2>/dev/null || true
grep_ok "текст: ▲ называет непрокрытый адрес (bouncer стоит)" "▲  whitelist na_filter не прикрыт в CrowdSec: 198.51.100.7" "$T/o16.txt"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o16n.txt" 2>/dev/null || true
grep_not "без bouncer'а — не ▲" "▲  whitelist na_filter не прикрыт" "$T/o16n.txt"
grep_ok "текст: лишний в allowlist CrowdSec — info" "в allowlist CrowdSec, но не в whitelist na_filter: 198.18.9.9" "$T/o16.txt"
# обратный дрейф: адрес есть в na_filter.nft и conf, но удалён из живого сета руками
cp "$NFTD/set-whitelist_v4" "$T/wl4.orig"
printf 'table inet na_filter {\n\tset whitelist_v4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { 198.51.100.7 }\n\t}\n}\n' > "$NFTD/set-whitelist_v4"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o16r.txt" 2>/dev/null || true
grep_ok "файл → живой: удалённый на ходу адрес назван" "но не в живом whitelist_v4: 192.0.2.0/24 203.0.113.5 (вернутся после ребута" "$T/o16r.txt"
grep_ok "conf → живой: тоже"                           "в WHITELIST= из protect.conf, но не в живом whitelist_v4: 192.0.2.0/24 203.0.113.5" "$T/o16r.txt"
cp "$T/wl4.orig" "$NFTD/set-whitelist_v4"
printf '    - "198.51.100.0/24"\n' >> "$S2/na-whitelist.yaml"
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/o16b.json" 2>/dev/null || true
check "json: адрес прикрыт CIDR'ом allowlist → 0" 0 "$(jget "$T/o16b.json" whitelist_drift_crowdsec)"
rm -rf "$T/etc/crowdsec"

echo "== 17. DNAT мимо na_filter, слушатели вне файрвола (v4.2) =="
printf '0.0.0.0:80->80/tcp, [::]:80->80/tcp, 127.0.0.1:9000->9000/tcp\n\n' > "$NFTD/docker-ports"
cat > "$NFTD/ruleset" <<'RS'
table ip nat {
	chain PREROUTING {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "eth0" tcp dport 8443 counter packets 0 bytes 0 dnat to 10.0.0.9:443
		ip daddr 127.0.0.1 tcp dport 9100 dnat to 172.17.0.3:9100
	}
}
RS
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/o17.json" 2>/dev/null || true
check "json: dnat_ports (docker + ручной relay, без loopback)" "80/tcp,8443/tcp" "$(jget "$T/o17.json" dnat_ports)"
check "json: dnat_guard=-1 (маркер ≤4.1 без ключа)" -1 "$(jget "$T/o17.json" dnat_guard)"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o17.txt" 2>/dev/null || true
grep_ok "текст: ▲ DNAT мимо na_filter с перечнем" "опубликованы через DNAT мимо na_filter: 80/tcp,8443/tcp" "$T/o17.txt"
printf 'dnat_guard=1\n' >> "$PROT"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o17b.txt" 2>/dev/null || true
grep_ok  "dnat_guard=1 → info" "под защитой na_filter (dnat_guard=1)" "$T/o17b.txt"
grep_not "dnat_guard=1 → ▲ нет" "мимо na_filter" "$T/o17b.txt"
cp "$T/protect.installed.orig" "$PROT"
rm -f "$NFTD/docker-ports" "$NFTD/ruleset"
cat > "$SSD/listen-tp" <<'LTP'
LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=10,fd=7))
LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
LISTEN 0 128 0.0.0.0:10050 0.0.0.0:* users:(("monitor-agent",pid=20,fd=4))
LISTEN 0 128 [::]:10050 [::]:* users:(("monitor-agent",pid=20,fd=5))
LISTEN 0 4096 127.0.0.1:10085 0.0.0.0:* users:(("xray",pid=10,fd=8))
LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=5,fd=14))
LTP
printf 'UNCONN 0 0 10.0.0.5%%eth0:68 0.0.0.0:* users:(("dhclient",pid=3,fd=6))\n' > "$SSD/listen-up"
cp "$NFTD/chain-input" "$T/chain.orig"
awk '{print} /meter cc4_443/ { print "\t\ttcp dport 8445 ct state new meter cc4_8445 { ip saddr ct count over 8192 } drop" }' "$T/chain.orig" > "$NFTD/chain-input"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o17c.txt" 2>/dev/null || true
grep_ok  "strict: слушатель вне портов — info, назван процесс" "strict их режет (доступны только whitelist/флоту): tcp/10050(monitor-agent)" "$T/o17c.txt"
grep_not "DHCP-клиент не в списке слушателей" "udp/68" "$T/o17c.txt"
grep_ok  "разрешён, но никто не слушает — info"   "разрешены в файрволе, но никто не слушает: tcp/8445" "$T/o17c.txt"
sed 's/^fw_mode=strict/fw_mode=open/' "$T/protect.installed.orig" > "$PROT"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o17d.txt" 2>/dev/null || true
grep_ok  "FW_MODE=open: вне перечисленных — по замыслу, info" "слушают вне перечисленных портов (FW_MODE=open — открыты по замыслу" "$T/o17d.txt"
grep_not "FW_MODE=open: ▲ нет"                               "▲  слушают" "$T/o17d.txt"
sed 's/^fw_mode=strict/fw_mode=skip/' "$T/protect.installed.orig" > "$PROT"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o17f.txt" 2>/dev/null || true
grep_ok  "FW_MODE=skip: слушатель вне портов открыт миру — ▲" "▲  слушают публично вне разрешённых портов и открыты миру (na_filter skip — правил нет): tcp/10050(monitor-agent)" "$T/o17f.txt"
cp "$T/protect.installed.orig" "$PROT"
# порт xray в эфемерном диапазоне без резерва — ▲; зарезервирован — тишина
grep_ok  "xray :10085 в эфемерном диапазоне без резерва → ▲" "без резерва: 10085(xray)" "$T/o17c.txt"
env TERM=dumb NA_TEST_RESV=10085,20000-20010 "$WBASH" "$DIAG" > "$T/o17e.txt" 2>/dev/null || true
grep_not "зарезервирован → ▲ нет" "без резерва:" "$T/o17e.txt"
cp "$T/chain.orig" "$NFTD/chain-input"
rm -f "$SSD/listen-tp" "$SSD/listen-up"

echo "== 18. память, nftables.service, счётчики, хэш файла, буферы от tier (v4.2) =="
cp "$T/proc/meminfo" "$T/meminfo.orig"
printf 'MemTotal:  1000000 kB\nMemAvailable: 100000 kB\nSwapTotal: 524288 kB\nSwapFree: 262144 kB\n' > "$T/proc/meminfo"
printf 'virtio_balloon 28672 0 - Live 0x0000000000000000\nvirtio_net 61440 0 - Live 0x0\n' > "$T/proc/modules"
printf 'flush ruleset\ntable inet filter {\n}\n' > "$T/etc/nftables.conf"
cat > "$NFTD/counters" <<'CNT'
table inet na_filter {
	counter c_synflood {
		packets 0 bytes 0
	}
	counter c_portscan {
		packets 1234 bytes 74040
	}
}
CNT
printf 'nft_sha256=0000000000000000000000000000000000000000000000000000000000000000\n' >> "$PROT"
env TERM=dumb NA_TEST_NFTS=1 NA_TEST_RMEM_MAX=16777216 NA_TEST_RMEM_DEF=212992 "$WBASH" "$DIAG" > "$T/o18.txt" 2>/dev/null || true
grep_ok  "MemAvailable 10% → ▲"                  "▲  MemAvailable 10%" "$T/o18.txt"
grep_ok  "своп занят — info"                      "своп занят: 256 из 512 МБ" "$T/o18.txt"
grep_ok  "balloon-драйвер — info"                 "balloon-драйвер: virtio_balloon" "$T/o18.txt"
grep_ok  "nftables.service + flush ruleset → ▲"   "▲  nftables.service enabled, а" "$T/o18.txt"
grep_ok  "…с советом disable без stop"            "systemctl disable nftables.service (без stop/--now)" "$T/o18.txt"
grep_ok  "ненулевые счётчики c_* показаны"        "счётчики дропов na_filter (с загрузки правил): c_portscan=1234" "$T/o18.txt"
grep_not "нулевой c_synflood не показан"          "c_synflood=" "$T/o18.txt"
grep_ok  "nft_sha256 ≠ файлу → ▲ «правлен руками»" "правлен руками после прогона protect" "$T/o18.txt"
grep_ok  "tier1 (≤1.2G): rmem_max 16M — ✔, а не ▲" "✔  net.core.rmem_max = 16777216" "$T/o18.txt"
grep_ok  "rmem_default ниже tier → ▲"             "▲  net.core.rmem_default = 212992 (рекоменд. ≥ 524288)" "$T/o18.txt"
SHA="$( { sha256sum "$T/etc/node-accelerator/na_filter.nft" 2>/dev/null || shasum -a 256 "$T/etc/node-accelerator/na_filter.nft"; } | awk '{print $1}')"
cp "$T/protect.installed.orig" "$PROT"; printf 'nft_sha256=%s\n' "$SHA" >> "$PROT"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o18b.txt" 2>/dev/null || true
grep_ok  "nft_sha256 совпадает → ✔"               "совпадает с записанным protect" "$T/o18b.txt"
cp "$T/protect.installed.orig" "$PROT"; cp "$T/meminfo.orig" "$T/proc/meminfo"
rm -f "$T/proc/modules" "$T/etc/nftables.conf" "$NFTD/counters"

echo "== 19. XanMod: доступное обновление; reboot-required от стоковых ядер (v4.2) =="
printf 'linux-xanmod-x64v3\n' > "$STATE/xanmod.pkg"
cat > "$T/aptpol" <<'POL'
linux-xanmod-x64v3:
  Installed: 6.18.47-x64v3-xanmod1-0~20260901.gabc
  Candidate: 6.18.52-x64v3-xanmod1-0~20260928.gdef
  Version table:
     6.18.52-x64v3-xanmod1-0~20260928.gdef 500
        500 https://deb.xanmod.org trixie/main amd64 Packages
 *** 6.18.47-x64v3-xanmod1-0~20260901.gabc 100
        100 /var/lib/dpkg/status
POL
env TERM=dumb NA_TEST_APTPOL="$T/aptpol" "$WBASH" "$DIAG" --json > "$T/o19.json" 2>/dev/null || true
check "json: xanmod_update = версия кандидата" "6.18.52-x64v3-xanmod1-0~20260928.gdef" "$(jget "$T/o19.json" xanmod_update)"
env TERM=dumb NA_TEST_APTPOL="$T/aptpol" "$WBASH" "$DIAG" > "$T/o19.txt" 2>/dev/null || true
grep_ok "текст: info про обновление XanMod" "доступно обновление XanMod: 6.18.52-x64v3-xanmod1-0~20260928.gdef" "$T/o19.txt"
sed 's#deb.xanmod.org#deb.example.test#' "$T/aptpol" > "$T/aptpol2"
env TERM=dumb NA_TEST_APTPOL="$T/aptpol2" "$WBASH" "$DIAG" --json > "$T/o19b.json" 2>/dev/null || true
check "json: кандидат не из репо XanMod → пусто" "" "$(jget "$T/o19b.json" xanmod_update)"
rm -f "$STATE/xanmod.pkg"
mkdir -p "$T/run"
: > "$T/run/reboot-required"; printf 'linux-image-6.12.48+deb13-amd64\nlinux-image-amd64\n' > "$T/run/reboot-required.pkgs"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o19c.txt" 2>/dev/null || true
grep_ok  "reboot-required от стоковых ядер при XanMod → info" "от стоковых ядер (linux-image-6.12.48+deb13-amd64 linux-image-amd64), а работает XanMod" "$T/o19c.txt"
grep_not "…и не ▲"                                            "система ждёт перезагрузки" "$T/o19c.txt"
printf 'libc6\n' > "$T/run/reboot-required.pkgs"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o19d.txt" 2>/dev/null || true
grep_ok  "reboot-required от libc6 → ▲"                      "reboot-required: libc6)" "$T/o19d.txt"
grep_ok  "…именно ▲"                                         "▲  система ждёт перезагрузки" "$T/o19d.txt"
rm -f "$T/run/reboot-required" "$T/run/reboot-required.pkgs"

echo "== 20. сертификаты: просроченный не маскируется, Caddy и nginx находятся (v4.2) =="
mkdir -p "$T/etc/letsencrypt/live/expired.example.test"
printf 'x\n' > "$T/etc/letsencrypt/live/expired.example.test/fullchain.pem"
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/o20.json" 2>/dev/null || true
check "json: просроченный серт: cert_min_days=-10" -10 "$(jget "$T/o20.json" cert_min_days)"
check "json: cert_found=true"                     true "$(jget "$T/o20.json" cert_found)"
env TERM=dumb "$WBASH" "$DIAG" > "$T/o20.txt" 2>/dev/null || true
grep_ok "текст: ✘ «ИСТЁК»"                          "✘  TLS-серт ИСТЁК 10 дн назад" "$T/o20.txt"
rm -rf "$T/etc/letsencrypt"
CADDY_D="$T/var/lib/docker/volumes/caddy_data/_data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/panel.example.test"
mkdir -p "$CADDY_D"; printf 'x\n' > "$CADDY_D/panel.example.test.crt"
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/o20b.json" 2>/dev/null || true
check "json: серт Caddy в docker volume найден (15 дн)" 15 "$(jget "$T/o20b.json" cert_min_days)"
rm -rf "$T/var/lib/docker/volumes"
mkdir -p "$T/etc/nginx/sites-enabled" "$T/etc/nginx/sites-available" "$T/srv/tls" "$T/srv/old"
printf 'x\n' > "$T/srv/tls/nginx-site.pem"
printf 'server {\n    listen 443 ssl;\n    ssl_certificate %s;\n    ssl_certificate_key /srv/tls/k.pem;\n}\n' "$T/srv/tls/nginx-site.pem" > "$T/etc/nginx/sites-enabled/default"
printf 'x\n' > "$T/srv/old/expired-old.pem"
printf 'server { ssl_certificate %s; }\n' "$T/srv/old/expired-old.pem" > "$T/etc/nginx/sites-available/old"
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/o20c.json" 2>/dev/null || true
check "json: nginx ssl_certificate найден (20 дн)" 20 "$(jget "$T/o20c.json" cert_min_days)"
check "json: sites-available (не включён) не считается" "$T/srv/tls/nginx-site.pem" "$(jget "$T/o20c.json" cert_min_file)"
rm -rf "$T/etc/nginx" "$T/srv"
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/o20d.json" 2>/dev/null || true
check "json: снова только живой серт (60), cert_found=true" "60 true" "$(jget "$T/o20d.json" cert_min_days) $(jget "$T/o20d.json" cert_found)"

echo "== 21. docker: лог без max-size; RPS при RX-очередей ≥ ядер (v4.2) =="
env TERM=dumb NA_TEST_DK_NOCAP=1 "$WBASH" "$DIAG" > "$T/o21.txt" 2>/dev/null || true
grep_ok  "контейнер json-file без max-size → ▲" "контейнеры с json-логом без max-size (растёт без предела): remnanode" "$T/o21.txt"
for q in 1 2 3; do mkdir -p "$T/sys/class/net/eth0/queues/rx-$q"; printf '0\n' > "$T/sys/class/net/eth0/queues/rx-$q/rps_cpus"; done
env TERM=dumb "$WBASH" "$DIAG" > "$T/o21b.txt" 2>/dev/null || true
grep_ok  "RX-очередей (4) ≥ ядер (4) → info «не нужен»" "RPS выключен — и не нужен: RX-очередей (4) ≥ ядер (4)" "$T/o21b.txt"
grep_not "…и не ▲ «RPS выключен»"                       "▲  RPS выключен" "$T/o21b.txt"
grep_not "…и не ▲ «гонка на буте»"                      "na-rps.service active, но rps_cpus пуст" "$T/o21b.txt"
rm -rf "$T/sys/class/net/eth0/queues/rx-1" "$T/sys/class/net/eth0/queues/rx-2" "$T/sys/class/net/eth0/queues/rx-3"

echo "== 22. --json по-прежнему одна валидная строка, новые поля — строго в хвосте =="
env TERM=dumb "$WBASH" "$DIAG" --json > "$T/o22.json" 2>/dev/null || true
check "одна строка" 1 "$(wc -l < "$T/o22.json" | tr -d ' ')"
check "новые поля строго после прежнего хвоста (dynset_no_timeout)" ok "$(python3 - "$T/o22.json" <<'PYK'
import json,sys
d=json.load(open(sys.argv[1])); k=list(d)
new=["udp_rcvbuf_errors_delta","softnet_drops_delta","time_squeeze_delta","listen_overflows_delta","delta_window_s",
     "cpu_steal_boot_pct","crowdsec_decisions_local","crowdsec_decisions_capi","crowdsec_scope",
     "whitelist_drift_crowdsec","dnat_ports","dnat_guard","xanmod_update","cert_found",
     "portscan_log_lines_24h","portscan_log_share_pct"]
i=k.index("dynset_no_timeout")
print("ok" if k[i+1:]==new and k[0]=="kernel" else "keys after tail: %s" % k[i+1:])
PYK
)"

echo
echo "  прогон: $PASS ok, $FAIL fail"
if [[ "$FAIL" -ne 0 ]]; then echo "DIAGNOSE-UNIT: FAIL"; exit 1; fi
echo "DIAGNOSE-UNIT: OK (--json валиден и честен, датчики меряют тот же срез, что и правила)"
