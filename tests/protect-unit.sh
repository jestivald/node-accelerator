#!/usr/bin/env bash
#
# protect-unit.sh — юнит-тесты кусков protect.sh, которые до этого нигде не исполнялись:
# сгенерированный хелпер `na-fw-status`, разбор WHITELIST и сборка анти-скан-правил.
# Все три блока правились по аудиту боевого флота v4.0.1:
#
#   1. na-fw-status (issue #32/#36): счётчики наборов считались `grep -c timeout` по
#      выводу nft, где строка `flags dynamic,timeout` есть ВСЕГДА → пустой набор давал
#      «1», непустой был завышен, а na-fw-status и na-diagnose расходились между собой.
#      Здесь хелпер РЕАЛЬНО исполняется против стаба nft, который печатает наборы так же,
#      как nft 1.0.9/1.1.x — пустой динамический, непустой, многострочный, v6.
#   2. add_wl (issue #38): дубликат из CSV оператора уезжал в ruleset/CrowdSec как есть,
#      а /24 и шире принимались молча — при том, что whitelist в na это полный обход
#      защиты. Проверяем дедуп, нормализацию /32 и /128, предупреждение о широком CIDR.
#   3. анти-скан-лог (issue #35): рейт лога вынесен в PORTSCAN_LOG_RATE (в МИНУТУ),
#      0 = не логировать вовсе; плюс оценка суточного объёма против капа journald.
#
# Не требует root/сети/nft/systemd. Запуск: bash tests/protect-unit.sh
# Проверить на старой версии:  NA_PROTECT_SH=<путь> bash tests/protect-unit.sh  (упадёт)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTECT="${NA_PROTECT_SH:-$REPO_ROOT/scripts/protect.sh}"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/etc" "$T/sbin"

# хелперам и protect.sh нужен bash ≥ 4.2 ([[ -v ]]) — на macOS системный древний
pick_bash() {
    local c
    for c in bash /opt/homebrew/bin/bash /usr/local/bin/bash; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" -c 'set -u; a=(); : "${a[@]}"; [[ -v HOME ]]' 2>/dev/null; then command -v "$c"; return 0; fi
    done
    return 1
}
WBASH="$(pick_bash)" || { echo "[x] не нашёл bash ≥ 4.4"; exit 1; }

PASS=0; FAIL=0
check() { # check "описание" <ожидание> <факт>
    if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); echo "  ok   $1"
    else FAIL=$((FAIL+1)); echo "  FAIL $1: ожидалось [$2], получено [$3]"; fi
}
checkf() { # checkf "описание" — фиксируем провал без сравнения
    FAIL=$((FAIL+1)); echo "  FAIL $1"
}

# ─── 1. Сгенерированный na-fw-status ─────────────────────────────────────────
echo "== 1. na-fw-status: счётчики наборов (issue #32/#36) =="

# Генератор хелпера — функция write_fw_status в protect.sh: вытаскиваем её целиком и
# исполняем с подсунутым lib/common.sh (оттуда declare -f вшивает nft_set_count).
awk '/^write_fw_status\(\) \{$/{f=1} f{print} f&&/^\}$/{exit}' "$PROTECT" > "$T/gen-fw-status.raw"
if [[ ! -s "$T/gen-fw-status.raw" ]]; then
    checkf "не нашёл генератор write_fw_status в $PROTECT (старая версия писала хелпер сырым heredoc'ом — счётчики там по grep -c)"
else
    sed -e "s#/usr/local/sbin/#$T/sbin/#g" "$T/gen-fw-status.raw" > "$T/gen-fw-status.sh"

    # стаб nft: печатает наборы ровно так, как настоящий nft 1.0.9/1.1.x
    cat > "$T/bin/nft" <<'NFT'
#!/usr/bin/env bash
# nft list table <family> <table>   |   nft list set <family> <table> <set>
if [[ "${1:-}" == "list" && "${2:-}" == "table" ]]; then
    case "${4:-}" in
        na_filter)  printf 'table inet na_filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n'; exit 0;;
        na_ctguard) exit 0;;
        *) exit 1;;
    esac
fi
[[ "${1:-}" == "list" && "${2:-}" == "set" ]] || exit 1
hdr() { printf 'table inet %s {\n\tset %s {\n\t\ttype %s\n\t\tsize 65536\n\t\tflags dynamic,timeout\n' "$3" "$1" "$2"; }
case "${5:-}" in
    autoban_v4)
        hdr autoban_v4 ipv4_addr na_filter
        printf '\t\telements = { 203.0.113.10 timeout 1d expires 1h11m50s608ms,\n\t\t\t     198.51.100.22 timeout 1d expires 55m }\n\t}\n}\n';;
    autoban_v6|suspect_v4|suspect_v6|phantom_v4)
        # ПУСТОЙ динамический набор: заголовок со словом timeout есть, элементов нет
        printf 'table inet t {\n\tset %s {\n\t\ttype addr\n\t\tsize 65536\n\t\tflags dynamic,timeout\n\t\ttimeout 30m\n\t}\n}\n' "${5}";;
    phantom_v6)
        printf 'table inet na_ctguard {\n\tset phantom_v6 {\n\t\ttype ipv6_addr\n\t\tflags dynamic,timeout\n\t\telements = { 2001:db8::66 timeout 15m expires 12m3s }\n\t}\n}\n';;
    blocklist_v4)
        printf 'table inet na_filter {\n\tset blocklist_v4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { 203.0.113.0/24, 198.51.100.0/24,\n\t\t\t     192.0.2.0/24 }\n\t}\n}\n';;
    blocklist_v6)
        printf 'table inet na_filter {\n\tset blocklist_v6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\tauto-merge\n\t}\n}\n';;
    na_fleet_v4)
        printf 'table inet na_filter {\n\tset na_fleet_v4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { 203.0.113.5, 203.0.113.6 }\n\t}\n}\n';;
    na_fleet_v6)
        printf 'table inet na_filter {\n\tset na_fleet_v6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { 2001:db8::5 }\n\t}\n}\n';;
    *) echo "Error: No such file or directory" >&2; exit 1;;
esac
NFT
    printf '#!/bin/sh\nexit 0\n' > "$T/bin/journalctl"
    chmod +x "$T/bin/nft" "$T/bin/journalctl"

    "$WBASH" -c "set -euo pipefail; . '$REPO_ROOT/scripts/lib/common.sh'; . '$T/gen-fw-status.sh'; write_fw_status" >/dev/null
    if [[ ! -x "$T/sbin/na-fw-status" ]]; then
        checkf "генератор не создал $T/sbin/na-fw-status"
    else
        check "тело nft_set_count вшито в хелпер (lib/common.sh рядом с ним не лежит)" \
              1 "$(grep -c '^nft_set_count ' "$T/sbin/na-fw-status")"
        OUT="$(PATH="$T/bin:$PATH" "$WBASH" "$T/sbin/na-fw-status" 2>&1)"
        check "autoban: 2 элемента v4 и ПУСТОЙ v6 (не «1» из-за flags dynamic,timeout)" \
              "v4: 2   v6: 0" "$(printf '%s\n' "$OUT" | sed -n 's/^\(v4: [0-9]*   v6: [0-9]*\)$/\1/p' | head -1)"
        check "suspect: оба набора пусты" \
              "suspect (наблюдение, ban-once) v4: 0   v6: 0" \
              "$(printf '%s\n' "$OUT" | grep -o 'suspect (наблюдение, ban-once) v4: [0-9]*   v6: [0-9]*')"
        check "blocklist: 3 интервала v4, пусто v6" "v4: 3   v6: 0" \
              "$(printf '%s\n' "$OUT" | grep -o 'v4: [0-9]*   v6: [0-9]*   (обновляет na-blocklist-update)' | sed 's/   (обновляет.*//')"
        check "fleet: 2 v4 + 1 v6" "v4: 2   v6: 1" \
              "$(printf '%s\n' "$OUT" | grep -o 'v4: [0-9]*   v6: [0-9]*   (последний синк' | sed 's/   (последний.*//')"
        check "ctguard: пусто v4, 1 фантом v6" "фантомов в блоке v4: 0   v6: 1" \
              "$(printf '%s\n' "$OUT" | grep -o 'фантомов в блоке v4: [0-9]*   v6: [0-9]*')"
        check "показаны сами баны (адрес + expires), а не только число" 2 \
              "$(printf '%s\n' "$OUT" | grep -c -E '^(203\.0\.113\.10|198\.51\.100\.22) timeout 1d expires')"
        check "строки заголовка набора в список банов не попадают" 0 \
              "$(printf '%s\n' "$OUT" | grep -c 'flags dynamic')"
    fi
fi

# ─── 2. add_wl: дедуп, нормализация, широкий CIDR ────────────────────────────
echo "== 2. WHITELIST: дедуп / нормализация / широкий CIDR (issue #38) =="
awk '/^WL4=""; WL6=""$/{f=1} /^add_wl "\$WHITELIST"/{f=0} f' "$PROTECT" > "$T/wl.sh"
if [[ ! -s "$T/wl.sh" ]]; then
    checkf "не смог извлечь блок разбора WHITELIST из $PROTECT"
else
    wl() { "$WBASH" -c "set -euo pipefail; . '$REPO_ROOT/scripts/lib/common.sh'; . '$T/wl.sh'; $1" 2>&1; }
    check "дубль в CSV → один элемент" "203.0.113.7" \
          "$(wl 'add_wl "203.0.113.7,203.0.113.7" >/dev/null; printf "%s" "$WL4"')"
    check "дубль замечен вслух (protect.conf не переписываем — чинит оператор)" 1 \
          "$(wl 'add_wl "203.0.113.7,203.0.113.7" | grep -c "указан дважды"')"
    check "о тройном повторе предупреждаем один раз, не простынёй" 1 \
          "$(wl 'add_wl "203.0.113.7,203.0.113.7,203.0.113.7" | grep -c "указан дважды"')"
    check "/32 и голый адрес — одно и то же значение" "203.0.113.7" \
          "$(wl 'add_wl "203.0.113.7/32,203.0.113.7" >/dev/null; printf "%s" "$WL4"')"
    check "/32 нормализован даже без дубля" "198.51.100.5" \
          "$(wl 'add_wl "198.51.100.5/32" >/dev/null; printf "%s" "$WL4"')"
    check "/128 нормализован, дубль по v6 ловится" "2001:db8::1" \
          "$(wl 'add_wl "2001:db8::1/128,2001:db8::1" >/dev/null; printf "%s" "$WL6"')"
    check "широкий v4 (/24) → warn про полный обход защиты" 1 \
          "$(wl 'add_wl "203.0.113.0/24" | grep -c "ПОЛНЫЙ обход защиты"')"
    check "в warn названо число адресов (2^8)" 1 \
          "$(wl 'add_wl "203.0.113.0/24" | grep -c "2\^8 адресов (256)"')"
    check "широкий v6 (/48) → warn" 1 \
          "$(wl 'add_wl "2001:db8:abc::/48" | grep -c "2\^80 адресов"')"
    check "/29 (порог) — молча" 0 \
          "$(wl 'add_wl "203.0.113.8/29" | grep -c "ПОЛНЫЙ обход"')"
    check "/64 v6 (порог) — молча" 0 \
          "$(wl 'add_wl "2001:db8:abc::/64" | grep -c "ПОЛНЫЙ обход"')"
    check "хост-адрес — молча" 0 \
          "$(wl 'add_wl "203.0.113.7,2001:db8::1" | grep -c "ПОЛНЫЙ обход\|дважды"')"
    check "auto-источник (IP текущей SSH-сессии) дублем не шумит" 0 \
          "$(wl 'add_wl "203.0.113.7" >/dev/null; add_wl "203.0.113.7" auto | grep -c "дважды"')"
    check "…и вторым элементом в набор не лезет" "203.0.113.7" \
          "$(wl 'add_wl "203.0.113.7" >/dev/null; add_wl "203.0.113.7" auto >/dev/null; printf "%s" "$WL4"')"
    check "мусор по-прежнему отвергается (rc=1)" "rc=1" \
          "$(wl 'add_wl "203.0.113.7; nft flush ruleset" >/dev/null 2>&1 || echo rc=1')"
    check "разделитель набора остаётся ', ' (формат elements = { … })" "203.0.113.7, 198.51.100.5" \
          "$(wl 'add_wl "203.0.113.7,198.51.100.5" >/dev/null; printf "%s" "$WL4"')"
fi

# ─── 3. Сборка анти-скан-правил: PORTSCAN_LOG_RATE ───────────────────────────
echo "== 3. анти-скан: рейт лога вынесен в ручку (issue #35) =="
awk '/^PORTSCAN=""/{f=1} f{print} f&&/^fi$/{exit}' "$PROTECT" > "$T/portscan.sh"
if [[ ! -s "$T/portscan.sh" ]]; then
    checkf "не смог извлечь сборку PORTSCAN из $PROTECT"
else
    ps_run() {   # ps_run "<переопределения через ;>"
        "$WBASH" -c "set -euo pipefail
ENABLE_PORTSCAN_BAN=1; FW_MODE=strict; ENABLE_BANONCE=1
PORTSCAN_RATE=15; PORTSCAN_BURST=30; PORTSCAN_BAN_TIME=1h; SUSPECT_TIME=30m
PORTSCAN_LOG_RATE=60; PORTSCAN_LOG_BURST=30
$1
. '$T/portscan.sh'
printf '%s\n' \"\$PORTSCAN\" \"\${PORTSCAN_CHAINS:-}\"" 2>&1
    }
    # v4.2: лог — только на переходе адреса в suspect/бан (цепочки ps_suspect*/ps_ban*), а не
    # на каждый SYN в закрытый порт: ban-once → 4 лог-правила (v4/v6 × suspect/ban)
    check "лог 60/минуту с burst 30 — в цепочках перехода (ban-once: 4)" 4 \
          "$(ps_run ':' | grep -c 'limit rate 60/minute burst 30 packets log prefix "\[na portscan\] "')"
    check "лога на КАЖДЫЙ SYN больше нет (правило с ct state new + log)" 0 \
          "$(ps_run ':' | grep -c 'ct state new limit rate .* log prefix "\[na portscan\]')"
    check "suspect логируется один раз: уже-suspect — return до лога" 1 \
          "$(ps_run ':' | grep -c 'ip saddr @suspect_v4 return')"
    check "прежние 5/second из правила ушли" 0 "$(ps_run ':' | grep -c '5/second log prefix "\[na portscan\]')"
    check "ручки доезжают до правила" 4 \
          "$(ps_run 'PORTSCAN_LOG_RATE=5; PORTSCAN_LOG_BURST=7' | grep -c 'limit rate 5/minute burst 7 packets')"
    check "PORTSCAN_LOG_RATE=0 → лог-правил нет вовсе" 0 \
          "$(ps_run 'PORTSCAN_LOG_RATE=0' | grep -c '\[na portscan\]')"
    check "…но бан продолжает работать (→ @autoban)" 1 \
          "$(ps_run 'PORTSCAN_LOG_RATE=0' | grep -c 'add @autoban_v4')"
    check "…и наблюдение ban-once тоже (→ @suspect)" 1 \
          "$(ps_run 'PORTSCAN_LOG_RATE=0' | grep -c 'add @suspect_v4 { ip saddr timeout 30m }')"
    check "бан считает именованный счётчик c_portscan" 2 \
          "$(ps_run ':' | grep -c 'counter name c_portscan drop')"
    check "в ruleset остаётся видно, ПОЧЕМУ лога нет" 4 \
          "$(ps_run 'PORTSCAN_LOG_RATE=0' | grep -c 'PORTSCAN_LOG_RATE=0')"
    check "без ban-once — лог только на бане (v4/v6)" 2 \
          "$(ps_run 'ENABLE_BANONCE=0' | grep -c 'limit rate 60/minute burst 30 packets log prefix "\[na portscan\] "')"
fi

# ─── 4. Бюджет журнала под лог анти-скана ────────────────────────────────────
echo "== 4. бюджет journald под [na portscan] (issue #35) =="
awk '/^NA_JOURNAL_LINE_BYTES=/{f=1} /^check_journal_budget$/{exit} f' "$PROTECT" > "$T/budget.raw"
if [[ ! -s "$T/budget.raw" ]]; then
    checkf "в $PROTECT нет оценки бюджета журнала (check_journal_budget)"
else
    sed -e "s#/etc/systemd/journald.conf#$T/etc/journald.conf#g" "$T/budget.raw" > "$T/budget.sh"
    mkdir -p "$T/etc/journald.conf.d"
    bud() {   # bud "<переопределения>" — окружение как у боевого прогона
        "$WBASH" -c "set -euo pipefail; . '$REPO_ROOT/scripts/lib/common.sh'; . '$T/budget.sh'
ENABLE_PORTSCAN_BAN=1; FW_MODE=strict; PORTSCAN_LOG_RATE=60
$1" 2>&1
    }
    printf '[Journal]\nSystemMaxUse=300M\nSystemKeepFree=500M\n' > "$T/etc/journald.conf.d/na-size.conf"
    check "кап 300M из drop-in optimize распознан" 314572800 "$(bud 'journald_cap_bytes')"
    check "дефолтный рейт 60/мин при капе 300M — тишина" "" "$(bud 'check_journal_budget')"
    check "300/мин (прежние 5/сек) при том же капе → warn" 1 \
          "$(bud 'PORTSCAN_LOG_RATE=300; check_journal_budget' | grep -c 'лог анти-скана')"
    check "…в warn названы оба числа: суточный объём и кап" 1 \
          "$(bud 'PORTSCAN_LOG_RATE=300; check_journal_budget' | grep -c 'МБ/сутки при капе journald 300 МБ')"
    check "…и сказано, что делать" 1 \
          "$(bud 'PORTSCAN_LOG_RATE=300; check_journal_budget' | grep -c 'снизь PORTSCAN_LOG_RATE')"
    check "PORTSCAN_LOG_RATE=0 → считать нечего" "" "$(bud 'PORTSCAN_LOG_RATE=0; check_journal_budget')"
    check "автобан за скан выключен → бюджет не при чём" "" \
          "$(bud 'ENABLE_PORTSCAN_BAN=0; PORTSCAN_LOG_RATE=300; check_journal_budget')"
    check "FW_MODE=open (анти-скан не ставится) → тишина" "" \
          "$(bud 'FW_MODE=open; PORTSCAN_LOG_RATE=300; check_journal_budget')"
    printf '[Journal]\nSystemMaxUse=2G\n' > "$T/etc/journald.conf.d/na-size.conf"
    check "суффикс G разбирается" 2147483648 "$(bud 'journald_cap_bytes')"
    check "большой кап — 300/мин уже не проблема" "" "$(bud 'PORTSCAN_LOG_RATE=300; check_journal_budget')"
    printf '[Journal]\nSystemMaxUse=64M\n' > "$T/etc/journald.conf.d/na-size.conf"
    check "маленький кап — предупреждаем даже на дефолтном рейте" 1 \
          "$(bud 'check_journal_budget' | grep -c 'лог анти-скана')"
    # drop-in перебивает основной конфиг (порядок чтения systemd)
    printf '[Journal]\nSystemMaxUse=1G\n' > "$T/etc/journald.conf"
    check "drop-in побеждает journald.conf" 67108864 "$(bud 'journald_cap_bytes')"
    rm -f "$T/etc/journald.conf.d/na-size.conf"
    check "без drop-in берётся journald.conf" 1073741824 "$(bud 'journald_cap_bytes')"
    printf '[Journal]\n#SystemMaxUse=4G\n' > "$T/etc/journald.conf"
    check "закомментированный кап игнорируется → дефолт 300M" 314572800 "$(bud 'journald_cap_bytes')"
    rm -f "$T/etc/journald.conf"
    check "конфига нет вовсе → дефолт 300M (столько ставит optimize)" 314572800 "$(bud 'journald_cap_bytes')"
fi

# ─── 5. Полный apply: дедуп доезжает до всех мест разом ──────────────────────
# Три места хранят whitelist: nft-сет (через na_filter.nft), CrowdSec-парсер и
# protect.conf. Первые два дедупим, третий обязан сохранить список оператора дословно.
echo "== 5. apply: whitelist в ruleset / CrowdSec-yaml / protect.conf (issue #38) =="
A="$T/apply"
mkdir -p "$A/bin" "$A/sys" "$A/sbin" "$A/modload" "$A/conf" "$A/state" "$A/backup" "$A/crowdsec"
cp -r "$REPO_ROOT/scripts" "$A/scripts"
cp "$PROTECT" "$A/scripts/protect.sh"
sed -e "s#/etc/systemd/system/#$A/sys/#g" -e "s#/usr/local/sbin/#$A/sbin/#g" \
    -e "s#/etc/modules-load.d/#$A/modload/#g" -e "s#/etc/crowdsec#$A/crowdsec#g" \
    "$A/scripts/protect.sh" > "$A/p.tmp" && mv "$A/p.tmp" "$A/scripts/protect.sh"
for c in systemctl modprobe nft systemd-run sysctl conntrack cscli sleep; do
    printf '#!/bin/sh\nexit 0\n' > "$A/bin/$c"; chmod +x "$A/bin/$c"
done
for c in curl docker ss dpkg apt-get; do
    printf '#!/bin/sh\nexit 1\n' > "$A/bin/$c"; chmod +x "$A/bin/$c"
done
cat >> "$A/scripts/lib/common.sh" <<STUB
require_root(){ :; }
detect_os(){ OS_ID=debian; OS_VER=12; OS_CODENAME=bookworm; }
default_iface(){ echo eth0; }
detect_ssh_port(){ echo 22; }
ssh_client_ip(){ echo "203.0.113.9"; }
apt_install(){ :; }
backup_dir(){ echo "$A/backup"; }
CONF_DIR="$A/conf"
STATE_DIR="$A/state"
STUB
DUPWL='198.51.100.4,203.0.113.7,198.51.100.4,203.0.113.7/32,203.0.113.0/24'
set +e
PATH="$A/bin:$PATH" WHITELIST="$DUPWL" ENABLE_CROWDSEC=1 \
    REMNAWAVE_NONINTERACTIVE=1 DRY_RUN=0 "$WBASH" "$A/scripts/protect.sh" >"$A/apply.log" 2>&1
rc=$?
set -e
check "apply отработал (exit 0)" 0 "$rc"
check "unbound-переменных нет" 0 "$(grep -ciE 'unbound variable|bad substitution' "$A/apply.log")"
NFTF="$A/conf/na_filter.nft"
check "в ruleset адрес ровно один раз" 1 \
      "$(grep -o '198\.51\.100\.4' "$NFTF" | wc -l | tr -d ' ')"
check "…и нормализованный /32 не задвоил второй" 1 \
      "$(grep -o '203\.0\.113\.7\b' "$NFTF" | wc -l | tr -d ' ')"
check "авто-whitelist SSH-IP на месте" 1 "$(grep -c '203\.0\.113\.9' "$NFTF")"
YAML="$A/crowdsec/parsers/s02-enrich/na-whitelist.yaml"
if [[ ! -f "$YAML" ]]; then
    checkf "CrowdSec-whitelist не сгенерирован ($YAML)"
else
    check "в CrowdSec-yaml адрес один раз (а не как в CSV оператора)" 1 \
          "$(grep -c '"198\.51\.100\.4"' "$YAML")"
    check "…/32 нормализован в ip:, а не в cidr:" 1 "$(grep -c '"203\.0\.113\.7"' "$YAML")"
    check "…широкий /24 остался как cidr (оператор так решил, мы лишь предупредили)" 1 \
          "$(grep -c '"203\.0\.113\.0/24"' "$YAML")"
    check "…SSH-IP тоже в CrowdSec-whitelist" 1 "$(grep -c '"203\.0\.113\.9"' "$YAML")"
fi
check "protect.conf хранит WHITELIST дословно (это intent оператора)" 1 \
      "$(grep -c "WHITELIST:=$DUPWL}" "$A/conf/protect.conf")"
check "новые ручки персистятся" "60 30" \
      "$(grep -oE '^: "\$\{PORTSCAN_LOG_(RATE|BURST):=[0-9]+\}"$' "$A/conf/protect.conf" | grep -oE '[0-9]+' | paste -sd' ' -)"
check "дубли названы поимённо (оба, включая нормализованный /32)" 2 \
      "$(grep -c 'указан дважды' "$A/apply.log")"
check "широкий /24 предупреждён" 1 "$(grep -c 'ПОЛНЫЙ обход защиты' "$A/apply.log")"
check "хелпер na-fw-status собран со вшитым счётчиком" 1 \
      "$(grep -c '^nft_set_count ' "$A/sbin/na-fw-status")"

# ─── 6. v4.2: CROWDSEC_SCOPE — блок-листы только на SSH ───────────────────────
echo "== 6. CrowdSec scope: set-only bouncer + правило только на SSH (v4.2) =="
CS="$T/cs"; mkdir -p "$CS/bin" "$CS/conf" "$CS/sys" "$CS/backup"
cat > "$CS/bouncer.yaml" <<'YML'
mode: nftables
deny_action: DROP
blacklists_ipv4: crowdsec-blacklists
blacklists_ipv6: crowdsec6-blacklists
nftables:
  ipv4:
    enabled: true
    set-only: false
    table: crowdsec
    chain: crowdsec-chain
    priority: -10
  ipv6:
    enabled: true
    set-only: false
    table: crowdsec6
    chain: crowdsec6-chain
    priority: -10
YML
printf '#!/bin/sh\necho "$*" >> "%s/nft.log"\nexit 0\n' "$CS" > "$CS/bin/nft"
# NA_TEST_BOUNCER_DOWN=1 — bouncer не поднимается (set-only без таблицы): is-active ≠ 0
printf '#!/bin/sh\necho "$*" >> "%s/systemctl.log"\ncase "$*" in "is-enabled --quiet crowdsec-nft-scope.service") exit 1;; "is-active --quiet crowdsec-firewall-bouncer") [ "${NA_TEST_BOUNCER_DOWN:-0}" = 1 ] && exit 3;; esac\nexit 0\n' "$CS" > "$CS/bin/systemctl"
printf '#!/bin/sh\nexit 0\n' > "$CS/bin/sleep"
chmod +x "$CS/bin"/*
sed -n '/^# ─── Область действия блок-листов CrowdSec/,/^# ─── Сейфти-таймер/p' "$PROTECT" | sed '$d' \
    | sed -e "s#/etc/systemd/system/#$CS/sys/#g" > "$CS/scope.sh"
if [[ ! -s "$CS/scope.sh" ]]; then
    checkf "в $PROTECT нет crowdsec_scope_apply (CROWDSEC_SCOPE)"
else
    cs_run() {   # cs_run <CROWDSEC_SCOPE>
        PATH="$CS/bin:$PATH" "$WBASH" -c "set -euo pipefail
. '$REPO_ROOT/scripts/lib/common.sh'
CONF_DIR='$CS/conf'; BACKUP='$CS/backup'; CS_BOUNCER_YAML='$CS/bouncer.yaml'
CROWDSEC_SCOPE='$1'; SSH_NFT='22, 2200'; SSH_EFF='22,2200'; WL4='203.0.113.7, 198.51.100.0/29'; WL6=''
. '$CS/scope.sh'
crowdsec_scope_apply" 2>&1
    }
    OUT="$(cs_run ssh)"
    check "ssh: bouncer переведён в set-only (обе семьи)" 2 "$(grep -c 'set-only: true' "$CS/bouncer.yaml")"
    check "ssh: правило дропа — только на SSH-портах" 1 \
          "$(grep -c 'tcp dport { 22, 2200 } ip saddr @crowdsec-blacklists counter drop' "$CS/conf/na-crowdsec-scope.nft")"
    check "ssh: whitelist — именованный интервальный набор (auto-merge)" 1 \
          "$(grep -c 'set na_wl4 { type ipv4_addr; flags interval; auto-merge; elements = { 203.0.113.7, 198.51.100.0/29 } } # na-wl4' "$CS/conf/na-crowdsec-scope.nft")"
    check "ssh: whitelist исключён раньше дропа (CAPI-адрес админа не режет SSH)" 1 "$(grep -c 'ip saddr @na_wl4 return' "$CS/conf/na-crowdsec-scope.nft")"
    check "ssh: пустой v6-whitelist — пустой набор с меткой для na-fw" 1 "$(grep -c 'set na_wl6 { type ipv6_addr; flags interval; auto-merge; } # na-wl6' "$CS/conf/na-crowdsec-scope.nft")"
    check "ssh: таблица/набор из конфига bouncer'а" 2 \
          "$(grep -cE '^table ip crowdsec \{$|set crowdsec-blacklists \{' "$CS/conf/na-crowdsec-scope.nft")"
    check "ssh: юнит грузит правила ДО bouncer'а" 1 "$(grep -c 'Before=crowdsec-firewall-bouncer.service' "$CS/sys/na-crowdsec-scope.service")"
    # порядок: stop bouncer → свои таблицы → start (рестарт ПОСЛЕ таблиц убивал их на выходе
    # старого процесса, и bouncer в set-only не стартовал — CrowdSec не блокировал ничего)
    check "ssh: bouncer остановлен ДО загрузки таблиц и запущен после" "stop start" \
          "$(grep -oE '^(stop|start|restart) crowdsec-firewall-bouncer' "$CS/systemctl.log" | cut -d' ' -f1 | paste -sd' ' -)"
    : > "$CS/systemctl.log"; : > "$CS/nft.log"
    OUT="$(cs_run all)"
    check "all: set-only снят" 0 "$(grep -c 'set-only: true' "$CS/bouncer.yaml")"
    check "all: наш юнит и правила убраны" 0 "$(ls "$CS/sys/na-crowdsec-scope.service" "$CS/conf/na-crowdsec-scope.nft" 2>/dev/null | wc -l | tr -d ' ')"
    check "all: наши таблицы удалены (цепочка na-scope-input не висит)" 2 \
          "$(grep -cE '^delete table ip6? crowdsec6?$' "$CS/nft.log")"
    check "all: stop → start (не restart)" "stop start" \
          "$(grep -oE '^(stop|start|restart) crowdsec-firewall-bouncer' "$CS/systemctl.log" | cut -d' ' -f1 | paste -sd' ' -)"
    : > "$CS/systemctl.log"
    OUT="$(cs_run all)"
    check "all на обычном bouncer'е — без лишнего stop/start (окна без блок-листов)" 0 \
          "$(grep -cE '^(stop|start|restart) crowdsec-firewall-bouncer' "$CS/systemctl.log")"
    # bouncer не поднялся в set-only (нет таблицы, старый процесс снёс и т.п.) — назад на all
    : > "$CS/systemctl.log"
    OUT="$(NA_TEST_BOUNCER_DOWN=1 cs_run ssh)"
    check "ssh, bouncer не поднялся → предупреждение и откат на all" 1 \
          "$(printf '%s\n' "$OUT" | grep -c 'возвращаю CROWDSEC_SCOPE=all')"
    check "…set-only снят, наш юнит убран" "0 0" \
          "$(grep -c 'set-only: true' "$CS/bouncer.yaml") $(ls "$CS/sys/na-crowdsec-scope.service" 2>/dev/null | wc -l | tr -d ' ')"
    sed -i.bak '/set-only/d' "$CS/bouncer.yaml"; rm -f "$CS/bouncer.yaml.bak"
    OUT="$(cs_run ssh)"
    check "старый bouncer без set-only → честный откат на all" 1 "$(printf '%s\n' "$OUT" | grep -c 'без опции set-only')"
fi

# ─── 7. v4.2: na-fw — whitelist во всех слоях одной командой ──────────────────
echo "== 7. na-fw allow/unban (v4.2) =="
F="$T/nafw"; mkdir -p "$F/bin" "$F/etc" "$F/state" "$F/crowdsec/parsers/s02-enrich"
sed -n "/cat > \/usr\/local\/sbin\/na-fw <<'NAFW'/,/^NAFW\$/p" "$PROTECT" | sed '1d;$d' \
    | sed -e "s#/etc/node-accelerator#$F/etc#g" -e "s#/var/lib/node-accelerator#$F/state#g" \
          -e "s#/etc/crowdsec/parsers/s02-enrich#$F/crowdsec/parsers/s02-enrich#g" \
          -e 's#\[\[ \${EUID:-\$(id -u)} -eq 0 \]\] || die "нужен root"#:#' > "$F/na-fw"
if [[ ! -s "$F/na-fw" ]]; then
    checkf "в $PROTECT нет генератора na-fw"
else
    printf '#!/bin/sh\necho "$*" >> "%s/nft.log"\nexit 0\n' "$F" > "$F/bin/nft"
    printf '#!/bin/sh\nexit 0\n' > "$F/bin/systemctl"; printf '#!/bin/sh\necho "$*" >> "%s/cscli.log"\nexit 0\n' "$F" > "$F/bin/cscli"
    printf '#!/bin/sh\nshasum -a 256 "$@" 2>/dev/null || /usr/bin/sha256sum "$@"\n' > "$F/bin/sha256sum"
    chmod +x "$F/bin"/*
    printf ': "${FW_MODE:=strict}"\n: "${WHITELIST:=203.0.113.7}"\n' > "$F/etc/protect.conf"
    cat > "$F/etc/na_filter.nft" <<'NF'
table inet na_filter {
    set whitelist_v4 { type ipv4_addr; flags interval; auto-merge; elements = { 203.0.113.7 } }
    set whitelist_v6 { type ipv6_addr; flags interval; auto-merge;  }
}
NF
    printf 'nft_sha256=old\n' > "$F/state/protect.installed"
    fw() { PATH="$F/bin:$PATH" "$WBASH" "$F/na-fw" "$@" 2>&1; }
    # только v4 при пустом v6-whitelist: под pipefail grep по пустой семье ронял na-fw посередине
    # (живой сет и v4-строка изменены, conf/CrowdSec/маркер — нет)
    rc=0; fw allow add 198.51.100.8 >/dev/null || rc=$?
    check "allow add только v4 (v6 пуст) — rc=0" 0 "$rc"
    check "…и conf обновлён (не оборвалось посередине)" 1 "$(grep -c 'WHITELIST:=203.0.113.7,198.51.100.8}' "$F/etc/protect.conf")"
    fw allow del 198.51.100.8 >/dev/null
    check "отказ на /0" 1 "$(fw allow add 0.0.0.0/0 | grep -c 'слишком широко')"
    # правило CROWDSEC_SCOPE=ssh стоит — его whitelist-наборы правятся поэлементно (nft 0.9.x
    # отвергал `flush` + `add` всем списком, когда адрес внутри CIDR того же списка)
    cat > "$F/etc/na-crowdsec-scope.nft" <<'SCN'
table ip crowdsec {
    set crowdsec-blacklists { type ipv4_addr; flags timeout; }
    set na_wl4 { type ipv4_addr; flags interval; auto-merge; elements = { 203.0.113.7 } } # na-wl4
}
table ip6 crowdsec6 {
    set crowdsec6-blacklists { type ipv6_addr; flags timeout; }
    set na_wl6 { type ipv6_addr; flags interval; auto-merge; } # na-wl6
}
SCN
    : > "$F/nft.log"
    fw allow add 198.51.100.9 2001:db8::5 >/dev/null
    check "scope: строка-набор v4 в файле переписана" 1 \
          "$(grep -c 'set na_wl4 { type ipv4_addr; flags interval; auto-merge; elements = { 198.51.100.9, 203.0.113.7 } } # na-wl4' "$F/etc/na-crowdsec-scope.nft")"
    check "scope: живые наборы — поэлементно, обе семьи" 2 \
          "$(grep -cE '^add element ip crowdsec na_wl4 \{ 198\.51\.100\.9 \}$|^add element ip6 crowdsec6 na_wl6 \{ 2001:db8::5 \}$' "$F/nft.log")"
    check "scope: без flush всего набора" 0 "$(grep -c '^flush set' "$F/nft.log")"
    check "allow add: protect.conf дополнен" 1 "$(grep -c 'WHITELIST:=203.0.113.7,198.51.100.9,2001:db8::5}' "$F/etc/protect.conf")"
    check "allow add: v4 в na_filter.nft" 1 "$(grep -c 'elements = { 198.51.100.9, 203.0.113.7 }' "$F/etc/na_filter.nft")"
    check "allow add: v6 в na_filter.nft" 1 "$(grep -c 'set whitelist_v6 { type ipv6_addr; flags interval; auto-merge; elements = { 2001:db8::5 } }' "$F/etc/na_filter.nft")"
    check "allow add: живой сет (nft add element)" 1 "$(grep -c 'add element inet na_filter whitelist_v4 { 198.51.100.9 }' "$F/nft.log")"
    check "allow add: снят из autoban" 1 "$(grep -c 'delete element inet na_filter autoban_v4 { 198.51.100.9 }' "$F/nft.log")"
    check "allow add: CrowdSec-yaml пересобран" 1 "$(grep -c '"198.51.100.9"' "$F/crowdsec/parsers/s02-enrich/na-whitelist.yaml")"
    check "allow add: хэш в маркере обновлён" 0 "$(grep -c '^nft_sha256=old$' "$F/state/protect.installed")"
    fw allow del 203.0.113.7 >/dev/null
    check "allow del: убран из conf" 1 "$(grep -c 'WHITELIST:=198.51.100.9,2001:db8::5}' "$F/etc/protect.conf")"
    check "allow del: убран из файла" 0 "$(grep -c '203.0.113.7' "$F/etc/na_filter.nft")"
    check "allow del: убран из живого сета" 1 "$(grep -c 'delete element inet na_filter whitelist_v4 { 203.0.113.7 }' "$F/nft.log")"
    check "allow del: убран из живого набора scope" 1 "$(grep -c '^delete element ip crowdsec na_wl4 { 203.0.113.7 }$' "$F/nft.log")"
    check "мусор вместо адреса — отказ" 1 "$(fw allow add '1.2.3.4;rm' | grep -c 'не IPv4/IPv6/CIDR')"
    fw unban 192.0.2.66 >/dev/null
    check "unban: autoban и suspect" 2 "$(grep -cE 'delete element inet na_filter (autoban|suspect)_v4 \{ 192.0.2.66 \}' "$F/nft.log")"
    check "unban: решения CrowdSec" 1 "$(grep -c 'decisions delete --ip 192.0.2.66' "$F/cscli.log")"
fi

# ─── 8. v4.2: активные баны переживают ре-ран ────────────────────────────────
echo "== 8. перенос autoban/suspect через ре-ран (v4.2) =="
B="$T/bans"; mkdir -p "$B/bin" "$B/state"
cat > "$B/bin/nft" <<'NFTB'
#!/bin/sh
case "$*" in
  "list set inet na_filter autoban_v4")
    printf 'table inet na_filter {\n\tset autoban_v4 {\n\t\ttype ipv4_addr\n\t\tsize 65536\n\t\tflags dynamic,timeout\n\t\telements = { 203.0.113.10 timeout 1h expires 59m10s608ms,\n\t\t\t     198.51.100.22 timeout 1d expires 220ms }\n\t}\n}\n' ;;
  "list set inet na_filter suspect_v4")
    printf 'table inet na_filter {\n\tset suspect_v4 {\n\t\ttype ipv4_addr\n\t\tflags dynamic,timeout\n\t\telements = { 192.0.2.5 timeout 30m expires 12m3s }\n\t}\n}\n' ;;
  "-f "*) cp "$2" "$NA_T_BANS_OUT" ;;
esac
exit 0
NFTB
chmod +x "$B/bin/nft"
sed -n '/^# ─── Активные баны переживают ре-ран/,/^snapshot_bans$/p' "$PROTECT" | sed '$d' > "$B/bans.sh"
if [[ ! -s "$B/bans.sh" ]]; then
    checkf "в $PROTECT нет snapshot_bans/restore_bans"
else
    OUT="$(PATH="$B/bin:$PATH" NA_T_BANS_OUT="$B/restored.nft" "$WBASH" -c "set -euo pipefail
. '$REPO_ROOT/scripts/lib/common.sh'
STATE_DIR='$B/state'; ENABLE_BANONCE=1
. '$B/bans.sh'
snapshot_bans; restore_bans" 2>&1)"
    check "бан с остатком срока возвращён (мс отброшены)" 1 \
          "$(grep -c 'add element inet na_filter autoban_v4 { 203.0.113.10 timeout 59m10s }' "$B/restored.nft" 2>/dev/null || true)"
    check "бан, которому осталось < 1с, не возвращается" 0 "$(grep -c '198.51.100.22' "$B/restored.nft" 2>/dev/null || true)"
    check "suspect возвращён" 1 "$(grep -c 'add element inet na_filter suspect_v4 { 192.0.2.5 timeout 12m3s }' "$B/restored.nft" 2>/dev/null || true)"
    check "временный файл убран" 0 "$(ls "$B/state"/.bans.* 2>/dev/null | wc -l | tr -d ' ')"
fi

echo
echo "итого: ok=$PASS fail=$FAIL"
[[ "$FAIL" -eq 0 ]]
