#!/usr/bin/env bash
# Общие функции для node-accelerator (⚡ оптимизатор + 🛡 защита + 🩺 диагностика).
# Namespace: всё наше живёт под префиксом "na-" / "na_" чтобы не конфликтовать
# с другими тулкитами и с CrowdSec/Docker.

# Версия тулкита — ЕДИНСТВЕННЫЙ источник. Пишется в installed-маркеры и отдаётся
# в na-diagnose/na-report --json, чтобы флот-мониторинг видел version-drift по нодам.
# shellcheck disable=SC2034
NA_VERSION="3.6"

# shellcheck disable=SC2034
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { printf "%b[*]%b %s\n" "$BLUE"   "$NC" "$*"; }
ok()    { printf "%b[+]%b %s\n" "$GREEN"  "$NC" "$*"; }
warn()  { printf "%b[!]%b %s\n" "$YELLOW" "$NC" "$*"; }
err()   { printf "%b[x]%b %s\n" "$RED"    "$NC" "$*" >&2; }
title() { printf "\n%b== %s ==%b\n" "$BOLD" "$*" "$NC"; }
hr()    { printf '%b%s%b\n' "$CYAN" "────────────────────────────────────────────────────" "$NC"; }

# Статус-строка для диагностики: status_line OK|WARN|FAIL "текст"
status_line() {
    local s="$1"; shift
    case "$s" in
        OK)   printf "  %b✔%b  %s\n" "$GREEN"  "$NC" "$*";;
        WARN) printf "  %b▲%b  %s\n" "$YELLOW" "$NC" "$*";;
        FAIL) printf "  %b✘%b  %s\n" "$RED"    "$NC" "$*";;
        *)    printf "  •  %s\n" "$*";;
    esac
}

require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        err "Запусти от root: sudo bash $0"
        exit 1
    fi
}

detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        err "Не нашёл /etc/os-release — ОС не поддерживается"
        exit 1
    fi
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VER="${VERSION_ID:-unknown}"
    OS_CODENAME="${VERSION_CODENAME:-}"
    case "$OS_ID" in
        ubuntu|debian) ;;
        *) err "Поддерживаются только Ubuntu/Debian. У тебя: $OS_ID"; exit 1;;
    esac
}

# Кодовое имя релиза (bookworm/noble/...) — без зависимости от lsb_release.
os_codename() {
    local c="${OS_CODENAME:-}"
    [[ -z "$c" && -f /etc/os-release ]] && c="$(. /etc/os-release; echo "${VERSION_CODENAME:-}")"
    [[ -z "$c" ]] && command -v lsb_release >/dev/null 2>&1 && c="$(lsb_release -sc 2>/dev/null)"
    echo "$c"
}

arch() { uname -m; }

# Тип виртуализации. "none" = железо/полноценная VM где можно ставить своё ядро.
# Контейнеры (openvz/lxc/docker) делят ядро хоста — кастомное ядро туда не поставить.
detect_virt() {
    # systemd-detect-virt на железе САМ печатает "none" И выходит с кодом 1 → наивный
    # `|| echo none` дописал бы ВТОРОЙ "none" (перевод строки внутри значения ломает
    # `diagnose --json` на bare-metal-дедиках). Берём вывод как есть, пустое → none.
    local v
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        v="$(systemd-detect-virt 2>/dev/null || true)"; echo "${v:-none}"
    else
        echo unknown
    fi
}
is_container() {
    case "$(detect_virt)" in
        openvz|lxc|lxc-libvirt|docker|podman|systemd-nspawn|wsl|rkt) return 0;;
        *) return 1;;
    esac
}

# Можно ли ставить кастомное ядро (XanMod): x86_64 + не контейнер.
can_install_kernel() {
    [[ "$(arch)" == "x86_64" ]] || return 1
    is_container && return 1
    return 0
}

# Уровень x86-64 psABI (1..4) по флагам CPU — для выбора сборки XanMod.
cpu_psabi_level() {
    local flags lvl=1
    flags=" $(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null | cut -d: -f2) "
    _hasall() { local x; for x in $1; do [[ "$flags" == *" $x "* ]] || return 1; done; return 0; }
    _hasall "cx16 lahf_lm popcnt sse4_1 sse4_2 ssse3"               && lvl=2
    [[ $lvl -eq 2 ]] && _hasall "avx avx2 bmi1 bmi2 f16c fma abm movbe xsave" && lvl=3
    [[ $lvl -eq 3 ]] && _hasall "avx512f avx512bw avx512cd avx512dq avx512vl" && lvl=4
    echo "$lvl"
}

backup_dir() {
    local ts d
    ts="$(date +%Y%m%d-%H%M%S)"
    d="/var/backups/node-accelerator/${ts}-$$"
    mkdir -p "$d"
    echo "$d"
}
backup_file() { [[ -f "$1" ]] && cp -a "$1" "$2/"; return 0; }

apt_install() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq 2>/dev/null || true
    if ! apt-get install -y -qq --no-install-recommends "$@" >/dev/null 2>&1; then
        # Прерванный прошлый прогон / битый dpkg — частый кейс на чужих нодах:
        # dpkg --configure -a + `apt-get -f install` чинят состояние, затем один ретрай.
        warn "apt install $*: первая попытка не прошла — чиню dpkg и повторяю"
        dpkg --configure -a >/dev/null 2>&1 || true
        apt-get install -y -qq -f >/dev/null 2>&1 || true
        apt-get update -qq 2>/dev/null || true
        apt-get install -y -qq --no-install-recommends "$@" >/dev/null
    fi
}

confirm() {
    local prompt="${1:-Продолжить?} [y/N]: " ans
    read -r -p "$prompt" ans
    [[ "$ans" =~ ^[yYдД] ]]
}

# Основной интерфейс по default route.
default_iface() { ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}'; }

# systemd-интервал ("5min"/"12h"/"90s"/"2d"/"300") → секунды. Для расчёта возраста
# последнего успешного синка (fleet/blocklist) в диагностике.
systime_to_s() {
    local v="$1" n u
    n="$(printf '%s' "$v" | grep -oE '^[0-9]+')" || true
    [[ -n "$n" ]] || { echo 0; return; }
    u="${v#"$n"}"
    case "$u" in
        ""|s|sec) echo "$n";;
        m|min)    echo $((n*60));;
        h|hr)     echo $((n*3600));;
        d|day)    echo $((n*86400));;
        *)        echo "$n";;
    esac
}

# SSH-порт: сперва из активной сессии sshd, потом из конфига.
detect_ssh_port() {
    local p
    p="$(ss -tnlp 2>/dev/null | awk '/sshd|"ssh"/{n=split($4,a,":"); print a[n]; exit}')"
    [[ -z "$p" ]] && p="$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)"
    echo "${p:-22}"
}

# IP клиента, с которого мы сейчас подключены по SSH (для авто-whitelist от самоблокировки).
# ${VAR:-} обязателен: при запуске из консоли (не по SSH) переменных нет, а вызов идёт под set -u.
ssh_client_ip() {
    local ip="${SSH_CONNECTION:-}"; ip="${ip%% *}"
    [[ -z "$ip" ]] && { ip="${SSH_CLIENT:-}"; ip="${ip%% *}"; }
    # отфильтруем мусор/локалхост
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$ip" == *:* ]] && [[ "$ip" != "127.0.0.1" && "$ip" != "::1" ]] && echo "$ip"
}

STATE_DIR=/var/lib/node-accelerator
CONF_DIR=/etc/node-accelerator
# Куда install.sh кладёт скрипты для постоянных CLI-обёрток (na-diagnose / na-report).
# curl|bash гоняет модули из временной папки → без персиста на ноде НЕ остаётся
# стабильной команды для мониторинга/повторного прогона. Снимается rollback'ом.
NA_LIB_DIR=/usr/local/lib/node-accelerator

# ─── Персист конфига ноды ─────────────────────────────────────────────────────
# Зачем: тулкит параметризуется через ENV. Без персиста ре-ран модуля БЕЗ ENV
# молча возвращал бы все ручки к встроенным дефолтам (напр. CONN_LIMIT/WHITELIST,
# поднятые под CDN/мост-ноду, слетели бы при curl|bash из main). Сохраняем
# эффективный конфиг и подхватываем на следующем прогоне. Прецеденс:
#   ENV  >  сохранённый конфиг  >  встроенный дефолт.
# Достигается идиомой `: "${KEY:=value}"` в файле: := присваивает ТОЛЬКО если
# переменная ещё не задана → ENV всегда побеждает. У optimize и protect — РАЗНЫЕ
# файлы, чтобы они не затирали ключи друг друга.

# load_conf <file> — подхватить сохранённый конфиг (no-op если файла нет).
load_conf() {
    local f="$1"
    [[ -n "$f" && -f "$f" && ! -L "$f" ]] || return 0
    # shellcheck disable=SC1090
    . "$f"
}

# save_conf <file> KEY1 KEY2 …  — записать эффективные значения перечисленных
# ключей. Атомарно (mktemp+mv), root-only (0600). Значения у нас валидированы и
# просты (порты/IP/CIDR/числа/duration); на всякий случай пропускаем ключ, если
# в значении есть спецсимволы, способные сломать heredoc-присваивание.
save_conf() {
    local f="$1"; shift
    local dir k v tmp
    dir="$(dirname "$f")"; mkdir -p "$dir"
    tmp="$(mktemp "${TMPDIR:-/tmp}/na-conf.XXXXXX")" || return 1
    {
        echo "# node-accelerator — сохранённый конфиг ноды @ $(date -Is)"
        echo "# ENV при ре-ране ПЕРЕОПРЕДЕЛЯЕТ эти значения (идиома :=)."
        echo "# Сбросить к встроенным дефолтам: rm $f"
        for k in "$@"; do
            v="${!k-}"
            case "$v" in
                *'"'*|*'`'*|*'$'*|*'}'*|*$'\n'*)
                    warn "node.conf: пропускаю $k (спецсимволы в значении)"; continue;;
            esac
            printf ': "${%s:=%s}"\n' "$k" "$v"
        done
    } > "$tmp"
    chmod 0600 "$tmp"
    mv -f "$tmp" "$f"
}
