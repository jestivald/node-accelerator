#!/usr/bin/env bash
# Общие функции для node-accelerator (⚡ оптимизатор + 🛡 защита + 🩺 диагностика).
# Namespace: всё наше живёт под префиксом "na-" / "na_" чтобы не конфликтовать
# с другими тулкитами и с CrowdSec/Docker.

# Версия тулкита — ЕДИНСТВЕННЫЙ источник. Пишется в installed-маркеры и отдаётся
# в na-diagnose/na-report --json, чтобы флот-мониторинг видел version-drift по нодам.
# shellcheck disable=SC2034
NA_VERSION="4.1.3"

# Числа — только с десятичной ТОЧКОЙ, сообщения утилит — на C. На ноде с LANG/LC_ALL=
# de_DE.UTF-8 mawk читал «0.35» из /proc/loadavg как 0 (в JSON уезжал "load1":0), printf
# печатал «0,99» прямо в na-report --json, а пороги --retrans сравнивали «4,99» как 4
# (аудит флота); локализованный вывод утилит (`free`: «Speicher:» вместо «Mem:») ломал
# разбор. Явный LC_ALL=C/POSIX/C.UTF-8 уважаем — он и так даёт ровно это. Любой другой
# LC_ALL перебил бы LC_* — переносим его в LANG: кодировка и кириллица в выводе остаются
# как были (а с ними и разбор «д/Д» в подтверждениях), фиксируем числа и сообщения.
case "${LC_ALL:-}" in
    C|POSIX|C.UTF-8|C.utf8) ;;
    *)
        [[ -n "${LC_ALL:-}" ]] && export LANG="$LC_ALL"
        unset LC_ALL
        export LC_NUMERIC=C LC_MESSAGES=C ;;
esac

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

# ─── Терминал ────────────────────────────────────────────────────────────────
# tput решает по TERM, а не по isatty(1): под `nohup … > log` / `curl | bash > log`
# при непустом TERM управляющие последовательности курсора уезжали в файл и ломали
# grep по логам раскатки (issue #28). Всё «курсорное» — только когда stdout терминал.
is_tty()   { [[ -t 1 ]]; }
tty_tput() { if is_tty; then tput "$@" 2>/dev/null || true; fi; return 0; }

# ─── JSON ────────────────────────────────────────────────────────────────────
# json_escape <строка> — значение для вставки внутрь JSON-строки: экранирует \ и ",
# переводит \n \r \t в escape-последовательности, остальные ASCII-контроль выкидывает.
# Один сырой перевод строки внутри значения ломал ВЕСЬ документ `--json` (issue #27):
# каждое строковое поле полагалось на то, что источник «и так чистый».
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"; s="${s//$'\t'/\\t}"
    printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037'
}

# ─── nft-наборы ──────────────────────────────────────────────────────────────
# nft_set_count <family> <table> <set> — число элементов набора. Считаем АДРЕСА внутри
# блока `elements = { … }`, а не строки вывода: в заголовке динамического набора всегда
# есть `flags dynamic,timeout` и `timeout 30m`, поэтому `grep -c timeout` давал «1» на
# пустом наборе и +1 (с 'expires' — +2) на непустом; к тому же nft переносит длинные
# списки, и «строка = адрес» не выполняется вовсе (issue #32/#36). Понимает v4, v6 и
# интервалы (CIDR). Регэксп v6 требует ≥2 двоеточий — иначе матчились бы «1d»/«608ms»
# из timeout/expires (hex-буквы).
nft_set_count() {
    local n
    n="$(nft list set "$1" "$2" "$3" 2>/dev/null | sed -n '/elements = {/,/^[[:space:]]*}/p' \
         | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?|[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}(/[0-9]+)?' \
         | sort -u | wc -l | tr -d ' ')"
    echo "${n:-0}"
}
# nft_set_elems <family> <table> <set> — сами адреса (по одному на строку), тем же срезом:
# оператору важно не «сколько», а «кто».
nft_set_elems() {
    nft list set "$1" "$2" "$3" 2>/dev/null | sed -n '/elements = {/,/^[[:space:]]*}/p' \
      | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?|[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}(/[0-9]+)?' \
      | sort -u
}

# ver_ge <a> <b> — «a ≥ b» для версий вида X.Y[.Z] (без sort -V: его нет в BSD-coreutils).
ver_ge() {
    local -a a b; local i x y
    IFS=. read -r -a a <<< "$1"; IFS=. read -r -a b <<< "$2"
    for i in 0 1 2; do
        x="${a[$i]:-0}"; y="${b[$i]:-0}"
        [[ "$x" =~ ^[0-9]+$ ]] || x=0; [[ "$y" =~ ^[0-9]+$ ]] || y=0
        (( 10#$x > 10#$y )) && return 0
        (( 10#$x < 10#$y )) && return 1
    done
    return 0
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
# ${2:?}: одноаргументный вызов обязан падать сразу и с внятным текстом — а не
# «$2: unbound variable» из глубины, и только на ре-ране, когда файл впервые
# существует и [[ -f ]] перестаёт коротить цепочку (issue #24).
backup_file() {
    local dst="${2:?backup_file: нужен каталог назначения}"
    [[ -f "$1" ]] && cp -a "$1" "$dst/"
    return 0
}

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

# SSH-порт. Источники по убыванию достоверности (выигрывает первый сработавший):
#   1. активный socket-юнит ssh.socket/sshd.socket — на Ubuntu 24.04+ сокет держит
#      systemd, а Port из sshd_config ИГНОРИРУЕТСЯ; в ss владельцем значится "systemd",
#      поэтому старая ss-эвристика (/sshd|"ssh"/) молча отдавала 22 — strict-файрвол
#      открывал не тот порт, а «проверь SSH в новом окне» этого не ловит (IP админа
#      целиком в whitelist: у него работает, у всех остальных — локаут);
#   2. `sshd -T` — раскрывает Include /etc/ssh/sshd_config.d/*.conf (сток bookworm/noble,
#      cloud-init пишет порт именно в drop-in), т.е. надёжнее чтения одного файла;
#   3. ss по слушателю; 4. сам sshd_config; 5. 22.
detect_ssh_port() {
    local p="" u sshd_bin=""
    for u in ssh.socket sshd.socket; do
        systemctl is-active --quiet "$u" 2>/dev/null || continue
        p="$(systemctl show "$u" -p ListenStream --value 2>/dev/null \
             | awk -F: 'NF{print $NF}' | grep -xE '[0-9]+' | head -1)"
        [[ -n "$p" ]] && break
    done
    if [[ -z "$p" ]]; then
        command -v sshd >/dev/null 2>&1 && sshd_bin=sshd
        [[ -z "$sshd_bin" && -x /usr/sbin/sshd ]] && sshd_bin=/usr/sbin/sshd
        [[ -n "$sshd_bin" ]] && p="$("$sshd_bin" -T 2>/dev/null | awk '$1=="port"{print $2; exit}')"
    fi
    [[ -z "$p" ]] && p="$(ss -tnlp 2>/dev/null | awk '/sshd|"ssh"|ssh\.socket/{n=split($4,a,":"); print a[n]; exit}')"
    [[ -z "$p" ]] && p="$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)"
    [[ "$p" =~ ^[0-9]+$ ]] || p=""
    echo "${p:-22}"
}

# Порт ЭТОГО сервера в текущей SSH-сессии. SSH_CONNECTION="<c-ip> <c-port> <s-ip> <s-port>" —
# сессия уже прошла через sshd, так что 4-е поле это ground truth, а не эвристика.
# Пусто, если запущено не по SSH (консоль/cron). Нужен, чтобы файрвол не отрезал порт,
# на котором ты прямо сейчас сидишь (протухший protect.conf / сменили порт / ошибка детекта).
ssh_session_port() {
    local p="${SSH_CONNECTION:-}"
    p="$(printf '%s' "$p" | awk '{print $4}')"
    [[ "$p" =~ ^[0-9]+$ ]] && (( p>=1 && p<=65535 )) && echo "$p"
}

# import_pinned_key <файл-с-ключом> <полный-fpr> <keyring-на-выходе>
# Кладёт в keyring РОВНО пиненый ключ. Почему не `gpg --dearmor` всего ответа: apt по
# signed-by=<keyring> доверяет КАЖДОМУ ключу файла, а проверка «наш отпечаток среди
# импортированных» пропускает лишние ключи, приехавшие тем же блобом. Это не теория:
# фолбэк за ключом XanMod ходит на keyserver по 64-битному keyid, а коллизию keyid
# сделать дёшево — чужой ключ лёг бы в тот же keyring и apt начал бы ему доверять.
import_pinned_key() {
    local src="$1" fp="$2" out="$3" home rc=1 got
    command -v gpg >/dev/null 2>&1 || { warn "нет gpg — не могу проверить отпечаток ключа"; return 1; }
    home="$(mktemp -d)" || return 1
    chmod 700 "$home"
    if GNUPGHOME="$home" gpg --batch --quiet --import "$src" >/dev/null 2>&1; then
        if GNUPGHOME="$home" gpg --batch --yes --export "$fp" > "$out" 2>/dev/null && [[ -s "$out" ]]; then
            # контроль: в получившемся keyring ровно один ПЕРВИЧНЫЙ ключ и это наш fpr
            got="$(gpg --show-keys --with-colons "$out" 2>/dev/null \
                   | awk -F: '$1=="pub"{p=1;next} $1=="fpr"&&p{print $10;p=0}')"
            [[ "$got" == "$fp" ]] && rc=0
        fi
    fi
    # gpg 2.x поднимает agent/dirmngr под временный GNUPGHOME — гасим, чтобы на ноде
    # не оставался процесс, смотрящий в удалённый каталог
    gpgconf --homedir "$home" --kill all >/dev/null 2>&1 || true
    rm -rf "$home"
    [[ $rc -eq 0 ]] || { rm -f "$out"; return 1; }
    chmod 0644 "$out"
    return 0
}

# IP клиента, с которого мы сейчас подключены по SSH (для авто-whitelist от самоблокировки).
# ${VAR:-} обязателен: при запуске из консоли (не по SSH) переменных нет, а вызов идёт под set -u.
ssh_client_ip() {
    local ip="${SSH_CONNECTION:-}"; ip="${ip%% *}"
    [[ -z "$ip" ]] && { ip="${SSH_CLIENT:-}"; ip="${ip%% *}"; }
    # отфильтруем мусор/локалхост
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$ip" == *:* ]] && [[ "$ip" != "127.0.0.1" && "$ip" != "::1" ]] && echo "$ip"
}

# ─── Порт node-agent (Remnawave node) ────────────────────────────────────────
# Фактический порт node-агента этой ноды. Источники по приоритету (выигрывает первый,
# где нашлось; несколько контейнеров внутри источника → объединяем):
#   1. env работающих контейнеров образа remnawave/node* (NODE_PORT= / APP_PORT=);
#   2. .env compose-каталога контейнера (label working_dir), затем NA_REMNANODE_ENV
#      (по умолчанию /opt/remnanode/.env) — ловит и временно остановленный контейнер;
#   3. ss: listening-порт процесса rw-node (бинарь node-агента 2.x).
# echo: порт(ы) через запятую; пусто = определить не удалось. Read-only, best-effort.
detect_node_port() {
    local out="" p c d f cands=""
    _np_add() {
        # 10#: ведущий ноль из чужого .env не должен читаться как октал (арифм. ошибка)
        [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1>=1 && 10#$1<=65535 )) || return 0
        [[ ",$out," == *",$1,"* ]] || out+="${out:+,}$1"
    }
    # docker-пайпы под `|| true`: protect живёт под set -e/pipefail — лежащий docker-демон
    # не должен убивать детект раньше фолбэков на .env/ss
    if command -v docker >/dev/null 2>&1; then
        cands="$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null \
                 | awk '$2 ~ /remnawave\/node(:|$)/{print $1}' || true)"
        # каноничное имя на случай кастом-образа/форка
        [[ -z "$cands" ]] && docker inspect remnanode >/dev/null 2>&1 && cands="remnanode"
        for c in $cands; do
            p="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$c" 2>/dev/null \
                 | awk -F= '$1=="NODE_PORT"||$1=="APP_PORT"{print $2; exit}' || true)"
            _np_add "${p:-}"
        done
        if [[ -z "$out" ]]; then
            for c in $cands; do
                d="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$c" 2>/dev/null || true)"
                [[ -n "$d" && -f "$d/.env" ]] || continue
                p="$(sed -nE 's/^[[:space:]]*(NODE_PORT|APP_PORT)=[^0-9]*([0-9]+).*/\2/p' "$d/.env" 2>/dev/null | head -1)"
                _np_add "${p:-}"
            done
        fi
    fi
    if [[ -z "$out" ]]; then
        f="${NA_REMNANODE_ENV:-/opt/remnanode/.env}"
        if [[ -f "$f" ]]; then
            p="$(sed -nE 's/^[[:space:]]*(NODE_PORT|APP_PORT)=[^0-9]*([0-9]+).*/\2/p' "$f" 2>/dev/null | head -1)"
            _np_add "${p:-}"
        fi
    fi
    if [[ -z "$out" ]]; then
        while read -r p; do _np_add "$p"; done < <(
            ss -Htlnp 2>/dev/null | awk '/"rw-node"/{n=split($4,a,":"); print a[n]}' | sort -u)
    fi
    unset -f _np_add
    [[ -n "$out" ]] && echo "$out"
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

# ─── Дефолты, менявшиеся между версиями (issue #34) ──────────────────────────
# Обратная сторона идиомы `:=`: встроенный дефолт НИКОГДА не выигрывает у записанного.
# Для ручек, которые оператор задавал сам (WHITELIST, NODE_PORT, FW_MODE), так и надо;
# для ручек, которых он не касался, это заморозка — ужесточение по безопасности в новой
# версии молча не доезжает до уже настроенных нод, и никто об этом не узнаёт.
# Различаем «оператор задал» и «записан тогдашний дефолт» маркером `# explicit: KEY`,
# который save_conf пишет для ключей, пришедших из ENV. Ключ БЕЗ маркера, пиннящий
# старый дефолт, — заморозка: warn с обоими значениями, а `NA_ADOPT_NEW_DEFAULTS=1`
# принимает новые дефолты разом (persist на том же прогоне).
# Формат: KEY|старый дефолт|новый дефолт|версия смены|зачем (без символа «|»).
# Пополнять при КАЖДОЙ смене дефолта.
NA_DEFAULT_CHANGES='
CROWDSEC_STRICT|0|1|4.0|CrowdSec только из пиннингованного APT-репо: curl-bash-фоллбэк форсируется атакующим
'

# Ключи из NA_DEFAULT_CHANGES, заданные ENV в ЭТОМ прогоне. Снимается ОДИН раз — до
# подхвата первого conf (после него все ключи «заданы», и маркеры explicit врали бы).
conf_note_env_keys() {
    [[ -z "${NA_CONF_ENV_KEYS+x}" ]] || return 0
    local k _o _n _v _w
    NA_CONF_ENV_KEYS=""
    while IFS='|' read -r k _o _n _v _w; do
        [[ -n "$k" ]] || continue
        [[ -v "$k" ]] && NA_CONF_ENV_KEYS+=" $k"
    done <<< "$NA_DEFAULT_CHANGES"
    return 0
}

# conf_stale_defaults <file> — строки «KEY|старый|новый|версия|зачем» для ключей, которые
# файл пиннит на СТАРЫЙ дефолт без маркера explicit. Общий срез для load_conf и diagnose.
conf_stale_defaults() {
    local f="$1" k old new ver why
    [[ -f "$f" ]] || return 0
    while IFS='|' read -r k old new ver why; do
        [[ -n "$k" ]] || continue
        grep -qE "^: \"\\\$\\{${k}:=${old}\\}\"[[:space:]]*$" "$f" 2>/dev/null || continue
        grep -qE "^# explicit: ${k}$" "$f" 2>/dev/null && continue
        printf '%s|%s|%s|%s|%s\n' "$k" "$old" "$new" "$ver" "$why"
    done <<< "$NA_DEFAULT_CHANGES"
    return 0
}

# load_conf <file> — подхватить сохранённый конфиг (no-op если файла нет), затем
# доложить о замороженных дефолтах (или принять новые при NA_ADOPT_NEW_DEFAULTS=1).
load_conf() {
    local f="$1" k old new ver why cur
    conf_note_env_keys
    [[ -n "$f" && -f "$f" && ! -L "$f" ]] || return 0
    # shellcheck disable=SC1090
    . "$f"
    while IFS='|' read -r k old new ver why; do
        [[ -n "$k" ]] || continue
        [[ " $NA_CONF_ENV_KEYS " == *" $k "* ]] && continue      # оператор задал сейчас
        cur="${!k-}"; [[ "$cur" == "$old" ]] || continue
        if [[ "${NA_ADOPT_NEW_DEFAULTS:-0}" == "1" ]]; then
            printf -v "$k" '%s' "$new"
            ok "conf: $k=$old → $new — принят дефолт v$ver ($why)"
        else
            warn "conf: $k=$old записан старой версией, а дефолт с v$ver = $new ($why). Принять: NA_ADOPT_NEW_DEFAULTS=1 (все новые дефолты) или $k=$new при ре-ране; оставить осознанно: $k=$old явно в ENV"
        fi
    done < <(conf_stale_defaults "$f")
    return 0
}

# save_conf <file> KEY1 KEY2 …  — записать эффективные значения перечисленных
# ключей. Атомарно (mktemp+mv), root-only (0600). Значения у нас валидированы и
# просты (порты/IP/CIDR/числа/duration); на всякий случай пропускаем ключ, если
# в значении есть спецсимволы, способные сломать heredoc-присваивание.
# Маркеры `# explicit: KEY` — для отслеживаемых ключей, заданных ENV сейчас или
# помеченных так в прежнем файле (осознанный выбор оператора переживает ре-раны).
save_conf() {
    local f="$1"; shift
    local dir k v tmp _o _n _v _w
    dir="$(dirname "$f")"; mkdir -p "$dir"
    tmp="$(mktemp "${TMPDIR:-/tmp}/na-conf.XXXXXX")" || return 1
    {
        echo "# node-accelerator — сохранённый конфиг ноды @ $(date -Is)"
        echo "# na_version=${NA_VERSION:-?}"
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
        while IFS='|' read -r k _o _n _v _w; do
            [[ -n "$k" ]] || continue
            if [[ " ${NA_CONF_ENV_KEYS:-} " == *" $k "* ]] \
               || { [[ -f "$f" ]] && grep -qE "^# explicit: ${k}$" "$f" 2>/dev/null; }; then
                echo "# explicit: $k"
            fi
        done <<< "$NA_DEFAULT_CHANGES"
    } > "$tmp"
    chmod 0600 "$tmp"
    mv -f "$tmp" "$f"
}
