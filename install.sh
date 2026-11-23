#!/usr/bin/env bash
#
# node-accelerator — ⚡ оптимизатор + 🩺 диагностика + 🛡 защита Remnawave/VPN-ноды.
#
#   sudo bash install.sh              — меню: состояние ноды, все действия, файрвол, откат
#   sudo bash install.sh optimize     — ⚡ XanMod+BBRv3 + тюнинг
#   sudo bash install.sh protect      — 🛡 nftables + CrowdSec
#   sudo bash install.sh diagnose     — 🩺 диагностика (read-only; --json для мониторинга)
#   sudo bash install.sh report       — 🔥 форензика атак (read-only; --hours N, --ip <адрес>)
#   sudo bash install.sh all          — optimize → protect → diagnose
#   sudo bash install.sh rollback [optimize|protect|all]
#   sudo bash install.sh persist      — (пере)создать CLI na-diagnose/na-report
#
# curl-bash (меню тоже работает: ввод берётся из терминала, а не из пайпа):
#   curl -fsSL https://raw.githubusercontent.com/jestivald/node-accelerator/main/install.sh | sudo bash -s all
#   # прод: пиньте тег (компрометация ветки main тогда не утечёт сразу на весь флот):
#   export NA_REF=v4.3; curl -fsSL "https://raw.githubusercontent.com/jestivald/node-accelerator/$NA_REF/install.sh" | sudo -E bash -s all
#   # + подписи модулей: NA_REQUIRE_SIG=1 NA_MINISIGN_PUBKEY=<ключ из README>
#
# ENV: NA_REF=<ветка|тег>  NA_REPO_URL=<база raw-URL, для форка/зеркала>
#      NA_REQUIRE_SIG=1 + NA_MINISIGN_PUBKEY=<pubkey> | NA_SIG_FINGERPRINT=<gpg-fpr>
#      NO_COLOR=1 — без цвета
#
# После optimize/protect/all на ноде остаётся read-only команда `na-diagnose --json`
# (стабильный JSON для мониторинга/панели — без повторного curl|bash). Снимается rollback'ом.

set -euo pipefail
# Модули рядом с собой берём ТОЛЬКО когда install.sh запущен из файла И каталог scripts/
# рядом доверенный. При curl|bash (`bash -s`) BASH_SOURCE пуст, а $0 = "bash" — до v4.1.3
# тут был фоллбэк на $0, то есть каталог скрипта = ТЕКУЩАЯ папка: лежит в ней scripts/
# (старый клон тулкита, подложенный /tmp/scripts) — и root исполнял его, минуя скачивание
# по NA_REF И проверку подписей NA_REQUIRE_SIG=1. Из файла — та же ловушка в общей папке
# (`curl -o /tmp/install.sh && sudo bash /tmp/install.sh` рядом с чужим /tmp/scripts),
# поэтому соседние модули доверенные, только если их владелец — root или тот, кто зовёт
# (SUDO_UID), запись группе/остальным закрыта и все модули на месте. Иначе — скачиваем.
NA_SELF="${BASH_SOURCE[0]:-}"
NA_MODULES="lib/common.sh optimize.sh protect.sh diagnose.sh na-report.sh rollback.sh"
SCRIPTS=""
_na_trusted() {   # _na_trusted <путь> — владелец root/вызывающий, без записи для группы/остальных
    local l mode uid
    l="$(ls -ldn "$1" 2>/dev/null)" || return 1
    mode="${l%% *}"; uid="$(awk '{print $3}' <<<"$l")"
    [[ "${mode:5:1}" != w && "${mode:8:1}" != w ]] || return 1
    [[ "$uid" == 0 || "$uid" == "$(id -u)" || ( -n "${SUDO_UID:-}" && "$uid" == "$SUDO_UID" ) ]]
}
if [[ -n "$NA_SELF" && -f "$NA_SELF" ]]; then
    _cand="$(cd "$(dirname "$NA_SELF")" && pwd)/scripts"
    _ok=1
    { _na_trusted "$_cand" && _na_trusted "$_cand/lib"; } || _ok=0
    for _m in $NA_MODULES; do { [[ -f "$_cand/$_m" ]] && _na_trusted "$_cand/$_m"; } || _ok=0; done
    if [[ "$_ok" == 1 ]]; then
        SCRIPTS="$_cand"
    elif [[ -d "$_cand" ]]; then
        echo "[!] $_cand не доверенный (чужой владелец, запись для группы/остальных или не все модули) — модули скачаю по NA_REF"
    fi
    unset _cand _ok _m
fi
# NA_REF — ветка/тег для curl|bash-режима (по умолчанию main). Для прода пиньте тег.
NA_REF="${NA_REF:-main}"
# NA_REF уходит в URL модулей — запрещаем path-traversal/инъекцию (увод на чужой репо).
[[ "$NA_REF" =~ ^[A-Za-z0-9._/-]+$ && "$NA_REF" != *..* ]] || { echo "[x] NA_REF '$NA_REF' невалиден"; exit 1; }
REPO_URL="${NA_REPO_URL:-https://raw.githubusercontent.com/jestivald/node-accelerator/$NA_REF}"

# Справка. В curl|bash-режиме $0 = "bash" (файла нет) — `sed по $0` там просто падал
# с ошибкой вместо вывода помощи, поэтому есть встроенный фоллбэк. Обрабатываем ДО
# скачивания модулей и require_root: за справкой не должно требоваться ни root, ни сеть.
usage() {
    if [[ -n "$NA_SELF" && -f "$NA_SELF" ]]; then
        # шапка файла до первой строки кода — а не диапазон строк, который съезжал бы с правкой
        awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$NA_SELF"
    else
        cat <<'U'
node-accelerator — ⚡ оптимизатор + 🩺 диагностика + 🛡 защита Remnawave/VPN-ноды.

  install.sh                        — меню: состояние ноды, все действия, файрвол, откат
  install.sh optimize               — ⚡ XanMod+BBRv3 + тюнинг
  install.sh protect                — 🛡 nftables + CrowdSec
  install.sh diagnose [--json|…]    — 🩺 диагностика (read-only)
  install.sh report [--hours N|…]   — 🔥 форензика атак (read-only)
  install.sh all                    — optimize → protect → diagnose
  install.sh rollback [optimize|protect|all]
  install.sh persist                — (пере)создать CLI na-diagnose/na-report

  ENV: NA_REF=<ветка|тег>  NA_REPO_URL=<база raw-URL>
       NA_REQUIRE_SIG=1 + NA_MINISIGN_PUBKEY=<pubkey> | NA_SIG_FINGERPRINT=<gpg-fpr>
       NO_COLOR=1 — без цвета
  Документация: https://github.com/jestivald/node-accelerator
U
    fi
}
case "${1:-}" in -h|--help) usage; exit 0;; esac

# Опц. проверка подписи модулей в curl|bash-режиме (supply-chain hardening). По умолч.
# выкл. NA_REQUIRE_SIG=1 + minisign-ключ (NA_MINISIGN_PUBKEY) ИЛИ GPG-отпечаток
# (NA_SIG_FINGERPRINT) → каждый модуль проверяется против .minisig/.asc рядом в репо.
NA_REQUIRE_SIG="${NA_REQUIRE_SIG:-0}"
NA_MINISIGN_PUBKEY="${NA_MINISIGN_PUBKEY:-}"
NA_SIG_FINGERPRINT="${NA_SIG_FINGERPRINT:-}"
# Скачиваем строго по https и НЕ разрешаем редиректу увести на cleartext http:
# по умолчанию curl такой даунгрейд-редирект молча выполняет.
CURL_PROTO=(--proto '=https' --proto-redir '=https')
verify_sig() {  # verify_sig <файл> [url-без-расширения] — без url: подпись лежит рядом с файлом
    local file="$1" url="${2:-}"
    if [[ -n "$NA_MINISIGN_PUBKEY" ]] && command -v minisign >/dev/null 2>&1; then
        if [[ -n "$url" ]]; then
            curl -fsSL "${CURL_PROTO[@]}" "$url.minisig" -o "$file.minisig" 2>/dev/null || { echo "[x] нет .minisig для $(basename "$file")"; return 1; }
        fi
        [[ -f "$file.minisig" ]] || { echo "[x] нет .minisig для $(basename "$file")"; return 1; }
        minisign -V -P "$NA_MINISIGN_PUBKEY" -m "$file" >/dev/null 2>&1
    elif [[ -n "$NA_SIG_FINGERPRINT" ]] && command -v gpg >/dev/null 2>&1; then
        if [[ -n "$url" ]]; then
            curl -fsSL "${CURL_PROTO[@]}" "$url.asc" -o "$file.asc" 2>/dev/null || { echo "[x] нет .asc для $(basename "$file")"; return 1; }
        fi
        [[ -f "$file.asc" ]] || { echo "[x] нет .asc для $(basename "$file")"; return 1; }
        # Судим по МАШИННОМУ статусу (--status-fd), а НЕ по человекочитаемому выводу:
        # `gpg --verify | grep <fpr>` матчил бы 'using RSA key <fpr>' — эта строка
        # печатается из пакета подписи ДАЖЕ для BAD-подписи, а exit-код терялся в пайпе
        # (валидная .asc настоящего ключа рядом с подменённым файлом проходила бы как ок).
        # VALIDSIG эмитится ТОЛЬКО для криптографически валидной подписи и несёт полный fpr.
        # Вывод сначала целиком в переменную: gpg пишет статус построчно, и `| grep -q`
        # под pipefail закрывал пайп на VALIDSIG — следующая строка статуса ловила SIGPIPE,
        # и валидная подпись отвергалась (141 вместо 0). Код возврата gpg при этом обязан
        # быть 0, а VALIDSIG сам по себе не достаточен: gpg печатает его и для подписи
        # отозванным/просроченным ключом — такие статусы отвергаем явно.
        local st rc=0
        st="$(gpg --status-fd=1 --verify "$file.asc" "$file" 2>/dev/null)" || rc=$?
        [[ "$rc" -eq 0 ]] || return 1
        grep -Eq '^\[GNUPG:\] (REVKEYSIG|EXPKEYSIG|EXPSIG|BADSIG|ERRSIG)( |$)' <<<"$st" && return 1
        grep -Eq "^\[GNUPG:\] VALIDSIG ${NA_SIG_FINGERPRINT// /}( |\$)" <<<"$st"
    else
        echo "[x] NA_REQUIRE_SIG=1, но нет minisign+NA_MINISIGN_PUBKEY или gpg+NA_SIG_FINGERPRINT"; return 1
    fi
}

# curl|bash — подтянуть модули (во временный каталог, который убираем на выходе)
if [[ -z "$SCRIPTS" || ! -d "$SCRIPTS" ]]; then
    NA_TMPD="$(mktemp -d)"
    trap 'rm -rf "$NA_TMPD"' EXIT
    SCRIPTS="$NA_TMPD/scripts"; mkdir -p "$SCRIPTS/lib"
    echo "[*] Скачиваю модули из $REPO_URL ..."
    for f in $NA_MODULES; do
        curl -fsSL "${CURL_PROTO[@]}" "$REPO_URL/scripts/$f" -o "$SCRIPTS/$f" || { echo "[x] Не скачал $f"; exit 1; }
        if [[ "$NA_REQUIRE_SIG" == "1" ]]; then
            verify_sig "$SCRIPTS/$f" "$REPO_URL/scripts/$f" \
                && echo "[+] подпись $f валидна" \
                || { echo "[x] подпись $f НЕ прошла — отказ (NA_REQUIRE_SIG=1)"; exit 1; }
        fi
    done
fi

# Локальные модули под NA_REQUIRE_SIG=1 проверяются так же, как скачанные (подписи в дереве).
if [[ -z "${NA_TMPD:-}" && "$NA_REQUIRE_SIG" == "1" ]]; then
    for f in $NA_MODULES; do
        verify_sig "$SCRIPTS/$f" \
            && echo "[+] подпись $f валидна (локальный модуль)" \
            || { echo "[x] подпись локального $f НЕ прошла — отказ (NA_REQUIRE_SIG=1)"; exit 1; }
    done
fi

# shellcheck source=scripts/lib/common.sh
. "$SCRIPTS/lib/common.sh"
require_root
detect_os

# ─── Персист CLI (na-diagnose / na-report) ───────────────────────────────────
# curl|bash гоняет модули из временной папки → после установки на ноде НЕ остаётся
# постоянной команды для мониторинга/повторного прогона. Панели/Zabbix/SSH-поллингу
# нужен стабильный `na-diagnose --json`. Кладём нужные скрипты в $NA_LIB_DIR и
# создаём тонкие обёртки в /usr/local/sbin. Идемпотентно; снимается rollback'ом.
_na_wrapper() {  # _na_wrapper <имя-команды> <путь-к-целевому-скрипту>
    local name="$1" target="$2"
    cat > "/usr/local/sbin/$name" <<EOF
#!/usr/bin/env bash
# node-accelerator CLI (создаётся install.sh, снимается rollback). Не редактировать.
exec bash "$target" "\$@"
EOF
    chmod +x "/usr/local/sbin/$name"
}
persist_toolkit() {
    local extra=""
    if [[ "${DRY_RUN:-0}" == "1" ]]; then info "DRY_RUN: пропускаю установку CLI (na-diagnose/na-report)"; return 0; fi
    install -d -m 0755 "$NA_LIB_DIR/lib"
    install -m 0644 "$SCRIPTS/lib/common.sh" "$NA_LIB_DIR/lib/common.sh"
    install -m 0755 "$SCRIPTS/diagnose.sh"   "$NA_LIB_DIR/diagnose.sh"
    _na_wrapper na-diagnose "$NA_LIB_DIR/diagnose.sh"
    # na-report появится в v3.1 (форензика для панели) — персистим, если есть в модулях.
    if [[ -f "$SCRIPTS/na-report.sh" ]]; then
        install -m 0755 "$SCRIPTS/na-report.sh" "$NA_LIB_DIR/na-report.sh"
        _na_wrapper na-report "$NA_LIB_DIR/na-report.sh"
        extra=", na-report"
    fi
    ok "CLI: na-diagnose${extra} (read-only, в /usr/local/sbin) → для мониторинга/панели"
}

# Ошибка модуля останавливает цепочку и до persist_toolkit не доходит — `|| return` явно:
# в меню и под `if`/`||` errexit внутри функции не действует.
run_optimize() { bash "$SCRIPTS/optimize.sh" || return; persist_toolkit; }
run_protect()  { bash "$SCRIPTS/protect.sh"  || return; persist_toolkit; }
run_diagnose() { bash "$SCRIPTS/diagnose.sh" "$@"; }
run_report()   { bash "$SCRIPTS/na-report.sh" "$@"; }
run_rollback() { bash "$SCRIPTS/rollback.sh" "${1:-all}"; }
# Всё подряд. diagnose в цепочке не чистит экран: отчёт стирал бы вывод protect про
# взведённый сейфти-таймер и «нужна перезагрузка» от optimize.
run_all() { run_optimize; run_protect; NA_NO_CLEAR=1 bash "$SCRIPTS/diagnose.sh"; }

# ─── Меню ────────────────────────────────────────────────────────────────────
# Ввод меню — терминал, а не stdin. При `curl … | sudo bash` stdin — это сам скрипт: `read`
# получал EOF, и под set -e меню закрывалось сразу после рамки (до v4.3). Модули из меню
# тоже получают терминал на stdin: protect спрашивает режим, порты и «Соединение работает?»
# только при -t 0 — иначе из меню под curl|bash молча применились бы дефолты.
# NA_TTY — откуда читать меню, когда stdin не терминал (по умолчанию /dev/tty).
NA_TTY="${NA_TTY:-/dev/tty}"
NA_FW=/usr/local/sbin/na-fw
NA_FW_STATUS=/usr/local/sbin/na-fw-status
NA_FW_TOP=/usr/local/sbin/na-fw-top-talkers
M_IN=""; M_PROMPT=0; MENU_NOTE=""; REPLY=""
M_ST=(); M_ADDRS=()

menu_open_input() {
    if [[ -t 0 ]]; then M_IN=0; return 0; fi
    { exec {M_IN}<"$NA_TTY"; } 2>/dev/null && return 0
    M_IN=""; return 1
}

# Ctrl+C во время действия получает модуль, а меню возвращается к выбору. На приглашении —
# выход: сам `read` на трапе SIGINT не прерывается, поэтому выходим из трапа.
menu_on_int() { if (( M_PROMPT )); then printf '\n'; exit 130; fi; return 0; }

# menu_ask <приглашение> — строка с терминала меню в REPLY, без крайних пробелов. rc≠0 — EOF.
menu_ask() {
    local rc=0
    printf '%s' "$1"
    REPLY=""; M_PROMPT=1
    IFS= read -r -u "$M_IN" REPLY || rc=$?
    M_PROMPT=0
    (( rc == 0 )) || { printf '\n'; return 1; }
    REPLY="${REPLY#"${REPLY%%[![:space:]]*}"}"
    REPLY="${REPLY%"${REPLY##*[![:space:]]}"}"
    return 0
}
menu_yes() { menu_ask " $1 [y/N] › " && is_yes "$REPLY"; }

# menu_exec <заголовок> <команда> [арг…] — действие из меню. Ошибки — как в CLI: подоболочка
# с set -e (функция в контексте `||`/`if` выполнялась бы без errexit целиком, и упавший
# optimize.sh дошёл бы до persist_toolkit). stdin — терминал меню, свой дескриптор меню
# модулю не достаётся (его унаследовал бы фоновый сейфти-таймер).
menu_exec() {
    local head="$1" rc t0=$SECONDS
    shift
    tty_tput clear
    printf '\n %s%s%s\n\n' "$M_BOLD" "$head" "$M_R"
    set +e
    ( [[ "$M_IN" == 0 ]] || exec {M_IN}<&-; set -e; "$@" ) <&"$M_IN"
    rc=$?
    set -e
    menu_done "$rc" $(( SECONDS - t0 ))
}
_m_dur() {
    local s="$1"
    if (( s < 60 )); then printf '%d с' "$s"
    elif (( s < 3600 )); then printf '%d мин %d с' $(( s / 60 )) $(( s % 60 ))
    else printf '%d ч %d мин' $(( s / 3600 )) $(( s % 3600 / 60 )); fi
}
# menu_done <код> <секунд> — итог действия и пауза, чтобы вывод не стёрся перерисовкой меню.
menu_done() {
    local d
    d="$(_m_dur "$2")"
    printf '\n'
    case "$1" in
        0)   printf ' %s✔%s Готово за %s\n' "$M_OK" "$M_R" "$d" ;;
        130) printf ' %s▲%s Прервано (Ctrl+C) через %s\n' "$M_WARN" "$M_R" "$d" ;;
        *)   printf ' %s✘%s Ошибка (код %s) через %s — подробности выше\n' "$M_FAIL" "$M_R" "$1" "$d" ;;
    esac
    menu_ask " ${M_DIM}Enter — в меню · 0 — выход${M_R} › " || exit 0
    case "$REPLY" in 0|q|Q) exit 0 ;; esac
    return 0
}

# ─── Оформление ──────────────────────────────────────────────────────────────
# Заново на каждую отрисовку (окно могли растянуть). Рамка — в терминале от 80 колонок:
# левая граница в колонке 2, содержимое с колонки 4, правая граница в колонке M_W+1.
# Колонки ставит CHA (ESC[<n>G — «курсор в колонку n»), а не пробелы: ширину эмодзи
# терминалы считают по-разному (🛡 и ↩️ — то 1, то 2 колонки), и рамка v4.2 «плыла» на каждой
# строке с эмодзи. Уже 80 колонок (SSH с телефона) — без рамки и описаний; не терминал —
# без цвета и escape-кодов вообще.
menu_style() {
    local cols s='ё'
    M_R='' M_BOLD='' M_DIM='' M_FR='' M_NUM='' M_OK='' M_WARN='' M_FAIL=''
    M_CHA=0 M_BOX=0 M_W=76 M_TXT=59 M_UTF8=0
    if (( ${#s} == 1 )); then M_UTF8=1; fi
    is_tty && [[ "${TERM:-dumb}" != dumb ]] || return 0
    M_CHA=1
    if [[ -z "${NO_COLOR:-}" ]]; then
        M_R=$'\033[0m' M_BOLD=$'\033[1m' M_DIM=$'\033[2m' M_FR=$'\033[36m' M_NUM=$'\033[1;36m'
        M_OK=$'\033[32m' M_WARN=$'\033[33m' M_FAIL=$'\033[31m'
    fi
    # ширина — с терминала меню: `tput cols` внутри $(…) смотрит на пайп и отдаёт 80
    cols="$(stty size <&"${M_IN:-0}" 2>/dev/null || true)"
    cols="${cols##* }"
    [[ "$cols" =~ ^[0-9]+$ && "$cols" -gt 0 ]] || cols="$(tput cols 2>/dev/null || true)"
    [[ "$cols" =~ ^[0-9]+$ && "$cols" -gt 0 ]] || cols=80
    # без рамки справа резать незачем — длинная строка состояния просто переносится
    if (( cols >= 80 )); then M_BOX=1
    else M_W=$(( cols > 30 ? cols - 2 : 28 )); M_TXT=999; fi
    return 0
}

# _m_row <кол> <текст> [<кол> <текст>…] — строка меню; кол — колонка содержимого (с 1)
_m_row() {
    local out=" " x0=1 sep=""
    if (( M_BOX )); then out=" ${M_FR}│${M_R}"; x0=3; fi
    while (( $# >= 2 )); do
        if [[ -n "$2" ]]; then
            if (( M_CHA )); then out+=$'\033['"$(( x0 + $1 ))G$2"
            else out+="$sep$2"; sep="  "; fi
        fi
        shift 2
    done
    if (( M_BOX )); then out+=$'\033['"$(( M_W + 1 ))G${M_FR}│${M_R}"; fi
    printf '%s\n' "$out"
}

# _m_line <угол> <угол> <заголовок> <подпись справа> — горизонталь. Сначала вся линия, потом
# заголовок и подпись поверх неё (CR + CHA): угол стоит там, где нарисован, какой бы ширины
# ни вышли эмодзи заголовка. Без CHA заголовок и подпись — отдельными строками.
_m_line() {
    local l n=$(( M_BOX ? M_W - 2 : M_W ))
    printf -v l '%*s' "$n" ''
    l="${l// /─}"
    if (( ! M_CHA )); then
        if [[ -n "$3" ]]; then printf ' %s\n' "$3"; fi
        printf ' %s\n' "$l"
        if [[ -n "$4" ]]; then printf ' %s\n' "$4"; fi
        return 0
    fi
    if (( M_BOX )); then printf ' %s%s%s%s%s' "$M_FR" "$1" "$l" "$2" "$M_R"
    else printf ' %s%s%s' "$M_FR" "$l" "$M_R"; fi
    if [[ -n "$3" ]]; then printf '\r\033[%dG %s%s%s ' $(( M_BOX ? 4 : 2 )) "$M_BOLD" "$3" "$M_R"; fi
    if [[ -n "$4" ]]; then printf '\033[%dG %s%s%s ' $(( M_W - ${#4} - 2 )) "$M_DIM" "$4" "$M_R"; fi
    printf '\n'
}
_m_top() { _m_line ╭ ╮ "${1:-}" "${2:-}"; }
_m_mid() { _m_line ├ ┤ "" ""; }
_m_bot() { _m_line ╰ ╯ "" "${1:-}"; }

# _m_item <клавиша> <эмодзи> <название> [описание] — пункт главного меню
_m_item() {
    local d="${4:-}"
    (( M_BOX )) || d=""
    _m_row 2 "${M_NUM}$1${M_R}" 5 "$2" 9 "${M_BOLD}$3${M_R}" 24 "${d:+$M_DIM$d$M_R}"
}
# _m_sub <клавиша> <название> [подсказка] — пункт подменю; подсказка — та же операция без меню
_m_sub() {
    local d="${3:-}"
    (( M_BOX )) || d=""
    _m_row 2 "${M_NUM}$1${M_R}" 6 "$2" 37 "${d:+$M_DIM$d$M_R}"
}
_m_note() {   # строка-подсказка под меню после неверного ввода и т.п.
    if [[ -n "$MENU_NOTE" ]]; then printf ' %s▲%s %s\n' "$M_WARN" "$M_R" "$MENU_NOTE"; MENU_NOTE=""; fi
    return 0
}

# ─── Состояние ноды для шапки меню (read-only, быстро, без падений под set -e) ─
_m_kv() { awk -F= -v k="$1" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$2" 2>/dev/null || true; }
_m_date() {   # 2026-11-20T12:34:56+03:00 → 20.11.2026
    if [[ "$1" =~ ^([0-9]{4})-([0-9]{2})-([0-9]{2}) ]]; then
        printf '%s.%s.%s' "${BASH_REMATCH[3]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[1]}"
    fi
    return 0
}
# _m_clip <строка> <макс> — поле с хоста (имя, ядро, ОС): только печатный ASCII (ширину
# остального без локали не посчитать), не длиннее макс — чтобы не налезть на рамку.
_m_clip() {
    local s="${1//[^[:ascii:]]/}"
    s="${s//[[:cntrl:]]/}"
    (( ${#s} <= $2 )) || s="${s:0:$(( $2 > 1 ? $2 - 1 : 1 ))}~"
    printf '%s' "$s"
}
# _m_fit <текст> <колонок> — обрезка строки состояния по символам (в UTF-8-локали)
_m_fit() {
    local t="$1"
    if (( M_UTF8 && ${#t} > $2 )); then t="${t:0:$(( $2 - 1 ))}…"; fi
    printf '%s' "$t"
}
_m_pid_alive() {
    local p
    [[ -f "$1" && ! -L "$1" ]] || return 1
    p="$(cat "$1" 2>/dev/null || true)"
    [[ "$p" =~ ^[0-9]+$ ]] && kill -0 "$p" 2>/dev/null
}

# menu_status — строки «ГЛИФ|метка|текст» в M_ST
menu_status() {
    local host os virt tail kern cc qd g t f ver cs=1
    M_ST=()
    host="$(hostname 2>/dev/null || uname -n 2>/dev/null || true)"
    os="${NAME:-${OS_ID:-linux}}"
    os="${os%% *}${VERSION_ID:+ $VERSION_ID}${VERSION_CODENAME:+ ($VERSION_CODENAME)}"
    virt="$(detect_virt)"
    case "$virt" in none|unknown) virt="" ;; esac
    tail=" · $(_m_clip "$os" 22) · $(_m_clip "$(arch)" 8)${virt:+ · $(_m_clip "$virt" 10)}"
    M_ST+=("|Узел|$(_m_clip "${host:-?}" $(( M_TXT - ${#tail} > 8 ? M_TXT - ${#tail} : 8 )))$tail")

    kern="$(uname -r 2>/dev/null || true)"
    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
    qd="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
    t="$(_m_clip "${kern:-?}" 26) · $(_m_clip "${cc:-?}" 10)${qd:+ + $(_m_clip "$qd" 10)}"
    if [[ "$cc" == bbr* ]]; then g=OK; else g=WARN; t+=" — без BBR"; fi
    M_ST+=("$g|Ядро|$t")

    f="$STATE_DIR/optimize.installed"
    if [[ -f "$f" ]]; then
        ver="$(_m_clip "$(_m_kv na_version "$f")" 10)"
        t="$(_m_date "$(_m_kv installed_at "$f")")"
        t="применён${t:+ $t}${ver:+ · v$ver}"
        if [[ -n "$ver" && "$ver" != "${NA_VERSION:-}" ]]; then t+=" · ре-ран → v${NA_VERSION:-?}"; fi
        M_ST+=("OK|Тюнинг|$t")
    else
        M_ST+=("NONE|Тюнинг|не применялся — пункт 1")
    fi
    if reboot_pending; then M_ST+=("WARN||нужна перезагрузка: новое ядро или параметры загрузки"); fi

    f="$STATE_DIR/protect.installed"
    if [[ -f "$f" ]]; then
        t="$(_m_clip "$(_m_kv fw_mode "$f")" 8)"
        t="${t:-strict}"
        if [[ "$t" == skip ]]; then
            g=NONE; t="FW_MODE=skip — файрвол не ставился"
        elif nft -t list table inet na_filter >/dev/null 2>&1; then
            g=OK; t+=" · na_filter работает"
        else
            g=FAIL; t+=" · na_filter НЕ загружена — защиты нет"
        fi
        if [[ "$(_m_kv crowdsec "$f")" == 1 ]]; then
            if systemctl is-active --quiet crowdsec 2>/dev/null; then
                ver="$(_m_clip "$(_m_kv crowdsec_scope "$f")" 6)"
                t+=" · CrowdSec${ver:+ ($ver)}"
            else
                cs=0
            fi
        fi
        M_ST+=("$g|Защита|$t")
        if [[ "$g" == FAIL && "$STATE_DIR/safety-fired.last" -nt "$f" ]]; then
            M_ST+=("||сработал сейфти-таймер: доступ не подтвердили — пункт 2")
        fi
        if (( ! cs )); then M_ST+=("WARN||CrowdSec не запущен: systemctl status crowdsec"); fi
        if systemctl is-active --quiet na-fw-safety.timer 2>/dev/null \
           || _m_pid_alive "$STATE_DIR/na-fw-safety.pid"; then
            M_ST+=("WARN||сейфти-таймер взведён — na_filter снимется сама")
            M_ST+=("||подтвердить доступ: systemctl stop na-fw-safety.timer")
        fi
    else
        M_ST+=("NONE|Защита|не установлена — пункт 2")
    fi
    return 0
}
_m_status_row() {   # «ГЛИФ|метка|текст»
    local g="${1%%|*}" rest="${1#*|}" lab t gl=""
    lab="${rest%%|*}"; t="${rest#*|}"
    case "$g" in
        OK)   gl="${M_OK}✔${M_R}" ;;
        WARN) gl="${M_WARN}▲${M_R}" ;;
        FAIL) gl="${M_FAIL}✘${M_R}" ;;
        NONE) gl="${M_DIM}•${M_R}" ;;
    esac
    _m_row 2 "${lab:+$M_DIM$lab$M_R}" 12 "$gl" 14 "$(_m_fit "$t" "$M_TXT")"
}

# ─── Экраны ──────────────────────────────────────────────────────────────────
menu_render() {
    local r src=""
    menu_style
    menu_status
    [[ -n "${NA_TMPD:-}" ]] && src="$(_m_clip "$NA_REF" 24)"
    tty_tput clear
    _m_top "⚡ node-accelerator v${NA_VERSION:-?}" "$src"
    if (( M_BOX )); then
        _m_row 2 "${M_DIM}Оптимизация · Защита · Диагностика VPN-ноды${M_R}"
        _m_mid
    fi
    for r in "${M_ST[@]}"; do _m_status_row "$r"; done
    _m_mid
    _m_item 1 "⚡" "Оптимизатор" "XanMod/BBRv3 · sysctl по RAM · RPS · лимиты"
    _m_item 2 "🛡" "Защита"      "nftables · анти-скан · анти-флуд · CrowdSec"
    _m_item 3 "🩺" "Диагностика" "отчёт ✔/▲/✘ с советами, ничего не меняет"
    _m_item 4 "🚀" "Всё сразу"   "1 → 2 → 3"
    _m_item 5 "⏪" "Откат"       "вернуть как было: тюнинг, защиту или всё"
    _m_item 6 "🔥" "Атаки"       "кто, откуда и чем бьёт · разбор IP"
    if [[ -x "$NA_FW" ]]; then _m_item 7 "🧱" "Файрвол" "статус · whitelist · разбан"
    else _m_item 7 "🧱" "Файрвол" "появится после пункта 2"; fi
    _m_item 0 ""   "Выход"
    _m_bot "h — справка"
    _m_note
}

menu_rollback() {
    menu_style
    tty_tput clear
    _m_top "⏪ Откат"
    _m_row 2 "${M_NUM}1${M_R}" 6 "⚡ Тюнинг" 20 "${M_DIM}sysctl, RPS, THP — сразу, лимиты — после ребута${M_R}"
    _m_row 2 "${M_NUM}2${M_R}" 6 "🛡 Защиту" 20 "${M_DIM}файрвол na_filter, таймеры; CrowdSec остаётся${M_R}"
    _m_row 2 "${M_NUM}3${M_R}" 6 "Всё"       20 "${M_DIM}защиту, затем тюнинг${M_R}"
    _m_row 2 "${M_NUM}0${M_R}" 6 "Назад"
    _m_bot "бэкапы: /var/backups/node-accelerator"
    menu_ask " Что откатить › " || return 0
    local what="" q=""
    case "$REPLY" in
        1) what=optimize; q="Откатить тюнинг? Ядро XanMod останется (снять — NA_REMOVE_XANMOD=1)" ;;
        2) what=protect;  q="Откатить защиту? Файрвол и баны снимутся, порты откроются" ;;
        3) what=all;      q="Откатить защиту и тюнинг?" ;;
        0|"") return 0 ;;
        *) MENU_NOTE="«$(_m_clip "$REPLY" 16)» — в откате нет такого пункта, ничего не тронуто"; return 0 ;;
    esac
    if menu_yes "$q"; then menu_exec "⏪ Откат: $what" run_rollback "$what"
    else MENU_NOTE="откат отменён — ничего не тронуто"; fi
    return 0
}

# _m_addrs — адреса из REPLY (через пробел или запятую) в M_ADDRS. Только символы IP/CIDR:
# проверка до разбиения, чтобы `*` не раскрылся в имена файлов. Сам адрес проверяет na-fw.
_m_addrs() {
    M_ADDRS=()
    [[ "$REPLY" =~ ^[0-9A-Fa-f:./,[:space:]]+$ ]] || return 1
    read -r -a M_ADDRS <<< "${REPLY//,/ }"
    (( ${#M_ADDRS[@]} > 0 ))
}

menu_report() {
    while :; do
        menu_style
        tty_tput clear
        _m_top "🔥 Атаки — форензика (read-only)"
        _m_sub 1 "Отчёт за 24 часа"         "na-report"
        _m_sub 2 "Отчёт за другое окно"     "na-report --hours N"
        _m_sub 3 "Разбор одного IP"          "na-report --ip <адрес>"
        _m_sub 4 "Кто бьёт в порт"           "na-report --port <порт>"
        _m_sub 5 "Самопроверка на proxyware" "na-report --proxyware"
        _m_sub 0 "Назад"
        _m_bot
        _m_note
        menu_ask " Выбор › " || return 0
        case "$REPLY" in
            1) menu_exec "🔥 Атаки за 24 часа" run_report ;;
            2) menu_ask " Окно, часов (1–720) › " || continue
               if [[ "$REPLY" =~ ^[0-9]{1,3}$ ]] && (( 10#$REPLY >= 1 && 10#$REPLY <= 720 )); then
                   menu_exec "🔥 Атаки за $(( 10#$REPLY )) ч" run_report --hours "$(( 10#$REPLY ))"
               else MENU_NOTE="окно — целое число часов от 1 до 720"; fi ;;
            3) menu_ask " IP-адрес › " || continue
               if _m_addrs && (( ${#M_ADDRS[@]} == 1 )); then
                   menu_exec "🔥 Разбор ${M_ADDRS[0]}" run_report --ip "${M_ADDRS[0]}"
               else MENU_NOTE="нужен один IPv4/IPv6-адрес"; fi ;;
            4) menu_ask " Порт › " || continue
               if [[ "$REPLY" =~ ^[0-9]{1,5}$ ]] && (( 10#$REPLY >= 1 && 10#$REPLY <= 65535 )); then
                   menu_exec "🔥 Порт $(( 10#$REPLY ))" run_report --port "$(( 10#$REPLY ))"
               else MENU_NOTE="порт — число от 1 до 65535"; fi ;;
            5) menu_exec "🔥 Самопроверка на proxyware" run_report --proxyware ;;
            0|"") return 0 ;;
            *) MENU_NOTE="«$(_m_clip "$REPLY" 16)» — нет такого пункта" ;;
        esac
    done
}

menu_firewall() {
    if [[ ! -x "$NA_FW" ]]; then
        MENU_NOTE="файрвол ещё не установлен — сначала пункт 2 (Защита)"; return 0
    fi
    while :; do
        menu_style
        tty_tput clear
        _m_top "🧱 Файрвол"
        _m_sub 1 "Статус и счётчики дропов"  "na-fw-status"
        _m_sub 2 "Whitelist — показать"      "na-fw allow list"
        _m_sub 3 "Whitelist — добавить"      "na-fw allow add <ip|cidr>"
        _m_sub 4 "Whitelist — убрать"        "na-fw allow del <ip|cidr>"
        _m_sub 5 "Разбанить адрес"           "na-fw unban <ip>"
        _m_sub 6 "Топ источников"            "na-fw-top-talkers"
        _m_sub 0 "Назад"
        _m_bot "whitelist — полный обход защиты"
        _m_note
        menu_ask " Выбор › " || return 0
        case "$REPLY" in
            1) menu_exec "🧱 Статус файрвола" "$NA_FW_STATUS" ;;
            2) menu_exec "🧱 Whitelist" "$NA_FW" allow list ;;
            3|4|5)
               local act="$REPLY"
               menu_ask " Адреса через пробел (IP или CIDR) › " || continue
               if ! _m_addrs; then MENU_NOTE="только IPv4/IPv6-адреса и CIDR"; continue; fi
               case "$act" in
                   3) menu_exec "🧱 Whitelist: добавить" "$NA_FW" allow add "${M_ADDRS[@]}" ;;
                   4) menu_exec "🧱 Whitelist: убрать" "$NA_FW" allow del "${M_ADDRS[@]}" ;;
                   5) menu_exec "🧱 Разбан" "$NA_FW" unban "${M_ADDRS[@]}" ;;
               esac ;;
            6) menu_exec "🧱 Топ источников" "$NA_FW_TOP" ;;
            0|"") return 0 ;;
            *) MENU_NOTE="«$(_m_clip "$REPLY" 16)» — нет такого пункта" ;;
        esac
    done
}

menu_help() {
    menu_style
    tty_tput clear
    _m_top "❓ Справка"
    usage
    cat <<'H'

Без меню — для скриптов, панелей и Ansible: параметры защиты через ENV, без вопросов
  sudo SSH_PORT=22 TCP_PORTS=443 UDP_PORTS=443 WHITELIST=1.2.3.4 \
       REMNAWAVE_NONINTERACTIVE=1 bash install.sh protect

После установки на ноде остаются команды:
  na-diagnose [--json]   na-report [--json]   na-fw allow|unban   na-fw-status
H
    menu_ask " ${M_DIM}Enter — в меню${M_R} › " || exit 0
    return 0
}

show_menu() {
    if ! menu_open_input; then
        err "Меню нужен терминал: stdin не терминал, а $NA_TTY не открывается. Команды без меню:"
        usage >&2
        exit 2
    fi
    trap menu_on_int INT
    while :; do
        menu_render
        menu_ask " Выбор › " || exit 0
        case "$REPLY" in
            1) menu_exec "⚡ Оптимизатор" run_optimize ;;
            2) menu_exec "🛡  Защита" run_protect ;;
            3) menu_exec "🩺 Диагностика" run_diagnose ;;
            4) menu_exec "🚀 Всё сразу: оптимизатор → защита → диагностика" run_all ;;
            5) menu_rollback ;;
            6) menu_report ;;
            7) menu_firewall ;;
            h|H|'?'|help) menu_help ;;
            0|q|Q|exit|quit) exit 0 ;;
            "") ;;
            *) MENU_NOTE="«$(_m_clip "$REPLY" 16)» — нет такого пункта" ;;
        esac
    done
}

case "${1:-}" in
    optimize) run_optimize ;;
    protect)  run_protect ;;
    diagnose|diag) shift; run_diagnose "$@" ;;
    report)   shift; run_report "$@" ;;
    all)      run_all ;;
    rollback) run_rollback "${2:-all}" ;;
    persist)  persist_toolkit ;;
    "")       show_menu ;;
    -h|--help) usage ;;
    *) err "Неизвестная команда: $1"; usage; exit 1 ;;
esac
