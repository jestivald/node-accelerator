#!/usr/bin/env bash
#
# optimize.sh — ⚡ Оптимизатор ноды.
#   • XanMod-ядро (BBRv3) — авто-выбор сборки по psABI, пропуск на контейнерах/ARM
#   • sysctl: BBR + fq, большие буферы, conntrack, anti-spoof, syncookies
#   • RPS/RFS/XPS — размазывает обработку пакетов по всем ядрам (главное на virtio-VPS)
#   • лимиты nofile/nproc, swap, journald cap, THP off, CPU governor=performance, NIC tune
#
# Идемпотентно. Откат: scripts/rollback.sh optimize
#
# ENV-флаги:
#   ENABLE_XANMOD=1   поставить XanMod-ядро (по умолч. 1; авто-skip на контейнере/не-x86_64)
#   XANMOD_FLAVOR=lts сборка: lts (стабильная, по умолч.) | main | edge | rt
#   XANMOD_PKG=...     полностью переопределить имя пакета
#   REMNAWAVE_SWAP_SIZE=2G
#   ENABLE_LOGROTATE=1 ротация файловых логов ноды + часовой таймер (0 = не трогать)
#   NA_LOG_PATHS="/var/log/nginx/*.log /var/log/remnanode/*.log"   что ротировать
#   NA_LOG_MAXSIZE=200M  NA_LOG_ROTATE=4  NA_LOG_INTERVAL=hourly
#   NA_JOURNAL_MAX_USE=300M  потолок journald (публичную ноду 300M держат <суток)
#   ENABLE_PSI=0      дописать psi=1 в cmdline → /proc/pressure (нужен reboot; 1 = вкл)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

# Прячем курсор для прогресс-бара установки ядра ниже; гарантированно возвращаем его
# при любом выходе, включая Ctrl-C, чтобы не оставить терминал с невидимым курсором.
# tty_tput, а не голый tput: tput решает по TERM, а не по isatty(1), и под
# `nohup … > log` управляющие последовательности уезжали в лог раскатки (issue #28).
trap 'tty_tput cnorm' EXIT
trap 'tty_tput cnorm; exit 130' INT

require_root
detect_os

# Один прогон optimize за раз: параллельные запуски дерутся за apt-lock и sysctl-файлы.
if [[ "${NA_NO_LOCK:-0}" != "1" ]] && command -v flock >/dev/null 2>&1 && mkdir -p "$STATE_DIR" 2>/dev/null; then
    exec 9>"$STATE_DIR/optimize.lock"
    flock -n 9 || { err "уже идёт другой прогон optimize.sh (лок $STATE_DIR/optimize.lock) — не мешаю"; exit 1; }
fi

# Подхватываем сохранённый конфиг оптимизатора (ENV по-прежнему переопределяет).
load_conf "$CONF_DIR/optimize.conf"

# apt по умолчанию НЕ ждёт чужой dpkg-лок, а падает сразу. На свежем боксе первые минуты
# лок держит unattended-upgrades, и без этого таймаута установка ядра обрывалась с
# «Could not get lock … held by unattended-upgr» — при живом репозитории и исправном боксе.
APT_LOCK=(-o DPkg::Lock::Timeout=300)

# DRY_RUN: protect.sh поддерживает полноценный dry-run (генерит ruleset, не применяет),
# и пользователь по аналогии может ждать того же от `DRY_RUN=1 install.sh optimize|all`.
# Оптимизатор же мутирует НЕОБРАТИМО (ставит ядро, свап, sysctl) — тихо отработать
# «как будто dry-run» здесь опаснее, чем честно отказать. Выходим ДО любых мутаций.
if [[ "${DRY_RUN:-0}" == "1" ]]; then
    info "DRY_RUN=1: детальный dry-run для оптимизатора НЕ поддержан (мутации ядро/свап/sysctl необратимы)."
    info "Было бы сделано: XanMod (ENABLE_XANMOD=${ENABLE_XANMOD:-1}), sysctl (BBR/буферы/conntrack),"
    info "  лимиты 1M, RPS/RFS/XPS, NIC-tune, swap/zram, journald-cap, ротация логов + часовой таймер,"
    info "  THP=never, governor=performance."
    info "Проверить XanMod-репо без установки: XANMOD_PROBE=1. Dry-run фаервола: DRY_RUN=1 protect.sh."
    exit 0
fi

# Подчищаем ТОЛЬКО XanMod-репозитории с мёртвыми suite (focal/jammy/releases выпилены
# из репо) — их 404 роняет 'apt-get update' на повторном прогоне через set -e. Рабочий
# list НЕ трогаем: иначе на уже настроенной ноде молча отключатся обновления ядра.
for _l in /etc/apt/sources.list.d/xanmod*.list; do
    [[ -e "$_l" ]] || continue
    if grep -qE 'deb\.xanmod\.org[[:space:]]+(focal|jammy|releases)([[:space:]]|$)' "$_l" 2>/dev/null; then
        rm -f "$_l"
    fi
done
unset _l

ENABLE_XANMOD="${ENABLE_XANMOD:-1}"
XANMOD_FLAVOR="${XANMOD_FLAVOR:-lts}"
BACKUP="$(backup_dir)"
REBOOT_NEEDED=0
# Причин ребута теперь может быть две (ядро и psi=1 в cmdline) — копим текстом,
# чтобы в финале не обещать «установлено новое ядро» там, где его не ставили.
REBOOT_WHY=""
info "Бэкап изменяемых файлов: $BACKUP"

# Прогресс-бар установки ядра (рисуется по APT::Status-Fd в install_xanmod).
# Вне терминала не рисуем ВООБЩЕ: перерисовка живёт на \r и \033[K, а в файле это
# мусор поверх строк лога (issue #28). Прогресс шага там несёт "Ставлю $p…" + итог.
draw_progress_bar() {
    is_tty || return 0
    local percent=$1 desc=$2 width=30 i bar=""
    local filled=$((percent * width / 100))
    local empty=$((width - filled))
    for ((i=0; i<filled; i++)); do bar+="#"; done
    for ((i=0; i<empty;  i++)); do bar+="-"; done
    local maxlen=35
    [[ ${#desc} -gt $maxlen ]] && desc="${desc:0:$((maxlen-3))}..."
    printf "\r[*] [%s] %3d%% (%s)\033[K" "$bar" "$percent" "$desc"
}

# Снять строку прогресс-бара и вернуть курсор. Всё «курсорное» — только в терминале.
progress_end() {
    if is_tty; then printf "\r\033[K"; fi
    tty_tput cnorm
}

# ─── 1. Зависимости ──────────────────────────────────────────────────────────
title "Зависимости"
apt_install ca-certificates curl gnupg irqbalance ethtool
ok "ok"

# ─── 2. XanMod-ядро (BBRv3) ──────────────────────────────────────────────────
title "XanMod-ядро (BBRv3)"
# Полный отпечаток ключа подписи XanMod (keyid 86F7D09EE734E623 — последние 16 hex).
# Проверяем именно его: 64-битный keyid подделать дёшево, полный fingerprint — нет.
XANMOD_FP="D38D7D1DA1349567ADED882D86F7D09EE734E623"

# Импорт ключа: 1) напрямую с XanMod; 2) при блокировке (CF-403 типичен для Hetzner/GCP)
# — с Ubuntu keyserver. Что бы ни сработало — сверяем полный отпечаток.
xanmod_import_key() {
    local keyring="$1" tmpkey
    mkdir -p /etc/apt/keyrings
    tmpkey="$(mktemp)" || return 1
    if ! curl -fsSL --connect-timeout 5 --max-time 20 https://dl.xanmod.org/archive.key -o "$tmpkey"; then
        warn "dl.xanmod.org недоступен (обычно CF-403 на хостингах) — пробую Ubuntu keyserver…"
        if ! curl -fsSL --connect-timeout 5 --max-time 20 \
                "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x${XANMOD_FP: -16}" -o "$tmpkey"; then
            warn "Ключ XanMod недоступен ни напрямую, ни с keyserver"; rm -f "$tmpkey"; return 1
        fi
    fi
    # keyserver ищется ПО 64-битному keyid, а его коллизию сделать дёшево → в ответе
    # рядом с настоящим ключом может приехать чужой. apt по signed-by= доверяет КАЖДОМУ
    # ключу keyring'а, поэтому кладём туда ровно наш отпечаток (import_pinned_key),
    # а не «всё, что прислали».
    if ! import_pinned_key "$tmpkey" "$XANMOD_FP" "$keyring"; then
        warn "Ключ XanMod не сошёлся с отпечатком $XANMOD_FP — отказываюсь использовать"
        rm -f "$tmpkey"; return 1
    fi
    rm -f "$tmpkey"
    return 0
}

# Готовим репозиторий XanMod (ключ + sources.list + apt update). Идемпотентно;
# вызывается и при установке, и для уже стоящего ядра (чтобы не заморозить обновления).
setup_xanmod_repo() {
    local keyring=/etc/apt/keyrings/xanmod-archive-keyring.gpg
    local list=/etc/apt/sources.list.d/xanmod-release.list
    local codename; codename="$(os_codename)"

    # focal/jammy выпилены из XanMod-репо → совместимый Debian 'bookworm' (LTS-ветка ядра).
    case "$codename" in
        focal|jammy)
            info "Ubuntu $codename: suite выпилен из XanMod-репо → беру 'bookworm' + lts-сборку"
            codename="bookworm"; XANMOD_FLAVOR="lts" ;;
        "") codename="bookworm" ;;   # релиз не определён — берём универсальный LTS-suite
    esac
    # Для oldstable (bookworm) XanMod оставил в репо ТОЛЬКО LTS-ветку — main/edge/rt
    # оттуда убраны, и запрос такой сборки просто не нашёл бы пакет.
    if [[ "$codename" == "bookworm" && "$XANMOD_FLAVOR" != "lts" ]]; then
        info "Debian bookworm: в репо XanMod осталась только LTS-ветка → беру lts вместо '$XANMOD_FLAVOR'"
        XANMOD_FLAVOR="lts"
    fi

    xanmod_import_key "$keyring" || return 1

    # Обновляем ТОЛЬКО свой list (как в setup_crowdsec_repo): глобальный apt-get update
    # возвращает rc≠0 из-за ЛЮБОГО чужого битого источника на боксе — а это типовая
    # ситуация на съёмных VPS. Без скоупа живой XanMod-репо ложно объявлялся мёртвым,
    # фоллбэк на bookworm падал так же, и ядро молча не ставилось «репо недоступен».
    local -a UPDSC=(-o "Dir::Etc::sourcelist=$list" -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0)
    echo "deb [signed-by=$keyring] https://deb.xanmod.org $codename main" > "$list"
    if ! apt-get "${APT_LOCK[@]}" update -qq "${UPDSC[@]}" 2>/dev/null; then
        if [[ "$codename" != "bookworm" ]]; then
            warn "Suite '$codename' не поднялся — откатываюсь на 'bookworm' (LTS)"
            codename="bookworm"; XANMOD_FLAVOR="lts"
            echo "deb [signed-by=$keyring] https://deb.xanmod.org $codename main" > "$list"
            apt-get "${APT_LOCK[@]}" update -qq "${UPDSC[@]}" 2>/dev/null || { warn "XanMod-репо недоступен"; rm -f "$list"; return 1; }
        else
            warn "XanMod-репо ('bookworm') недоступен"; rm -f "$list"; return 1
        fi
    fi
    # общий кэш (чтобы apt-cache/install видели пакеты); чужие битые источники не фатальны
    apt-get "${APT_LOCK[@]}" update -qq 2>/dev/null || true
    return 0
}

# Список пакетов-кандидатов по psABI-уровню (деградация v3→v2→v1). Вынесено отдельно,
# чтобы install_xanmod и XANMOD_PROBE брали кандидатов из одного источника.
xanmod_candidates() {
    local flv="$XANMOD_FLAVOR" pref="" lvl
    case "$flv" in lts) pref="lts-";; edge) pref="edge-";; rt) pref="rt-";; *) pref="";; esac
    lvl="$(cpu_psabi_level)"; [[ "$lvl" =~ ^[1-4]$ ]] || lvl=2
    if [[ -n "${XANMOD_PKG:-}" ]]; then echo "$XANMOD_PKG"; return; fi
    case "$lvl" in
        4|3) echo "linux-xanmod-${pref}x64v3 linux-xanmod-${pref}x64v2 linux-xanmod-lts-x64v2";;
        2)   echo "linux-xanmod-${pref}x64v2 linux-xanmod-lts-x64v2";;
        *)   echo "linux-xanmod-lts-x64v1";;
    esac
}

install_xanmod() {
    setup_xanmod_repo || return 1
    info "psABI уровень CPU: x86-64-v$(cpu_psabi_level), сборка: $XANMOD_FLAVOR"

    local p pkg="" err_log candidates
    read -ra candidates <<< "$(xanmod_candidates)"
    for p in "${candidates[@]}"; do
        apt-cache show "$p" >/dev/null 2>&1 || continue
        info "Ставлю $p (это надолго — компилит initramfs)…"
        err_log="$(mktemp)"
        tty_tput civis
        # APT::Status-Fd=1 → машинный прогресс в stdout; stdbuf -oL снимает буферизацию пайпа.
        # pkg НЕ трогаем в subshell справа от пайпа (там только отрисовка) — ставим в родителе.
        if DEBIAN_FRONTEND=noninteractive stdbuf -oL \
                apt-get -o APT::Status-Fd=1 "${APT_LOCK[@]}" install -y "$p" 2>"$err_log" \
                | while IFS=: read -r f1 f2 f3 f4 _r; do
                    case "$f1" in
                        pmstatus|dlstatus)
                            pct="$f3"; dsc="$f4"
                            if ! [[ "$pct" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
                                if [[ "$f2" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then pct="$f2"; dsc="$f3"; else continue; fi
                            fi
                            pct="${pct%%.*}"
                            [[ "$pct" =~ ^[0-9]+$ ]] || continue
                            [[ "$pct" -gt 100 ]] && pct=100
                            [[ "$f1" == "dlstatus" ]] && act="Загрузка" || act="Установка"
                            draw_progress_bar "$pct" "$act: $dsc"
                            ;;
                    esac
                done
        then
            progress_end
            rm -f "$err_log"; pkg="$p"; break
        else
            progress_end
            warn "Сборка $p не установилась — пробую следующую. Хвост ошибки:"
            tail -n 3 "$err_log" >&2; rm -f "$err_log"
        fi
    done
    [[ -z "$pkg" ]] && { warn "Ни одна сборка XanMod не поставилась"; return 1; }

    mkdir -p "$STATE_DIR"; echo "$pkg" > "$STATE_DIR/xanmod.pkg"
    update-grub >/dev/null 2>&1 || true
    ok "XanMod установлен: $pkg (активируется ПОСЛЕ перезагрузки)"
    REBOOT_NEEDED=1
    REBOOT_WHY="${REBOOT_WHY:+$REBOOT_WHY; }новое ядро XanMod ($pkg)"
    return 0
}

# PROBE: проверить, что репозиторий+ключ+кандидат резолвятся на этой ОС, БЕЗ установки.
# Используется в CI (матрица дистрибутивов) и как ops-проба. Обходит гейт «контейнер».
if [[ "${XANMOD_PROBE:-0}" == "1" ]]; then
    setup_xanmod_repo || { err "XANMOD_PROBE: репозиторий не поднялся"; exit 1; }
    cand="$(xanmod_candidates)"; info "кандидаты: $cand"
    for p in $cand; do
        if apt-cache show "$p" >/dev/null 2>&1; then
            ok "XANMOD_PROBE: '$p' доступен в репозитории"
            DEBIAN_FRONTEND=noninteractive apt-get "${APT_LOCK[@]}" install --download-only -y "$p" >/dev/null 2>&1 \
                && ok "XANMOD_PROBE: '$p' скачивается" \
                || warn "XANMOD_PROBE: '$p' в индексе есть, но download-only не прошёл (зависимости дистрибутива)"
            exit 0
        fi
    done
    err "XANMOD_PROBE: ни один кандидат не доступен"; exit 1
fi

if [[ "$ENABLE_XANMOD" == "1" ]]; then
    if ! can_install_kernel; then
        if is_container; then
            warn "Виртуализация: $(detect_virt) — это контейнер, делит ядро хоста."
            warn "XanMod поставить нельзя. BBR возьмётся из стокового ядра (если поддерживается)."
        else
            warn "Архитектура $(arch) — XanMod только под x86_64. Пропускаю ядро."
        fi
    elif [[ "$(uname -r)" == *xanmod* ]]; then
        ok "XanMod уже стоит ($(uname -r)) — обновляю только репозиторий (чтобы шли апдейты ядра)"
        setup_xanmod_repo || warn "репозиторий XanMod не обновлён (само ядро не тронуто)"
    else
        install_xanmod || warn "XanMod не установлен — продолжаю с текущим ядром"
    fi
else
    info "ENABLE_XANMOD=0 — установка ядра пропущена"
fi

# ─── 2b. PSI: учёт давления CPU/памяти/IO (opt-in) ───────────────────────────
# XanMod и стоковые ядра Debian собраны с CONFIG_PSI_DEFAULT_DISABLED=y: PSI в ядре
# ЕСТЬ, но /proc/pressure не появляется без psi=1 в командной строке. То есть тулкит
# сам ставит ядро, на котором его же сенсор давления слеп на 100% нод (issue #37).
# Ручка opt-in и по умолчанию 0: учёт PSI не бесплатен для планировщика, а параметр
# требует ребута. Идемпотентно: второй прогон psi=1 не дублирует.
title "PSI (учёт давления, psi=1 в cmdline)"
ENABLE_PSI="${ENABLE_PSI:-0}"
[[ "$ENABLE_PSI" =~ ^[01]$ ]] || { warn "ENABLE_PSI='$ENABLE_PSI' — ожидается 0|1, беру 0"; ENABLE_PSI=0; }
# Маркер «psi=1 в GRUB прописали МЫ» — только по нему rollback имеет право его снять.
# Переносим с прошлого прогона: ре-ран не должен превратить нашу запись в «чужую».
PSI_MARK=0
if grep -qx 'psi=1' "$STATE_DIR/optimize.installed" 2>/dev/null; then PSI_MARK=1; fi

if [[ "$ENABLE_PSI" != "1" ]]; then
    # Осознанно НЕ снимаем уже стоящий psi=1: оператор мог включить его сам.
    info "psi=1 не трогаю (ENABLE_PSI=1 — включить /proc/pressure, применится после reboot)"
elif [[ ! -f /etc/default/grub ]]; then
    info "нет /etc/default/grub (контейнер или загрузчик не GRUB) — psi=1 прописать некуда"
else
    # Конфиг ТЕКУЩЕГО ядра. Если ядро только что поставили — грузимся ещё на старом,
    # и проверять нечего: лишний параметр загрузки безвреден, дописываем.
    _kcfg="/boot/config-$(uname -r)"
    _psi_line="$(grep -m1 -E '^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT="[^"]*"[[:space:]]*$' /etc/default/grub 2>/dev/null || true)"
    if [[ "$REBOOT_NEEDED" != "1" && -r "$_kcfg" ]] && ! grep -q '^CONFIG_PSI=y' "$_kcfg" 2>/dev/null; then
        info "в ядре нет CONFIG_PSI ($_kcfg) — psi=1 ничего не включит, пропускаю"
    elif [[ -z "$_psi_line" ]]; then
        warn "GRUB_CMDLINE_LINUX_DEFAULT не в ожидаемом виде KEY=\"…\" — psi=1 допиши вручную + update-grub"
    elif [[ "$_psi_line" == *psi=1* ]]; then
        ok "psi=1 уже в GRUB_CMDLINE_LINUX_DEFAULT"
        [[ -r /proc/pressure/cpu ]] || { REBOOT_NEEDED=1; REBOOT_WHY="${REBOOT_WHY:+$REBOOT_WHY; }psi=1 в cmdline (сенсор давления)"; }
    else
        backup_file /etc/default/grub "$BACKUP"
        # Дописываем ВНУТРЬ кавычек значения (за ними идёт остальной cmdline ядра).
        # rc≠0 (ro-раздел/битые права) не должен ронять весь прогон — ниже проверяем факт.
        sed -i -E 's/^([[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT="[^"]*)"[[:space:]]*$/\1 psi=1"/' /etc/default/grub || true
        sed -i -E 's/^([[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=")[[:space:]]+/\1/' /etc/default/grub || true
        if grep -qE '^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=.*psi=1' /etc/default/grub; then
            PSI_MARK=1
            update-grub >/dev/null 2>&1 || warn "update-grub не отработал — psi=1 доедет только после ручного update-grub"
            ok "psi=1 дописан в GRUB_CMDLINE_LINUX_DEFAULT (/proc/pressure — после reboot)"
            [[ -r /proc/pressure/cpu ]] || { REBOOT_NEEDED=1; REBOOT_WHY="${REBOOT_WHY:+$REBOOT_WHY; }psi=1 в cmdline (сенсор давления)"; }
        else
            warn "не смог дописать psi=1 в /etc/default/grub — оставил как было"
        fi
    fi
    unset _kcfg _psi_line
fi

# ─── 3. Sysctl ───────────────────────────────────────────────────────────────
title "Sysctl: BBR, буферы (tier-aware), conntrack, anti-spoof, syncookies"
# Tier-aware буферы: масштабируем ПОТОЛКИ сокетов по RAM. На мелкой VPS 64MB-буфер на
# сокет × сотни сокетов уводит ядро в OOM; на крупной — даём полный размер. Ёмкость
# conntrack масштабируется отдельным drop-in ниже (тоже от RAM).
_mem_kb="$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo 1048576)"
_mem_mb=$(( _mem_kb / 1024 ))
if   [[ $_mem_mb -le 1200 ]]; then TIER=1; SOCK_MAX=16777216;  SOCK_DEF=524288
elif [[ $_mem_mb -le 2500 ]]; then TIER=2; SOCK_MAX=33554432;  SOCK_DEF=1048576
elif [[ $_mem_mb -le 8500 ]]; then TIER=3; SOCK_MAX=67108864;  SOCK_DEF=2097152
else                               TIER=4; SOCK_MAX=134217728; SOCK_DEF=2097152
fi
# tcp_ecn: 2 (пассивный — принимаем ECN от клиента, но НЕ инициируем на исходящих)
# безопаснее 1 на путях с битыми middlebox (исходящие коннекты ноды к апстримам).
TCP_ECN_MODE="${TCP_ECN_MODE:-2}"; [[ "$TCP_ECN_MODE" =~ ^[012]$ ]] || TCP_ECN_MODE=2
# TFO можно выключить (DISABLE_TFO=1): часть сетей режет SYN с TFO-payload.
DISABLE_TFO="${DISABLE_TFO:-0}"; [[ "$DISABLE_TFO" =~ ^[01]$ ]] || DISABLE_TFO=0
TFO_VAL=3; [[ "$DISABLE_TFO" == "1" ]] && TFO_VAL=0
# nf_conntrack_tcp_timeout_established: за сколько «established» без трафика реклеймится.
# Дефолт 7440с (124 мин) — выше keepalive живого VLESS-мультиплекса, но много короче
# стокового 5-суточного потолка ядра: брошенные / connect-and-hold сессии не раздувают
# таблицу. idle-туннели/мосты без частого keepalive могут поднять (напр. 14400=4ч).
CT_EST_TIMEOUT="${CT_EST_TIMEOUT:-7440}"
[[ "$CT_EST_TIMEOUT" =~ ^[0-9]+$ ]] && [[ "$CT_EST_TIMEOUT" -ge 120 && "$CT_EST_TIMEOUT" -le 432000 ]] || CT_EST_TIMEOUT=7440
# qdisc: fq (дефолт, BBR-классика) | fq_codel | cake. BBR пейсит внутренне (ядро 4.20+),
# так что cake — легальная альтернатива для bufferbloat-аплинков дешёвых VPS; включать
# осознанно и сравнивать A/B (cake добавляет свой шейпинг-оверхед на PPS).
QDISC="${QDISC:-fq}"
[[ "$QDISC" =~ ^(fq|fq_codel|cake)$ ]] || { warn "QDISC='$QDISC' не из fq|fq_codel|cake — беру fq"; QDISC=fq; }
# overcommit: на tier1 (≤1.2G) heuristic (0) безопаснее агрессивного always-overcommit (1).
OVERCOMMIT=1; [[ "$TIER" -le 1 ]] && OVERCOMMIT=0
info "RAM-tier $TIER (~${_mem_mb} MB): sock_max=$SOCK_MAX def=$SOCK_DEF ecn=$TCP_ECN_MODE tfo=$TFO_VAL overcommit=$OVERCOMMIT qdisc=$QDISC"
backup_file /etc/sysctl.d/99-node-accelerator.conf "$BACKUP"
cat > /etc/sysctl.d/99-node-accelerator.conf <<SYSCTL
# === node-accelerator / optimize (RAM-tier $TIER, ~${_mem_mb} MB) ===

# --- Network core ---
net.core.default_qdisc            = $QDISC
net.core.netdev_max_backlog       = 250000
net.core.somaxconn                = 65535
net.core.rmem_default             = $SOCK_DEF
net.core.wmem_default             = $SOCK_DEF
net.core.rmem_max                 = $SOCK_MAX
net.core.wmem_max                 = $SOCK_MAX
net.core.optmem_max               = 65536
# netdev_budget: сколько пакетов softirq дренирует за цикл (дефолт 300) — поднимаем под высокий PPS
net.core.netdev_budget            = 600
net.core.netdev_budget_usecs      = 8000
# RPS: глобальная таблица flow-привязок (дополняет per-queue настройку из na-rps)
net.core.rps_sock_flow_entries    = 32768

# --- TCP (под XanMod congestion=bbr == BBRv3) ---
net.ipv4.tcp_congestion_control   = bbr
net.ipv4.tcp_fastopen             = $TFO_VAL
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse             = 1
net.ipv4.tcp_fin_timeout          = 15
# keepalive 1200с: 300с резало клиентов за NAT/мобилой раньше, чем доходила проба.
net.ipv4.tcp_keepalive_time       = 1200
net.ipv4.tcp_keepalive_intvl      = 30
net.ipv4.tcp_keepalive_probes     = 5
net.ipv4.tcp_max_syn_backlog      = 65535
net.ipv4.tcp_max_tw_buckets       = 2000000
net.ipv4.tcp_mtu_probing          = 1
# Floor the probe MSS well above the kernel default of 48: with mtu_probing on,
# repeated RTOs on a lossy link make the kernel suspect a PMTU black hole and
# ratchet the send MSS down toward this floor. At 48B a segment is ~97% header
# overhead and throughput collapses with no recovery. 512 keeps probing useful
# for genuine black holes while never destroying goodput (and stays above the
# CVE-2019-11479 mitigation minimum).
net.ipv4.tcp_min_snd_mss          = 512
net.ipv4.tcp_no_metrics_save      = 1
net.ipv4.tcp_rfc1337              = 1
net.ipv4.tcp_sack                 = 1
net.ipv4.tcp_window_scaling       = 1
net.ipv4.tcp_rmem                 = 4096 87380 $SOCK_MAX
net.ipv4.tcp_wmem                 = 4096 65536 $SOCK_MAX
net.ipv4.tcp_notsent_lowat        = 131072
net.ipv4.tcp_ecn                  = $TCP_ECN_MODE
net.ipv4.ip_local_port_range      = 10000 65535

# --- UDP (QUIC/Hysteria2/TUIC). Потолок буфера берётся из rmem_max выше. ---
net.ipv4.udp_rmem_min             = 16384
net.ipv4.udp_wmem_min             = 16384

# --- IP forwarding (XRay/VLESS в network_mode: host + Docker) ---
net.ipv4.ip_forward               = 1
net.ipv4.conf.all.forwarding      = 1
net.ipv6.conf.all.forwarding      = 1

# --- Conntrack: timeout здесь (tunable CT_EST_TIMEOUT); ёмкость (max/buckets) —
# отдельным drop-in ниже, масштабируется от RAM (99-node-accelerator-conntrack.conf),
# чтобы мелкая VPS под флудом не словила OOM в ядре ---
net.netfilter.nf_conntrack_tcp_timeout_established = $CT_EST_TIMEOUT

# --- SYN flood (ядро) ---
net.ipv4.tcp_syncookies           = 1
net.ipv4.tcp_synack_retries       = 2
net.ipv4.tcp_syn_retries          = 2

# --- Anti-spoof / ICMP ---
# rp_filter=2 (loose): на VPN-нодах с host-network часто асимметричный роутинг,
# strict (1) рубит легитимные пакеты.
net.ipv4.conf.all.rp_filter                = 2
net.ipv4.conf.default.rp_filter            = 2
net.ipv4.conf.all.accept_source_route      = 0
net.ipv4.conf.default.accept_source_route  = 0
net.ipv4.conf.all.send_redirects           = 0
net.ipv4.conf.default.send_redirects       = 0
net.ipv4.conf.all.accept_redirects         = 0
net.ipv4.conf.default.accept_redirects     = 0
net.ipv4.conf.all.secure_redirects         = 0
net.ipv4.icmp_echo_ignore_broadcasts       = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv6.conf.all.accept_redirects         = 0
net.ipv6.conf.all.accept_source_route      = 0

# --- Память ---
vm.swappiness                = 10
vm.dirty_ratio               = 10
vm.dirty_background_ratio    = 5
vm.overcommit_memory         = $OVERCOMMIT
vm.max_map_count             = 262144

# --- Файловые дескрипторы ---
fs.file-max                   = 2097152
fs.nr_open                    = 2097152
fs.inotify.max_user_watches   = 524288
fs.inotify.max_user_instances = 8192
SYSCTL

# Ёмкость conntrack под RAM ноды: ~320 B на запись, держим таблицу ≤ ~1/8 RAM, чтобы
# под флудом мелкая VPS не упёрлась в OOM ядра. Потолок 2M, пол 262144 (как было).
_mem_kb="$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo 1048576)"
CT_MAX=$(( _mem_kb * 1024 / 8 / 320 ))
[[ "$CT_MAX" -gt 2000000 ]] && CT_MAX=2000000
[[ "$CT_MAX" -lt 262144  ]] && CT_MAX=262144
CT_BUCKETS=$(( CT_MAX / 4 ))
cat > /etc/sysctl.d/99-node-accelerator-conntrack.conf <<CT
# node-accelerator: ёмкость conntrack под RAM этой ноды (~$(( _mem_kb / 1024 )) MB)
net.netfilter.nf_conntrack_max     = $CT_MAX
net.netfilter.nf_conntrack_buckets = $CT_BUCKETS
CT
info "conntrack: max=$CT_MAX buckets=$CT_BUCKETS (под ~$(( _mem_kb / 1024 )) MB RAM)"

modprobe tcp_bbr 2>/dev/null || true
modprobe nf_conntrack 2>/dev/null || true
echo "tcp_bbr"      > /etc/modules-load.d/na-bbr.conf
echo "nf_conntrack" > /etc/modules-load.d/na-conntrack.conf
sysctl --system >/dev/null 2>&1 || true

if [[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" == "bbr" ]]; then
    ok "BBR активен (под XanMod это BBRv3)"
else
    warn "BBR пока не активен — модуль/ядро подхватятся после reboot"
fi

# ─── 4. Лимиты ───────────────────────────────────────────────────────────────
title "Лимиты nofile/nproc"
backup_file /etc/security/limits.conf "$BACKUP"
sed -i '/# === node-accelerator ===/,/# === \/node-accelerator ===/d' /etc/security/limits.conf
cat >> /etc/security/limits.conf <<'LIMITS'
# === node-accelerator ===
*       soft    nofile  1048576
*       hard    nofile  1048576
*       soft    nproc   1048576
*       hard    nproc   1048576
root    soft    nofile  1048576
root    hard    nofile  1048576
# === /node-accelerator ===
LIMITS

mkdir -p /etc/systemd/system.conf.d /etc/systemd/user.conf.d
cat > /etc/systemd/system.conf.d/na-limits.conf <<'L'
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=1048576
L
cp /etc/systemd/system.conf.d/na-limits.conf /etc/systemd/user.conf.d/na-limits.conf

for pam in common-session common-session-noninteractive; do
    f="/etc/pam.d/$pam"
    [[ -f "$f" ]] && ! grep -q '^session.*pam_limits.so' "$f" && echo "session required pam_limits.so" >> "$f"
done
ok "nofile/nproc → 1048576 (shell-сессии подхватят после перелогина)"

# ─── 5. RPS/RFS/XPS — раскидываем softirq по ядрам ───────────────────────────
title "RPS/RFS/XPS (масштабирование приёма пакетов по ядрам)"
# Интерфейс детектим ЗДЕСЬ (раньше это делала секция 6 «NIC tuning»): имя нужно вшить
# в ExecStart юнита RPS — на буте default route появляется ПОЗЖЕ network-online.target,
# и автодетект в этот момент пуст (issue #30). Секция 6 берёт уже готовое значение.
NIC="$(default_iface || true)"
cat > /usr/local/sbin/na-rps-setup <<'RPS'
#!/usr/bin/env bash
# Включает Receive/Transmit Packet Steering на основном интерфейсе.
# На virtio/single-queue VPS весь RX-softirq иначе висит на cpu0 — это потолок PPS.
#
# Почему тут ожидание маршрута и два фолбэка: network-online.target на буте
# достигается РАНЬШЕ, чем в таблице появляется default route (гонка с dhcpcd, та же,
# что известна по /etc/resolv.conf). Прежняя версия в этот момент молча делала exit 0,
# и юнит с RemainAfterExit навсегда оставался active (exited) с НЕприменённым RPS —
# отказ был полностью бесшумным (issue #30). Теперь: имя NIC с момента optimize →
# ожидание маршрута → все физические интерфейсы → отказ с ненулевым кодом.
set -u
want="${1:-}"
sysdir=/sys/class/net

nics=""
# 1) Интерфейс, определённый при установке. После смены ядра он мог переименоваться
#    (eth0→ens18) — тогда имени в /sys нет, и полагаться на него нельзя.
if [ -n "$want" ] && [ -d "$sysdir/$want" ]; then
    nics="$want"
else
    [ -n "$want" ] && echo "na-rps: интерфейс '$want' не найден — автодетект" >&2
    # 2) Ждём default route до ~20 с: сеть на буте поднимается позже юнита.
    i=0
    while [ "$i" -lt 20 ]; do
        nics="$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')"
        if [ -n "$nics" ]; then break; fi
        i=$((i + 1))
        sleep 1
    done
    # 3) Маршрута нет и через 20 с (IPv6-only, бридж без default) — берём ВСЕ
    #    физические интерфейсы: RPS на лишнем NIC безвреден, отсутствующий — потолок PPS.
    if [ -z "$nics" ]; then
        for d in "$sysdir"/*/device; do
            [ -e "$d" ] || continue
            n="${d%/device}"; n="${n##*/}"
            case "$n" in lo|veth*|docker*|br-*) continue;; esac
            nics="${nics:+$nics }$n"
        done
        [ -n "$nics" ] && echo "na-rps: default route не появился за 20с — беру физические: $nics" >&2
    fi
fi

ncpu="$(nproc)"
# Битовая маска всех CPU в формате rps_cpus (группы по 32 бита, старшая первой).
mask="$(awk -v n="$ncpu" 'BEGIN{
    s=""; while(n>0){ b=(n>=32?32:n); n-=32;
        v=(b>=32?4294967295:(2^b)-1);
        s=(s==""?sprintf("%x",v):sprintf("%x,%s",v,s)); } print (s==""?"0":s) }')"
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true

applied=0
for NIC in $nics; do
    [ -d "$sysdir/$NIC" ] || continue
    for q in "$sysdir/$NIC"/queues/rx-*; do
        [ -e "$q/rps_cpus" ] && echo "$mask" > "$q/rps_cpus" 2>/dev/null || true
        [ -e "$q/rps_flow_cnt" ] && echo 4096 > "$q/rps_flow_cnt" 2>/dev/null || true
    done
    for q in "$sysdir/$NIC"/queues/tx-*; do
        [ -e "$q/xps_cpus" ] && echo "$mask" > "$q/xps_cpus" 2>/dev/null || true
    done
    # Эта строка — маркер успеха в журнале: её отсутствие в `journalctl -u na-rps`
    # означает, что RPS не применён, чем бы ни рапортовал статус юнита.
    echo "na-rps: NIC=$NIC mask=$mask cpus=$ncpu"
    applied=1
done

# Молчаливый exit 0 здесь и делал «зелёный юнит при выключенном RPS» — падаем честно,
# юнит перезапустится (Restart=on-failure) и отказ будет виден в статусе.
if [ "$applied" -ne 1 ]; then
    echo "na-rps: no usable interface (default route not found, no physical NIC) — giving up" >&2
    exit 1
fi
RPS
chmod +x /usr/local/sbin/na-rps-setup

# Restart= для Type=oneshot systemd принимает с v244 (в матрице поддержки минимум —
# Debian 11 с 247 и Ubuntu 20.04 с 245, так что версию не гейтим). StartLimit* — чтобы
# нода без сети не перезапускала юнит вечно: после 5 неудач он остаётся failed и виден.
cat > /etc/systemd/system/na-rps.service <<EOF
[Unit]
Description=node-accelerator RPS/RFS/XPS tuning
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/na-rps-setup ${NIC:-}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
# Уже активный oneshot с RemainAfterExit=yes `enable --now` повторно НЕ запускает —
# ре-ран переписывал хелпер, а rps_cpus оставался старым (после гонки с маршрутом на
# буте — нулём), при этом печатался ok. Поэтому: enable + явный restart на каждом прогоне.
systemctl enable na-rps.service >/dev/null 2>&1 || true
if systemctl restart na-rps.service >/dev/null 2>&1; then
    ok "RPS/RFS/XPS включены ($(nproc) ядер, NIC=${NIC:-автодетект на буте})"
else
    warn "na-rps.service: не удалось применить RPS — проверь journalctl -u na-rps.service"
fi

# ─── 6. NIC tuning ───────────────────────────────────────────────────────────
title "NIC tuning (ring buffer, offloads)"
if [[ -n "${NIC:-}" ]]; then
    cat > /etc/systemd/system/na-nic-tune.service <<EOF
[Unit]
Description=node-accelerator NIC tuning ($NIC)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '\
    ethtool -G $NIC rx 4096 tx 4096 2>/dev/null || true; \
    ethtool -K $NIC gro on gso on tso on 2>/dev/null || true; \
    ethtool -K $NIC lro off 2>/dev/null || true; \
    ip link set $NIC txqueuelen 10000 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now na-nic-tune.service >/dev/null 2>&1 || true
    ok "NIC=$NIC: ring 4096, GRO/GSO/TSO on, LRO off, txqueuelen 10000"
else
    warn "Основной интерфейс не определён — NIC tuning пропущен"
fi

# ─── 6b. MSS clamp к PMTU (opt-in, для routed/WireGuard-VPN) ──────────────────
# Для xray/VLESS форвард не задействован (proxy терминирует TCP), поэтому opt-in.
# Дополняет, не заменяет tcp_min_snd_mss-пол выше (тот — для собственных сокетов ноды).
title "MSS clamp (PMTU)"
ENABLE_MSS_CLAMP="${ENABLE_MSS_CLAMP:-0}"
if [[ "$ENABLE_MSS_CLAMP" == "1" ]]; then
    apt_install nftables || warn "nftables не доустановился"
    mkdir -p "$CONF_DIR"
    cat > "$CONF_DIR/na_mss.nft" <<'EOF'
#!/usr/sbin/nft -f
# MSS clamp к PMTU на форварде — против PMTU-блэкхолов на туннелях (WireGuard/routed).
# Своя таблица (НЕ flush ruleset). На прокси-нодах правило просто не матчится.
table inet na_mss {
    chain forward {
        type filter hook forward priority mangle; policy accept;
        tcp flags syn tcp option maxseg size set rt mtu
    }
}
EOF
    if nft -c -f "$CONF_DIR/na_mss.nft" 2>/dev/null; then
        cat > /etc/systemd/system/na-mss-clamp.service <<EOF
[Unit]
Description=node-accelerator MSS clamp to PMTU (forward)
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $CONF_DIR/na_mss.nft
ExecStop=/usr/sbin/nft delete table inet na_mss

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now na-mss-clamp.service >/dev/null 2>&1 || true
        ok "MSS clamp к PMTU включён (forward)"
    else
        warn "MSS-clamp ruleset не прошёл nft -c (нет nft/ядро?) — пропускаю"
        rm -f "$CONF_DIR/na_mss.nft"
    fi
else
    info "MSS clamp выкл (ENABLE_MSS_CLAMP=1 — для routed/WireGuard-нод)"
fi

# ─── 7. Swap ─────────────────────────────────────────────────────────────────
# На мелких нодах (tier 1/2) zram-swap (компрессированный swap в RAM) лучше дискового:
# меньше IO-просадок под анти-OOM. На крупных — обычный /swapfile. SETUP_NO_ZRAM=1 форсит swapfile.
title "Swap"
SETUP_NO_ZRAM="${SETUP_NO_ZRAM:-0}"

swap_size_mb() {   # "2G" / "512M" / "2048" → мегабайты (для dd-фоллбэка)
    local v="${1:-2G}" n u
    n="${v%[GgMmKk]}"; u="${v#"$n"}"
    [[ "$n" =~ ^[0-9]+$ ]] || { echo 2048; return; }
    case "$u" in
        G|g) echo $((n*1024));;
        K|k) echo $((n/1024));;
        *)   echo "$n";;      # M/m или без единицы — уже мегабайты
    esac
}

# Создание /swapfile — с полной обработкой ошибок. Под `set -e` падение swapon (btrfs/CoW:
# «swapfile has holes», запрет свапа у хостера) роняло ВЕСЬ optimize посреди прогона:
# sysctl/лимиты уже применены, а journald-cap, THP, governor, маркер и save_conf — ещё
# нет, и бокс оставался в полу-настроенном состоянии, про которое сам тулкит не знал.
# Swap не стоит того, чтобы бросать тюнинг на полпути — не вышло, предупредили, поехали.
make_swapfile() {
    local size="${REMNAWAVE_SWAP_SIZE:-2G}" mb
    mb="$(swap_size_mb "$size")"
    if [[ $'\n'"$(swapon --show=NAME --noheadings 2>/dev/null)"$'\n' == *$'\n'/swapfile$'\n'* ]]; then
        info "/swapfile уже активен — пропускаю"; return 0
    fi
    if ! fallocate -l "$size" /swapfile 2>/dev/null; then
        rm -f /swapfile
        # dd-фоллбэк уважает запрошенный размер (раньше был хардкод 2048 МБ)
        dd if=/dev/zero of=/swapfile bs=1M count="$mb" status=none 2>/dev/null || {
            warn "не смог создать /swapfile (нет места?) — swap пропущен"; rm -f /swapfile; return 1; }
    fi
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1 || { warn "mkswap не прошёл — swap пропущен"; rm -f /swapfile; return 1; }
    if ! swapon /swapfile 2>/dev/null; then
        warn "swapon не прошёл (btrfs/CoW «swapfile has holes» или запрет хостера) — swap пропущен"
        rm -f /swapfile; return 1
    fi
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    # метка «свап наш» — только по ней rollback имеет право его снимать
    mkdir -p "$STATE_DIR" && date -Is > "$STATE_DIR/swapfile.created"
    ok "Создан /swapfile $size"
}
if [[ -n "$(swapon --show 2>/dev/null)" ]]; then
    info "Swap уже есть — пропускаю"
elif [[ "$TIER" -le 2 && "$SETUP_NO_ZRAM" != "1" ]] && modprobe zram 2>/dev/null; then
    cat > /usr/local/sbin/na-zram-setup <<'ZR'
#!/usr/bin/env bash
# zram-swap ~50% RAM (lz4). Идемпотентно: если наш zram-swap уже активен — выходим.
set -e
modprobe zram 2>/dev/null || exit 0
case "$(swapon --show=NAME --noheadings 2>/dev/null)" in *"/dev/zram"*) exit 0;; esac
SIZE="$(awk '/^MemTotal:/{printf "%d", $2*1024/2}' /proc/meminfo 2>/dev/null)"
[ -n "$SIZE" ] || exit 0
DEV="$(zramctl --find --size "$SIZE" --algorithm lz4 2>/dev/null || zramctl --find --size "$SIZE" 2>/dev/null || true)"
[ -n "$DEV" ] || exit 0
mkswap "$DEV" >/dev/null 2>&1 || exit 0
swapon -p 100 "$DEV" 2>/dev/null || true
echo "na-zram: $DEV size=$SIZE"
ZR
    chmod +x /usr/local/sbin/na-zram-setup
    cat > /etc/systemd/system/na-zram.service <<'EOF'
[Unit]
Description=node-accelerator zram-swap
After=local-fs.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/na-zram-setup
ExecStop=/bin/sh -c 'for d in $(swapon --show=NAME --noheadings 2>/dev/null | grep /dev/zram); do swapoff "$d" 2>/dev/null || true; done'
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now na-zram.service >/dev/null 2>&1 || true
    if [[ "$(swapon --show 2>/dev/null)" == *zram* ]]; then
        ok "zram-swap включён ($(swapon --show=NAME,SIZE --noheadings 2>/dev/null | grep zram | tr '\n' ' '))"
    else
        warn "zram не поднялся — fallback на /swapfile"
        make_swapfile || true
    fi
else
    make_swapfile || true
fi

# ─── 8. journald cap ─────────────────────────────────────────────────────────
# Кап — ручка, а не константа: на публичной ноде поток логов фаервола (анти-скан)
# съедает 300M меньше чем за сутки, и журнал перестаёт хранить историю, по которой
# вообще разбирают инцидент — на minimal-образах он ЕДИНСТВЕННЫЙ её источник
# (issue #35). Ноде, которую активно сканируют, ставь NA_JOURNAL_MAX_USE=1G.
title "journald (ограничение логов)"
NA_JOURNAL_MAX_USE="${NA_JOURNAL_MAX_USE:-300M}"
[[ "$NA_JOURNAL_MAX_USE" =~ ^[0-9]+[KMG]?$ ]] \
    || { warn "NA_JOURNAL_MAX_USE='$NA_JOURNAL_MAX_USE' — ожидается размер вида 300M/1G; беру 300M"; NA_JOURNAL_MAX_USE=300M; }
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/na-size.conf <<J
[Journal]
SystemMaxUse=$NA_JOURNAL_MAX_USE
SystemKeepFree=500M
SystemMaxFileSize=50M
Compress=yes
J
systemctl restart systemd-journald
ok "journald ≤ $NA_JOURNAL_MAX_USE"

# ─── 8b. Ротация файловых логов ноды ─────────────────────────────────────────
# journald-cap выше держит только журнал systemd. Логи, которые пишут nginx и ядро ноды
# (xray) в /var/log, к нему отношения не имеют и растут без предела: на боевой ноде это
# сотни МБ в сутки, и диск уходит в 100% за недели. Диск на 100% тише, чем кажется:
# контейнеры перестают писать логи (нода становится ненаблюдаемой), а acme.sh не может
# обновить сертификат.
#
# Почему свой таймер, а не штатной ротации достаточно: `maxsize` проверяется ТОЛЬКО в
# момент запуска logrotate, а системный logrotate.timer суточный. При росте в сотни МБ
# в сутки файл спокойно проскакивает лимит между прогонами — наблюдалось превышение
# заявленного капа в девять раз. Часовой прогон гоняет ВЕСЬ /etc/logrotate.conf с тем же
# системным state-файлом: стансы со своим периодом (daily/weekly) от этого чаще не
# ротируются — только те, что реально переросли размер.
title "ротация логов ноды"
ENABLE_LOGROTATE="${ENABLE_LOGROTATE:-1}"
NA_LOG_PATHS="${NA_LOG_PATHS:-/var/log/nginx/*.log /var/log/remnanode/*.log}"
NA_LOG_MAXSIZE="${NA_LOG_MAXSIZE:-200M}"
NA_LOG_ROTATE="${NA_LOG_ROTATE:-4}"
NA_LOG_INTERVAL="${NA_LOG_INTERVAL:-hourly}"
LR_CONF=/etc/logrotate.d/na-node-logs

LR_CEDED_N=0
if [[ "$ENABLE_LOGROTATE" != "1" ]]; then
    info "ротация логов пропущена (ENABLE_LOGROTATE=0)"
    rm -f "$STATE_DIR/logrotate.ceded" "$STATE_DIR/logrotate.owned" 2>/dev/null || true
else
    [[ "$NA_LOG_MAXSIZE" =~ ^[0-9]+[kKMG]$ ]] || { err "NA_LOG_MAXSIZE='$NA_LOG_MAXSIZE' — ожидается размер вида 200M"; exit 1; }
    [[ "$NA_LOG_ROTATE"  =~ ^[0-9]+$ ]]       || { err "NA_LOG_ROTATE='$NA_LOG_ROTATE' — ожидается целое число"; exit 1; }
    # Пути уходят в конфиг logrotate, который исполняется root'ом: пускаем только
    # безопасный набор символов, без подстановок и разделителей команд.
    [[ "$NA_LOG_PATHS" =~ ^[A-Za-z0-9_/*.\ -]+$ ]] || { err "NA_LOG_PATHS: недопустимые символы"; exit 1; }

    # Сам бинарь может отсутствовать: на минимальных образах его нет, и тогда конфиг
    # лежит мёртвым грузом — ротации не происходит вообще, а выглядит как настроенная.
    if ! command -v logrotate >/dev/null 2>&1; then
        apt_install logrotate || warn "logrotate не доустановился — ротация работать не будет"
    fi

    # Маски, уже покрытые ЧУЖОЙ стансой, забирать себе нельзя: logrotate на дубликат пути
    # отвечает «duplicate log entry», целиком пропускает ту стансу, которой файл достался
    # вторым, и выходит с ошибкой — na-logrotate.service уходит в failed при внешне
    # здоровом таймере. Сверять маски СТРОКАМИ бесполезно: logrotate дедуплицирует по
    # РАСКРЫТЫМ файлам, и чужая станса с явными путями или другим глобом проходит мимо
    # текстового сравнения. Единственный честный арбитр — сам logrotate (`-d` по ВСЕМУ
    # набору): пишем стансу целиком, спрашиваем его и конфликтные маски отдаём чужим
    # стансам — у них может быть сигнальный reload вместо copytruncate, им и владеть.
    # read -a, а не голый word-split: иначе шелл сам раскроет глобы по живым файлам,
    # и в стансу лягут ЯВНЫЕ пути — лог нового vhost'а никогда не начнёт ротироваться.
    _want=(); _dup=(); _dup_paths=""
    read -r -a _want <<<"$NA_LOG_PATHS"

    _na_lr_write() {
        if [[ "${#_want[@]}" -eq 0 ]]; then
            rm -f "$LR_CONF"
            return 0
        fi
        {
            printf '%s ' "${_want[@]}"
            cat <<LRC
{
    su root root
    daily
    rotate $NA_LOG_ROTATE
    maxsize $NA_LOG_MAXSIZE
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
LRC
        } > "$LR_CONF"
        chmod 0644 "$LR_CONF"
    }

    # copytruncate, а не reopen-сигнал: nginx и ядро ноды живут в контейнерах, послать им
    # USR1 из хостовой ротации некому.
    backup_file "$LR_CONF" "$BACKUP"
    _na_lr_write

    if command -v logrotate >/dev/null 2>&1; then
        while [[ "${#_want[@]}" -gt 0 ]]; do
            _dupf="$({ logrotate -d /etc/logrotate.conf 2>&1 || true; } \
                     | sed -n 's/.*duplicate log entry for //p' | sort -u)"
            [[ -n "$_dupf" ]] || break
            _keep=()
            for _m in "${_want[@]}"; do
                _hit=0
                while IFS= read -r _f; do
                    [[ -n "$_f" ]] || continue
                    # shellcheck disable=SC2053  # маска без кавычек — намеренный glob-матч
                    if [[ "$_f" == $_m ]]; then _hit=1; _dup_paths+="${_dup_paths:+$'\n'}$_f"; fi
                done <<<"$_dupf"
                if [[ "$_hit" -eq 1 ]]; then _dup+=("$_m"); else _keep+=("$_m"); fi
            done
            if [[ "${#_keep[@]}" -eq "${#_want[@]}" ]]; then
                # наших масок дубликаты не задевают — это конфликт между чужими
                # стансами, чинить его не нам
                warn "дубликаты путей вне наших масок — часть чужих станс пропускается: logrotate -d /etc/logrotate.conf"
                break
            fi
            _want=("${_keep[@]}")
            _na_lr_write
        done
    fi

    # Уступка — не конец истории (issue #40). Раньше модуль печатал «проверь, что там
    # задан maxsize» и рапортовал зелёным, а na-diagnose видел только активный таймер:
    # на трёх нодах флота ротацию держала ручная станса `weekly` без maxsize — то есть
    # никакого капа не было, а всё выглядело настроенным. Теперь: ищем стансу-владельца,
    # САМИ смотрим в ней maxsize/size, и пишем факт уступки в состояние —
    # его показывает na-diagnose (текст и --json), а не только лог этого прогона.
    #
    # _na_lr_owner <путь> — файл в /etc/logrotate.d (кроме нашего), чья маска покрывает
    # путь. Шапка стансы — строки, начинающиеся с «/», до «{»; кавычки снимаем.
    _na_lr_owner() {
        local f pat
        for f in /etc/logrotate.d/*; do
            [[ -f "$f" && "$f" != "$LR_CONF" ]] || continue
            while IFS= read -r pat; do
                [[ -n "$pat" ]] || continue
                # shellcheck disable=SC2053  # маска без кавычек — намеренный glob-матч
                if [[ "$1" == $pat ]]; then echo "$f"; return 0; fi
            done < <(sed -nE 's/^[[:space:]]*(\/[^{]*).*/\1/p' "$f" 2>/dev/null | tr -d '"' | tr ' \t' '\n\n')
        done
        return 1
    }
    # _na_lr_cap <файл-стансы> — есть ли в стансе ограничение по размеру: maxsize (по
    # размеру ИЛИ периоду) либо size (только по размеру). minsize капом НЕ является —
    # он лишь запрещает ротировать мелкие файлы.
    _na_lr_cap() { grep -qE '^[[:space:]]*(maxsize|size)[[:space:]]+[0-9]' "$1" 2>/dev/null; }

    mkdir -p "$STATE_DIR"
    : > "$STATE_DIR/logrotate.ceded.tmp"
    for _m in "${_dup[@]}"; do
        # владельца ищем по РЕАЛЬНЫМ путям, которые logrotate назвал дубликатами и
        # которые покрыты этой маской: у чужой стансы маска может быть другой
        _owner=""
        while IFS= read -r _f; do
            [[ -n "$_f" ]] || continue
            # shellcheck disable=SC2053
            [[ "$_f" == $_m ]] || continue
            _owner="$(_na_lr_owner "$_f" || true)"; [[ -n "$_owner" ]] && break
        done <<<"${_dup_paths:-}"
        if [[ -z "$_owner" ]]; then
            warn "маска $_m отдана чужой стансе, но владелец в /etc/logrotate.d не найден (станса в /etc/logrotate.conf?) — проверь, что там задан maxsize"
            printf '%s\t%s\t%s\n' "$_m" "?" "unknown" >> "$STATE_DIR/logrotate.ceded.tmp"
        elif _na_lr_cap "$_owner"; then
            info "маска $_m уже покрыта чужой стансой $_owner — отдана ей (там есть maxsize/size — кап на размер работает)"
            printf '%s\t%s\t%s\n' "$_m" "$_owner" "capped" >> "$STATE_DIR/logrotate.ceded.tmp"
        else
            # `|| true` обязателен: под set -e -o pipefail пустой grep ронял бы весь прогон
            _period="$(grep -owE '(hourly|daily|weekly|monthly|yearly)' "$_owner" 2>/dev/null | head -1 || true)"
            warn "маска $_m отдана чужой стансе $_owner: там ${_period:-период не задан} БЕЗ maxsize/size — размер логов ничем не ограничен; добавь в неё 'maxsize $NA_LOG_MAXSIZE' или сузь NA_LOG_PATHS"
            printf '%s\t%s\t%s\n' "$_m" "$_owner" "none" >> "$STATE_DIR/logrotate.ceded.tmp"
        fi
    done
    unset _owner _period
    if [[ -s "$STATE_DIR/logrotate.ceded.tmp" ]]; then
        mv -f "$STATE_DIR/logrotate.ceded.tmp" "$STATE_DIR/logrotate.ceded"
    else
        rm -f "$STATE_DIR/logrotate.ceded.tmp" "$STATE_DIR/logrotate.ceded"
    fi
    LR_CEDED_N="${#_dup[@]}"
    if [[ "${#_want[@]}" -gt 0 ]]; then
        printf '%s\n' "${_want[@]}" > "$STATE_DIR/logrotate.owned"
        ok "стансa $LR_CONF: ${_want[*]} (maxsize $NA_LOG_MAXSIZE, rotate $NA_LOG_ROTATE)"
    else
        rm -f "$STATE_DIR/logrotate.owned"
        warn "все заданные пути уже покрыты чужими стансами — свою НЕ создаю: ротацию логов ноды держат они (см. выше, есть ли там maxsize); таймер ниже гоняет весь /etc/logrotate.conf, т.е. и их"
    fi

    cat > /etc/systemd/system/na-logrotate.service <<'EOF'
[Unit]
Description=node-accelerator hourly log rotation
Documentation=https://github.com/jestivald/node-accelerator
[Service]
Type=oneshot
Nice=10
IOSchedulingClass=idle
ExecStart=/usr/sbin/logrotate /etc/logrotate.conf
EOF
    cat > /etc/systemd/system/na-logrotate.timer <<EOF
[Unit]
Description=node-accelerator log rotation timer
[Timer]
OnCalendar=$NA_LOG_INTERVAL
# Ноды флота не должны просыпаться в одну и ту же секунду.
RandomizedDelaySec=300
Persistent=true
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now na-logrotate.timer >/dev/null 2>&1 \
        && ok "na-logrotate.timer: прогон $NA_LOG_INTERVAL" \
        || warn "na-logrotate.timer не включился"
fi

# ─── 9. THP off ──────────────────────────────────────────────────────────────
title "Transparent Huge Pages → never"
cat > /etc/systemd/system/na-thp-off.service <<'EOF'
[Unit]
Description=node-accelerator disable THP
After=multi-user.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true; echo never > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now na-thp-off.service >/dev/null 2>&1 || true
ok "THP отключён"

# ─── 10. CPU governor ────────────────────────────────────────────────────────
title "CPU governor → performance"
if [[ -d /sys/devices/system/cpu/cpu0/cpufreq ]]; then
    cat > /etc/systemd/system/na-cpu-perf.service <<'EOF'
[Unit]
Description=node-accelerator CPU governor performance
After=multi-user.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'for c in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$c" 2>/dev/null || true; done'

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now na-cpu-perf.service >/dev/null 2>&1 || true
    ok "governor → performance"
else
    info "cpufreq недоступен (обычная VPS) — пропуск"
fi

# ─── 11. irqbalance ──────────────────────────────────────────────────────────
title "irqbalance"
systemctl enable --now irqbalance >/dev/null 2>&1 || true
ok "irqbalance запущен"

# ─── 12. Маркер ──────────────────────────────────────────────────────────────
mkdir -p "$STATE_DIR"
cat > "$STATE_DIR/optimize.installed" <<EOF
installed_at=$(date -Is)
na_version=$NA_VERSION
backup=$BACKUP
nic=${NIC:-none}
xanmod=$([[ -f "$STATE_DIR/xanmod.pkg" ]] && cat "$STATE_DIR/xanmod.pkg" || echo none)
reboot_needed=$REBOOT_NEEDED
boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
psi=$PSI_MARK
EOF

# Персист конфига оптимизатора → ре-ран без ENV не сбрасывает выбор сборки/флейвора.
save_conf "$CONF_DIR/optimize.conf" \
    ENABLE_XANMOD XANMOD_FLAVOR REMNAWAVE_SWAP_SIZE \
    DISABLE_TFO TCP_ECN_MODE ENABLE_MSS_CLAMP SETUP_NO_ZRAM CT_EST_TIMEOUT QDISC \
    ENABLE_LOGROTATE NA_LOG_PATHS NA_LOG_MAXSIZE NA_LOG_ROTATE NA_LOG_INTERVAL \
    ENABLE_PSI NA_JOURNAL_MAX_USE

title "ГОТОВО"
ok "Оптимизатор применён."
echo
printf "    %-32s %s\n" "congestion_control:" "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo n/a)"
printf "    %-32s %s\n" "default_qdisc:"      "$(sysctl -n net.core.default_qdisc 2>/dev/null || echo n/a)"
printf "    %-32s %s\n" "somaxconn:"          "$(sysctl -n net.core.somaxconn 2>/dev/null || echo n/a)"
printf "    %-32s %s\n" "nf_conntrack_max:"   "$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo n/a)"
printf "    %-32s %s\n" "file-max:"           "$(sysctl -n fs.file-max 2>/dev/null || echo n/a)"
echo
if [[ "$REBOOT_NEEDED" == "1" ]]; then
    warn "НУЖНА ПЕРЕЗАГРУЗКА (reboot): ${REBOOT_WHY:-изменения в параметрах загрузки}"
    if [[ "$REBOOT_WHY" == *XanMod* ]]; then
        warn "После reboot проверь: uname -r  (должно содержать 'xanmod') — тогда работает BBRv3."
    fi
    if [[ "$REBOOT_WHY" == *psi=1* ]]; then
        warn "После reboot проверь: ls /proc/pressure  (сенсор давления в na-diagnose оживёт)."
    fi
fi
warn "Часть лимитов применится после перелогина/reboot (DefaultLimit* для systemd-сервисов)."
if [[ "${LR_CEDED_N:-0}" -gt 0 ]]; then
    warn "РОТАЦИЯ ЛОГОВ: $LR_CEDED_N маск(и) отданы чужим стансам logrotate — тулкит их НЕ ротирует; кто и с каким капом: cat $STATE_DIR/logrotate.ceded (см. предупреждения секции «ротация логов ноды»)"
fi
