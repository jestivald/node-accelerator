#!/usr/bin/env bash
#
# node-accelerator — ⚡ оптимизатор + 🩺 диагностика + 🛡 защита Remnawave/VPN-ноды.
#
#   sudo bash install.sh              — меню
#   sudo bash install.sh optimize     — ⚡ XanMod+BBRv3 + тюнинг
#   sudo bash install.sh protect      — 🛡 nftables + CrowdSec
#   sudo bash install.sh diagnose     — 🩺 диагностика (read-only)
#   sudo bash install.sh all          — optimize → protect → diagnose
#   sudo bash install.sh rollback [optimize|protect|all]
#   sudo bash install.sh persist      — (пере)создать CLI na-diagnose/na-report
#
# curl-bash:
#   curl -fsSL https://raw.githubusercontent.com/jestivald/node-accelerator/main/install.sh | sudo bash -s all
#   # прод: пиньте тег (компрометация ветки main тогда не утечёт сразу на весь флот):
#   export NA_REF=v3.7; curl -fsSL "https://raw.githubusercontent.com/jestivald/node-accelerator/$NA_REF/install.sh" | sudo -E bash -s all
#   # + подписи модулей: NA_REQUIRE_SIG=1 NA_MINISIGN_PUBKEY=<ключ из README>
#
# После optimize/protect/all на ноде остаётся read-only команда `na-diagnose --json`
# (стабильный JSON для мониторинга/панели — без повторного curl|bash). Снимается rollback'ом.

set -euo pipefail
# ${BASH_SOURCE[0]:-$0}: при запуске через curl|bash (bash -s) BASH_SOURCE пуст, и под
# set -u голый ${BASH_SOURCE[0]} даёт «unbound variable». Фоллбэк на $0 убирает шум.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SCRIPTS="$SCRIPT_DIR/scripts"
# NA_REF — ветка/тег для curl|bash-режима (по умолчанию main). Для прода пиньте тег.
NA_REF="${NA_REF:-main}"
# NA_REF уходит в URL модулей — запрещаем path-traversal/инъекцию (увод на чужой репо).
[[ "$NA_REF" =~ ^[A-Za-z0-9._/-]+$ && "$NA_REF" != *..* ]] || { echo "[x] NA_REF '$NA_REF' невалиден"; exit 1; }
REPO_URL="${NA_REPO_URL:-https://raw.githubusercontent.com/jestivald/node-accelerator/$NA_REF}"

# Опц. проверка подписи модулей в curl|bash-режиме (supply-chain hardening). По умолч.
# выкл. NA_REQUIRE_SIG=1 + minisign-ключ (NA_MINISIGN_PUBKEY) ИЛИ GPG-отпечаток
# (NA_SIG_FINGERPRINT) → каждый модуль проверяется против .minisig/.asc рядом в репо.
NA_REQUIRE_SIG="${NA_REQUIRE_SIG:-0}"
NA_MINISIGN_PUBKEY="${NA_MINISIGN_PUBKEY:-}"
NA_SIG_FINGERPRINT="${NA_SIG_FINGERPRINT:-}"
verify_sig() {  # verify_sig <файл> <url-без-расширения>
    local file="$1" url="$2"
    if [[ -n "$NA_MINISIGN_PUBKEY" ]] && command -v minisign >/dev/null 2>&1; then
        curl -fsSL "$url.minisig" -o "$file.minisig" 2>/dev/null || { echo "[x] нет .minisig для $(basename "$file")"; return 1; }
        minisign -V -P "$NA_MINISIGN_PUBKEY" -m "$file" >/dev/null 2>&1
    elif [[ -n "$NA_SIG_FINGERPRINT" ]] && command -v gpg >/dev/null 2>&1; then
        curl -fsSL "$url.asc" -o "$file.asc" 2>/dev/null || { echo "[x] нет .asc для $(basename "$file")"; return 1; }
        # Судим по МАШИННОМУ статусу (--status-fd), а НЕ по человекочитаемому выводу:
        # `gpg --verify | grep <fpr>` матчил бы 'using RSA key <fpr>' — эта строка
        # печатается из пакета подписи ДАЖЕ для BAD-подписи, а exit-код терялся в пайпе
        # (валидная .asc настоящего ключа рядом с подменённым файлом проходила бы как ок).
        # VALIDSIG эмитится ТОЛЬКО для криптографически валидной подписи и несёт полный fpr.
        gpg --status-fd=1 --verify "$file.asc" "$file" 2>/dev/null \
          | grep -Eq "^\[GNUPG:\] VALIDSIG ${NA_SIG_FINGERPRINT// /}( |\$)"
    else
        echo "[x] NA_REQUIRE_SIG=1, но нет minisign+NA_MINISIGN_PUBKEY или gpg+NA_SIG_FINGERPRINT"; return 1
    fi
}

# curl|bash — подтянуть модули
if [[ ! -d "$SCRIPTS" ]]; then
    SCRIPTS="$(mktemp -d)/scripts"; mkdir -p "$SCRIPTS/lib"
    echo "[*] Скачиваю модули из $REPO_URL ..."
    for f in lib/common.sh optimize.sh protect.sh diagnose.sh na-report.sh rollback.sh; do
        curl -fsSL "$REPO_URL/scripts/$f" -o "$SCRIPTS/$f" || { echo "[x] Не скачал $f"; exit 1; }
        if [[ "$NA_REQUIRE_SIG" == "1" ]]; then
            verify_sig "$SCRIPTS/$f" "$REPO_URL/scripts/$f" \
                && echo "[+] подпись $f валидна" \
                || { echo "[x] подпись $f НЕ прошла — отказ (NA_REQUIRE_SIG=1)"; exit 1; }
        fi
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

run_optimize() { bash "$SCRIPTS/optimize.sh"; persist_toolkit; }
run_protect()  { bash "$SCRIPTS/protect.sh"; persist_toolkit; }
run_diagnose() { bash "$SCRIPTS/diagnose.sh" "$@"; }
run_rollback() { bash "$SCRIPTS/rollback.sh" "${1:-all}"; }

show_menu() {
    clear 2>/dev/null || true
    cat <<BANNER
┌────────────────────────────────────────────────────┐
│            ⚡ node-accelerator v${NA_VERSION:-?} ⚡                │
│   Оптимизация · Диагностика · Защита VPN-ноды       │
├────────────────────────────────────────────────────┤
│                                                      │
│   1) ⚡ Оптимизатор                                  │
│        XanMod (BBRv3) + sysctl + RPS/RFS +           │
│        лимиты + swap + NIC + governor                │
│                                                      │
│   2) 🛡 Защита                                       │
│        nftables (AntiScan/flag-drop/anti-spoof/      │
│        SYN+UDP-flood/ssh-flood) + CrowdSec bouncer   │
│                                                      │
│   3) 🩺 Диагностика (read-only)                      │
│                                                      │
│   4) 🚀 Всё сразу (1 → 2 → 3)                        │
│                                                      │
│   5) ↩️  Откат                                       │
│                                                      │
│   0) Выход                                           │
│                                                      │
└────────────────────────────────────────────────────┘
BANNER
    read -r -p "Выбор: " choice
    case "$choice" in
        1) run_optimize ;;
        2) run_protect ;;
        3) run_diagnose ;;
        4) run_optimize; run_protect; run_diagnose ;;
        5)
            echo "  a) optimize   b) protect   c) всё"
            read -r -p "Что откатить? [c]: " r
            case "$r" in a|A) run_rollback optimize ;; b|B) run_rollback protect ;; *) run_rollback all ;; esac
            ;;
        0) exit 0 ;;
        *) warn "Неверный выбор" ;;
    esac
}

case "${1:-}" in
    optimize) run_optimize ;;
    protect)  run_protect ;;
    diagnose|diag) shift; run_diagnose "$@" ;;
    all)      run_optimize; run_protect; run_diagnose ;;
    rollback) run_rollback "${2:-all}" ;;
    persist)  persist_toolkit ;;
    "")       show_menu ;;
    -h|--help) sed -n '2,20p' "$0" ;;
    *) err "Неизвестная команда: $1"; sed -n '2,20p' "$0"; exit 1 ;;
esac
