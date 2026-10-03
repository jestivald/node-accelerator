#!/usr/bin/env bash
#
# install-unit.sh — install.sh в режиме curl|bash НЕ берёт scripts/ из текущей папки.
#
# До v4.1.3 SCRIPT_DIR вычислялся из `${BASH_SOURCE[0]:-$0}`: при `curl … | bash -s`
# BASH_SOURCE пуст, $0 = "bash", dirname → «.», то есть ТЕКУЩАЯ папка. Лежал в ней каталог
# scripts/ (старый клон тулкита, подложенный /tmp/scripts) — root исполнял его, минуя и
# скачивание по NA_REF, и проверку подписей NA_REQUIRE_SIG=1.
#
# Сеть не нужна: curl подменён стабом, который «скачивает» модули из рабочего дерева и
# пишет журнал запросов. Root не нужен: после скачивания install.sh упирается в
# require_root — к этому моменту выбор источника модулей уже сделан.
# Запуск: bash tests/install-unit.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/decoy/scripts/lib"

pick_bash() {
    local c
    for c in bash /opt/homebrew/bin/bash /usr/local/bin/bash; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" -c 'set -u; a=(); : "${a[@]}"; [[ -v HOME ]]' 2>/dev/null; then command -v "$c"; return 0; fi
    done
    return 1
}
WBASH="$(pick_bash)" || { echo "[x] не нашёл bash ≥ 4.2"; exit 1; }

# Приманка: «модули» в текущей папке, которые громко сообщают, что их исполнили.
for m in lib/common.sh optimize.sh protect.sh diagnose.sh na-report.sh rollback.sh; do
    printf '#!/usr/bin/env bash\necho DECOY-EXECUTED\nrequire_root(){ :; }\ndetect_os(){ :; }\n' > "$T/decoy/scripts/$m"
done

# curl-стаб: `curl … <url> -o <файл>` → копия scripts/<путь> из рабочего дерева.
export NA_TEST_CURL_LOG="$T/curl.log" NA_TEST_REPO="$REPO_ROOT"
cat > "$T/bin/curl" <<'CURL'
#!/usr/bin/env bash
out=""; url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2; continue ;;
        http*://*) url="$1" ;;
    esac
    shift
done
printf '%s\n' "$url" >> "$NA_TEST_CURL_LOG"
rel="${url#*/scripts/}"
[ -f "$NA_TEST_REPO/scripts/$rel" ] || exit 22
cp "$NA_TEST_REPO/scripts/$rel" "$out"
CURL
chmod +x "$T/bin/curl"

PASS=0; FAIL=0
ok_()   { PASS=$((PASS+1)); echo "  ok   $1"; }
fail_() { FAIL=$((FAIL+1)); echo "  FAIL $1"; }

echo "== 1. curl|bash из папки с чужим scripts/ =="
: > "$NA_TEST_CURL_LOG"
# Зовём именно как `bash` (относительное имя, $0 = "bash") — ровно так выглядит
# `curl … | sudo bash -s`; по абсолютному пути dirname($0) уводил бы мимо текущей папки.
BDIR="$(dirname "$WBASH")"
( cd "$T/decoy" && PATH="$T/bin:$BDIR:$PATH" bash -s diagnose < "$REPO_ROOT/install.sh" ) > "$T/out1.log" 2>&1 || true
if grep -q DECOY-EXECUTED "$T/out1.log"; then fail_ "исполнены модули из ТЕКУЩЕЙ папки (scripts/ приманки)"
else ok_ "модули из текущей папки не исполнялись"; fi
if grep -q '/scripts/lib/common.sh$' "$NA_TEST_CURL_LOG"; then ok_ "модули скачаны по NA_REF (curl вызван)"
else fail_ "модули не скачивались (curl не вызывался)"; fi

echo "== 2. запуск из файла берёт модули рядом с install.sh =="
: > "$NA_TEST_CURL_LOG"
( cd "$T/decoy" && PATH="$T/bin:$PATH" "$WBASH" "$REPO_ROOT/install.sh" diagnose ) > "$T/out2.log" 2>&1 || true
if [ -s "$NA_TEST_CURL_LOG" ]; then fail_ "при запуске из файла install.sh полез в сеть"
else ok_ "из файла: модули рядом, без скачивания"; fi
grep -q DECOY-EXECUTED "$T/out2.log" && fail_ "из файла: исполнена приманка из текущей папки" || ok_ "из файла: приманка не тронута"

echo "== 3. --help в curl|bash-режиме не читает файл по имени «bash» =="
printf '#!/bin/sh\necho DECOY-HELP\n' > "$T/decoy/bash"
( cd "$T/decoy" && PATH="$BDIR:$PATH" bash -s -- --help < "$REPO_ROOT/install.sh" ) > "$T/out3.log" 2>&1 || true
if grep -q DECOY-HELP "$T/out3.log"; then fail_ "справка напечатана из файла ./bash"
elif grep -q 'install.sh rollback' "$T/out3.log"; then ok_ "встроенная справка"
else fail_ "справки нет: $(head -c 200 "$T/out3.log")"; fi

echo
echo "  прогон: $PASS ok, $FAIL fail"
[[ "$FAIL" -eq 0 ]] || { echo "INSTALL-UNIT: FAIL"; exit 1; }
echo "INSTALL-UNIT: OK (curl|bash всегда качает модули; из файла — берёт свои)"
