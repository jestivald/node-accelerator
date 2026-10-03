#!/usr/bin/env bash
#
# lint-pipefail.sh — запрещает `cmd | grep -q` в скриптах, живущих под `set -o pipefail`.
#
# grep -q выходит на ПЕРВОМ совпадении и закрывает пайп. Если команда слева пишет ещё —
# она ловит SIGPIPE, пайплайн под pipefail отдаёт 141, и условие становится ложным ровно
# тогда, когда совпадение ЕСТЬ. Так в v4.1.2 через раз пропадал сенсор лога анти-скана
# (справка journalctl 5 КБ уходит двумя записями), никогда не срабатывало предупреждение
# «сокеты на cubic» (ss -tin — мегабайты) и не виден был дубликат в `logrotate -d`.
#
# Разрешено: источник — одиночный `printf '%s[\n]' "$var"` (одна маленькая запись, писать
# после выхода grep нечего) и строки с пометкой `# pipefail-ok` (осознанное исключение).
# Правильные замены: вывод в переменную + `[[ $v == *pat* ]]` / `grep -q … <<<"$v"`,
# `grep -c` (дочитывает вход), `awk '…{f=1} END{exit !f}'`.
#
# Не требует root/сети. Запуск: bash tests/lint-pipefail.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

bad=0
for f in install.sh scripts/*.sh scripts/lib/*.sh; do
    # common.sh своего set не имеет, но исполняется внутри скриптов с pipefail
    if [[ "$f" != scripts/lib/common.sh ]] && ! grep -qE '^set -[a-z]*o pipefail' "$f"; then
        continue
    fi
    while IFS= read -r hit; do
        line="${hit#*:}"   # grep -n по одному файлу: «N:строка»
        code="${line%%#*}"   # хвостовой комментарий не в счёт
        [[ "$line" == *'# pipefail-ok'* ]] && continue
        [[ "$code" =~ \|[[:space:]]*grep[[:space:]]+-[A-Za-z]*q ]] || continue
        if [[ "$code" =~ printf\ \'%s(\\n)?\'\ \"\$[A-Za-z_][A-Za-z_0-9]*\"[[:space:]]*\|[[:space:]]*grep ]]; then
            continue
        fi
        echo "  [x] $f:${hit%%:*}: $(sed -E 's/^[[:space:]]+//' <<<"$line")"
        bad=$((bad+1))
    done < <(grep -nE '\|[[:space:]]*grep[[:space:]]+-[A-Za-z]*q' "$f" || true)
done

if [[ "$bad" -gt 0 ]]; then
    echo "LINT-PIPEFAIL: FAIL — $bad пайп(ов) в grep -q под pipefail (SIGPIPE → ложное «нет»)"
    exit 1
fi
echo "LINT-PIPEFAIL: OK (под pipefail нет пайпов в grep -q)"
