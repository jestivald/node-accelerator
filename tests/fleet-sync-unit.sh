#!/usr/bin/env bash
#
# fleet-sync-unit.sh — ИСПОЛНЯЕТ сгенерированный protect.sh хелпер `na-fleet-sync`
# против стабов curl/nft/logger. До этого теста хелперы проверялись только grep'ом по
# тексту: фикс утечки X-Api-Key на редиректе (v3.9.1) не имел ни одного поведенческого
# теста, хотя это ровно тот код, что ходит в сеть с секретом каждые 5 минут.
#
# Что стережём:
#   1. секреты НЕ уходят в argv curl (виден всей системе в /proc/<pid>/cmdline);
#   2. секреты РЕАЛЬНО отправляются — через файл заголовков (-H @file);
#   3. в journald пишется URL без userinfo (README предлагает basic-auth для NODES_URL);
#   4. при заданном Caddy-токене редиректы не следуются (--max-redirs 0, без -L);
#   5. разобранные адреса доезжают до nft-транзакции.
#
# Не требует root/сети/systemd. Запуск: bash tests/fleet-sync-unit.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/conf" "$T/state" "$T/rec"

PASSWORD='sup3rs3cret'
CADDY_TOKEN='caddy-token-xyz'
BEARER_TOKEN='panel-bearer-abc'

# ── Достаём сам хелпер из heredoc protect.sh (без запуска всего модуля) ──────────
awk "/cat > \/usr\/local\/sbin\/na-fleet-sync <<'FSYNC'/{f=1;next} f&&/^FSYNC\$/{exit} f" \
    "$REPO_ROOT/scripts/protect.sh" > "$T/na-fleet-sync.raw"
[ -s "$T/na-fleet-sync.raw" ] || { echo "[x] не смог извлечь na-fleet-sync из protect.sh"; exit 1; }
# системные пути → в песочницу
sed -e "s#/etc/node-accelerator#$T/conf#g" -e "s#/var/lib/node-accelerator#$T/state#g" \
    "$T/na-fleet-sync.raw" > "$T/na-fleet-sync"
chmod +x "$T/na-fleet-sync"

# ── Стабы ───────────────────────────────────────────────────────────────────────
export REC="$T/rec"
printf '203.0.113.10\n# комментарий\n203.0.113.11\r\n2001:db8::42\n' > "$REC/fixture.txt"

# curl: записывает argv и содержимое файла заголовков, отдаёт фикстуру и код 200
cat > "$T/bin/curl" <<'CURL'
#!/bin/sh
printf '%s\n' "$*" >> "$REC/curl.argv"
OUT=""; HDR=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) OUT="$2"; shift;;
        -H) case "$2" in @*) HDR="${2#@}";; *) printf '%s\n' "$2" >> "$REC/curl.inline-headers";; esac; shift;;
    esac
    shift
done
[ -n "$HDR" ] && [ -f "$HDR" ] && cat "$HDR" >> "$REC/curl.headers"
[ -n "$OUT" ] && cp "$REC/fixture.txt" "$OUT"
printf '200'
exit 0
CURL
# nft: сет «существует», транзакцию складываем в файл
cat > "$T/bin/nft" <<'NFT'
#!/bin/sh
case "$1" in
    list) exit 0;;
    -f)   cat "$2" >> "$REC/nft.applied"; exit 0;;
esac
exit 0
NFT
cat > "$T/bin/logger" <<'LOG'
#!/bin/sh
# logger [-t TAG] MESSAGE
while [ $# -gt 0 ]; do case "$1" in -t) shift;; *) printf '%s\n' "$1" >> "$REC/logger.out";; esac; shift; done
exit 0
LOG
chmod +x "$T/bin/curl" "$T/bin/nft" "$T/bin/logger"
export PATH="$T/bin:$PATH"

fail=0
check()   { if [ "$1" = 0 ]; then echo "  ✔ $2"; else echo "  ✘ $2"; fail=1; fi; }
nocontain() { if grep -qF "$2" "$1" 2>/dev/null; then return 1; else return 0; fi; }

# ── Кейс 1: NODES_URL с basic-auth + Caddy-токен ────────────────────────────────
echo "== NODES_URL (basic-auth в URL) + CADDY_AUTH_API_TOKEN =="
rm -f "$REC"/curl.* "$REC"/logger.out "$REC"/nft.applied
cat > "$T/conf/fleet.env" <<ENVF
REMNAWAVE_NODES_URL=https://fleetuser:$PASSWORD@panel.example.com/fleet/nodes.json
CADDY_AUTH_API_TOKEN=$CADDY_TOKEN
ENVF
bash "$T/na-fleet-sync"

nocontain "$REC/curl.argv" "$CADDY_TOKEN"; check $? "Caddy-токен НЕ попал в argv curl"
grep -qF "X-Api-Key: $CADDY_TOKEN" "$REC/curl.headers"; check $? "Caddy-токен отправлен через файл заголовков"
grep -qF -- '--max-redirs 0' "$REC/curl.argv"; check $? "при токене редиректы не следуются (--max-redirs 0)"
nocontain "$REC/curl.argv" "-L "; check $? "при токене нет -L"
grep -qF -- "--proto-redir =https" "$REC/curl.argv"; check $? "редирект на cleartext http запрещён"
nocontain "$REC/logger.out" "$PASSWORD"; check $? "пароль из URL НЕ попал в лог"
grep -qF '***@panel.example.com' "$REC/logger.out"; check $? "в логе URL с зачищенным userinfo"
grep -qF '203.0.113.10' "$REC/nft.applied"; check $? "адреса доехали до nft-транзакции"
grep -qF '203.0.113.11' "$REC/nft.applied"; check $? "CRLF-строка распарсилась"
grep -qF '2001:db8::42' "$REC/nft.applied"; check $? "IPv6-адрес попал в na_fleet_v6"
nocontain "$REC/nft.applied" '# комментарий'; check $? "комментарии отфильтрованы"
[ -f "$T/state/fleet-sync.last" ]; check $? "штамп успешного синка проставлен"

# ── Кейс 2: /api/nodes по Bearer ────────────────────────────────────────────────
echo "== REMNAWAVE_URL + REMNAWAVE_TOKEN (Bearer) =="
rm -f "$REC"/curl.* "$REC"/logger.out "$REC"/nft.applied
cat > "$T/conf/fleet.env" <<ENVF
REMNAWAVE_URL=https://panel.example.com
REMNAWAVE_TOKEN=$BEARER_TOKEN
ENVF
bash "$T/na-fleet-sync"

nocontain "$REC/curl.argv" "$BEARER_TOKEN"; check $? "Bearer-токен НЕ попал в argv curl"
grep -qF "Authorization: Bearer $BEARER_TOKEN" "$REC/curl.headers"; check $? "Bearer-токен отправлен через файл заголовков"
nocontain "$REC/curl.argv" "-L "; check $? "ветка /api/nodes не следует редиректам"

# ── Кейс 3: источник отвечает не-200 → last-known-good, nft не трогаем ──────────
echo "== источник недоступен → last-known-good =="
rm -f "$REC"/curl.* "$REC"/logger.out "$REC"/nft.applied
printf '#!/bin/sh\nprintf "503"\nexit 0\n' > "$T/bin/curl"; chmod +x "$T/bin/curl"
bash "$T/na-fleet-sync"
[ ! -f "$REC/nft.applied" ]; check $? "при HTTP 503 nft-транзакция не выполняется"
grep -qF 'last-known-good' "$REC/logger.out"; check $? "в лог ушёл fail-safe last-known-good"

if [ "$fail" -ne 0 ]; then echo "FLEET-SYNC-UNIT: FAIL"; exit 1; fi
echo "FLEET-SYNC-UNIT: OK (секреты не в argv, уходят через -H @file, URL в логе без userinfo, редиректы заблокированы, парсинг адресов и fail-safe работают)"
