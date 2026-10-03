#!/usr/bin/env bash
#
# common-unit.sh — юнит-тесты хелперов lib/common.sh, добавленных по аудиту флота v4.1:
#   1. nft_set_count / nft_set_elems считают АДРЕСА, а не строки вывода nft — пустой
#      динамический набор = 0, непустой = число элементов, многострочный вывод и v6
#      разбираются (issue #32/#36);
#   2. json_escape: перевод строки / кавычка / бэкслеш внутри значения не ломают
#      JSON-документ (issue #27);
#   3. tty_tput ничего не пишет, когда stdout — не терминал (issue #28);
#   4. персист конфига (issue #34): замороженный старый дефолт без маркера explicit
#      → warn; NA_ADOPT_NEW_DEFAULTS=1 → принят; ENV-значение → маркер `# explicit:`
#      и тишина на следующем прогоне; ver_ge.
#
# Не требует root/сети/nft. Запуск: bash tests/common-unit.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/etc"

# хелперам нужен bash ≥ 4.2 ([[ -v ]]) — на нодах и CI есть всегда, на macOS системный
# древний: берём первый подходящий.
pick_bash() {
    local c
    for c in bash /opt/homebrew/bin/bash /usr/local/bin/bash; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" -c 'set -u; a=(); : "${a[@]}"; [[ -v HOME ]]' 2>/dev/null; then command -v "$c"; return 0; fi
    done
    return 1
}
WBASH="$(pick_bash)" || { echo "[x] не нашёл bash ≥ 4.4"; exit 1; }
[[ "$(basename "$WBASH")" == bash ]] || true

# ── стаб nft: печатает наборы как настоящий nft 1.0.9/1.1.x ───────────────────
cat > "$T/bin/nft" <<'NFT'
#!/usr/bin/env bash
# nft list set <family> <table> <set>
set="${5:-}"
case "$set" in
    empty_v4)
        printf 'table inet na_filter {\n\tset empty_v4 {\n\t\ttype ipv4_addr\n\t\tsize 65536\n\t\tflags dynamic,timeout\n\t\ttimeout 30m\n\t}\n}\n';;
    one_v4)
        printf 'table inet na_filter {\n\tset one_v4 {\n\t\ttype ipv4_addr\n\t\tsize 65536\n\t\tflags dynamic,timeout\n\t\telements = { 198.51.100.23 timeout 1d expires 1h11m50s608ms }\n\t}\n}\n';;
    many_v4)
        printf 'table inet na_filter {\n\tset many_v4 {\n\t\ttype ipv4_addr\n\t\tsize 65536\n\t\tflags dynamic,timeout\n\t\telements = { 1.2.3.4 timeout 1d expires 1h,\n\t\t\t     5.6.7.8 timeout 1d expires 2h, 9.9.9.9 timeout 1d expires 3h,\n\t\t\t     10.0.0.1 timeout 1d expires 4h }\n\t}\n}\n';;
    empty_v6)
        printf 'table inet na_filter {\n\tset empty_v6 {\n\t\ttype ipv6_addr\n\t\tsize 65536\n\t\tflags dynamic,timeout\n\t}\n}\n';;
    two_v6)
        printf 'table inet na_filter {\n\tset two_v6 {\n\t\ttype ipv6_addr\n\t\tsize 65536\n\t\tflags dynamic,timeout\n\t\telements = { 2001:db8::1 timeout 1d expires 5m30s608ms,\n\t\t\t     2001:db8:abcd::5 timeout 1d expires 1h }\n\t}\n}\n';;
    cidr_v4)
        printf 'table inet na_filter {\n\tset cidr_v4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { 10.0.0.0/8, 203.0.113.7, 192.0.2.0/24 }\n\t}\n}\n';;
    *) echo "Error: No such file or directory" >&2; exit 1;;
esac
NFT
chmod +x "$T/bin/nft"
export PATH="$T/bin:$PATH"

PASS=0; FAIL=0
check() { # check "описание" <ожидание> <факт>
    if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); echo "  ok   $1"
    else FAIL=$((FAIL+1)); echo "  FAIL $1: ожидалось [$2], получено [$3]"; fi
}
run() { "$WBASH" -c "set -uo pipefail; . '$REPO_ROOT/scripts/lib/common.sh'; $1" 2>&1; }

echo "== 1. nft_set_count / nft_set_elems =="
check "пустой динамический набор v4 = 0 (не 1 из-за 'flags dynamic,timeout')" 0 "$(run 'nft_set_count inet na_filter empty_v4')"
check "один элемент v4 = 1 (не 2 из-за timeout+expires)"                       1 "$(run 'nft_set_count inet na_filter one_v4')"
check "многострочный список v4 = 4"                                              4 "$(run 'nft_set_count inet na_filter many_v4')"
check "пустой набор v6 = 0"                                                      0 "$(run 'nft_set_count inet na_filter empty_v6')"
check "два элемента v6 = 2 ('1d'/'608ms' из timeout не считаются адресами)"      2 "$(run 'nft_set_count inet na_filter two_v6')"
check "интервальный набор (CIDR) = 3"                                            3 "$(run 'nft_set_count inet na_filter cidr_v4')"
check "несуществующий набор = 0"                                                 0 "$(run 'nft_set_count inet na_filter nope')"
check "nft_set_elems отдаёт адреса по одному в строку"  "$(printf '1.2.3.4\n10.0.0.1\n5.6.7.8\n9.9.9.9')" "$(run 'nft_set_elems inet na_filter many_v4')"

echo "== 2. json_escape =="
check "перевод строки → \\n"     'a\nb'      "$(run 'json_escape "$(printf "a\nb")"')"
check "кавычка и бэкслеш"        'x\"y\\z'   "$(run 'json_escape "x\"y\\z"')"
check "таб → \\t, прочий контроль выкинут" 'p\tq' "$(run 'json_escape "$(printf "p\tq\001")"')"
check "UTF-8 проходит как есть"  'нода'      "$(run 'json_escape "нода"')"
J="$(run 'printf "{\"s\":\"%s\"}\n" "$(json_escape "$(printf "\nabsent")")"')"
if command -v jq >/dev/null 2>&1; then
    check "экранированное значение парсится jq" '"\nabsent"' "$(printf '%s' "$J" | jq -c '.s')"
elif command -v python3 >/dev/null 2>&1; then
    check "экранированное значение парсится python" "ok" "$(printf '%s' "$J" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("ok" if d["s"]=="\nabsent" else d["s"])')"
fi

echo "== 3. tty_tput =="
# stdout здесь — пайп, не терминал: ничего не должно печататься и код 0
check "tty_tput civis в пайпе молчит" "" "$(TERM=xterm run 'tty_tput civis; tty_tput cnorm' | od -c | grep -v '^[0-9]* *$' || true)"
check "tty_tput возвращает 0 не в терминале" "0" "$(TERM=xterm run 'tty_tput civis; echo $?')"

echo "== 4. ver_ge =="
check "4.1 ≥ 4.0"      yes "$(run 'ver_ge 4.1 4.0 && echo yes || echo no')"
check "4.0.1 ≥ 4.0"    yes "$(run 'ver_ge 4.0.1 4.0 && echo yes || echo no')"
check "3.9.2 ≥ 4.0 нет" no  "$(run 'ver_ge 3.9.2 4.0 && echo yes || echo no')"
check "4.0 ≥ 4.0.1 нет" no  "$(run 'ver_ge 4.0 4.0.1 && echo yes || echo no')"
check "10.0 ≥ 9.9"     yes "$(run 'ver_ge 10.0 9.9 && echo yes || echo no')"

echo "== 5. персист: замороженный дефолт (issue #34) =="
CONF="$T/etc/protect.conf"
# conf, записанный v3.9: CROWDSEC_STRICT=0 — тогдашний дефолт, оператор не трогал
printf '# node-accelerator — сохранённый конфиг ноды @ 2026-07-11\n: "${CROWDSEC_STRICT:=0}"\n: "${CONN_LIMIT:=2048}"\n' > "$CONF"
OUT="$(run "load_conf '$CONF'; echo VAL=\$CROWDSEC_STRICT")"
check "старый дефолт без explicit → warn"           1 "$(printf '%s\n' "$OUT" | grep -c 'CROWDSEC_STRICT=0 записан старой версией')"
check "значение при этом НЕ меняется (статус-кво)"  "VAL=0" "$(printf '%s\n' "$OUT" | grep '^VAL=')"
check "conf_stale_defaults перечисляет ключ"        "CROWDSEC_STRICT|0|1|4.0" "$(run "conf_stale_defaults '$CONF'" | cut -d'|' -f1-4)"
OUT="$(run "NA_ADOPT_NEW_DEFAULTS=1 load_conf '$CONF'; echo VAL=\$CROWDSEC_STRICT")"
check "NA_ADOPT_NEW_DEFAULTS=1 → принят новый дефолт" "VAL=1" "$(printf '%s\n' "$OUT" | grep '^VAL=')"
check "…и об этом сказано ok, без warn"              0 "$(printf '%s\n' "$OUT" | grep -c 'записан старой версией')"
# оператор задал ENV сам → warn нет, save_conf пишет маркер explicit
OUT="$(run "export CROWDSEC_STRICT=0; load_conf '$CONF'; save_conf '$CONF' CROWDSEC_STRICT CONN_LIMIT; cat '$CONF'")"
check "ENV-значение: warn нет"                          0 "$(printf '%s\n' "$OUT" | grep -c 'записан старой версией')"
check "save_conf пишет маркер explicit"                 1 "$(printf '%s\n' "$OUT" | grep -c '^# explicit: CROWDSEC_STRICT$')"
check "save_conf пишет na_version в шапку"              1 "$(grep -c '^# na_version=' "$CONF")"
check "значение сохранено идиомой :="                   1 "$(grep -c '^: "${CROWDSEC_STRICT:=0}"$' "$CONF")"
# следующий прогон БЕЗ ENV: маркер есть → тишина, conf_stale_defaults пуст
OUT="$(run "load_conf '$CONF'; echo VAL=\$CROWDSEC_STRICT")"
check "ре-ран без ENV при маркере explicit: тишина"     0 "$(printf '%s\n' "$OUT" | grep -c 'записан старой версией')"
check "conf_stale_defaults пуст при маркере"            "" "$(run "conf_stale_defaults '$CONF'")"
# маркер переживает следующий save_conf без ENV
OUT="$(run "load_conf '$CONF'; save_conf '$CONF' CROWDSEC_STRICT; cat '$CONF'")"
check "маркер explicit переживает ре-сохранение без ENV" 1 "$(printf '%s\n' "$OUT" | grep -c '^# explicit: CROWDSEC_STRICT$')"
# conf, в котором ключ уже на новом дефолте — не дрейф
printf ': "${CROWDSEC_STRICT:=1}"\n' > "$CONF"
check "новый дефолт в conf — не дрейф"                  "" "$(run "conf_stale_defaults '$CONF'")"
# ключа в conf нет вовсе (старый conf до появления ручки) — не дрейф
printf ': "${CONN_LIMIT:=2048}"\n' > "$CONF"
check "ключа нет в conf — не дрейф"                     "" "$(run "conf_stale_defaults '$CONF'")"
# conf_note_env_keys фиксирует ENV один раз — второй load_conf не «видит» ключи первого файла как ENV
printf ': "${CROWDSEC_STRICT:=0}"\n' > "$CONF"
printf ': "${CROWDSEC_STRICT:=0}"\n' > "$T/etc/second.conf"
OUT="$(run "load_conf '$CONF' >/dev/null; load_conf '$T/etc/second.conf'")"
check "второй load_conf: ключ из первого файла — не ENV (warn есть)" 1 "$(printf '%s\n' "$OUT" | grep -c 'записан старой версией')"

echo "== 6. v4.2: save_conf отсекает обратный слэш =="
OUT="$(run "export REMNAWAVE_SWAP_SIZE='2G\\'; save_conf '$T/etc/bs.conf' REMNAWAVE_SWAP_SIZE; cat '$T/etc/bs.conf'")"
check "значение с \\ пропущено (иначе load_conf падал бы на синтаксисе всего файла)" 0 \
      "$(printf '%s\n' "$OUT" | grep -c 'REMNAWAVE_SWAP_SIZE:=')"
check "…и об этом предупреждено" 1 "$(printf '%s\n' "$OUT" | grep -c 'пропускаю REMNAWAVE_SWAP_SIZE')"
OUT="$(run "export NA_EXPLICIT_KEYS=' SSH_PORT'; export SSH_PORT=2222; save_conf '$T/etc/ex.conf' SSH_PORT; conf_is_explicit '$T/etc/ex.conf' SSH_PORT && echo EXPL")" || true
check "NA_EXPLICIT_KEYS → метка # explicit: SSH_PORT" 1 "$(grep -cx '# explicit: SSH_PORT' "$T/etc/ex.conf" 2>/dev/null || true)"
check "conf_is_explicit её видит" EXPL "$(printf '%s\n' "$OUT" | tail -1)"

echo "== 7. v4.2: detect_ssh_port — все порты, свойство Listen сокет-юнита =="
mkdir -p "$T/bin2"
cat > "$T/bin2/systemctl" <<'SC'
#!/bin/sh
case "$*" in
  "is-active --quiet ssh.socket") [ "${NA_T_SOCK:-0}" = 1 ] && exit 0; exit 3 ;;
  "is-active --quiet sshd.socket") exit 3 ;;
  "show ssh.socket -p Listen --value") echo "[::]:2222 (Stream) 0.0.0.0:22 (Stream)" ;;
esac
exit 0
SC
cat > "$T/bin2/sshd" <<'SD'
#!/bin/sh
[ "$1" = "-T" ] && printf 'port 22\nport 2200\naddressfamily any\n'
SD
chmod +x "$T/bin2"/*
check "ssh.socket активен → оба порта из Listen" "2222,22" "$(PATH="$T/bin2:$PATH" NA_T_SOCK=1 run 'detect_ssh_port')"
check "без сокета → все port из sshd -T" "22,2200" "$(PATH="$T/bin2:$PATH" NA_T_SOCK=0 run 'detect_ssh_port')"

echo "== 8. v4.2: detect_node_port — свой агент, а не второй тенант =="
cat > "$T/bin2/ss" <<'SS'
#!/bin/sh
[ "${NA_T_RWNODE:-0}" = 1 ] && echo 'LISTEN 0 511 *:2222 *:* users:(("rw-node",pid=10,fd=20))'
exit 0
SS
cat > "$T/bin2/docker" <<'DK'
#!/bin/sh
# три контейнера: свой агент (образ по digest, host-сеть), второй тенант (bridge, тот же
# внутренний порт), агент третьего тенанта (host-сеть, свой порт)
case "$*" in
  "ps -a --format {{.Names}}") printf 'remnanode\nreka-remnanode\nremnanode-dbn\nnginx\n' ;;
  "inspect -f {{.Config.Image}} remnanode") echo 'remnawave/node@sha256:0cdf386dd49f' ;;
  "inspect -f {{.Config.Image}} reka-remnanode") echo 'remnawave/node:3.4.1' ;;
  "inspect -f {{.Config.Image}} remnanode-dbn") echo 'remnawave/node:latest' ;;
  "inspect -f {{.Config.Image}} nginx") echo 'nginx:alpine' ;;
  "inspect -f {{.HostConfig.NetworkMode}} remnanode") echo host ;;
  "inspect -f {{.HostConfig.NetworkMode}} reka-remnanode") echo reka-node ;;
  "inspect -f {{.HostConfig.NetworkMode}} remnanode-dbn") echo host ;;
  *"{{range .Config.Env}}"*remnanode-dbn) printf 'NODE_PORT=2322\n' ;;
  *"{{range .Config.Env}}"*reka-remnanode) printf 'NODE_PORT=9999\n' ;;
  *"{{range .Config.Env}}"*remnanode) printf 'NODE_PORT=2222\n' ;;
  *) exit 1 ;;
esac
DK
chmod +x "$T/bin2"/*
check "слушатель rw-node — первый источник" "2222" "$(PATH="$T/bin2:$PATH" NA_T_RWNODE=1 NA_REMNANODE_ENV=/nonexistent run 'detect_node_port')"
check "без слушателя: host-сеть агенты (digest-образ найден, bridge-тенант не в счёт)" "2222,2322" \
      "$(PATH="$T/bin2:$PATH" NA_T_RWNODE=0 NA_REMNANODE_ENV=/nonexistent run 'detect_node_port')"

echo "== 9. v4.2: SSH_CONNECTION у предков (sudo вычищает его из env) =="
# /proc в песочнице: процесс теста → «предок» 4242 (sshd-сессия) с SSH_CONNECTION
PCOPY="$T/common-proc.sh"
sed -e "s#/proc/#$T/proc/#g" "$REPO_ROOT/scripts/lib/common.sh" > "$PCOPY"
cat > "$T/ancestor.sh" <<ANC
mkdir -p "$T/proc/\$\$" "$T/proc/4242"
printf 'Name:\tbash\nPPid:\t4242\n' > "$T/proc/\$\$/status"
: > "$T/proc/\$\$/environ"
printf 'HOME=/root\0SSH_CONNECTION=198.51.100.77 50022 10.0.0.5 2200\0' > "$T/proc/4242/environ"
printf 'Name:\tsshd\nPPid:\t1\n' > "$T/proc/4242/status"
unset SSH_CONNECTION SSH_CLIENT
. "$PCOPY"
echo "\$(ssh_client_ip) \$(ssh_session_port)"
ANC
check "IP и порт сессии найдены у предка" "198.51.100.77 2200" "$("$WBASH" "$T/ancestor.sh" 2>&1)"
check "без SSH_CONNECTION нигде — пусто, без ошибок" "" "$(env -u SSH_CONNECTION "$WBASH" -c ". '$PCOPY'; ssh_client_ip" 2>&1)"

echo
echo "итого: ok=$PASS fail=$FAIL"
[[ "$FAIL" -eq 0 ]]
