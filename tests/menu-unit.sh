#!/usr/bin/env bash
#
# menu-unit.sh — интерактивное меню install.sh (v4.3) против стабов.
#
# До v4.3 меню при `curl … | sudo bash` читало выбор из stdin — то есть из пайпа со
# скриптом: `read` получал EOF, и под set -e меню закрывалось сразу после рамки. Модули из
# меню при этом не получили бы терминал: protect задаёт вопросы только при -t 0. Теперь ввод
# меню и stdin модулей — терминал (NA_TTY, по умолчанию /dev/tty).
#
# Терминал здесь не нужен: NA_TTY указывает на файл с ответами, stdin — /dev/null или пайп
# со скриптом (как в curl|bash). Модули — стабы, которые пишут, как их вызвали, и читают
# одну строку «вопроса» из своего stdin. Root не нужен: require_root/detect_os подменены,
# системные пути — в песочницу. Рамку (CHA, ESC[<n>G) проверяет необязательная секция на
# псевдотерминале через python3 — без python3 она пропускается.
# Запуск: bash tests/menu-unit.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

pick_bash() {
    local c
    for c in bash /opt/homebrew/bin/bash /usr/local/bin/bash; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" -c 'set -u; a=(); : "${a[@]}"; [[ -v HOME ]]' 2>/dev/null; then command -v "$c"; return 0; fi
    done
    return 1
}
WBASH="$(pick_bash)" || { echo "[x] не нашёл bash ≥ 4.2"; exit 1; }
BDIR="$(dirname "$WBASH")"

PASS=0; FAIL=0
ok_()   { PASS=$((PASS+1)); echo "  ok   $1"; }
fail_() { FAIL=$((FAIL+1)); echo "  FAIL $1"; }
has()   { if grep -qF -- "$2" "$3"; then ok_ "$1"; else fail_ "$1 — нет «$2» в выводе"; sed 's/^/        | /' "$3" | tail -25; fi; }
hasnt() { if grep -qF -- "$2" "$3"; then fail_ "$1 — лишнее «$2» в выводе"; else ok_ "$1"; fi; }

# ── Песочница: install.sh + модули-стабы, системные пути → $SB ─────────────────
SB="$T/sb"
mkdir -p "$SB/bin" "$SB/state" "$SB/conf" "$SB/sbin" "$SB/scripts/lib"
sed -e "s#/usr/local/sbin/#$SB/sbin/#g" "$REPO_ROOT/install.sh" > "$SB/install.sh"
sed -e "s#/proc/sys/kernel/random/boot_id#$SB/boot_id#g" "$REPO_ROOT/scripts/lib/common.sh" > "$SB/scripts/lib/common.sh"
cat >> "$SB/scripts/lib/common.sh" <<STUB
require_root(){ :; }
detect_os(){ OS_ID=debian; OS_VER=12; NAME="Debian GNU/Linux"; VERSION_ID=12; VERSION_CODENAME=bookworm; }
STATE_DIR="$SB/state"; CONF_DIR="$SB/conf"; NA_LIB_DIR="$SB/lib"
STUB
echo "boot-now" > "$SB/boot_id"
# Модуль-стаб: строка «MODULE:<имя> args=[…] stdin=<что прочитал> no_clear=…» в журнал;
# код выхода — STUB_RC_<имя>; STUB_SLEEP — «долгий» модуль (для Ctrl+C и ввода наперёд).
# LEAK:<fd> — модулю достался чужой дескриптор (ввод меню открывается на fd ≥ 10).
for m in optimize protect diagnose na-report rollback; do
    v="STUB_RC_${m//-/_}"
    cat > "$SB/scripts/$m.sh" <<S
#!/usr/bin/env bash
a=""; [[ -n "\${STUB_ASK:-}" ]] && { IFS= read -r a || true; }
for fd in 10 11 12 13 14 15; do [[ -e /dev/fd/\$fd ]] && echo "LEAK:\$fd" >> "$SB/calls.log"; done
echo "MODULE:$m args=[\$*] stdin=[\$a] no_clear=[\${NA_NO_CLEAR:-}]" >> "$SB/calls.log"
echo "MODULE:$m"
[[ -n "\${STUB_SLEEP:-}" ]] && sleep "\$STUB_SLEEP"
exit \${$v:-0}
S
done
cat > "$SB/bin/hostname" <<'S'
#!/bin/sh
echo vne-de1
S
cat > "$SB/bin/uname" <<'S'
#!/bin/sh
case "$1" in -r) echo 6.18.64-x64v3-xanmod1;; -m) echo x86_64;; -n) echo vne-de1;; *) echo Linux;; esac
S
cat > "$SB/bin/sysctl" <<'S'
#!/bin/sh
case "$2" in net.ipv4.tcp_congestion_control) echo "${STUB_CC:-bbr}";; net.core.default_qdisc) echo fq;; *) exit 1;; esac
S
cat > "$SB/bin/systemd-detect-virt" <<'S'
#!/bin/sh
echo kvm
S
cat > "$SB/bin/systemctl" <<'S'
#!/bin/sh
[ "$1" = is-active ] || exit 0
case " ${STUB_ACTIVE:-} " in *" $3 "*) exit 0;; esac; exit 3
S
cat > "$SB/bin/nft" <<'S'
#!/bin/sh
[ "${STUB_NFT:-1}" = 1 ]
S
# curl-стаб для режима curl|bash: «скачивает» модули из песочницы
cat > "$SB/bin/curl" <<S
#!/usr/bin/env bash
out=""; url=""
while [ \$# -gt 0 ]; do case "\$1" in -o) out="\$2"; shift 2; continue;; http*://*) url="\$1";; esac; shift; done
rel="\${url#*/scripts/}"; [ -f "$SB/scripts/\$rel" ] || exit 22; cp "$SB/scripts/\$rel" "\$out"
S
chmod +x "$SB/bin/"* "$SB/scripts/"*.sh
chmod -R go-w "$SB"
export PATH="$SB/bin:$BDIR:$PATH"

# menu <файл-вывода> <ответы…> — меню из файла, ответы по строке; вывод не терминал
menu() {
    local out="$1"; shift
    if (( $# )); then printf '%s\n' "$@" > "$T/answers"; else : > "$T/answers"; fi
    : > "$SB/calls.log"
    local rc=0
    NA_TTY="$T/answers" TERM=xterm "$WBASH" "$SB/install.sh" < /dev/null > "$out" 2>&1 || rc=$?
    echo "$rc" > "$out.rc"
}
calls() { cat "$SB/calls.log" 2>/dev/null || true; }

echo "== 1. выход и мусорный ввод =="
menu "$T/o1" 9 "" 0
[[ "$(cat "$T/o1.rc")" == 0 ]] && ok_ "0 — выход с кодом 0" || fail_ "код выхода $(cat "$T/o1.rc")"
has "неверный пункт назван, меню не закрылось" "«9» — нет такого пункта" "$T/o1"
[[ -z "$(calls)" ]] && ok_ "ни один модуль не вызван" || fail_ "вызваны модули: $(calls)"
menu "$T/o1b"
[[ "$(cat "$T/o1b.rc")" == 0 ]] && ok_ "EOF на вводе (Ctrl+D) — выход с кодом 0" || fail_ "EOF: код $(cat "$T/o1b.rc")"
hasnt "не терминал — без escape-кодов в выводе" $'\033' "$T/o1"

echo "== 2. модуль получает ввод меню на stdin; ошибка модуля не закрывает меню =="
STUB_ASK=1 menu "$T/o2" 1 "ответ модулю" "" 0
grep -q 'MODULE:optimize args=\[\] stdin=\[ответ модулю\]' "$SB/calls.log" \
    && ok_ "optimize прочитал ответ с терминала меню (а не со stdin скрипта)" || fail_ "stdin модуля: $(calls)"
has "итог действия показан" "Готово за" "$T/o2"
[[ -x "$SB/sbin/na-diagnose" ]] && ok_ "после optimize — persist_toolkit (CLI na-diagnose)" || fail_ "CLI na-diagnose не создан"
rm -f "$SB/sbin/na-diagnose" "$SB/sbin/na-report"
STUB_RC_protect=3 menu "$T/o2b" 2 "" 0
has "код ошибки модуля назван" "Ошибка (код 3)" "$T/o2b"
[[ ! -e "$SB/sbin/na-diagnose" ]] && ok_ "упавший protect не доходит до persist_toolkit" || fail_ "persist_toolkit после упавшего protect"
[[ "$(cat "$T/o2b.rc")" == 0 ]] && ok_ "меню пережило ошибку модуля и вышло по 0" || fail_ "код $(cat "$T/o2b.rc")"
STUB_ASK=1 menu "$T/o2c" 1 "x" "" 0
hasnt "дескриптор ввода меню модулю не достаётся" "LEAK:" "$SB/calls.log"
# запуск из файла, ответы пайпом в stdin, NA_TTY не задан — читается пайп, как до v4.3
printf '%s\n' 3 "" 0 > "$T/answers"; : > "$SB/calls.log"; rc=0
TERM=xterm "$WBASH" "$SB/install.sh" < "$T/answers" > "$T/o2d" 2>&1 || rc=$?
{ [[ "$rc" == 0 ]] && grep -q 'MODULE:diagnose' "$SB/calls.log"; } \
    && ok_ "из файла: ответы из stdin-пайпа (printf '3\\n' | bash install.sh) — как раньше" \
    || fail_ "из файла с пайпом: rc=$rc, $(calls)"

echo "== 3. откат: подтверждение, «н» — нет в любой локали =="
LC_ALL=C menu "$T/o3" 5 2 "н" 0
hasnt "LC_ALL=C: «н» (клавиша Y в русской раскладке) не откатывает" "MODULE:rollback" "$SB/calls.log"
has "отказ назван" "откат отменён" "$T/o3"
LC_ALL=C menu "$T/o3b" 5 2 "нет" 0
[[ -z "$(calls)" ]] && ok_ "LC_ALL=C: «нет» не откатывает" || fail_ "откат на «нет»: $(calls)"
menu "$T/o3c" 5 x 0
[[ -z "$(calls)" ]] && ok_ "мусор в подменю отката — ничего не тронуто" || fail_ "$(calls)"
has "мусор назван" "в откате нет такого пункта" "$T/o3c"
LC_ALL=C menu "$T/o3d" 5 2 "д" "" 0
grep -q 'MODULE:rollback args=\[protect\]' "$SB/calls.log" && ok_ "LC_ALL=C: «д» откатывает защиту" || fail_ "«д»: $(calls)"

echo "== 4. файрвол: адреса только как IP/CIDR, без раскрытия глобов =="
menu "$T/o4" 7 0
has "без na-fw — подсказка про пункт 2" "сначала пункт 2" "$T/o4"
printf '#!/bin/sh\necho "NA-FW [$*]" >> "%s/calls.log"\n' "$SB" > "$SB/sbin/na-fw"; chmod +x "$SB/sbin/na-fw"
touch "$SB/aaa-file"
( cd "$SB" && menu "$T/o4b" 7 3 "1.2.3.4, 10.0.0.0/8  2001:db8::/32" "" 0 )
grep -q 'NA-FW \[allow add 1.2.3.4 10.0.0.0/8 2001:db8::/32\]' "$SB/calls.log" \
    && ok_ "allow add: адреса через пробел/запятую разобраны" || fail_ "na-fw: $(calls)"
( cd "$SB" && menu "$T/o4c" 7 3 "*" 5 "1.2.3.4;reboot" 0 0 )
[[ -z "$(calls)" ]] && ok_ "«*» и «;» не дошли до na-fw" || fail_ "na-fw вызван: $(calls)"
has "причина отказа названа" "только IPv4/IPv6-адреса и CIDR" "$T/o4c"

echo "== 5. форензика: аргументы na-report =="
menu "$T/o5" 6 3 "2001:db8::1" "" 2 "08" "" 2 "999" 0 0
grep -q 'MODULE:na-report args=\[--ip 2001:db8::1\]' "$SB/calls.log" && ok_ "--ip" || fail_ "--ip: $(calls)"
grep -q 'MODULE:na-report args=\[--hours 8\]' "$SB/calls.log" && ok_ "--hours 08 → 8 (не восьмеричное)" || fail_ "--hours: $(calls)"
has "окно 999 отвергнуто" "от 1 до 720" "$T/o5"

echo "== 6. шапка: состояние ноды =="
menu "$T/o6" 0
has "свежая нода: тюнинга нет" "не применялся — пункт 1" "$T/o6"
has "свежая нода: защиты нет" "не установлена — пункт 2" "$T/o6"
has "ядро и BBR" "6.18.64-x64v3-xanmod1 · bbr + fq" "$T/o6"
printf 'installed_at=2026-11-20T12:34:56+03:00\nna_version=4.2\nreboot_needed=1\nboot_id=boot-now\n' > "$SB/state/optimize.installed"
printf 'installed_at=2026-11-21T10:00:00+03:00\nfw_mode=strict\ncrowdsec=1\ncrowdsec_scope=ssh\n' > "$SB/state/protect.installed"
STUB_ACTIVE="crowdsec na-fw-safety.timer" menu "$T/o6b" 0
has "тюнинг: дата, версия маркера и подсказка ре-рана" "применён 20.11.2026 · v4.2 · ре-ран →" "$T/o6b"
has "та же загрузка, что при установке, — нужна перезагрузка" "нужна перезагрузка" "$T/o6b"
has "защита работает, CrowdSec с областью" "strict · na_filter работает · CrowdSec (ssh)" "$T/o6b"
has "взведённый сейфти-таймер виден" "сейфти-таймер взведён" "$T/o6b"
printf 'reboot_risk=нет /boot/initrd.img-6.18.64-x64v3-xanmod1\n' >> "$SB/state/optimize.installed"
menu "$T/o6r" 0
has "ядро не готово к загрузке — ✘ «НЕ перезагружайся», а не «нужна перезагрузка»" "НЕ перезагружайся" "$T/o6r"
has "…с причиной из optimize" "нет /boot/initrd.img-6.18.64-x64v3-xanmod1" "$T/o6r"
hasnt "…и без призыва к перезагрузке" "нужна перезагрузка" "$T/o6r"
# длинная причина переносится, а не обрезается; глоб в ней не раскрывается
sed -i.bak '/^reboot_risk=/d' "$SB/state/optimize.installed" && rm -f "$SB/state/optimize.installed.bak"
printf 'reboot_risk=версия ядра пакета linux-xanmod-x64v3 не определена — initrd и драйвер NIC не проверены (ls /boot/initrd.img-*xanmod* /lib/modules)\n' >> "$SB/state/optimize.installed"
touch "$SB/boot-glob-bait"
( cd "$SB" && menu "$T/o6w" 0 )
has "длинная причина: начало на месте" "версия ядра пакета linux-xanmod-x64v3" "$T/o6w"
has "…и хвост-подсказка не обрезан, глоб не раскрыт" "/boot/initrd.img-*xanmod* /lib/modules)" "$T/o6w"
hasnt "…и в шапку не попало имя файла из каталога (глоб)" "boot-glob-bait" "$T/o6w"
if command -v python3 >/dev/null 2>&1; then
    # длина в СИМВОЛАХ (awk на macOS/mawk считает байты); линейки рамки не в счёт
    if python3 -I -c 'import sys; sys.exit(any(len(l.rstrip("\n")) > 80 and "──" not in l for l in open(sys.argv[1], encoding="utf-8")))' "$T/o6w"
    then ok_ "строки шапки перенесены (не длиннее 80 символов)"; else fail_ "строка шапки длиннее 80 символов"; fi
fi
sed -i.bak '/^reboot_risk=/d' "$SB/state/optimize.installed" && rm -f "$SB/state/optimize.installed.bak"
# маркер новее запущенного тулкита — не «ре-ран», а предупреждение
sed -i.bak 's/^na_version=4.2$/na_version=9.9/' "$SB/state/optimize.installed" && rm -f "$SB/state/optimize.installed.bak"
menu "$T/o6v" 0
has "маркер новее: запущен старый тулкит" "запущен v" "$T/o6v"
hasnt "маркер новее: без «ре-ран →» (откатил бы версию)" "ре-ран →" "$T/o6v"
sed -i.bak 's/^na_version=9.9$/na_version=4.2/' "$SB/state/optimize.installed" && rm -f "$SB/state/optimize.installed.bak"
# фолбэк-таймер сейфти (pid-файл): наш процесс — «взведён» с подсказкой kill; чужой PID — нет
( exec -a "sh -c sleep 30; /usr/local/sbin/na-fw-safety-revert" sleep 30 ) & sp=$!
echo "$sp" > "$SB/state/na-fw-safety.pid"
menu "$T/o6p" 0
has "pid-файл сейфти с живым процессом сейфти — «взведён»" "сейфти-таймер взведён" "$T/o6p"
has "…и подсказка для nohup-режима — kill, а не systemctl" "kill \$(cat" "$T/o6p"
kill "$sp" 2>/dev/null || true; wait "$sp" 2>/dev/null || true
sleep 30 & sp=$!
echo "$sp" > "$SB/state/na-fw-safety.pid"
menu "$T/o6q" 0
hasnt "PID из pid-файла занят посторонним процессом (после ребута) — не «взведён»" "сейфти-таймер взведён" "$T/o6q"
kill "$sp" 2>/dev/null || true; wait "$sp" 2>/dev/null || true
rm -f "$SB/state/na-fw-safety.pid"
# FW_MODE=skip, а таблица прошлой установки загружена
sed -i.bak 's/^fw_mode=strict$/fw_mode=skip/' "$SB/state/protect.installed" && rm -f "$SB/state/protect.installed.bak"
menu "$T/o6s" 0
has "skip + загруженная na_filter прошлой установки — предупреждение" "na_filter прошлой установки загружена" "$T/o6s"
STUB_NFT=0 menu "$T/o6t" 0
has "skip без таблицы — «файрвол не ставился»" "файрвол не ставился" "$T/o6t"
sed -i.bak 's/^fw_mode=skip$/fw_mode=strict/' "$SB/state/protect.installed" && rm -f "$SB/state/protect.installed.bak"
echo "boot-later" > "$SB/boot_id"
sleep 1; date +%s > "$SB/state/safety-fired.last"
STUB_NFT=0 STUB_CC=cubic menu "$T/o6c" 0
hasnt "после ребута «нужна перезагрузка» пропадает" "нужна перезагрузка" "$T/o6c"
has "таблицы нет — ✘ и «защиты нет»" "na_filter НЕ загружена — защиты нет" "$T/o6c"
has "причина — сработавший сейфти" "сработал сейфти-таймер" "$T/o6c"
has "CrowdSec не запущен — отдельной строкой" "CrowdSec не запущен" "$T/o6c"
has "без BBR — предупреждение" "cubic + fq — без BBR" "$T/o6c"
rm -f "$SB/state/"*

echo "== 7. curl | sudo bash: stdin — пайп со скриптом, ввод меню — терминал =="
printf '%s\n' 3 "" 0 > "$T/answers"; : > "$SB/calls.log"
rc=0; ( cd "$T" && cat "$SB/install.sh" | NA_REF=menu-unit-ref NA_TTY="$T/answers" TERM=xterm bash -s ) > "$T/o7" 2>&1 || rc=$?
[[ "$rc" == 0 ]] && ok_ "меню из пайпа отработало и вышло по 0" || fail_ "код $rc: $(tail -3 "$T/o7")"
grep -q 'MODULE:diagnose' "$SB/calls.log" && ok_ "выбор «3» прочитан с терминала — диагностика запущена" || fail_ "диагностика не запущена"
hasnt "…и модулю не достался дескриптор ввода меню" "LEAK:" "$SB/calls.log"
if grep -v 'Скачиваю' "$T/o7" | grep -qx ' menu-unit-ref'; then ok_ "источник модулей (NA_REF) в шапке"
else fail_ "NA_REF не показан в шапке"; fi
rc=0; ( cd "$T" && cat "$SB/install.sh" | NA_TTY=/nonexistent/tty bash -s ) > "$T/o7b" 2>&1 || rc=$?
[[ "$rc" == 2 ]] && ok_ "без терминала — код 2, а не тихий выход" || fail_ "без терминала: код $rc"
has "без терминала — подсказка про команды" "Меню нужен терминал" "$T/o7b"

echo "== 8. CLI: all и report =="
: > "$SB/calls.log"; rc=0
"$WBASH" "$SB/install.sh" all > "$T/o8" 2>&1 || rc=$?
[[ "$rc" == 0 && "$(grep -c MODULE "$SB/calls.log")" == 3 ]] && ok_ "all: три модуля" || fail_ "all: rc=$rc $(calls)"
grep -q 'MODULE:diagnose args=\[\] stdin=\[\] no_clear=\[1\]' "$SB/calls.log" \
    && ok_ "all: diagnose не чистит экран (вывод protect про сейфти не стирается)" || fail_ "NA_NO_CLEAR: $(calls)"
: > "$SB/calls.log"; rc=0
STUB_RC_optimize=4 "$WBASH" "$SB/install.sh" all > "$T/o8b" 2>&1 || rc=$?
[[ "$rc" == 4 ]] && ok_ "all: упавший optimize — код 4" || fail_ "all: код $rc"
hasnt "all: после упавшего optimize protect не запускается" "MODULE:protect" "$SB/calls.log"
: > "$SB/calls.log"
"$WBASH" "$SB/install.sh" report --hours 6 --json > "$T/o8c" 2>&1 || true
grep -q 'MODULE:na-report args=\[--hours 6 --json\]' "$SB/calls.log" && ok_ "report передаёт аргументы na-report" || fail_ "report: $(calls)"

echo "== 9. на псевдотерминале (python3): рамка, Ctrl+C, ввод наперёд, история =="
if command -v python3 >/dev/null 2>&1; then
    # na_menu_pty.py <колонок> <шаги JSON> <команда…> — терминал заданной ширины; шаги
    # [[ждать_строку|null, отправить|null, пауза_с], …]; вывод — в stdout, код — в «[exit=N]»
    cat > "$T/na_menu_pty.py" <<'PY'
import os, pty, select, sys, time, fcntl, termios, struct, json
cols = int(sys.argv[1]); steps = json.loads(sys.argv[2]); argv = sys.argv[3:]
pid, fd = pty.fork()
if pid == 0:
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack('HHHH', 40, cols, 0, 0))
    os.execvp(argv[0], argv)
out = b''; pos = 0; alive = True; t0 = time.time()
def pump(sec):
    global out, alive
    end = time.time() + sec
    while alive and time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try: d = os.read(fd, 65536)
            except OSError: alive = False; break
            if not d: alive = False; break
            out += d
for want, send, pause in steps:
    if want:
        w = want.encode()
        while alive and w not in out[pos:] and time.time() - t0 < 20: pump(0.1)
        i = out.find(w, pos); pos = i + len(w) if i >= 0 else pos
    if pause: pump(pause)
    if send and alive: os.write(fd, send.encode())
while alive and time.time() - t0 < 25: pump(0.2)
try: _, st = os.waitpid(pid, 0); code = os.waitstatus_to_exitcode(st)
except ChildProcessError: code = -1
sys.stdout.buffer.write(out + ('\n[exit=%d]\n' % code).encode())
PY
    P='› '
    pty_run() { local cols="$1" steps="$2" out="$3"; shift 3; TERM=xterm python3 -I "$T/na_menu_pty.py" "$cols" "$steps" "$@" > "$out" 2>&1 || true; }
    pty_run 100 "[[\"$P\",\"0\r\",0]]" "$T/o9" "$WBASH" "$SB/install.sh"
    n_box="$(grep -c '│' "$T/o9" || true)"
    n_cha="$(grep -c $'\033\\[77G.*│' "$T/o9" || true)"
    if [[ "$n_box" -gt 10 && "$n_box" == "$n_cha" ]]; then
        ok_ "100 колонок: правая граница каждой строки поставлена CHA в колонку 77 ($n_box строк)"
    else fail_ "100 колонок: строк с │ — $n_box, из них с ESC[77G — $n_cha"; head -c 400 "$T/o9" | od -c | head -8; fi
    hasnt "экран чистится без ESC[3J — история прокрутки цела" $'\033[3J' "$T/o9"
    pty_run 56 "[[\"$P\",\"0\r\",0]]" "$T/o9b" "$WBASH" "$SB/install.sh"
    if grep -q 'Оптимизатор' "$T/o9b" && ! grep -q '│' "$T/o9b"; then ok_ "56 колонок: без рамки"
    else fail_ "56 колонок: рамка или пустой экран"; fi
    NO_COLOR=1 pty_run 100 "[[\"$P\",\"0\r\",0]]" "$T/o9c" "$WBASH" "$SB/install.sh"
    if grep -qE $'\033\\[[0-9;]*m' "$T/o9c"; then fail_ "NO_COLOR: в выводе коды цвета (SGR)"
    elif grep -q '│' "$T/o9c"; then ok_ "NO_COLOR: рамка есть, кодов цвета нет"
    else fail_ "NO_COLOR: пустой экран"; fi
    # Ctrl+C на приглашении — выход 130 (сам read на трапе не прерывается — выходим из трапа)
    pty_run 100 "[[\"$P\",\"\u0003\",0]]" "$T/o9d" "$WBASH" "$SB/install.sh"
    has "Ctrl+C на приглашении — выход с кодом 130" "[exit=130]" "$T/o9d"
    # Ctrl+C во время модуля — модуль прерван, меню живо
    STUB_SLEEP=5 pty_run 100 "[[\"$P\",\"1\r\",0],[\"MODULE:optimize\",\"\u0003\",0.3],[\"Enter — в меню\",\"\r\",0],[\"$P\",\"0\r\",0]]" "$T/o9e" "$WBASH" "$SB/install.sh"
    has "Ctrl+C в модуле — «Прервано»" "Прервано (Ctrl+C)" "$T/o9e"
    has "…меню живо и выходит по 0" "[exit=0]" "$T/o9e"
    # Enter, нажатый во время работы модуля, не съедает паузу: итог остаётся на экране, пока
    # не нажмёшь Enter ещё раз (иначе «Выбор ›» появился бы второй раз до нашего «0»)
    STUB_SLEEP=1 pty_run 100 "[[\"$P\",\"1\r\",0],[\"MODULE:optimize\",\"\r\",0],[\"Enter — в меню\",null,1.5],[null,\"0\r\",0]]" "$T/o9f" "$WBASH" "$SB/install.sh"
    n_prompt="$(grep -o 'Выбор ›' "$T/o9f" | wc -l | tr -d ' ')"
    [[ "$n_prompt" == 1 ]] && ok_ "ввод наперёд во время модуля сброшен — пауза ждёт" \
        || fail_ "ввод наперёд съел паузу: «Выбор ›» показан $n_prompt раз(а)"
else
    echo "  skip (нет python3)"
fi

echo
echo "  прогон: $PASS ok, $FAIL fail"
[[ "$FAIL" -eq 0 ]] || { echo "MENU-UNIT: FAIL"; exit 1; }
echo "MENU-UNIT: OK (меню из пайпа читает терминал, модули получают его на stdin, откат с подтверждением, рамка через CHA)"
