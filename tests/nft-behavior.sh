#!/usr/bin/env bash
#
# nft-behavior.sh — поведение per-IP лимитеров на НАСТОЯЩЕМ nft/ядре (два netns + veth).
#
# Юнит-тесты сверяют текст ruleset; здесь проверяется то, что текст не доказывает:
#   0. контроль: старая схема (meter без timeout, «в лимите → accept, иначе drop») на
#      полном наборе РЕЖЕТ новых клиентов — ровно отказ, найденный на флоте;
#   1. ruleset 4.1.3 встаёт поверх живой таблицы со старыми meter (переход 4.1.2 → 4.1.3);
#   2. наборы-лимитеры объявлены с timeout;
#   3. лимит работает: сверх burst новые SYN с одного адреса дропаются, счётчик растёт;
#   4. после простоя записи истекают;
#   5. ПОЛНЫЙ набор не режет новых клиентов (fail-open) — v4 и v6;
#   6. SSH: пара лишних попыток → только suspect, настоящий перебор → бан (ban-once v4.2),
#      а на полном наборе — общий потолок, а не открытая дверь для перебора;
#   7. опубликованный (DNAT) порт: забаненный адрес режется в forward, whitelist проходит;
#   8. SYNPROXY: рукопожатие на защищённом порту завершается (v4.2: synproxy до invalid-drop
#      + nf_conntrack_tcp_loose=0); SYN-rate, бан и whitelist решаются ДО synproxy.
# Размер набора и пол timeout ужаты ручками NA_RATE_SET_SIZE/NA_RATE_TO_*, чтобы проверить
# переполнение и истечение за секунды.
#
# Нужны: Linux, root, nft, ip, python3. CI: job nft-behavior. Запуск: sudo bash tests/nft-behavior.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$(uname -s)" == Linux ]] || { echo "SKIP: нужен Linux (netns + nftables)"; exit 0; }
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "[x] нужен root (sudo bash $0)"; exit 1; }
for c in nft ip python3; do command -v "$c" >/dev/null || { echo "[x] нет $c"; exit 1; }; done

T="$(mktemp -d)"
SRV=na-t-srv; CLI=na-t-cli
cleanup() {
    [[ -n "${LPID:-}" ]] && kill "$LPID" 2>/dev/null || true
    [[ -n "${CPID:-}" ]] && kill "$CPID" 2>/dev/null || true
    ip netns del na-t-ctr 2>/dev/null || true
    ip netns del "$SRV" 2>/dev/null || true
    ip netns del "$CLI" 2>/dev/null || true
    rm -rf "$T"
}
trap cleanup EXIT

# ── Генерация ruleset тем же protect.sh (DRY_RUN: генерация + nft -c на этом ядре) ──
cp -R "$REPO_ROOT/scripts" "$T/scripts"
cat >> "$T/scripts/lib/common.sh" <<'STUB'
apt_install(){ :; }
default_iface(){ echo na-wan0; }
detect_ssh_port(){ echo 22; }
ssh_client_ip(){ :; }
STUB
SIZE=4; RATE=2; BURST=3
OUT="$(TERM=dumb NA_NO_LOCK=1 DRY_RUN=1 REMNAWAVE_NONINTERACTIVE=1 ENABLE_CROWDSEC=0 \
       TCP_PORTS=8443 UDP_PORTS=8443 NODE_PORT=2222 NODE_PORT_WHITELIST_ONLY=0 \
       SYN_RATE=$RATE SYN_BURST=$BURST SSH_RATE=6 SSH_BURST=2 ENABLE_BANONCE=1 \
       NA_RATE_SET_SIZE=$SIZE NA_RATE_TO_SEC=1s NA_RATE_TO_MIN=1s \
       bash "$T/scripts/protect.sh" 2>&1)" || { echo "$OUT" | tail -20; echo "[x] генерация/nft -c не прошли"; exit 1; }
F="$(sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' <<<"$OUT" | sed -nE 's/.*Генерация nftables → (\/tmp\/na_filter\.[A-Za-z0-9]+\.nft).*/\1/p' | tail -1)"
[[ -n "$F" && -s "$F" ]] || { echo "[x] не нашёл сгенерированный ruleset"; echo "$OUT" | tail -20; exit 1; }
cp "$F" "$T/ruleset.nft"; rm -f "$F"
# вариант с SYNPROXY — отдельный ruleset (synproxy меняет путь рукопожатия на TCP_PORTS)
OUT="$(TERM=dumb NA_NO_LOCK=1 DRY_RUN=1 REMNAWAVE_NONINTERACTIVE=1 ENABLE_CROWDSEC=0 \
       TCP_PORTS=8443 UDP_PORTS=none NODE_PORT=none ENABLE_SYNPROXY=1 \
       SYN_RATE=$RATE SYN_BURST=$BURST NA_RATE_TO_SEC=1s NA_RATE_TO_MIN=1s \
       bash "$T/scripts/protect.sh" 2>&1)" || { echo "$OUT" | tail -20; echo "[x] генерация SYNPROXY-варианта не прошла"; exit 1; }
F="$(sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' <<<"$OUT" | sed -nE 's/.*Генерация nftables → (\/tmp\/na_filter\.[A-Za-z0-9]+\.nft).*/\1/p' | tail -1)"
cp "$F" "$T/ruleset-sp.nft"; rm -f "$F"
# timeout набора = max(пол, 2× восстановление корзины): 3/2 с → 2 с × 2 = 4 с
SET_TO=4

# ── Стенд: srv ←veth→ cli (10 адресов v4 и 8 адресов v6) ─────────────────────────
CTR=na-t-ctr
ip netns add "$SRV"; ip netns add "$CLI"; ip netns add "$CTR"
ip link add na-t0 type veth peer name na-t1
ip link set na-t0 netns "$SRV"; ip link set na-t1 netns "$CLI"
ip -n "$SRV" addr add 10.77.0.1/24 dev na-t0
ip -n "$SRV" -6 addr add fd77::1/64 dev na-t0 nodad
for i in $(seq 11 20); do ip -n "$CLI" addr add "10.77.0.$i/24" dev na-t1; done
for i in $(seq 11 18); do ip -n "$CLI" -6 addr add "fd77::$i/64" dev na-t1 nodad; done
for ns in "$SRV" "$CLI"; do ip -n "$ns" link set lo up; done
ip -n "$SRV" link set na-t0 up; ip -n "$CLI" link set na-t1 up
# «контейнер» за DNAT: srv:9090 → ctr:80 (как docker -p 9090:80 в bridge-сети)
ip link add na-c0 type veth peer name na-c1
ip link set na-c0 netns "$SRV"; ip link set na-c1 netns "$CTR"
ip -n "$SRV" addr add 10.78.0.1/24 dev na-c0; ip -n "$CTR" addr add 10.78.0.2/24 dev na-c1
ip -n "$SRV" link set na-c0 up; ip -n "$CTR" link set na-c1 up; ip -n "$CTR" link set lo up
ip -n "$CTR" route add default via 10.78.0.1
ip netns exec "$SRV" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$SRV" nft -f - <<'DNAT'
table ip t_docker {
    chain pre  { type nat hook prerouting priority dstnat; policy accept; tcp dport 9090 dnat to 10.78.0.2:80; }
}
DNAT
ip netns exec "$CTR" python3 - <<'CTRPY' &
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.78.0.2", 80)); s.listen(128)
while True:
    c, _ = s.accept(); c.close()
CTRPY
CPID=$!

ip netns exec "$SRV" python3 - <<'PY' &
import socket, threading
def serve(fam, addr, port):
    s = socket.socket(fam, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port)); s.listen(512)
    while True:
        c, _ = s.accept(); c.close()
for fam, addr, port in ((socket.AF_INET, "10.77.0.1", 8443), (socket.AF_INET6, "fd77::1", 8443), (socket.AF_INET, "10.77.0.1", 22)):
    threading.Thread(target=serve, args=(fam, addr, port), daemon=True).start()
threading.Event().wait()
PY
LPID=$!
sleep 1

connects() {   # connects <src> <dst> <port> <n> → число удачных TCP-соединений
    ip netns exec "$CLI" python3 - "$@" <<'PY'
import socket, sys
src, dst, port, n, ok = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), 0
fam = socket.AF_INET6 if ":" in dst else socket.AF_INET
for _ in range(n):
    s = socket.socket(fam, socket.SOCK_STREAM); s.settimeout(0.7)
    try:
        s.bind((src, 0)); s.connect((dst, port)); ok += 1
    except OSError:
        pass
    finally:
        s.close()
print(ok)
PY
}
elems() {   # elems <set|meter> <имя> → число адресов в наборе
    ip netns exec "$SRV" nft list "$1" inet na_filter "$2" 2>/dev/null | sed -n '/elements = {/,/^[[:space:]]*}/p' \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}|fd77::[0-9a-f]+' | sort -u | wc -l | tr -d ' '
}
in_set() { ip netns exec "$SRV" nft get element inet na_filter "$1" "{ $2 }" >/dev/null 2>&1; }

PASS=0; FAIL=0
check() { if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); echo "  ok   $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1: ожидалось [$2], получено [$3]"; fi; }
ok_()   { PASS=$((PASS+1)); echo "  ok   $1"; }
fail_() { FAIL=$((FAIL+1)); echo "  FAIL $1"; }

echo "== 0. контроль: meter без timeout на полном наборе режет новых (схема ≤4.1.2) =="
ip netns exec "$SRV" nft -f - <<'LEGACY'
table inet na_filter {
    chain input {
        type filter hook input priority filter; policy accept;
        tcp dport 8443 ct state new meter syn4_8443 size 4 { ip saddr limit rate 200/second burst 400 packets } accept
        tcp dport 8443 ct state new drop
    }
}
LEGACY
okc=0
for i in $(seq 11 16); do okc=$(( okc + $(connects "10.77.0.$i" 10.77.0.1 8443 1) )); done
check "из 6 новых адресов прошли только 4 (размер набора) — отказ воспроизведён" 4 "$okc"

echo "== 1. ruleset 4.1.3 встаёт поверх живой таблицы со старыми meter =="
if ip netns exec "$SRV" nft -f "$T/ruleset.nft"; then ok_ "nft -f поверх таблицы с meter прошёл"; else fail_ "nft -f поверх таблицы с meter НЕ прошёл"; exit 1; fi

echo "== 2. наборы-лимитеры объявлены с timeout =="
for st in syn4_8443 syn6_8443 udp4_8443 ssh4 sshs4 icmp4 ps4; do
    hdr="$(ip netns exec "$SRV" nft list set inet na_filter "$st" 2>/dev/null | grep -E 'flags|timeout' | tr -s '\t ' ' ')"
    if [[ "$hdr" == *"dynamic,timeout"* && "$hdr" == *" timeout "* ]]; then ok_ "$st: flags dynamic,timeout + timeout"
    else fail_ "$st: нет timeout в объявлении набора ($hdr)"; fi
done

echo "== 3. лимит действует: сверх burst $BURST при $RATE/с новые SYN дропаются =="
okr="$(connects 10.77.0.19 10.77.0.1 8443 10)"
[[ "$okr" -lt 10 ]] && ok_ "из 10 быстрых соединений прошли не все (лимит сработал), прошло $okr" || fail_ "лимит не сработал: прошло $okr из 10"
[[ "$okr" -ge "$BURST" ]] && ok_ "burst отработал: прошло не меньше $BURST ($okr)" || fail_ "burst не отработал: прошло $okr < $BURST"
cnt() { ip netns exec "$SRV" nft list counter inet na_filter "$1" 2>/dev/null | grep -oE 'packets [0-9]+' | grep -oE '[0-9]+' | head -1; }
drops="$(cnt c_synflood)"
[[ "${drops:-0}" -gt 0 ]] && ok_ "именованный счётчик c_synflood вырос (${drops})" || fail_ "счётчик c_synflood не вырос"

echo "== 4. записи истекают после простоя (timeout ${SET_TO}s) =="
for _ in $(seq 1 20); do [[ "$(elems set syn4_8443)" == 0 ]] && break; sleep 1; done
check "набор syn4_8443 пуст после простоя" 0 "$(elems set syn4_8443)"
# листинг прячет истёкшие записи сразу, а счётчик набора ядро уменьшает только на сборке
# мусора (отложенно) — даём ей пройти, иначе тест ниже увидел бы «полный» набор раньше
sleep 5

echo "== 5. полный набор НЕ режет новых клиентов (fail-open), v4 и v6 =="
okc=0
for i in $(seq 11 18); do okc=$(( okc + $(connects "10.77.0.$i" 10.77.0.1 8443 1) )); done
check "v4: 8 новых адресов при наборе на $SIZE — все соединились" 8 "$okc"
check "v4: в наборе ровно $SIZE записей (потолок)" "$SIZE" "$(elems set syn4_8443)"
okc=0
for i in $(seq 11 18); do okc=$(( okc + $(connects "fd77::$i" fd77::1 8443 1) )); done
check "v6: 8 новых адресов при наборе на $SIZE — все соединились" 8 "$okc"

echo "== 6. SSH: ban-once и полный набор =="
# .19: burst 2, ещё 3 попытки сверх — это не перебор: suspect, но БЕЗ бана (v4.2)
connects 10.77.0.19 10.77.0.1 22 5 >/dev/null
in_set suspect_v4 10.77.0.19 && ok_ "пара лишних попыток → suspect" || fail_ "лишние попытки не дали suspect"
in_set autoban_v4 10.77.0.19 && fail_ "пара лишних попыток → бан (ban-once банит с первого превышения)" || ok_ "пара лишних попыток — без бана"
# .20: настоящий перебор — сверх лимита и дальше, пока suspect → бан
connects 10.77.0.20 10.77.0.1 22 14 >/dev/null
in_set autoban_v4 10.77.0.20 && ok_ "перебор SSH: адрес в autoban (suspect → повторный перебор → бан)" || fail_ "перебор SSH не привёл к бану"
[[ "$(cnt c_sshflood)" -gt 0 ]] && ok_ "счётчик c_sshflood вырос" || fail_ "счётчик c_sshflood не вырос"
# ssh4 полон (.19, .20 + два новых), новые адреса — под общий потолок 30/мин, а не открытая дверь
for i in 11 12; do connects "10.77.0.$i" 10.77.0.1 22 1 >/dev/null; done
check "ssh4 заполнен до $SIZE" "$SIZE" "$(elems set ssh4)"
okc=0
for i in 14 15 16 17; do okc=$(( okc + $(connects "10.77.0.$i" 10.77.0.1 22 1) )); done
check "полный ssh4: новые адреса проходят по общему потолку" 4 "$okc"
in_set autoban_v4 10.77.0.14 && fail_ "полный ssh4: невиновный адрес забанен" || ok_ "полный ssh4: без бана невиновных"

echo "== 7. опубликованный (DNAT) порт: вердикты по источнику в forward =="
check "DNAT: обычный адрес проходит к «контейнеру»" 1 "$(connects 10.77.0.18 10.77.0.1 9090 1)"
ip netns exec "$SRV" nft add element inet na_filter autoban_v4 '{ 10.77.0.18 timeout 5m }'
check "DNAT: забаненный адрес режется (до v4.2 проходил мимо na_filter)" 0 "$(connects 10.77.0.18 10.77.0.1 9090 1)"
[[ "$(cnt c_dnat_guard)" -gt 0 ]] && ok_ "счётчик c_dnat_guard вырос" || fail_ "счётчик c_dnat_guard не вырос"
ip netns exec "$SRV" nft add element inet na_filter whitelist_v4 '{ 10.77.0.18 }'
check "DNAT: whitelist сильнее autoban" 1 "$(connects 10.77.0.18 10.77.0.1 9090 1)"

echo "== 8. SYNPROXY: рукопожатие на защищённом порту завершается =="
if modprobe nft_synproxy 2>/dev/null || [[ -d /sys/module/nft_synproxy ]]; then
    ip netns exec "$SRV" sysctl -q -w net.netfilter.nf_conntrack_tcp_loose=0
    grep -q 'synproxy mss' "$T/ruleset-sp.nft" && ok_ "SYNPROXY в ruleset (не degraded: до v4.2 проверялся несуществующий модуль nf_synproxy)" \
        || fail_ "SYNPROXY-вариант сгенерирован без synproxy (degraded)"
    if ip netns exec "$SRV" nft -f "$T/ruleset-sp.nft"; then
        ok_ "SYNPROXY-ruleset загружен"
        check "соединение через synproxy устанавливается (до v4.2 — нет)" 3 "$(connects 10.77.0.13 10.77.0.1 8443 3)"
        # после synproxy соединение уже established: лимиты на `ct state new` и блок-листы ниже
        # его не видят — всё, что решается до рукопожатия, стоит перед synproxy (ревью v4.2)
        okr="$(connects 10.77.0.15 10.77.0.1 8443 10)"
        [[ "$okr" -lt 10 ]] && ok_ "SYN-rate до synproxy: из 10 быстрых прошли не все ($okr)" || fail_ "SYN-rate до synproxy не сработал: прошло $okr из 10"
        ip netns exec "$SRV" nft add element inet na_filter autoban_v4 '{ 10.77.0.16 timeout 5m }'
        check "забаненный не завершает рукопожатие через synproxy" 0 "$(connects 10.77.0.16 10.77.0.1 8443 1)"
        ip netns exec "$SRV" nft add element inet na_filter whitelist_v4 '{ 10.77.0.16 }'
        check "whitelist сильнее бана и на synproxy-порту" 1 "$(connects 10.77.0.16 10.77.0.1 8443 1)"
    else
        fail_ "SYNPROXY-ruleset не загрузился"
    fi
else
    echo "  skip (нет nft_synproxy в ядре раннера)"
fi

echo
echo "  прогон: $PASS ok, $FAIL fail"
[[ "$FAIL" -eq 0 ]] || { echo "NFT-BEHAVIOR: FAIL"; exit 1; }
echo "NFT-BEHAVIOR: OK (старая схема режет новых, новая — нет; лимит, истечение, SSH ban-once и потолок работают)"
