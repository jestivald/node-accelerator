#!/usr/bin/env bash
#
# nft-behavior.sh — поведение per-IP лимитеров на НАСТОЯЩЕМ nft/ядре (два netns + veth).
#
# Юнит-тесты сверяют текст ruleset; здесь проверяется то, что текст не доказывает:
#   1. наборы-лимитеры создаются с timeout (записи истекают, а не копятся до ребута);
#   2. ПОЛНЫЙ набор не режет новых клиентов (fail-open): до v4.1.3 meter без timeout на
#      65535 записях отсекал каждый новый адрес — `… accept` для него не срабатывал, и
#      пакет падал в `ct state new drop` (аудит флота: 22 764 адреса за 32 дня аптайма);
#   3. после простоя записи истекают, и лимит снова действует;
#   4. сам лимит работает: сверх burst новые SYN с одного адреса дропаются.
# Размер набора и timeout ужаты ручками NA_RATE_SET_SIZE/NA_RATE_TO_SEC, чтобы проверить
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
    ip netns del "$SRV" 2>/dev/null || true
    ip netns del "$CLI" 2>/dev/null || true
    rm -rf "$T"
}
trap cleanup EXIT

# ── 1. Генерация ruleset тем же protect.sh (DRY_RUN: генерация + nft -c на этом ядре) ──
cp -R "$REPO_ROOT/scripts" "$T/scripts"
cat >> "$T/scripts/lib/common.sh" <<'STUB'
apt_install(){ :; }
default_iface(){ echo na-wan0; }
detect_ssh_port(){ echo 22; }
ssh_client_ip(){ :; }
STUB
SIZE=4; TO=3s; RATE=2; BURST=3
OUT="$(TERM=dumb NA_NO_LOCK=1 DRY_RUN=1 REMNAWAVE_NONINTERACTIVE=1 ENABLE_CROWDSEC=0 \
       TCP_PORTS=8443 UDP_PORTS=8443 NODE_PORT=2222 NODE_PORT_WHITELIST_ONLY=0 \
       SYN_RATE=$RATE SYN_BURST=$BURST NA_RATE_SET_SIZE=$SIZE NA_RATE_TO_SEC=$TO \
       bash "$T/scripts/protect.sh" 2>&1)" || { echo "$OUT" | tail -20; echo "[x] генерация/nft -c не прошли"; exit 1; }
F="$(sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' <<<"$OUT" | sed -nE 's/.*Генерация nftables → (\/tmp\/na_filter\.[A-Za-z0-9]+\.nft).*/\1/p' | tail -1)"
[[ -n "$F" && -s "$F" ]] || { echo "[x] не нашёл сгенерированный ruleset"; echo "$OUT" | tail -20; exit 1; }
cp "$F" "$T/ruleset.nft"; rm -f "$F"

# ── 2. Стенд: srv (ruleset) ←veth→ cli (10 адресов-источников) ─────────────────
ip netns add "$SRV"; ip netns add "$CLI"
ip link add na-t0 type veth peer name na-t1
ip link set na-t0 netns "$SRV"; ip link set na-t1 netns "$CLI"
ip -n "$SRV" addr add 10.77.0.1/24 dev na-t0
for i in $(seq 11 20); do ip -n "$CLI" addr add "10.77.0.$i/24" dev na-t1; done
for ns in "$SRV" "$CLI"; do ip -n "$ns" link set lo up; done
ip -n "$SRV" link set na-t0 up; ip -n "$CLI" link set na-t1 up
ip netns exec "$SRV" nft -f "$T/ruleset.nft"

ip netns exec "$SRV" python3 - <<'PY' &
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.77.0.1", 8443)); s.listen(512)
while True:
    c, _ = s.accept(); c.close()
PY
LPID=$!
sleep 1

connects() {   # connects <src-ip> <n> → печатает число удачных TCP-соединений
    ip netns exec "$CLI" python3 - "$1" "$2" <<'PY'
import socket, sys
src, n, ok = sys.argv[1], int(sys.argv[2]), 0
for _ in range(n):
    try:
        socket.create_connection(("10.77.0.1", 8443), timeout=0.7, source_address=(src, 0)).close(); ok += 1
    except OSError:
        pass
print(ok)
PY
}
elems() { ip netns exec "$SRV" nft list set inet na_filter "$1" | sed -n '/elements = {/,/}/p' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l | tr -d ' '; }

PASS=0; FAIL=0
check() { if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); echo "  ok   $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1: ожидалось [$2], получено [$3]"; fi; }
cond()  { if eval "$2"; then PASS=$((PASS+1)); echo "  ok   $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1 ($2)"; fi; }

echo "== наборы-лимитеры объявлены с timeout =="
for st in syn4_8443 udp4_8443 ssh4 icmp4 ps4; do
    hdr="$(ip netns exec "$SRV" nft list set inet na_filter "$st" 2>/dev/null | grep -E 'flags|timeout' | tr -s '\t ' ' ')"
    if [[ "$hdr" == *"dynamic,timeout"* && "$hdr" == *" timeout "* ]]; then
        PASS=$((PASS+1)); echo "  ok   $st: flags dynamic,timeout + timeout"
    else
        FAIL=$((FAIL+1)); echo "  FAIL $st: нет timeout в объявлении набора ($hdr)"
    fi
done

echo "== полный набор НЕ режет новых клиентов (fail-open) =="
okc=0
for i in $(seq 11 18); do okc=$(( okc + $(connects "10.77.0.$i" 1) )); done
check "8 новых адресов при наборе на $SIZE — все соединились" 8 "$okc"
check "в наборе ровно $SIZE записей (потолок)" "$SIZE" "$(elems syn4_8443)"

echo "== записи истекают после простоя ($TO) =="
sleep 5
check "набор syn4_8443 пуст после простоя" 0 "$(elems syn4_8443)"

echo "== лимит действует: сверх burst $BURST при $RATE/с новые SYN дропаются =="
okr="$(connects 10.77.0.19 10)"
cond "из 10 быстрых соединений прошли не все (лимит сработал), получено $okr" '[[ "$okr" -lt 10 ]]'
cond "burst отработал: прошло не меньше $BURST, получено $okr" '[[ "$okr" -ge '"$BURST"' ]]'
drops="$(ip netns exec "$SRV" nft list chain inet na_filter synflood_drop | grep -oE 'counter packets [0-9]+' | grep -oE '[0-9]+' | head -1)"
cond "счётчик synflood_drop вырос (${drops:-0})" '[[ "${drops:-0}" -gt 0 ]]'

echo
echo "  прогон: $PASS ok, $FAIL fail"
[[ "$FAIL" -eq 0 ]] || { echo "NFT-BEHAVIOR: FAIL"; exit 1; }
echo "NFT-BEHAVIOR: OK (лимитеры с timeout, полный набор не режет клиентов, лимит работает)"
