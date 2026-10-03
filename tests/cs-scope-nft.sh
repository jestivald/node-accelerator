#!/usr/bin/env bash
#
# cs-scope-nft.sh — правило CROWDSEC_SCOPE=ssh на НАСТОЯЩЕМ nft (root или CAP_NET_ADMIN).
#
# protect-unit подменяет nft и сверяет текст. Здесь — что файл, который генерирует
# crowdsec_scope_apply, грузится nft этой ОС (0.9.3 на Ubuntu 20.04, 0.9.8 на Debian 11,
# 1.x дальше), что whitelist-набор с auto-merge принимает адрес внутри CIDR из того же
# WHITELIST, что правка живого набора так, как её делает `na-fw allow`, проходит, и что
# повторная загрузка файла (ре-ран/юнит на буте) идемпотентна. Bouncer'а здесь нет —
# systemctl стаб; переключение на настоящем bouncer'е проверяет crowdsec-e2e.sh.
#
# CI: smoke-матрица (контейнер --privileged) и job nft-behavior. Запуск: sudo bash tests/cs-scope-nft.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$(uname -s)" == Linux ]] || { echo "SKIP: нужен Linux (nftables)"; exit 0; }
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "[x] нужен root (sudo bash $0)"; exit 1; }
command -v nft >/dev/null || { echo "[x] нет nft"; exit 1; }

T="$(mktemp -d)"
TB4=na_t_cs; TB6=na_t_cs6
cleanup() { nft delete table ip "$TB4" 2>/dev/null || true; nft delete table ip6 "$TB6" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
mkdir -p "$T/bin" "$T/conf" "$T/sys" "$T/backup" "$T/state"
cat > "$T/bouncer.yaml" <<YML
mode: nftables
blacklists_ipv4: na-t-blacklists
blacklists_ipv6: na-t6-blacklists
nftables:
  ipv4:
    enabled: true
    set-only: false
    table: $TB4
    chain: crowdsec-chain
  ipv6:
    enabled: true
    set-only: false
    table: $TB6
    chain: crowdsec6-chain
YML
printf '#!/bin/sh\nexit 0\n' > "$T/bin/systemctl"; printf '#!/bin/sh\nexit 0\n' > "$T/bin/sleep"
chmod +x "$T/bin"/*
# секция protect.sh как есть; юнит — в песочницу. `nft list set` после «старта bouncer'а»
# найдёт набор, который создал наш же файл: стаб systemctl отвечает «active».
sed -n '/^# ─── Область действия блок-листов CrowdSec/,/^# ─── Сейфти-таймер/p' "$REPO_ROOT/scripts/protect.sh" | sed '$d' \
    | sed -e "s#/etc/systemd/system/#$T/sys/#g" > "$T/scope.sh"
[[ -s "$T/scope.sh" ]] || { echo "[x] нет секции CROWDSEC_SCOPE в protect.sh"; exit 1; }

PASS=0; FAIL=0
check() { if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); echo "  ok   $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1: ожидалось [$2], получено [$3]"; fi; }
echo "== nft $(nft --version 2>/dev/null | head -1)"

apply() {
    PATH="$T/bin:$PATH" bash -c "set -euo pipefail
. '$REPO_ROOT/scripts/lib/common.sh'
CONF_DIR='$T/conf'; STATE_DIR='$T/state'; BACKUP='$T/backup'; CS_BOUNCER_YAML='$T/bouncer.yaml'
CROWDSEC_SCOPE=ssh; SSH_NFT='22, 2200'; SSH_EFF='22,2200'
# адрес внутри CIDR из того же списка: без auto-merge старый nft отказывал (conflicting intervals)
WL4='198.51.100.0/24, 198.51.100.7, 203.0.113.7'; WL6='2001:db8::/64, 2001:db8::5'
. '$T/scope.sh'
crowdsec_scope_apply
echo \"EFF=\$CROWDSEC_SCOPE_EFF\"" 2>&1
}
OUT="$(apply)"
check "файл scope прошёл nft -c и загружен (EFF=ssh)" 1 "$(grep -c '^EFF=ssh$' <<<"$OUT")"
[[ "$OUT" == *"EFF=ssh"* ]] || printf '%s\n' "$OUT"
check "дроп по блок-листу — только на SSH-портах" 1 \
      "$(nft list chain ip "$TB4" na-scope-input 2>/dev/null | grep -cE 'tcp dport \{ 22, 2200 \} ip saddr @na-t-blacklists')"
check "v4-whitelist: CIDR в живом наборе" 1 "$(nft list set ip "$TB4" na_wl4 2>/dev/null | grep -c '198.51.100.0/24')"
check "v6-whitelist: CIDR в живом наборе" 1 "$(nft list set ip6 "$TB6" na_wl6 2>/dev/null | grep -c '2001:db8::/64')"
# bouncer добавляет решения с timeout — набор обязан это принимать
rc=0; nft add element ip "$TB4" na-t-blacklists '{ 192.0.2.10 timeout 1h }' || rc=$?
check "в набор блок-листа добавляется адрес с timeout (как это делает bouncer)" 0 "$rc"
# na-fw allow: flush + add element в живой набор (тем же текстом, что генерирует na-fw)
rc=0; printf 'flush set ip %s na_wl4\nadd element ip %s na_wl4 { 203.0.113.7, 198.51.100.0/24, 198.51.100.9 }\n' "$TB4" "$TB4" | nft -f - || rc=$?
check "правка живого набора как в na-fw allow (с адресом внутри CIDR)" 0 "$rc"
# ре-ран / юнит na-crowdsec-scope на буте: тот же файл поверх живой таблицы
rc=0; nft -f "$T/conf/na-crowdsec-scope.nft" || rc=$?
check "повторная загрузка файла поверх живой таблицы" 0 "$rc"
check "…и после неё правило на месте (одно)" 1 \
      "$(nft list chain ip "$TB4" na-scope-input 2>/dev/null | grep -c 'ip saddr @na-t-blacklists')"

echo
echo "  прогон: $PASS ok, $FAIL fail"
[[ "$FAIL" -eq 0 ]] || { echo "CS-SCOPE-NFT: FAIL"; exit 1; }
echo "CS-SCOPE-NFT: OK (файл правила CROWDSEC_SCOPE=ssh грузится этим nft, whitelist с auto-merge, правка как в na-fw)"
