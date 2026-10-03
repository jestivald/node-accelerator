#!/usr/bin/env bash
#
# crowdsec-e2e.sh — переключение CROWDSEC_SCOPE на НАСТОЯЩЕМ crowdsec-firewall-bouncer
# (root, systemd, пакеты crowdsec + crowdsec-firewall-bouncer-nftables уже стоят и запущены).
#
# Регрессия блокера v4.2: protect грузил свою таблицу и делал `restart` bouncer'а. Старый
# процесс (обычный режим) на выходе удалял таблицу — уже нашу; новый в set-only её не
# находил и не стартовал: CrowdSec не блокировал ничего, даже SSH. Юнит-тест подменяет
# systemctl и nft и этого не видит — поэтому здесь настоящий bouncer:
#   ssh  → bouncer active, наша цепочка на месте, решения доезжают в набор (и новые тоже);
#   ssh  → повтор (ре-ран protect) не роняет bouncer;
#   all  → bouncer снова ставит свои правила, нашей цепочки нет;
#   ssh  → и обратно.
#
# CI: job crowdsec-e2e. Запуск: sudo bash tests/crowdsec-e2e.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "[x] нужен root (sudo bash $0)"; exit 1; }
Y=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
for c in nft cscli systemctl; do command -v "$c" >/dev/null || { echo "[x] нет $c"; exit 1; }; done
[[ -f "$Y" ]] || { echo "[x] нет $Y (crowdsec-firewall-bouncer-nftables не установлен?)"; exit 1; }

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/backup"
sed -n '/^# ─── Область действия блок-листов CrowdSec/,/^# ─── Сейфти-таймер/p' "$REPO_ROOT/scripts/protect.sh" | sed '$d' > "$T/scope.sh"
[[ -s "$T/scope.sh" ]] || { echo "[x] нет секции CROWDSEC_SCOPE в protect.sh"; exit 1; }

PASS=0; FAIL=0
check() { if [[ "$2" == "$3" ]]; then PASS=$((PASS+1)); echo "  ok   $1"; else FAIL=$((FAIL+1)); echo "  FAIL $1: ожидалось [$2], получено [$3]"; fi; }
active() { systemctl is-active --quiet crowdsec-firewall-bouncer; }
wait_for() {   # wait_for <сек> <команда…> — ждать, пока команда не вернёт 0
    local n="$1"; shift
    while (( n-- > 0 )); do "$@" && return 0; sleep 1; done
    return 1
}
in_table() { nft list table ip "$T4" 2>/dev/null | grep -qF "$1"; }
in_set()   { nft list set ip "$T4" "$S4" 2>/dev/null | grep -qF "$1"; }
apply() {
    bash -c "set -euo pipefail
. '$REPO_ROOT/scripts/lib/common.sh'
BACKUP='$T/backup'; CROWDSEC_SCOPE='$1'; SSH_NFT='22'; SSH_EFF='22'; WL4='203.0.113.7'; WL6=''
mkdir -p \"\$CONF_DIR\" \"\$STATE_DIR\"
. '$T/scope.sh'
crowdsec_scope_apply
echo \"EFF=\$CROWDSEC_SCOPE_EFF\"" 2>&1
}
dump() { echo "---- bouncer:"; systemctl status crowdsec-firewall-bouncer --no-pager -l 2>&1 | tail -15 || true
         journalctl -u crowdsec-firewall-bouncer -n 30 --no-pager 2>&1 || true; nft list tables 2>&1 || true; }

T4="$(awk '/^nftables:/{n=1} n && $1=="ipv4:"{f=1} f && $1=="table:"{print $2; exit}' "$Y")"; T4="${T4:-crowdsec}"
S4="$(awk -F': *' '$1=="blacklists_ipv4"{gsub(/[" ]/,"",$2); print $2; exit}' "$Y")"; S4="${S4:-crowdsec-blacklists}"
echo "== bouncer $(crowdsec-firewall-bouncer -V 2>&1 | head -1 || true); таблица $T4, набор $S4"
grep -nE '^[[:space:]]+set-only:' "$Y" || echo "  (в конфиге нет set-only — старый bouncer, ждём откат на all)"

echo "== 0. исходно: bouncer в обычном режиме, решение доезжает"
wait_for 60 active || { dump; echo "[x] bouncer не active после установки"; exit 1; }
cscli decisions add --ip 198.51.100.77 --duration 2h --reason na-e2e >/dev/null
wait_for 40 in_table 198.51.100.77 && check "обычный режим: решение в таблице bouncer'а" 1 1 \
    || { check "обычный режим: решение в таблице bouncer'а" 1 0; dump; }

# diagnose/na-report считают решения через `decisions list [-a] --limit 0 -o raw`: флаг должен
# приниматься этим cscli, а строки данных — начинаться с числового id (как разбирает awk)
rc=0; raw="$(cscli decisions list -a --limit 0 -o raw 2>&1)" || rc=$?
check "cscli принимает --limit 0 (-a, -o raw)" 0 "$rc"
check "…строка решения с числовым id и нашим адресом" 1 \
      "$(awk -F, '$1 ~ /^[0-9]+$/ && /198\.51\.100\.77/ {c++} END {print (c > 0)}' <<<"$raw")"

for step in "1:ssh" "2:ssh" "3:all" "4:ssh"; do
    n="${step%%:*}"; want="${step#*:}"
    echo "== $n. CROWDSEC_SCOPE=$want"
    OUT="$(apply "$want")"
    check "$n: итоговая область = $want" "EFF=$want" "$(grep -oE '^EFF=[a-z]*$' <<<"$OUT" | tail -1)"
    if active; then check "$n: bouncer active" 1 1; else check "$n: bouncer active" 1 0; printf '%s\n' "$OUT"; dump; fi
    if [[ "$want" == ssh ]]; then
        check "$n: наша цепочка na-scope-input на месте" 1 "$(nft list chain ip "$T4" na-scope-input 2>/dev/null | grep -c "@$S4")"
        wait_for 40 in_set 198.51.100.77 && check "$n: старое решение доехало в набор (set-only)" 1 1 \
            || { check "$n: старое решение доехало в набор (set-only)" 1 0; dump; }
    else
        check "$n: нашей цепочки нет" 0 "$(nft list chain ip "$T4" na-scope-input >/dev/null 2>&1 && echo 1 || echo 0)"
        wait_for 40 in_table 198.51.100.77 && check "$n: bouncer снова держит решения сам" 1 1 \
            || { check "$n: bouncer снова держит решения сам" 1 0; dump; }
    fi
    if [[ "$n" == 2 ]]; then
        cscli decisions add --ip 198.51.100.78 --duration 2h --reason na-e2e >/dev/null
        wait_for 40 in_set 198.51.100.78 && check "2: новое решение доезжает в set-only" 1 1 \
            || { check "2: новое решение доезжает в set-only" 1 0; dump; }
    fi
done
apply all >/dev/null 2>&1 || true
cscli decisions delete --ip 198.51.100.77 >/dev/null 2>&1 || true
cscli decisions delete --ip 198.51.100.78 >/dev/null 2>&1 || true

echo
echo "  прогон: $PASS ok, $FAIL fail"
[[ "$FAIL" -eq 0 ]] || { echo "CROWDSEC-E2E: FAIL"; exit 1; }
echo "CROWDSEC-E2E: OK (ssh↔all на настоящем bouncer'е: не падает, решения доезжают в обе стороны)"
