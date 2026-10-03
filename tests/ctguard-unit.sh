#!/usr/bin/env bash
#
# ctguard-unit.sh — ИСПОЛНЯЕТ сгенерированный protect.sh хелпер `na-ctguard` против
# стабов ss/conntrack/nft/logger. Модуль решает, кого выкинуть с ноды, и делает это
# `conntrack -D`, то есть ошибка в его арифметике рвёт живые пользовательские сессии —
# а до этого теста он не исполнялся нигде.
#
# Что стережём (оба сценария — из issue #22, воспроизведены на боевой ноде):
#   1. live-lookup видит сокеты, когда сервис слушает на `*:443`: ss печатает пиров как
#      `[::ffff:1.2.3.4]`, conntrack — голым `1.2.3.4`. Без нормализации live читается
#      как 0 ВСЕГДА, и LIVE_FLOOR (вся CGNAT-защита) не срабатывает ни разу;
#   2. собственный адрес ноды не попадает в кандидаты: первый `src=` в записи conntrack
#      это клиент только для входящих, а для исходящих — сама нода, и на relay они
#      преобладают. Иначе нода банит себя и сносит стейт всех проксируемых сессий;
#   3. приватные диапазоны (docker-бриджи, туннельные плечи) тоже не кандидаты;
#   4. настоящий фантом-холдер по-прежнему эвиктится.
#
# Не требует root/сети/systemd. Запуск: bash tests/ctguard-unit.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/conf" "$T/rec"

SELF_IP='198.51.100.7'      # адрес самой ноды
PHANTOM='203.0.113.66'      # холдер без живых сокетов — законный кандидат
LEGIT='192.0.2.55'          # клиент за CGNAT: много conntrack, но есть живые сокеты
DOCKER='172.17.0.4'         # контейнерный бридж
DNATCLI='192.0.2.77'        # клиент второго тенанта: DNAT в контейнер, сокеты в его netns

# ── Достаём хелпер из heredoc protect.sh ────────────────────────────────────────
awk "/cat > \/usr\/local\/sbin\/na-ctguard <<'CTG'/{f=1;next} f&&/^CTG\$/{exit} f" \
    "$REPO_ROOT/scripts/protect.sh" > "$T/na-ctguard.raw"
[ -s "$T/na-ctguard.raw" ] || { echo "[x] не смог извлечь na-ctguard из protect.sh"; exit 1; }
sed -e "s#/etc/node-accelerator#$T/conf#g" "$T/na-ctguard.raw" > "$T/na-ctguard"
chmod +x "$T/na-ctguard"

export REC="$T/rec"

# ── Стабы ───────────────────────────────────────────────────────────────────────
# ss: established-пиры приходят v4-mapped (сервис слушает на `*:443`) — как на живой ноде
cat > "$T/bin/ss" <<SS
#!/bin/sh
case "\$*" in
  *-tnH*) i=0; while [ \$i -lt 40 ]; do
            echo "0 0 [::ffff:$SELF_IP]:443 [::ffff:$LEGIT]:\$((40000+i))"; i=\$((i+1)); done ;;
  *) echo "" ;;
esac
SS

# conntrack: исходящие ноды (первый src= = сам бокс) заведомо преобладают, как на relay
cat > "$T/bin/conntrack" <<CT
#!/bin/sh
printf '%s\n' "\$*" >> "$REC/conntrack.argv"
case "\$*" in
  *-D*) exit 0 ;;
esac
i=0; while [ \$i -lt 5000 ]; do
  echo "ipv4 2 tcp 6 431999 ESTABLISHED src=$SELF_IP dst=1.1.1.1 sport=\$((30000+i)) dport=443"
  i=\$((i+1)); done
i=0; while [ \$i -lt 4500 ]; do
  echo "ipv4 2 tcp 6 7440 ESTABLISHED src=$PHANTOM dst=$SELF_IP sport=\$((40000+i)) dport=443"
  i=\$((i+1)); done
i=0; while [ \$i -lt 4200 ]; do
  echo "ipv4 2 tcp 6 7440 ESTABLISHED src=$LEGIT dst=$SELF_IP sport=\$((50000+i)) dport=443"
  i=\$((i+1)); done
i=0; while [ \$i -lt 4100 ]; do
  echo "ipv4 2 tcp 6 7440 ESTABLISHED src=$DOCKER dst=$SELF_IP sport=\$((60000+i)) dport=443"
  i=\$((i+1)); done
# DNAT: reply-src (контейнер) ≠ orig-dst (адрес ноды) — живые сокеты не в netns хоста
i=0; while [ \$i -lt 4300 ]; do
  echo "ipv4 2 tcp 6 7440 ESTABLISHED src=$DNATCLI dst=$SELF_IP sport=\$((20000+i)) dport=8443 src=172.31.250.2 dst=$DNATCLI sport=443 dport=\$((20000+i)) [ASSURED]"
  i=\$((i+1)); done
CT

cat > "$T/bin/ip" <<IP
#!/bin/sh
echo "2: eth0    inet $SELF_IP/24 scope global eth0\\       valid_lft forever"
IP

# nft: whitelist пуст (кандидатов ничто не щадит), add element — записываем
cat > "$T/bin/nft" <<NFT
#!/bin/sh
printf '%s\n' "\$*" >> "$REC/nft.argv"
case "\$*" in
  *"get element"*) exit 1 ;;
  *"list table"*)  exit 0 ;;
esac
exit 0
NFT

cat > "$T/bin/logger" <<LOG
#!/bin/sh
shift 2 2>/dev/null || true
printf '%s\n' "\$*" >> "$REC/logger.txt"
LOG

chmod +x "$T/bin"/*
export PATH="$T/bin:$PATH"

# conntrack_count читается из /proc — подсовываем свой путь через коарс-гейт:
# PHANTOM_MIN опускаем так, чтобы гейт прошёл на стабовых объёмах.
mkdir -p "$T/conf"
cat > "$T/conf/ctguard.conf" <<CONF
NA_CTG_ENFORCE=1
NA_CTG_PHANTOM_MIN=1000
NA_CTG_LIVE_FLOOR=2
NA_CTG_COARSE_MULT=3
CONF

# /proc/sys/.../nf_conntrack_count на маке нет: хелпер прочитает его как 0 и выйдет по
# коарс-гейту. Подменяем чтение на фиксированное значение.
sed -i.bak "s#cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null#echo 17800#" "$T/na-ctguard"

FAILED=0
chk() { if eval "$2"; then echo "  ✔ $1"; else echo "  ✘ $1"; FAILED=1; fi; }

echo "== ctguard: разбор кандидатов =="
bash "$T/na-ctguard" >/dev/null 2>&1 || true
LOGTXT="$(cat "$REC/logger.txt" 2>/dev/null || true)"
CTARGV="$(cat "$REC/conntrack.argv" 2>/dev/null || true)"

chk "фантом-холдер попал в эвикт" \
    "grep -q 'evict $PHANTOM' <<<\"\$LOGTXT\""
chk "собственный адрес ноды НЕ эвиктится (иначе рвёт все проксируемые сессии)" \
    "! grep -q 'evict $SELF_IP' <<<\"\$LOGTXT\""
chk "conntrack -D НЕ вызывался по своему адресу" \
    "! grep -q -- '-D -s $SELF_IP' <<<\"\$CTARGV\""
chk "приватный адрес контейнера НЕ эвиктится" \
    "! grep -q 'evict $DOCKER' <<<\"\$LOGTXT\""
chk "клиент за DNAT (второй тенант) НЕ фантом — его сокеты в netns контейнера (v4.2)" \
    "! grep -q '$DNATCLI' <<<\"\$LOGTXT\""
chk "клиент с живыми сокетами пощажён (live-lookup видит ::ffff:-пиров)" \
    "! grep -q 'evict $LEGIT' <<<\"\$LOGTXT\""
chk "live у клиента с сокетами прочитан НЕ как 0 (ровно баг #22)" \
    "! grep -qE '${LEGIT}[^0-9].*live=0' <<<\"\$LOGTXT\""

if [[ "$FAILED" -eq 0 ]]; then
    echo "CTGUARD-UNIT: OK (::ffff: нормализуется, свои и приватные адреса не кандидаты, фантом эвиктится)"
else
    echo "CTGUARD-UNIT: FAILED"; exit 1
fi
