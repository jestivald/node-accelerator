#!/usr/bin/env bash
#
# protect.sh — 🛡 Защита ноды.
#   • nftables (своя таблица inet na_filter, БЕЗ flush ruleset — сосуществует с
#     CrowdSec-bouncer и Docker-NAT):
#       AntiScan (portscan→autoban), flag-drop (XMAS/NULL/SYN+FIN/SYN+RST/FIN+RST/…),
#       anti-spoofing (bogon на WAN), SYN-flood + UDP-flood (per-IP rate-limit),
#       connect-flood SSH (per-IP→бан), per-IP connlimit (ct count), ICMP rate-limit.
#   • CrowdSec + crowdsec-firewall-bouncer-nftables — поведенческий IPS и community-блоклист.
#   • Авто-whitelist IP, с которого ты сейчас по SSH + сейфти-таймер от самоблокировки.
#
# Откат: scripts/rollback.sh protect
#
# ENV (всё опционально):
#   SSH_PORT, TCP_PORTS=443,2087, UDP_PORTS=443,2087
#   NODE_PORT=auto                     порт(ы) node-agent через запятую; auto = детект с
#                                      ноды (env контейнера remnawave/node → .env → ss),
#                                      не нашлось → оба известных дефолта 2222,3000
#   NODE_PORT_AUTOWL=auto              при whitelist-only пускать текущих established-пиров
#                                      node-порта отдельным сетом na_nodeport_wl_* (анти-
#                                      самоотстрел панели); auto|0|1
#   WHITELIST="1.2.3.4,5.6.7.0/24"     IP/CIDR панели/мониторинга (v4 и v6)
#   SYN_RATE=200  SYN_BURST=400        per-IP лимит новых TCP-конн./сек на сервисный порт
#   UDP_RATE=200  UDP_BURST=400        per-IP лимит UDP пакетов/сек
#   CONN_LIMIT=2048                    макс. одновременных конн. с одного IP (ct count)
#   SSH_RATE=6    SSH_BURST=5          per-IP новых SSH/мин до бана
#   SSH_BAN_TIME=24h  PORTSCAN_BAN_TIME=1h
#   PORTSCAN_LOG_RATE=60               строк [na portscan] в МИНУТУ в журнал (0 = не
#   PORTSCAN_LOG_BURST=30              логировать вовсе; на бан не влияет — он по meter'ам)
#   ENABLE_PORTSCAN_BAN=1  ENABLE_CROWDSEC=1  ENABLE_SYNPROXY=0
#   CROWDSEC_STRICT=1                  ставить CrowdSec ТОЛЬКО из пиннингованного APT-репо;
#                                      не поднялся — пропустить (0 = разрешить curl|bash)
#   UDP_BULK_PORTS=""                  порты объёмного UDP-туннеля (Hysteria2/TUIC): свой,
#   UDP_BULK_RATE=50000                намного более высокий per-IP потолок, иначе общий
#   UDP_BULK_BURST=100000              UDP_RATE душит туннель до ~2 Мбит/с
#   FW_MODE=strict|open|skip           strict: блок всех портов, кроме разрешённых (дефолт);
#                                      open: защита без блокировки прочих портов (3x-ui);
#                                      skip: nftables не трогать вообще (только CrowdSec)
#   CROWDSEC_ENROLL_KEY=...            enroll в CrowdSec Console (опц.)
#   SAFETY_DELAY=300  DRY_RUN=0  REMNAWAVE_NONINTERACTIVE=1

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

require_root
detect_os

# Один прогон protect за раз. Параллельные запуски (оркестратор из панели + руками)
# не рвут nft-транзакцию, но перекрываются сейфти-таймером: таймер прогона A удалит
# таблицу, которую прогон B уже применил и подтвердил. NA_NO_LOCK=1 — отключить.
if [[ "${NA_NO_LOCK:-0}" != "1" ]] && command -v flock >/dev/null 2>&1 && mkdir -p "$STATE_DIR" 2>/dev/null; then
    exec 9>"$STATE_DIR/protect.lock"
    flock -n 9 || { err "уже идёт другой прогон protect.sh (лок $STATE_DIR/protect.lock) — не мешаю"; exit 1; }
fi

BACKUP="$(backup_dir)"

# SSH_PORT задан оператором (ENV сейчас) — запоминаем ДО подхвата conf: после него ключ
# «задан» всегда, и отличить намерение оператора от сохранённого автодетекта уже нельзя.
NA_SSH_PORT_ENV="${SSH_PORT:-}"

# Подхватываем сохранённый конфиг ноды (если есть): ре-ран без ENV не сбрасывает
# поднятые под эту ноду ручки на дефолты. ENV по-прежнему всё переопределяет. Пустой ENV
# значит «как в conf» (обёртка с незаданной переменной не должна молча стереть whitelist);
# явное «пусто» — слово none (WHITELIST=none, UDP_PORTS=none, NODE_PORT=none).
load_conf "$CONF_DIR/protect.conf"

# ─── Параметры ───────────────────────────────────────────────────────────────
# SSH_PORT: явный (ENV / помечен explicit в conf) — как есть. Сохранённый БЕЗ пометки —
# это автодетект прошлых версий (до v4.2 он персистился и на ре-ране побеждал новый
# детект: сменил порт sshd — strict открывал старый). Такой сверяем с фактом: совпал —
# дальше не храним; расходится — открываем ОБА и предупреждаем.
NA_SSH_DETECTED="$(detect_ssh_port)"
NA_EXPLICIT_KEYS=""
if [[ -n "$NA_SSH_PORT_ENV" ]] || conf_is_explicit "$CONF_DIR/protect.conf" SSH_PORT; then
    NA_EXPLICIT_KEYS+=" SSH_PORT"
elif [[ -n "${SSH_PORT:-}" && "$SSH_PORT" != "$NA_SSH_DETECTED" ]]; then
    warn "SSH_PORT=$SSH_PORT в protect.conf сохранён старой версией (автодетект), а sshd сейчас слушает $NA_SSH_DETECTED — открываю ОБА; закрепи нужный: SSH_PORT=<порт> ре-ран"
    for _p in ${NA_SSH_DETECTED//,/ }; do [[ ",$SSH_PORT," == *",$_p,"* ]] || SSH_PORT+=",$_p"; done
    NA_EXPLICIT_KEYS+=" SSH_PORT"
    unset _p
else
    SSH_PORT=""
fi
SSH_PORT="${SSH_PORT:-$NA_SSH_DETECTED}"
TCP_PORTS="${TCP_PORTS:-443,2087}"
UDP_PORTS="${UDP_PORTS:-443,2087}"
# Порт(ы) node-agent. 'auto' (дефолт) = взять с самой ноды: env работающего контейнера
# remnawave/node → .env compose-каталога → ss (процесс rw-node). Remnawave node 2.x
# слушает :3000, старые гайды ставили :2222 — захардкоженный дефолт при несовпадении
# МОЛЧА отрезал панель от ноды (strict: не перечисленный порт падает в catch-all drop).
# Детект не нашёл ничего и прошлых прогонов не было → правила на ОБА дефолта (2222,3000).
NODE_PORT="${NODE_PORT:-auto}"
NODE_PORT_FALLBACK="2222,3000"
NODE_PORT_LAST="${NODE_PORT_LAST:-}"    # кэш последнего удачного детекта (persist)
WHITELIST="${WHITELIST:-}"
SYN_RATE="${SYN_RATE:-200}";  SYN_BURST="${SYN_BURST:-400}"
UDP_RATE="${UDP_RATE:-200}";  UDP_BURST="${UDP_BURST:-400}"
# Порты, по которым идёт объёмный туннельный UDP (Hysteria2/TUIC), а не запросы к сервису.
# Общий UDP_RATE=200 пакетов/с на IP при ~1200 Б/пакет — это потолок около 2 Мбит/с: живая
# HY2-сессия упирается в него сразу, лишнее уходит в drop, клиент ретранслитит и видит
# огромную задержку либо N/A на хосте. Перечисленные здесь порты получают свой, намного
# более высокий per-IP потолок — настоящий флуд он всё ещё срезает. Пусто по умолчанию:
# ослабление лимита должно быть осознанным. Порт должен присутствовать и в UDP_PORTS.
UDP_BULK_PORTS="${UDP_BULK_PORTS:-}"
UDP_BULK_RATE="${UDP_BULK_RATE:-50000}"; UDP_BULK_BURST="${UDP_BULK_BURST:-100000}"
# CONN_LIMIT — потолок ОДНОВРЕМЕННЫХ конн. с одного IP. За CGNAT (мобильные операторы,
# частый кейс в RU/IR) один egress-IP агрегирует много абонентов → держим с большим
# запасом, чтобы не рубить целые операторские пулы. Реальный VLESS-юзер — десятки конн.
CONN_LIMIT="${CONN_LIMIT:-2048}"
ICMP_RATE="${ICMP_RATE:-10}"; ICMP_BURST="${ICMP_BURST:-20}"   # PER-IP (не глобально)
SSH_RATE="${SSH_RATE:-6}";    SSH_BURST="${SSH_BURST:-5}"
SSH_BAN_TIME="${SSH_BAN_TIME:-24h}"
PORTSCAN_BAN_TIME="${PORTSCAN_BAN_TIME:-1h}"
# Порог автобана за скан: банить IP только если он бьёт по закрытым портам БЫСТРЕЕ
# порога (реальный сканер). Одиночные шальные SYN из CGNAT-пула не банят весь оператор.
PORTSCAN_RATE="${PORTSCAN_RATE:-15}"; PORTSCAN_BURST="${PORTSCAN_BURST:-30}"  # /minute, per-IP
# Сколько строк `[na portscan]` в МИНУТУ пишем в журнал (единицы как у PORTSCAN_RATE).
# До v4.1 тут было 5/second — до 432 000 строк в сутки. Вместе с journald-капом, который
# ставит наш же optimize (SystemMaxUse=300M), это давало на публичной ноде ГЛУБИНУ
# журнала меньше суток: скан вытеснял историю входов, а на Debian minimal journald —
# единственный её источник (ни rsyslog, ни wtmp). Замер флота: 405 822 строки за буту,
# журнал 291.8 МБ, самая старая запись — 20 часов назад (issue #35).
# 60/минуту (≈1/с) хватает, чтобы увидеть скан и построить топ сканеров в na-report.
# 0 = лог-правило анти-скана не ставится вовсе: САМ БАН от этого не меняется — он
# работает по meter'ам (add @suspect / add @autoban), а не по строкам лога.
PORTSCAN_LOG_RATE="${PORTSCAN_LOG_RATE:-60}"; PORTSCAN_LOG_BURST="${PORTSCAN_LOG_BURST:-30}"
ENABLE_PORTSCAN_BAN="${ENABLE_PORTSCAN_BAN:-1}"
ENABLE_CROWDSEC="${ENABLE_CROWDSEC:-1}"
# CROWDSEC_STRICT=1 (дефолт с v4.0) — никакого curl|bash-фоллбэка: не поднялся
# пиннингованный репо, значит CrowdSec просто не ставим. Фоллбэк форсируется атакующим
# (достаточно сделать packagecloud недостижимым — egress-фильтр, DNS), а это подмена
# проверенного по отпечатку APT-репо на неверифицированный код из сети, запускаемый
# root'ом. Осознанно ослабить до прежнего поведения можно `CROWDSEC_STRICT=0`.
CROWDSEC_STRICT="${CROWDSEC_STRICT:-1}"
ENABLE_SYNPROXY="${ENABLE_SYNPROXY:-0}"
# Режим файрвола:
#   strict — input policy drop: открыты ТОЛЬКО SSH/сервисные/node-agent порты
#            (Remnawave node: все нужные порты известны заранее).
#   open   — вся защита (bad-flags/анти-спуф/SYN+UDP-flood/SSH-бан/CrowdSec) активна,
#            но НЕ перечисленные порты НЕ блокируются (3x-ui: inbound-порты создаются
#            из панели динамически — strict их молча отрезал бы).
#   skip   — nftables-файрвол не ставится вообще (CrowdSec/ctguard — по своим флагам);
#            печатаем инструкцию, как закрыть порты вручную.
# Пусто = спросить интерактивно (с автодетектом 3x-ui); неинтерактивно = strict.
FW_MODE="${FW_MODE:-}"
SAFETY_DELAY="${SAFETY_DELAY:-300}"
DRY_RUN="${DRY_RUN:-0}"
WAN="$(default_iface || true)"

# ── v3.0: ban-once, защита node-port, блоклисты, fleet-sync, ctguard ──────────
# ban-once: первое нарушение → suspect (наблюдение, без drop), второе в окне →
# confirmed (drop). Режет ложные баны за CGNAT. 1=вкл (дефолт), 0=сразу банить.
ENABLE_BANONCE="${ENABLE_BANONCE:-1}"
SUSPECT_TIME="${SUSPECT_TIME:-30m}"        # окно наблюдения за «подозреваемым»
# node-agent порт: открыт миру (мягкий лимит) или только whitelist. 'auto' =
# whitelist-only, если оператор задал WHITELIST (значит, знает свой доверенный набор);
# если WHITELIST пуст — оставляем мягкий лимит, чтобы не отрезать неизвестную панель.
NODE_PORT_WHITELIST_ONLY="${NODE_PORT_WHITELIST_ONLY:-auto}"
# Анти-самоотстрел панели: при whitelist-only текущие established-пиры node-порта
# (= панель, даже если её IP забыли в WHITELIST) пускаются отдельным сетом
# na_nodeport_wl_* (ТОЛЬКО этот порт, не общий whitelist) и персистятся. 'auto' =
# включено, когда whitelist-only ВЫВЕЛСЯ сам из заданного WHITELIST; при явном
# NODE_PORT_WHITELIST_ONLY=1 уважаем строгий intent (только warn). 1=форс, 0=выкл.
NODE_PORT_AUTOWL="${NODE_PORT_AUTOWL:-auto}"
NODE_PORT_PEERS="${NODE_PORT_PEERS:-}"   # персист авто-подхваченных пиров (IP через ,)
# Статич-блоклисты (Spamhaus DROP + FireHOL L1 [+ Tor]) — opt-in, обновляются таймером.
ENABLE_BLOCKLISTS="${ENABLE_BLOCKLISTS:-0}"
BLOCK_TOR="${BLOCK_TOR:-0}"
BLOCKLIST_REFRESH="${BLOCKLIST_REFRESH:-12h}"
# Remnawave fleet auto-sync: ноды флота сами держат IP друг друга в whitelist.
# 'auto' = вкл при заданных REMNAWAVE_URL+TOKEN (или REMNAWAVE_NODES_URL); 1=форс; 0=выкл.
# REMNAWAVE_NODES_URL — альтернатива БЕЗ токена панели на ноде: статический JSON того же
# вида, что /api/nodes (панель публикует кроном, доступ ограничить basic-auth/allowlist),
# либо plain-text: адрес/hostname на строку, # — комментарий. Снимает blast-radius
# полноценного API-токена, лежащего на каждой ноде.
REMNAWAVE_URL="${REMNAWAVE_URL:-}"
REMNAWAVE_TOKEN="${REMNAWAVE_TOKEN:-}"
REMNAWAVE_NODES_URL="${REMNAWAVE_NODES_URL:-}"
# Caddy Security / Tiny Auth перед панелью → заголовок X-Api-Key (как subscription-page).
# REMNAWAVE_CADDY_TOKEN — алиас (bedolaga-бот); приоритет у CADDY_AUTH_API_TOKEN.
CADDY_AUTH_API_TOKEN="${CADDY_AUTH_API_TOKEN:-${REMNAWAVE_CADDY_TOKEN:-}}"
FLEET_SYNC="${FLEET_SYNC:-auto}"
FLEET_SYNC_INTERVAL="${FLEET_SYNC_INTERVAL:-5min}"
# conntrack phantom-eviction (защита от distributed connect-and-hold) — opt-in,
# по умолчанию observe-режим (только лог, без эвикта), включать осознанно.
ENABLE_CTGUARD="${ENABLE_CTGUARD:-0}"
NA_CTG_ENFORCE="${NA_CTG_ENFORCE:-0}"
NA_CTG_PHANTOM_MIN="${NA_CTG_PHANTOM_MIN:-4000}"  # conntrack-порог «холдера» (выше CGNAT-churn)
NA_CTG_LIVE_FLOOR="${NA_CTG_LIVE_FLOOR:-2}"       # ≤ столько живых сокетов = фантом
NA_CTG_COARSE_MULT="${NA_CTG_COARSE_MULT:-3}"     # дамп conntrack только если ct ≥ ss×N
NA_CTG_BANTIME="${NA_CTG_BANTIME:-15m}"
NA_CTG_INTERVAL="${NA_CTG_INTERVAL:-20s}"
# Где действуют блок-листы CrowdSec. ssh (дефолт с v4.2) — только SSH-порт: community-лист
# CAPI (~25k адресов) на ВСЕХ портах отрезал целые пулы мобильных абонентов за CGNAT (адрес
# попал в лист за чужой перебор — аудит флота: сотни тысяч дропов клиентского трафика на
# ноде, где это не сузили руками). all — как раньше, на всех портах (bouncer сам ставит
# правила). CrowdSec на ноде парсит только журнал sshd, так что его собственные решения —
# это переборщики SSH: для них SSH-порт и есть нужная область.
CROWDSEC_SCOPE="${CROWDSEC_SCOPE:-ssh}"
# Опубликованные Docker-порты (bridge, DNAT) идут через hook forward и цепочку input не
# проходят: до v4.2 на них не действовали ни autoban, ни блок-листы, ни анти-спуф. 1 (дефолт)
# — в forward для НОВЫХ DNAT-соединений те же вердикты по источнику, что в input
# (whitelist → пропуск, autoban/blocklist/bogon → drop). 0 — forward не трогаем.
DNAT_GUARD="${DNAT_GUARD:-1}"
# Анти-амплификация: новые UDP на сервисные порты с исходных портов отражателей (DNS, NTP,
# SSDP, memcached, CLDAP, chargen) — это отражённый флуд, а не клиенты: per-IP лимиты против
# тысяч отражателей бессильны. Ответы на свои запросы ноды — established, их не касается.
UDP_AMP_DROP="${UDP_AMP_DROP:-1}"

# 3x-ui на этой машине? У него панель + inbound-порты создаются динамически —
# strict-файрвол молча отрежет всё, чего нет в TCP_PORTS/UDP_PORTS. Детект по
# типовым артефактам установщика 3x-ui/x-ui.
xui_detected() {
    [[ -f /etc/systemd/system/x-ui.service || -d /usr/local/x-ui ]] && return 0
    command -v x-ui >/dev/null 2>&1
}

if [[ -t 0 && -z "${REMNAWAVE_NONINTERACTIVE:-}" && "$DRY_RUN" != "1" && "${CROWDSEC_PROBE:-0}" != "1" ]]; then
    title "Параметры защиты"
    _fwdef="$FW_MODE"
    if [[ -z "$_fwdef" ]]; then _fwdef=strict; xui_detected && _fwdef=open; fi
    echo "Режим файрвола — блокировать ли все порты, кроме явно разрешённых:"
    echo "  1) strict — да: открыты только SSH + сервисные + node-agent порты"
    echo "              (Remnawave node: нужные порты известны заранее)"
    echo "  2) open   — нет: анти-флуд/баны/анти-спуф работают, прочие порты НЕ блокируются"
    echo "              (3x-ui: inbound-порты создаются из панели динамически)"
    echo "  3) skip   — файрвол не трогать вообще (только CrowdSec);"
    echo "              подскажу, как закрыть порты вручную"
    xui_detected && warn "Обнаружен 3x-ui: strict заблокирует панель и все не перечисленные inbound'ы!"
    _v=""; read -rp "Режим файрвола [1-3 или strict/open/skip, дефолт $_fwdef]: " _v || true
    case "${_v:-$_fwdef}" in
        1|strict) FW_MODE=strict;;
        2|open)   FW_MODE=open;;
        3|skip)   FW_MODE=skip;;
        *) warn "«$_v» не понял — беру $_fwdef"; FW_MODE="$_fwdef";;
    esac
    if [[ "$FW_MODE" != "skip" ]]; then
        read -rp "SSH порт                         [$SSH_PORT]: "  _v && SSH_PORT="${_v:-$SSH_PORT}"
        [[ -n "${_v:-}" ]] && NA_EXPLICIT_KEYS+=" SSH_PORT"
        read -rp "TCP порты сервиса (через ,)       [$TCP_PORTS]: " _v && TCP_PORTS="${_v:-$TCP_PORTS}"
        read -rp "UDP порты сервиса (через ,)       [$UDP_PORTS]: " _v && UDP_PORTS="${_v:-$UDP_PORTS}"
        # node-agent порт — понятие Remnawave; в open-режиме его правила не ставятся
        [[ "$FW_MODE" == "strict" ]] && read -rp "Порт node-agent (auto = детект)  [$NODE_PORT]: " _v && NODE_PORT="${_v:-$NODE_PORT}"
    fi
    read -rp "Whitelist IP/CIDR (панель, твои)  [пусто]: "     _v && WHITELIST="${_v:-$WHITELIST}"
fi
# Неинтерактивно и без явного FW_MODE — strict (прежнее поведение не меняется).
[[ -z "$FW_MODE" ]] && FW_MODE=strict

# none = осознанно пусто (пустой ENV — «как в conf», см. load_conf выше). В conf уходит само
# слово none — иначе на следующем прогоне вернулся бы встроенный дефолт (UDP_PORTS → 443,2087).
NA_NONE_KEYS=""
for _k in TCP_PORTS UDP_PORTS WHITELIST UDP_BULK_PORTS NODE_PORT_PEERS; do
    if [[ "${!_k:-}" == none ]]; then NA_NONE_KEYS+=" $_k"; printf -v "$_k" '%s' ""; fi
done
unset _k

# ─── Валидация ───────────────────────────────────────────────────────────────
_is_port()  { [[ "$1" =~ ^[0-9]+$ ]] && (( $1>=1 && $1<=65535 )); }
validate_port_list() {
    local v="$1" name="$2" p
    [[ -z "$v" ]] && return 0
    [[ "$v" =~ ^[0-9,]+$ ]] || { err "$name: '$v' — только цифры и запятые"; return 1; }
    for p in ${v//,/ }; do _is_port "$p" || { err "$name: '$p' вне 1..65535"; return 1; }; done
}
# SSH_PORT допускает список (sshd на двух портах — типичная миграция порта).
[[ -n "$SSH_PORT" ]] || { err "SSH_PORT пуст"; exit 1; }
validate_port_list "$SSH_PORT" SSH_PORT || exit 1
[[ "$NODE_PORT" == "auto" || "$NODE_PORT" == "none" ]] || validate_port_list "$NODE_PORT" NODE_PORT || exit 1
validate_port_list "$TCP_PORTS" TCP_PORTS || exit 1
validate_port_list "$UDP_PORTS" UDP_PORTS || exit 1
# Список, а не число: валидировать его как uint — значит уронить любой прогон с дефолтом
# (пустая строка не uint), поэтому только validate_port_list, который пустое пропускает.
validate_port_list "$UDP_BULK_PORTS" UDP_BULK_PORTS || exit 1
# кэш прошлого детекта приходит из conf — битый молча сбрасываем (уйдёт в nft-ruleset)
validate_port_list "$NODE_PORT_LAST" NODE_PORT_LAST 2>/dev/null || NODE_PORT_LAST=""

# Числовые/duration параметры тоже валидируем: они разворачиваются в nft-ruleset и
# (SAFETY_DELAY) в sh-таймер. Тулкит параметризуется неинтерактивно из панели/оркестратора,
# поэтому непровалидированный ENV здесь — не «root сам себе», а реальный вектор.
_is_uint()     { [[ "$1" =~ ^[0-9]+$ ]]; }
_is_duration() { [[ "$1" =~ ^[0-9]+(s|m|h|d)?$ ]]; }
# systemd-time (OnUnitActiveSec): один числовой терм с опц. словом-единицей. Уходит
# в .timer-юнит → валидируем, чтобы непровалидированный ENV не дописал директив.
_is_systime()  { [[ "$1" =~ ^[0-9]+(s|sec|m|min|h|hr|d|day)?$ ]]; }
for _k in SYN_RATE SYN_BURST UDP_RATE UDP_BURST UDP_BULK_RATE UDP_BULK_BURST CONN_LIMIT ICMP_RATE ICMP_BURST \
          SSH_RATE SSH_BURST PORTSCAN_RATE PORTSCAN_BURST PORTSCAN_LOG_RATE PORTSCAN_LOG_BURST SAFETY_DELAY \
          NA_CTG_PHANTOM_MIN NA_CTG_LIVE_FLOOR NA_CTG_COARSE_MULT; do
    _is_uint "${!_k}" || { err "$_k='${!_k}' — ожидается целое число"; exit 1; }
done
for _k in SSH_BAN_TIME PORTSCAN_BAN_TIME SUSPECT_TIME NA_CTG_BANTIME; do
    _is_duration "${!_k}" || { err "$_k='${!_k}' — ожидается число с опц. суффиксом s|m|h|d"; exit 1; }
done
for _k in BLOCKLIST_REFRESH FLEET_SYNC_INTERVAL NA_CTG_INTERVAL; do
    _is_systime "${!_k}" || { err "$_k='${!_k}' — ожидается systemd-интервал (напр. 12h, 5min)"; exit 1; }
done
# enum-флаги 0/1 (+auto где уместно)
for _k in ENABLE_PORTSCAN_BAN ENABLE_CROWDSEC ENABLE_SYNPROXY ENABLE_BANONCE \
          ENABLE_BLOCKLISTS BLOCK_TOR ENABLE_CTGUARD NA_CTG_ENFORCE CROWDSEC_STRICT DNAT_GUARD UDP_AMP_DROP; do
    [[ "${!_k}" =~ ^[01]$ ]] || { err "$_k='${!_k}' — ожидается 0 или 1"; exit 1; }
done
[[ "$NODE_PORT_WHITELIST_ONLY" =~ ^(auto|0|1)$ ]] || { err "NODE_PORT_WHITELIST_ONLY должно быть auto|0|1"; exit 1; }
[[ "$NODE_PORT_AUTOWL" =~ ^(auto|0|1)$ ]] || { err "NODE_PORT_AUTOWL должно быть auto|0|1"; exit 1; }
[[ "$FLEET_SYNC" =~ ^(auto|0|1)$ ]] || { err "FLEET_SYNC должно быть auto|0|1"; exit 1; }
[[ "$FW_MODE" =~ ^(strict|open|skip)$ ]] || { err "FW_MODE='$FW_MODE' — ожидается strict|open|skip"; exit 1; }
[[ "$CROWDSEC_SCOPE" =~ ^(ssh|all)$ ]] || { err "CROWDSEC_SCOPE='$CROWDSEC_SCOPE' — ожидается ssh|all"; exit 1; }
# Сейфти короче 30с снёс бы правила раньше, чем оператор успеет проверить вход (0 — сразу,
# наперегонки с nft -f и включением автозагрузки).
(( SAFETY_DELAY >= 30 )) || { err "SAFETY_DELAY=$SAFETY_DELAY — минимум 30 секунд"; exit 1; }
if [[ -n "$REMNAWAVE_URL" && ! "$REMNAWAVE_URL" =~ ^https?://[A-Za-z0-9._~:/?#=%@-]+$ ]]; then
    err "REMNAWAVE_URL='$REMNAWAVE_URL' — ожидается http(s)://… без спецсимволов"; exit 1
fi
if [[ -n "$REMNAWAVE_NODES_URL" && ! "$REMNAWAVE_NODES_URL" =~ ^https?://[A-Za-z0-9._~:/?#=%@-]+$ ]]; then
    err "REMNAWAVE_NODES_URL='$REMNAWAVE_NODES_URL' — ожидается http(s)://… без спецсимволов"; exit 1
fi
# http:// + секрет = токен уходит по проводу открытым текстом. Редирект-даунгрейд мы
# блокируем (--proto-redir), а вот явно заданную cleartext-схему запретить нельзя
# (бывают внутренние сети) — но молчать об этом нельзя тем более.
if [[ -n "$CADDY_AUTH_API_TOKEN" || -n "$REMNAWAVE_TOKEN" ]]; then
    for _u in "$REMNAWAVE_URL" "$REMNAWAVE_NODES_URL"; do
        [[ "$_u" == http://* ]] && warn "'$_u' по http:// — токен панели/Caddy уйдёт открытым текстом. Возьми https."
    done
    unset _u
fi
unset _k

# Порт ТЕКУЩЕЙ SSH-сессии — ground truth (sshd её уже принял, гадать не нужно). Если он
# не входит в SSH_PORT (ошибка детекта, протухший protect.conf, порт меняли между
# прогонами), strict уронил бы его в catch-all drop → после срабатывания сейфти вход
# закрыт. Открываем ОБА + громкий warn — та же логика, что для node-port в v3.8.
# В маркер уходит эффективный список, в protect.conf — intent оператора (SSH_PORT).
SSH_EFF="$SSH_PORT"
SSH_SESSION_PORT="$(ssh_session_port || true)"
if [[ -n "$SSH_SESSION_PORT" && ",$SSH_EFF," != *",$SSH_SESSION_PORT,"* ]]; then
    warn "твоя SSH-сессия пришла на :$SSH_SESSION_PORT, а SSH_PORT=$SSH_PORT — открываю ОБА (иначе локаут после сейфти); сверь и закрепи SSH_PORT=$SSH_SESSION_PORT"
    SSH_EFF="$SSH_EFF,$SSH_SESSION_PORT"
fi
SSH_NFT="${SSH_EFF//,/, }"

# Резолв NODE_PORT_WHITELIST_ONLY=auto: whitelist-only только если оператор задал
# WHITELIST (знает доверенный набор). Пустой WHITELIST → мягкий лимит (не отрезаем панель).
# NPWL_SRC помнит, откуда взялось решение: авто-вывод из WHITELIST vs явный intent
# оператора — от этого зависит дефолт авто-допуска пиров (NODE_PORT_AUTOWL=auto).
NPWL_SRC="explicit"
if [[ "$NODE_PORT_WHITELIST_ONLY" == "auto" ]]; then
    NPWL_SRC="auto"
    [[ -n "$WHITELIST" ]] && NODE_PORT_WHITELIST_ONLY=1 || NODE_PORT_WHITELIST_ONLY=0
fi

# strict на машине с 3x-ui — почти наверняка отрежет панель и inbound'ы. Громко.
if [[ "$FW_MODE" == "strict" ]] && xui_detected; then
    warn "Найден 3x-ui, а FW_MODE=strict: панель и inbound-порты вне TCP_PORTS/UDP_PORTS ($TCP_PORTS / $UDP_PORTS) будут ЗАБЛОКИРОВАНЫ."
    warn "Для 3x-ui обычно нужен FW_MODE=open, либо перечисли порт панели и ВСЕ inbound-порты в TCP_PORTS/UDP_PORTS."
fi
# FW_MODE=open: понятия «закрытый порт» нет — любой порт может оказаться inbound'ом.
# Анти-скан meter ловил бы легитимные коннекты к неперечисленным портам → баны юзеров,
# поэтому автобан за скан в open-режиме не ставится (само значение ENABLE_PORTSCAN_BAN
# не трогаем — при возврате на strict оно снова заработает).
if [[ "$FW_MODE" == "open" && "$ENABLE_PORTSCAN_BAN" == "1" ]]; then
    info "FW_MODE=open: анти-скан автобан не ставится (нет закрытых портов — meter банил бы легитимный трафик на inbound-порты)"
fi

# whitelist → v4/v6
# Whitelist в na — это НЕ «доверенный список», а ПОЛНЫЙ обход защиты: accept стоит выше
# автобана, CrowdSec-бунсера и всех per-IP лимитов, а при whitelist-only даёт ещё и
# допуск к контрол-порту node-агента. Отсюда два правила гигиены (issue #38):
#   • дубликат из CSV оператора раньше уезжал как есть в nft-сет, в na_filter.nft и в
#     CrowdSec-yaml (на боевых нодах один адрес был прописан дважды во всех трёх местах
#     сразу) — дедупим, как это давно делает соседний add_npwl; /32 и /128 нормализуем к
#     голому адресу: для nft это одно и то же значение, а как ТЕКСТ — два разных, и
#     дедуп без нормализации их бы не поймал;
#   • широкий CIDR принимался молча: /24 в конфиге ноды означает «256 чужих адресов
#     имеют иммунитет», и такие строки живут годами — просто потому, что никто вслух
#     не сказал, что это иммунитет, а не «список наших».
# protect.conf при этом хранит WHITELIST РОВНО как задал оператор (это его intent),
# поэтому дубликат там только предупреждается, а не переписывается за него.
WL4=""; WL6=""
WL_DUP_SEEN=""
# Дубль: предупреждаем ОДИН раз на значение (CSV с тройным повтором не должен
# превращать вывод в простыню); из служебного источника (авто-IP сессии) — молча.
wl_warn_dup() {   # wl_warn_dup <адрес> <источник>
    [[ "$2" == "auto" ]] && return 0
    [[ ",$WL_DUP_SEEN," == *",$1,"* ]] && return 0
    WL_DUP_SEEN+="${WL_DUP_SEEN:+,}$1"
    warn "WHITELIST: '$1' указан дважды — в правила пойдёт один раз; в protect.conf твой список остаётся как есть, почисти его сам"
    return 0
}
# Широкий префикс: короче /29 (v4) или /64 (v6). 2^N — сколько адресов получают обход.
wl_warn_wide() {   # wl_warn_wide <cidr> <разрядность> <порог>
    local cidr="$1" width="$2" floor="$3" p n human=""
    [[ "$cidr" == */* ]] || return 0
    p="${cidr#*/}"
    [[ "$p" =~ ^[0-9]+$ ]] || return 0
    (( p < floor )) || return 0
    n=$(( width - p ))
    if (( n <= 31 )); then human=" ($(( 1 << n )))"; fi
    warn "WHITELIST: $cidr — это ПОЛНЫЙ обход защиты (accept раньше автобана/CrowdSec/лимитов, допуск к node-port при whitelist-only) для 2^$n адресов$human; сузь до хостов"
    return 0
}
add_wl() {   # add_wl <csv> [auto]  — 'auto' = служебный источник (IP текущей SSH-сессии)
    local x src="${2:-}"
    for x in ${1//,/ }; do
        [[ -z "$x" ]] && continue
        if [[ "$x" == *:* ]]; then
            # строго hex+двоеточия (+опц. /prefix) — иначе значение уходит дословно в
            # nft-heredoc 'elements = { ... }' и может дописать произвольные правила
            [[ "$x" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]] || { err "WHITELIST: '$x' не валидный IPv6/CIDR"; return 1; }
            [[ "$x" == */128 ]] && x="${x%/128}"
            if [[ ",${WL6//, /,}," == *",$x,"* ]]; then wl_warn_dup "$x" "$src"; continue; fi
            wl_warn_wide "$x" 128 64
            WL6+="${WL6:+, }$x"
        elif [[ "$x" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
            [[ "$x" == */32 ]] && x="${x%/32}"
            if [[ ",${WL4//, /,}," == *",$x,"* ]]; then wl_warn_dup "$x" "$src"; continue; fi
            wl_warn_wide "$x" 32 29
            WL4+="${WL4:+, }$x"
        else err "WHITELIST: '$x' не IPv4/IPv6/CIDR"; return 1; fi
    done
}
add_wl "$WHITELIST" || exit 1
ADMIN_IP="$(ssh_client_ip || true)"
if [[ -n "$ADMIN_IP" ]]; then
    add_wl "$ADMIN_IP" auto || true
    info "Авто-whitelist твоего SSH-IP: $ADMIN_IP (защита от самоблокировки)"
elif [[ -t 0 && "$FW_MODE" != "skip" && "$DRY_RUN" != "1" ]]; then
    # Сессия есть (терминал), а SSH_CONNECTION не нашли ни у себя, ни у предков: screen/tmux,
    # su без -l, нестандартный sudo. Молчать нельзя — защиты от самоблокировки сейчас нет.
    warn "SSH-сессию не вижу (нет SSH_CONNECTION у процесса и предков: screen/tmux/su?) — твой IP НЕ добавлен в whitelist и порт сессии не закреплён. Проверь SSH_PORT и доступ из второго окна до снятия сейфти."
fi

# ─── Зависимости ─────────────────────────────────────────────────────────────
title "Зависимости"
apt_install nftables curl ca-certificates iproute2 gnupg
ok "ok"

# ─── CrowdSec: пиннингованный APT-репозиторий (supply-chain) ─────────────────
# Вместо curl|bash с install.crowdsec.net — их packagecloud-репо с проверкой ПОЛНОГО
# отпечатка ключа (64-битный keyid подделать дёшево) и экспортом в keyring РОВНО этого
# ключа (см. import_pinned_key).
# Порядок suite-кандидатов:
#   1. any/any — канон апстрима (их же install.crowdsec.net пишет именно его). Один
#      набор пакетов на все дистрибутивы, Release всегда есть;
#   2. <os>/<codename> — нативный suite, если он у них собран;
#   3. <os>/bookworm|noble — фоллбэк для свежих релизов.
# Почему any/any первым: под Debian 13 (trixie) suite debian/trixie у CrowdSec ПУСТОЙ —
# нет Release-файла (upstream issues #3834/#3909), а родной пакет самого Debian 13 —
# древний 1.4.6, который апстрим сам не рекомендует.
CROWDSEC_FP="6A89E3C2303A901A889971D3376ED5326E93CD0C"
setup_crowdsec_repo() {
    local keyring=/etc/apt/keyrings/crowdsec-archive-keyring.gpg
    local list=/etc/apt/sources.list.d/crowdsec.list
    local os="$OS_ID" codename fb tmpkey cand path suite seen="" okrepo=0
    codename="$(os_codename)"; [[ -n "$codename" ]] || codename=bookworm
    fb=bookworm; [[ "$os" == "ubuntu" ]] && fb=noble
    mkdir -p /etc/apt/keyrings
    tmpkey="$(mktemp)" || return 1
    if ! curl -fsSL --connect-timeout 5 --max-time 20 \
            https://packagecloud.io/crowdsec/crowdsec/gpgkey -o "$tmpkey"; then
        warn "ключ CrowdSec (packagecloud) недоступен"; rm -f "$tmpkey"; return 1
    fi
    if ! import_pinned_key "$tmpkey" "$CROWDSEC_FP" "$keyring"; then
        warn "ключ CrowdSec не сошёлся с отпечатком $CROWDSEC_FP — отказываюсь использовать"
        rm -f "$tmpkey"; return 1
    fi
    rm -f "$tmpkey"
    # ВАЖНО: обновляем ТОЛЬКО свой list. Глобальный `apt-get update` вернул бы rc≠0 из-за
    # ЛЮБОГО постороннего битого источника на боксе (протухший сторонний репо — типовой
    # съёмный VPS), и пиннинг ложно самоотключился бы на живом packagecloud. Скоуп через
    # Dir::Etc даёт вердикт именно о нашем репо.
    local -a UPDSC=(-o "Dir::Etc::sourcelist=$list" -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0)
    for cand in "any any" "$os $codename" "$os $fb"; do
        path="${cand%% *}"; suite="${cand##* }"
        [[ ",$seen," == *",$path/$suite,"* ]] && continue
        seen+="${seen:+,}$path/$suite"
        echo "deb [signed-by=$keyring] https://packagecloud.io/crowdsec/crowdsec/$path $suite main" > "$list"
        if apt-get update -qq "${UPDSC[@]}" 2>/dev/null; then okrepo=1; break; fi
        warn "репо CrowdSec '$path $suite' не поднялся — пробую следующий вариант"
    done
    if [[ "$okrepo" != "1" ]]; then
        rm -f "$list"; apt-get update -qq 2>/dev/null || true; return 1
    fi
    # общий кэш подтянуть (наш list валиден); чужие битые источники тут не фатальны
    apt-get update -qq 2>/dev/null || true
    return 0
}

# PROBE: репозиторий+ключ+пакеты CrowdSec резолвятся на этой ОС, БЕЗ установки.
# Для CI-матрицы и ops-проверки совместимости (аналог XANMOD_PROBE в optimize.sh).
if [[ "${CROWDSEC_PROBE:-0}" == "1" ]]; then
    setup_crowdsec_repo || { err "CROWDSEC_PROBE: репозиторий не поднялся"; exit 1; }
    apt-cache show crowdsec >/dev/null 2>&1 \
        && ok "CROWDSEC_PROBE: пакет crowdsec резолвится" \
        || { err "CROWDSEC_PROBE: пакет crowdsec не резолвится"; exit 1; }
    apt-cache show crowdsec-firewall-bouncer-nftables >/dev/null 2>&1 \
        && ok "CROWDSEC_PROBE: bouncer резолвится" \
        || warn "CROWDSEC_PROBE: crowdsec-firewall-bouncer-nftables не резолвится в этом suite"
    exit 0
fi

# ─── Область действия блок-листов CrowdSec (CROWDSEC_SCOPE) ─────────────────────
# ssh: bouncer только наполняет наборы (set-only), а правило, которое по ним дропает, ставим
# мы — на SSH-порт(ы), с исключением для whitelist (адрес админа/панели может оказаться в
# community-листе: whitelist парсера CrowdSec от решений CAPI не защищает). Таблицы и наборы
# — те, что прописаны в конфиге bouncer'а; файл грузит na-crowdsec-scope.service ДО
# bouncer'а. all: прежнее поведение — правила ставит сам bouncer, на всех портах.
CS_BOUNCER_YAML="${CS_BOUNCER_YAML:-/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml}"
CS_SCOPE_NFT="$CONF_DIR/na-crowdsec-scope.nft"
CS_SCOPE_UNIT="/etc/systemd/system/na-crowdsec-scope.service"
CROWDSEC_SCOPE_EFF=""
_cs_yaml_get() {   # _cs_yaml_get <ключ верхнего уровня> | <ipv4|ipv6> <ключ> — значение из yaml bouncer'а
    if [[ $# -eq 1 ]]; then
        awk -F': *' -v k="$1" '$1==k{gsub(/[" ]/,"",$2); print $2; exit}' "$CS_BOUNCER_YAML" 2>/dev/null
    else
        awk -v fam="$1" -v k="$2" '
            /^nftables:/ {in_nft=1; next}
            in_nft && /^[^ ]/ {in_nft=0}
            in_nft && $1==fam":" {in_fam=1; next}
            in_nft && in_fam && /^  [a-z]/ && $1!=k":" && $1 ~ /^(ipv4|ipv6):$/ {in_fam=0}
            in_nft && in_fam && $1==k":" {v=$2; gsub(/"/,"",v); print v; exit}' "$CS_BOUNCER_YAML" 2>/dev/null
    fi
}
crowdsec_scope_apply() {
    local want="$CROWDSEC_SCOPE" t4 t6 s4 s6 wl4="" wl6="" legacy=crowdsec-nft-scope.service
    [[ -f "$CS_BOUNCER_YAML" ]] || { info "CrowdSec scope: конфига bouncer'а нет ($CS_BOUNCER_YAML) — пропуск"; return 0; }
    if [[ "$want" == ssh ]] && ! grep -qE '^[[:space:]]+set-only:' "$CS_BOUNCER_YAML"; then
        warn "CrowdSec scope: bouncer без опции set-only (старая версия) — блок-листы остаются на ВСЕХ портах (как CROWDSEC_SCOPE=all)"
        want=all
    fi
    backup_file "$CS_BOUNCER_YAML" "$BACKUP"
    if [[ "$want" == all ]]; then
        sed -i.na-tmp -E 's/^([[:space:]]+set-only:)[[:space:]]*true[[:space:]]*$/\1 false/' "$CS_BOUNCER_YAML" && rm -f "$CS_BOUNCER_YAML.na-tmp"
        if [[ -f "$CS_SCOPE_UNIT" ]]; then
            systemctl disable na-crowdsec-scope.service >/dev/null 2>&1 || true
            rm -f "$CS_SCOPE_UNIT" "$CS_SCOPE_NFT"
            systemctl daemon-reload 2>/dev/null || true
        fi
        systemctl is-enabled --quiet "$legacy" 2>/dev/null \
            && warn "CrowdSec scope: найден ручной $legacy (сужает блок-листы до SSH) — CROWDSEC_SCOPE=all его не трогает; сними сам, если нужно"
        systemctl restart crowdsec-firewall-bouncer >/dev/null 2>&1 || true
        CROWDSEC_SCOPE_EFF=all
        info "CrowdSec: блок-листы действуют на ВСЕХ портах (CROWDSEC_SCOPE=all)"
        return 0
    fi
    t4="$(_cs_yaml_get ipv4 table)"; t4="${t4:-crowdsec}"
    t6="$(_cs_yaml_get ipv6 table)"; t6="${t6:-crowdsec6}"
    s4="$(_cs_yaml_get blacklists_ipv4)"; s4="${s4:-crowdsec-blacklists}"
    s6="$(_cs_yaml_get blacklists_ipv6)"; s6="${s6:-crowdsec6-blacklists}"
    # строки с меткой na-wl4/na-wl6 переписывает `na-fw allow` — не трогать руками
    wl4="        # na-wl4 (whitelist пуст)"; wl6="        # na-wl6 (whitelist пуст)"
    [[ -n "$WL4" ]] && wl4="        ip saddr { $WL4 } return # na-wl4"
    [[ -n "$WL6" ]] && wl6="        ip6 saddr { $WL6 } return # na-wl6"
    cat > "$CS_SCOPE_NFT.new" <<CSN
#!/usr/sbin/nft -f
# node-accelerator: блок-листы CrowdSec только на SSH (CROWDSEC_SCOPE=ssh).
# Наборы наполняет crowdsec-firewall-bouncer (set-only: true), правила — здесь.
table ip $t4 {}
delete table ip $t4
table ip $t4 {
    set $s4 { type ipv4_addr; flags timeout; }
    chain na-scope-input {
        type filter hook input priority filter - 10; policy accept;
$wl4
        tcp dport { ${SSH_NFT} } ip saddr @$s4 counter drop
    }
}
table ip6 $t6 {}
delete table ip6 $t6
table ip6 $t6 {
    set $s6 { type ipv6_addr; flags timeout; }
    chain na-scope-input {
        type filter hook input priority filter - 10; policy accept;
$wl6
        tcp dport { ${SSH_NFT} } ip6 saddr @$s6 counter drop
    }
}
CSN
    if ! nft -c -f "$CS_SCOPE_NFT.new" 2>/dev/null; then
        rm -f "$CS_SCOPE_NFT.new"
        warn "CrowdSec scope: сгенерированные правила не прошли nft -c — оставляю как было"
        return 0
    fi
    mv -f "$CS_SCOPE_NFT.new" "$CS_SCOPE_NFT"
    sed -i.na-tmp -E 's/^([[:space:]]+set-only:)[[:space:]]*false[[:space:]]*$/\1 true/' "$CS_BOUNCER_YAML" && rm -f "$CS_BOUNCER_YAML.na-tmp"
    cat > "$CS_SCOPE_UNIT" <<CSU
[Unit]
Description=node-accelerator: CrowdSec blocklists on SSH only (set-only bouncer)
DefaultDependencies=no
After=local-fs.target
Before=crowdsec-firewall-bouncer.service network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $CS_SCOPE_NFT
[Install]
WantedBy=multi-user.target
CSU
    if systemctl is-enabled --quiet "$legacy" 2>/dev/null; then
        systemctl disable "$legacy" >/dev/null 2>&1 || true
        info "CrowdSec scope: ручной $legacy выключен из автозагрузки — его роль теперь у na-crowdsec-scope.service (файл оставлен)"
    fi
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable na-crowdsec-scope.service >/dev/null 2>&1 || true
    nft -f "$CS_SCOPE_NFT" 2>/dev/null || warn "CrowdSec scope: nft -f $CS_SCOPE_NFT не прошёл"
    # bouncer в set-only заполняет уже существующие наборы — перезапуск после таблиц
    systemctl restart crowdsec-firewall-bouncer >/dev/null 2>&1 || true
    CROWDSEC_SCOPE_EFF=ssh
    ok "CrowdSec: блок-листы — только на SSH (:${SSH_EFF}); whitelist исключён; клиентские порты их не видят (CROWDSEC_SCOPE=all — как раньше)"
}

# ─── Сейфти-таймер: если потеряем SSH — снести нашу таблицу через N сек ───────
# Действие сработавшей подстраховки. Снимает и живую таблицу, И автозагрузку правил.
# Почему второе обязательно: раньше сейфти удалял ТОЛЬКО таблицу, а na-firewall.service
# оставался enabled — доступ возвращался, оператор видел живой бокс и уходил, а ПЕРВЫЙ
# ЖЕ ребут применял тот самый локаут-руллсет заново, теперь уже без всякого сейфти.
write_safety_revert() {
    cat > /usr/local/sbin/na-fw-safety-revert <<'SREV'
#!/bin/sh
# na-fw-safety-revert — аварийный откат файрвола (ставится protect.sh, снимается rollback).
/usr/sbin/nft delete table inet na_filter 2>/dev/null
systemctl disable na-firewall.service >/dev/null 2>&1
mkdir -p /var/lib/node-accelerator 2>/dev/null
date +%s > /var/lib/node-accelerator/safety-fired.last 2>/dev/null
rm -f /var/lib/node-accelerator/na-fw-safety.pid 2>/dev/null
logger -t na-fw-safety "СЕЙФТИ СРАБОТАЛ: na_filter удалена, автозагрузка правил выключена — защиты сейчас НЕТ, нужен повторный прогон protect"
exit 0
SREV
    chmod +x /usr/local/sbin/na-fw-safety-revert
}

arm_safety() {
    [[ "$DRY_RUN" == "1" ]] && return 0
    title "Подстраховка от блокировки"
    warn "Если SSH отвалится — через ${SAFETY_DELAY}s na_filter удалится И автозагрузка правил выключится (доступ вернётся, в т.ч. после ребута)."
    write_safety_revert
    if command -v systemd-run >/dev/null 2>&1; then
        systemctl stop na-fw-safety.timer 2>/dev/null || true
        systemd-run --quiet --unit=na-fw-safety --on-active="${SAFETY_DELAY}s" \
            /usr/local/sbin/na-fw-safety-revert >/dev/null 2>&1 \
            && { ok "safety: systemd-таймер na-fw-safety на ${SAFETY_DELAY}s"; return 0; }
    fi
    # fallback (нет systemd-run): nohup-таймер. Стейт в $STATE_DIR (root-only), НЕ в общей
    # /tmp — убирает симлинк/TOCTOU через предсказуемый путь. SAFETY_DELAY и pid передаём
    # позиционными аргументами в sh -c (без интерполяции в строку оболочки).
    mkdir -p "$STATE_DIR"
    local pidf="$STATE_DIR/na-fw-safety.pid" logf="$STATE_DIR/na-fw-safety.log"
    [[ -f "$pidf" && ! -L "$pidf" ]] && { kill "$(cat "$pidf")" 2>/dev/null || true; }
    nohup sh -c 'sleep "$1"; /usr/local/sbin/na-fw-safety-revert 2>/dev/null; rm -f "$2"' \
        _ "$SAFETY_DELAY" "$pidf" >"$logf" 2>&1 &
    echo $! > "$pidf"
    ok "safety: nohup pid $(cat "$pidf")"
}
disarm_safety() {
    systemctl stop na-fw-safety.timer 2>/dev/null || true
    local pidf="$STATE_DIR/na-fw-safety.pid"
    [[ -f "$pidf" && ! -L "$pidf" ]] && { kill "$(cat "$pidf")" 2>/dev/null || true; rm -f "$pidf"; }
    rm -f /tmp/na-fw-safety.pid /tmp/na-fw-safety.log 2>/dev/null || true   # legacy-стейт старых версий
}

# ─── FW_MODE=skip: nftables-файрвол не ставим ────────────────────────────────
print_fw_howto() {
    info "Как закрыть порты самому, когда определишься со списком:"
    echo "  A) Этим же модулем (рекомендуется — + анти-скан/флуд/автобаны/анти-спуф):"
    echo "       FW_MODE=strict TCP_PORTS=443,8443 UDP_PORTS=443 bash install.sh protect"
    echo "     Для 3x-ui: перечисли порт панели (по умолч. 2053) и ВСЕ порты inbound'ов —"
    echo "     всё, чего нет в списке (кроме SSH), будет заблокировано."
    echo "  B) Вручную минимальным nftables-allowlist'ом:"
    echo "       nft add table inet my_fw"
    echo "       nft 'add chain inet my_fw input { type filter hook input priority 0; policy drop; }'"
    echo "       nft add rule inet my_fw input iif lo accept"
    echo "       nft add rule inet my_fw input ct state established,related accept"
    echo "       nft add rule inet my_fw input meta l4proto { icmp, ipv6-icmp } accept"
    echo "       nft add rule inet my_fw input tcp dport { 22, 443 } accept   # СНАЧАЛА впиши свой SSH-порт!"
    echo "       nft add rule inet my_fw input udp dport { 443 } accept"
    echo "     Персист через reboot: положи ТОЛЬКО свою таблицу в файл (nft list table inet my_fw > /etc/nftables.d/my_fw.nft)"
    echo "     и грузи его своим юнитом. НЕ делай 'nft list ruleset > /etc/nftables.conf': туда уедут"
    echo "     таблицы CrowdSec/Docker, а дефолтный nftables.service начинает с 'flush ruleset'."
    echo "  C) Или ufw: ufw default deny incoming && ufw allow 22/tcp && ufw allow 443 && ufw enable"
}
if [[ "$FW_MODE" == "skip" ]]; then
    title "Файрвол (nftables)"
    warn "FW_MODE=skip: nftables-защита НЕ ставится — порты не блокируются, анти-скан/флуд-лимиты/автобаны выключены."
    print_fw_howto
    # Переключение strict→skip: старая na_filter сама не исчезнет — порты остались бы
    # заблокированы «непонятно чем». Интерактивно предлагаем снять, иначе громкий hint.
    if [[ "$DRY_RUN" != "1" ]] && { nft -t list table inet na_filter >/dev/null 2>&1 || [[ -f /etc/systemd/system/na-firewall.service ]]; }; then
        warn "Найден ранее установленный файрвол na_filter — FW_MODE=skip сам его НЕ удаляет."
        if [[ -t 0 && -z "${REMNAWAVE_NONINTERACTIVE:-}" ]] && confirm "Удалить na_filter сейчас (порты разблокируются)?"; then
            nft delete table inet na_filter 2>/dev/null || true
            systemctl disable --now na-firewall.service >/dev/null 2>&1 || true
            systemctl disable --now na-fleet-sync.timer na-blocklist.timer >/dev/null 2>&1 || true
            rm -f /etc/systemd/system/na-firewall.service "$CONF_DIR/na_filter.nft" \
                  "$CONF_DIR/na_filter.nft.rejected" "$CONF_DIR"/.na_filter.nft.*
            systemctl daemon-reload 2>/dev/null || true
            ok "na_filter удалена, порты разблокированы (полный откат модуля: bash install.sh rollback protect)"
        else
            info "Оставил как есть. Снять целиком: bash install.sh rollback protect"
        fi
    fi
    if [[ "$DRY_RUN" == "1" ]]; then
        ok "DRY-RUN: FW_MODE=skip — генерировать нечего."
        exit 0
    fi
fi

# ─── CrowdSec + firewall-bouncer ─────────────────────────────────────────────
# Стоит ДО файрвола: установка CrowdSec — самая долгая сетевая операция прогона, и раньше
# она шла уже под взведённым сейфти — таймер мог сработать посреди прогона, а на «y» скрипт
# всё равно печатал «защита активна». В DRY_RUN не ставим ничего.
if [[ "$ENABLE_CROWDSEC" == "1" && "$DRY_RUN" != "1" ]]; then
    title "CrowdSec + nftables firewall-bouncer"
    if ! command -v cscli >/dev/null 2>&1; then
        info "Подключаю APT-репозиторий CrowdSec (пиннингованный ключ $CROWDSEC_FP)…"
        if setup_crowdsec_repo; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec >/dev/null 2>&1 || warn "crowdsec не установился"
        elif [[ "$CROWDSEC_STRICT" == "1" ]]; then
            warn "пиннингованный репо CrowdSec не поднялся, CROWDSEC_STRICT=1 → CrowdSec пропущен (curl|bash-фоллбэк запрещён)"
        else
            # last-resort: официальный установщик. -fsSL (а не -s): при HTTP-ошибке/
            # редиректе curl падает, а не отдаёт HTML в bash. Осознанный компромисс:
            # достаточно СДЕЛАТЬ packagecloud недостижимым (egress-фильтр/DNS), чтобы
            # сюда свалиться — кто параноит, ставит CROWDSEC_STRICT=1.
            warn "пиннингованный репо не поднялся — fallback на официальный установщик (curl|bash; отключается CROWDSEC_STRICT=1)"
            curl -fsSL https://install.crowdsec.net | bash >/dev/null 2>&1 || warn "install.crowdsec.net недоступен"
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec >/dev/null 2>&1 || warn "crowdsec не установился"
        fi
    fi
    if command -v cscli >/dev/null 2>&1; then
        systemctl enable --now crowdsec >/dev/null 2>&1 || true
        sleep 2
        cscli collections install crowdsecurity/sshd crowdsecurity/linux >/dev/null 2>&1 || true

        # whitelist админа/панели в самом CrowdSec — чтобы IPS их не банил.
        # Ключи ip:/cidr: пишем ТОЛЬКО при наличии записей (пустые ключи валят парсер).
        mkdir -p /etc/crowdsec/parsers/s02-enrich
        # Источник — УЖЕ разобранные WL4/WL6 (дедуп + нормализация /32,/128), а не сырой
        # WHITELIST: иначе дубликат из CSV оператора попадал сюда третьим экземпляром,
        # мимо чистки, сделанной для nft-сета и na_filter.nft (issue #38). ADMIN_IP тут
        # отдельно не нужен — add_wl уже влил его в WL4/WL6.
        IP_ITEMS=""; CIDR_ITEMS=""
        for x in ${WL4//,/ } ${WL6//,/ }; do
            [[ -z "$x" ]] && continue
            if [[ "$x" == */* ]]; then CIDR_ITEMS+="    - \"$x\""$'\n'; else IP_ITEMS+="    - \"$x\""$'\n'; fi
        done
        if [[ -n "$IP_ITEMS$CIDR_ITEMS" ]]; then
            {
                echo "name: node-accelerator/whitelist"
                echo "description: never ban admin/panel"
                echo "whitelist:"
                echo "  reason: node-accelerator trusted"
                [[ -n "$IP_ITEMS"   ]] && { echo "  ip:";   printf "%s" "$IP_ITEMS"; }
                [[ -n "$CIDR_ITEMS" ]] && { echo "  cidr:"; printf "%s" "$CIDR_ITEMS"; }
            } > /etc/crowdsec/parsers/s02-enrich/na-whitelist.yaml
        else
            rm -f /etc/crowdsec/parsers/s02-enrich/na-whitelist.yaml
        fi

        # источник логов sshd через journald (на системах без /var/log/auth.log)
        mkdir -p /etc/crowdsec/acquis.d
        cat > /etc/crowdsec/acquis.d/na-sshd.yaml <<'ACQ'
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=ssh.service"
labels:
  type: syslog
---
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=sshd.service"
labels:
  type: syslog
ACQ
        systemctl reload crowdsec >/dev/null 2>&1 || systemctl restart crowdsec >/dev/null 2>&1 || true

        # firewall-bouncer (nftables-режим): своя таблица crowdsec/crowdsec6, priority -10
        if ! dpkg -s crowdsec-firewall-bouncer-nftables >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec-firewall-bouncer-nftables >/dev/null 2>&1 \
                || warn "bouncer не установился"
        fi
        systemctl enable --now crowdsec-firewall-bouncer >/dev/null 2>&1 || true
        crowdsec_scope_apply

        # опциональный enroll в Console
        if [[ -n "${CROWDSEC_ENROLL_KEY:-}" ]]; then
            cscli console enroll "$CROWDSEC_ENROLL_KEY" >/dev/null 2>&1 \
                && { systemctl reload crowdsec >/dev/null 2>&1 || true; ok "enroll в CrowdSec Console отправлен"; } \
                || warn "enroll не прошёл (проверь ключ)"
        fi

        if systemctl is-active --quiet crowdsec && systemctl is-active --quiet crowdsec-firewall-bouncer; then
            ok "CrowdSec + bouncer активны (community-блоклист + поведенческий бан)"
        else
            warn "CrowdSec/bouncer установлены, но сервис не active — проверь: cscli metrics"
        fi
    fi
elif [[ "$ENABLE_CROWDSEC" != "1" ]]; then
    info "ENABLE_CROWDSEC=0 — CrowdSec пропущен"
fi


# fleet-sync живёт в сетах таблицы na_filter → при FW_MODE=skip невозможен.
FLEET_ON=0
if [[ "$FW_MODE" != "skip" ]]; then
    case "$FLEET_SYNC" in
        1) FLEET_ON=1;;
        auto) { [[ -n "$REMNAWAVE_URL" && -n "$REMNAWAVE_TOKEN" ]] || [[ -n "$REMNAWAVE_NODES_URL" ]]; } && FLEET_ON=1 \
              || { [[ -f "$CONF_DIR/fleet.env" ]] && FLEET_ON=1; };;
    esac
elif [[ "$FLEET_SYNC" == "1" || -n "$REMNAWAVE_NODES_URL" || ( -n "$REMNAWAVE_URL" && -n "$REMNAWAVE_TOKEN" ) ]]; then
    info "FW_MODE=skip: fleet-sync живёт в сетах na_filter — пропущен"
fi
[[ "$FW_MODE" == "skip" && "$ENABLE_BLOCKLISTS" == "1" ]] && info "FW_MODE=skip: блоклисты живут в сетах na_filter — пропущены"

# ═══ ФАЙРВОЛ (nftables) — весь блок до CrowdSec пропускается при FW_MODE=skip ═══
NP_EFF="$NODE_PORT"   # skip-режим: детект не гоняем, в маркер значение уходит как есть
if [[ "$FW_MODE" != "skip" ]]; then

# ─── Резолв NODE_PORT: auto → фактический порт node-агента ───────────────────
# Правило надёжности: панель никогда не должна МОЛЧА терять ноду из-за порта.
#   auto + детект ок     → детект (кэш в NODE_PORT_LAST на случай остановленного агента);
#   auto + агент молчит  → прошлый детект, иначе оба известных дефолта (2222,3000);
#   явный порт ≠ детекту → правила на ОБА + громкий warn (кейс миграции агента 2222→3000:
#                          сохранённый conf держал 2222, strict ронял :3000 в catch-all drop).
NP_DETECTED="$(detect_node_port || true)"
if [[ "$NP_DETECTED" == *,* ]]; then
    warn "node-agent: на хосте несколько агентов с host-сетью (порты $NP_DETECTED) — правила node-порта ставлю на все; если часть не твоя — закрепи NODE_PORT=<порт>"
fi
if [[ "$NODE_PORT" == "none" ]]; then
    # Явный отказ от правил node-порта (бокс без агента: панель, CDN-origin). Фолбэк на
    # 2222,3000 там открывал бы миру два порта, которые никто не слушает.
    NP_EFF=""
    info "NODE_PORT=none: правила node-порта не ставятся"
elif [[ "$NODE_PORT" == "auto" ]]; then
    if [[ -n "$NP_DETECTED" ]]; then
        NP_EFF="$NP_DETECTED"
        ok "node-agent: автодетект порта → $NP_EFF"
    elif [[ -n "$NODE_PORT_LAST" ]]; then
        NP_EFF="$NODE_PORT_LAST"
        warn "node-agent сейчас не детектится (контейнер остановлен?) — беру прошлый детект: $NP_EFF"
    else
        NP_EFF="$NODE_PORT_FALLBACK"
        warn "node-agent не найден — правила на оба известных дефолта ($NP_EFF); закрепить: NODE_PORT=<порт>"
    fi
else
    NP_EFF="$NODE_PORT"
    if [[ -n "$NP_DETECTED" ]]; then
        for _p in ${NP_DETECTED//,/ }; do
            if [[ ",$NP_EFF," != *",$_p,"* ]]; then
                NP_EFF+=",$_p"
                warn "node-agent фактически слушает :$_p (задан NODE_PORT=$NODE_PORT) — открываю ОБА, чтобы не отрезать панель; сверь и закрепи NODE_PORT"
            fi
        done
        unset _p
    fi
fi
[[ -n "$NP_DETECTED" ]] && NODE_PORT_LAST="$NP_DETECTED"
NP_NFT="${NP_EFF//,/, }"

# ─── Наборы per-IP лимитеров ─────────────────────────────────────────────────
# До v4.1.3 каждый per-IP лимит был голым `meter … { ip saddr limit rate … } accept`:
# набор `size 65535; flags dynamic` БЕЗ timeout. Записи с `limit` ядро не чистит никогда
# (в отличие от `ct count`, у которого есть GC), поэтому набор копил КАЖДЫЙ адрес,
# хоть раз пришедший на порт, до ребута или перезагрузки таблицы. Аудит флота: 22 764
# адреса в syn4_2087 за 32 дня аптайма, рост 700–1300 в сутки на порт. На полном наборе
# ядро не может завести запись новому адресу, правило `… accept` для него не срабатывает,
# и пакет падает в `ct state new drop` — новые клиенты молча отрезаны (а для ssh4 новый
# адрес админа уходит в suspect/бан).
# Теперь: набор объявлен явно, с timeout (запись живёт, пока адрес активен: `update`
# продлевает её на каждом пакете), а правило построено «превысил → drop, иначе accept».
# Переполнение (спуф-флуд с десятков тысяч адресов) тогда выключает лимит для новых
# адресов, а не отрезает их: syncookies и ct count продолжают работать.
# Timeout — не меньше пола и не меньше ДВУХ времён восстановления корзины (burst/rate):
# иначе адрес после паузы получал бы свежий burst. Пол: секундным лимитам 60s, минутным
# (SSH, анти-скан) 10m; при медленном rate (PORTSCAN_RATE=1, burst 30 → 30 мин) timeout
# растёт вместе с ним. Ручки NA_RATE_* — для тестов на настоящем nft (маленький набор,
# быстрое истечение), оператору их трогать незачем.
NA_RATE_SET_SIZE="${NA_RATE_SET_SIZE:-65535}"
NA_RATE_TO_SEC="${NA_RATE_TO_SEC:-60s}"
NA_RATE_TO_MIN="${NA_RATE_TO_MIN:-10m}"
_is_uint "$NA_RATE_SET_SIZE" && (( NA_RATE_SET_SIZE > 0 )) || { err "NA_RATE_SET_SIZE='$NA_RATE_SET_SIZE' — ожидается целое > 0"; exit 1; }
for _k in NA_RATE_TO_SEC NA_RATE_TO_MIN; do
    # 0 = запись без срока, то есть ровно та вечная корзина, от которой и уходим
    _is_duration "${!_k}" && (( $(systime_to_s "${!_k}") > 0 )) || { err "$_k='${!_k}' — ожидается длительность > 0 (напр. 60s, 10m)"; exit 1; }
done
unset _k
RATE_SETS=""
rate_set() {   # rate_set <имя> <ipv4_addr|ipv6_addr> <rate> <burst> <second|minute>
    local unit_s=1 floor refill to
    [[ "$5" == minute ]] && unit_s=60
    if [[ "$5" == minute ]]; then floor="$(systime_to_s "$NA_RATE_TO_MIN")"; else floor="$(systime_to_s "$NA_RATE_TO_SEC")"; fi
    refill=$(( ($4 * unit_s + $3 - 1) / ($3 > 0 ? $3 : 1) ))
    to=$(( refill * 2 > floor ? refill * 2 : floor ))
    RATE_SETS+="
    set $1 { type $2; size ${NA_RATE_SET_SIZE}; flags dynamic,timeout; timeout ${to}s; }"
}

# ─── Сборка per-port правил ──────────────────────────────────────────────────
TCP_RULES=""
for p in ${TCP_PORTS//,/ }; do
    [[ -z "$p" ]] && continue
    TCP_RULES+="
        # порт ${p}: per-IP лимит одновременных коннектов (анти-exhaustion; записи ct count ядро чистит само)
        tcp dport ${p} ct state new meter cc4_${p} { ip saddr ct count over ${CONN_LIMIT} } drop
        tcp dport ${p} ct state new meter cc6_${p} { ip6 saddr ct count over ${CONN_LIMIT} } drop
        # порт ${p}: per-IP SYN-rate (масштабируется по числу клиентов, не глобальный потолок)
        tcp dport ${p} ct state new update @syn4_${p} { ip saddr limit rate over ${SYN_RATE}/second burst ${SYN_BURST} packets } jump synflood_drop
        tcp dport ${p} ct state new update @syn6_${p} { ip6 saddr limit rate over ${SYN_RATE}/second burst ${SYN_BURST} packets } jump synflood_drop
        tcp dport ${p} ct state new accept"
    rate_set "syn4_${p}" ipv4_addr "$SYN_RATE" "$SYN_BURST" second
    rate_set "syn6_${p}" ipv6_addr "$SYN_RATE" "$SYN_BURST" second
done

UDP_RULES=""
for p in ${UDP_PORTS//,/ }; do
    [[ -z "$p" ]] && continue
    # порт объёмного туннеля получает свой потолок (см. UDP_BULK_PORTS выше)
    _urate="$UDP_RATE"; _uburst="$UDP_BURST"; _ukind="анти-UDP-flood"
    if [[ ",${UDP_BULK_PORTS}," == *",${p},"* ]]; then
        _urate="$UDP_BULK_RATE"; _uburst="$UDP_BULK_BURST"; _ukind="объёмный туннель, высокий потолок"
    fi
    UDP_RULES+="
        # порт ${p}/udp: per-IP rate (QUIC/Hysteria2/TUIC) — ${_ukind}
        udp dport ${p} update @udp4_${p} { ip saddr limit rate over ${_urate}/second burst ${_uburst} packets } counter name c_udpflood drop
        udp dport ${p} update @udp6_${p} { ip6 saddr limit rate over ${_urate}/second burst ${_uburst} packets } counter name c_udpflood drop
        udp dport ${p} accept"
    rate_set "udp4_${p}" ipv4_addr "$_urate" "$_uburst" second
    rate_set "udp6_${p}" ipv6_addr "$_urate" "$_uburst" second
done
# анти-амплификация: новые UDP на сервисные порты с исходных портов типичных отражателей
# (chargen 19, qotd 17, DNS 53, NTP 123, CLDAP 389, SSDP 1900, memcached 11211) — отражённый
# флуд, а не клиенты (их исходный порт — эфемерный). Стоит ДО per-IP лимитов: против тысяч
# отражателей они бессильны. Ответы на запросы самой ноды — established, сюда не доходят.
UDP_AMP=""
if [[ "$UDP_AMP_DROP" == "1" && -n "$UDP_PORTS" ]]; then
    UDP_AMP="        # анти-амплификация (UDP_AMP_DROP=0 — выключить)
        udp sport { 17, 19, 53, 123, 389, 1900, 11211 } udp dport { ${UDP_PORTS//,/, } } ct state new counter name c_udp_amp drop"
fi
# Порт в bulk-списке, но не в UDP_PORTS — правило для него не сгенерится вообще: молчать нельзя.
for p in ${UDP_BULK_PORTS//,/ }; do
    [[ -z "$p" ]] && continue
    [[ ",${UDP_PORTS}," == *",${p},"* ]] || warn "UDP_BULK_PORTS: порт $p не входит в UDP_PORTS — правило для него не создаётся"
done

# anti-spoofing (только на WAN-интерфейсе)
ANTISPOOF=""
if [[ -n "$WAN" ]]; then
    # DHCP-ответы (v4 и v6) — до анти-спуфа: в strict их отрезал бы catch-all, и на хосте со
    # stateful DHCPv6 адрес/маршрут v6 пропадали бы с истечением аренды
    ANTISPOOF="        # anti-spoofing: приватные/bogon источники на WAN = спуф
        udp sport 67 udp dport 68 accept
        ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept
        iifname \"${WAN}\" ip saddr @bogon_v4 counter name c_bogon drop
        iifname \"${WAN}\" ip6 saddr @bogon_v6 counter name c_bogon drop"
fi

# node-agent порт: whitelist-only (drop мир) или мягкий per-IP лимит для неизвестных.
# FW_MODE=open: блок не ставим вовсе — node-agent это понятие Remnawave, а на 3x-ui
# NODE_PORT может оказаться чьим-то inbound'ом: скрытый drop/лимит именно на нём
# стал бы кошмаром при отладке.
#
# Анти-самоотстрел панели (whitelist-only): IP панели узнаётся ПО ФАКТУ — established-
# пиры node-порта (ss + conntrack: панель могла оказаться между keepalive-коннектами,
# «0 established в моменте» — норма) идут в отдельный сет na_nodeport_wl_* (допуск
# ТОЛЬКО к node-порту, НЕ общий whitelist) и персистятся в NODE_PORT_PEERS.
harvest_node_port_peers() {   # stdout: IP через запятую (v4/v6, без портов/скобок)
    local filt="" p
    for p in ${NP_EFF//,/ }; do filt="${filt:+$filt or }sport = :$p"; done
    [[ -n "$filt" ]] || return 0
    {
        ss -Hnt state established "( $filt )" 2>/dev/null | awk '{print $NF}' \
            | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//'
        if command -v conntrack >/dev/null 2>&1; then
            for p in ${NP_EFF//,/ }; do
                conntrack -L -p tcp --dport "$p" --state ESTABLISHED 2>/dev/null \
                    | awk '{for(i=1;i<=NF;i++) if($i ~ /^src=/){print substr($i,5); break}}'
            done
        fi
    } | sed -E 's/^::ffff:([0-9.]+)$/\1/' \
      | awk 'NF && $0!="127.0.0.1" && $0!="::1"' | sort -u | paste -sd, -
}
NPWL4=""; NPWL6=""
add_npwl() {   # как add_wl, но в сет только-node-порта; битые значения warn+skip (не fatal)
    local x
    for x in ${1//,/ }; do
        [[ -z "$x" ]] && continue
        if [[ "$x" == *:* ]]; then
            [[ "$x" =~ ^[0-9a-fA-F:]+$ ]] || { warn "node-port peers: '$x' не IPv6 — пропущен"; continue; }
            [[ ",$NPWL6," == *",$x,"* ]] || NPWL6+="${NPWL6:+,}$x"
        elif [[ "$x" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            [[ ",$NPWL4," == *",$x,"* ]] || NPWL4+="${NPWL4:+,}$x"
        else warn "node-port peers: '$x' не IP — пропущен"; fi
    done
}
NP_SETS=""
if [[ -z "$NP_EFF" ]]; then
    NODE_RULES=""   # NODE_PORT=none
elif [[ "$FW_MODE" == "open" ]]; then
    NODE_RULES=""
    [[ "$NODE_PORT_WHITELIST_ONLY" == "1" ]] && \
        info "FW_MODE=open: node-port правила не ставятся — NODE_PORT_WHITELIST_ONLY не действует (на 3x-ui порт(ы) ${NP_EFF} могут быть inbound'ом)"
elif [[ "$NODE_PORT_WHITELIST_ONLY" == "1" ]]; then
    # авто-допуск пиров: auto = вкл, когда whitelist-only ВЫВЕЛСЯ из WHITELIST;
    # явный NODE_PORT_WHITELIST_ONLY=1 — уважаем строгий intent (warn вместо допуска)
    NP_AUTOWL_ON=0
    case "$NODE_PORT_AUTOWL" in
        1) NP_AUTOWL_ON=1;;
        auto) [[ "$NPWL_SRC" == "auto" ]] && NP_AUTOWL_ON=1;;
    esac
    NP_FRESH="$(harvest_node_port_peers || true)"
    if [[ "$NP_AUTOWL_ON" == "1" ]]; then
        add_npwl "$NODE_PORT_PEERS"
        add_npwl "$NP_FRESH"
        NODE_PORT_PEERS="$NPWL4${NPWL4:+${NPWL6:+,}}$NPWL6"
        # cap: десятки «пиров» = это не контрол-порт панели (порт перепутан с сервисным?)
        _npc=0; for _p in ${NODE_PORT_PEERS//,/ }; do _npc=$((_npc+1)); done
        if (( _npc > 16 )); then
            warn "node-port peers: $_npc адресов — не похоже на контрол-порт панели; авто-допуск пропущен, проверь NODE_PORT"
            NPWL4=""; NPWL6=""; NODE_PORT_PEERS=""
        fi
        unset _npc _p
    fi
    NP_WL4_LINE=""; [[ -n "$NPWL4" ]] && NP_WL4_LINE="elements = { ${NPWL4//,/, } }"
    NP_WL6_LINE=""; [[ -n "$NPWL6" ]] && NP_WL6_LINE="elements = { ${NPWL6//,/, } }"
    NP_SETS="    set na_nodeport_wl_v4 { type ipv4_addr; $NP_WL4_LINE }
    set na_nodeport_wl_v6 { type ipv6_addr; $NP_WL6_LINE }"
    NODE_RULES="        # node-agent: ТОЛЬКО whitelist (общий — принят выше) + пиры панели из
        # @na_nodeport_wl_* (допуск лишь к этому порту) — остальным drop (контрол-порт не светим).
        # Пожарно пустить панель без ре-рана: nft add element inet na_filter na_nodeport_wl_v4 '{ <IP> }'
        tcp dport { ${NP_NFT} } ip  saddr @na_nodeport_wl_v4 accept
        tcp dport { ${NP_NFT} } ip6 saddr @na_nodeport_wl_v6 accept
        tcp dport { ${NP_NFT} } ct state new counter name c_nodeport drop"
    info "node-agent порт(ы) ${NP_EFF}: whitelist-only (WHITELIST задан)"
    if [[ "$NP_AUTOWL_ON" == "1" && -n "$NODE_PORT_PEERS" ]]; then
        ok "node-agent: авто-допуск established-пиров (панель): $NODE_PORT_PEERS (сет na_nodeport_wl_*; выкл: NODE_PORT_AUTOWL=0)"
    elif [[ "$NP_AUTOWL_ON" != "1" && -n "$NP_FRESH" ]]; then
        warn "node-port сейчас держат коннект: $NP_FRESH — если среди них панель, добавь её в WHITELIST (или авто-допуск: NODE_PORT_AUTOWL=1)"
    elif [[ -z "$NP_FRESH" && -z "$NODE_PORT_PEERS" ]]; then
        warn "established-пиров node-порта не вижу — УБЕДИСЬ, что IP панели в WHITELIST, иначе нода отвалится от панели"
    fi
else
    NODE_RULES="        # node-agent: whitelist (выше) + мягкий per-IP лимит для неизвестных
        tcp dport { ${NP_NFT} } ct state new update @na4 { ip saddr limit rate over 30/second burst 60 packets } counter name c_nodeport drop
        tcp dport { ${NP_NFT} } ct state new update @na6 { ip6 saddr limit rate over 30/second burst 60 packets } counter name c_nodeport drop
        tcp dport { ${NP_NFT} } ct state new accept"
    rate_set na4 ipv4_addr 30 60 second
    rate_set na6 ipv6_addr 30 60 second
fi

# portscan → autoban (включается флагом). При ENABLE_BANONCE=1 — двухступенчато:
# 1-й быстрый скан → suspect (наблюдение, БЕЗ полного бана: скан-пакеты и так дропает
# финальный catch-all, но легит-трафик IP не режется), повторный в окне SUSPECT_TIME →
# confirmed-бан. Снимает ложные баны целых CGNAT-операторов из-за одного шального скана.
PORTSCAN=""; PORTSCAN_CHAINS=""
if [[ "$ENABLE_PORTSCAN_BAN" == "1" && "$FW_MODE" != "open" ]]; then
    # Лог анти-скана — ТОЛЬКО на переходе адреса в suspect/бан (цепочки ps_suspect*/ps_ban*).
    # До v4.2 лог-правило стояло первым и писало КАЖДЫЙ новый SYN в закрытый порт: одиночные
    # стуки интернет-шума в 23/445/3389 давали 70–99% всех строк журнала (аудит флота), а
    # настоящие сканеры среди них терялись. Теперь в журнал попадает адрес, который превысил
    # порог, — один раз при пометке suspect и один раз при бане; PORTSCAN_LOG_RATE — общий
    # потолок этих строк в минуту (0 = не логировать; бан от лога не зависит). Объём всего
    # отброшенного сканом — в счётчиках (c_catchall, c_portscan), а не в строках журнала.
    _ps_log="# лог анти-скана выключен (PORTSCAN_LOG_RATE=0) — бан и счётчики работают и без него"
    [[ "$PORTSCAN_LOG_RATE" != "0" ]] && \
        _ps_log="limit rate ${PORTSCAN_LOG_RATE}/minute burst ${PORTSCAN_LOG_BURST} packets log prefix \"[na portscan] \" level info"
    _syn="tcp flags & (fin|syn|rst|ack) == syn ct state new"
    PORTSCAN_CHAINS="    # адрес превысил порог скана → бан ${PORTSCAN_BAN_TIME} (лог — один раз, дальше его режет autoban)
    chain ps_ban4 {
        add @autoban_v4 { ip saddr timeout ${PORTSCAN_BAN_TIME} }
        $_ps_log
        counter name c_portscan drop
    }
    chain ps_ban6 {
        add @autoban_v6 { ip6 saddr timeout ${PORTSCAN_BAN_TIME} }
        $_ps_log
        counter name c_portscan drop
    }"
    if [[ "$ENABLE_BANONCE" == "1" ]]; then
        PORTSCAN_CHAINS+="
    # первый быстрый скан → suspect на ${SUSPECT_TIME} (без бана; сам пакет дропнет catch-all);
    # уже suspect — без повторного лога
    chain ps_suspect4 {
        ip saddr @suspect_v4 return
        add @suspect_v4 { ip saddr timeout ${SUSPECT_TIME} }
        $_ps_log
    }
    chain ps_suspect6 {
        ip6 saddr @suspect_v6 return
        add @suspect_v6 { ip6 saddr timeout ${SUSPECT_TIME} }
        $_ps_log
    }"
        PORTSCAN="        # ANTI-SCAN (ban-once): 1-й быстрый скан → suspect, 2-й в окне ${SUSPECT_TIME} → бан.
        # уже suspect и снова бьёт быстрее порога → confirmed-бан
        meta nfproto ipv4 $_syn ip saddr @suspect_v4 update @psc4 { ip saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } jump ps_ban4
        meta nfproto ipv6 $_syn ip6 saddr @suspect_v6 update @psc6 { ip6 saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } jump ps_ban6
        # ещё не suspect и бьёт быстрее порога → пометить suspect
        meta nfproto ipv4 $_syn update @ps4 { ip saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } jump ps_suspect4
        meta nfproto ipv6 $_syn update @ps6 { ip6 saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } jump ps_suspect6"
    else
        PORTSCAN="        # ANTI-SCAN: бьёт по закрытым портам быстрее ${PORTSCAN_RATE}/min → бан ${PORTSCAN_BAN_TIME}.
        meta nfproto ipv4 $_syn update @ps4 { ip saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } jump ps_ban4
        meta nfproto ipv6 $_syn update @ps6 { ip6 saddr limit rate over ${PORTSCAN_RATE}/minute burst ${PORTSCAN_BURST} packets } jump ps_ban6"
    fi
fi
# наборы анти-скана — вне блока выше: tests/protect-unit.sh исполняет его отдельно
if [[ -n "$PORTSCAN" ]]; then
    rate_set ps4 ipv4_addr "$PORTSCAN_RATE" "$PORTSCAN_BURST" minute
    rate_set ps6 ipv6_addr "$PORTSCAN_RATE" "$PORTSCAN_BURST" minute
    if [[ "$ENABLE_BANONCE" == "1" ]]; then
        rate_set psc4 ipv4_addr "$PORTSCAN_RATE" "$PORTSCAN_BURST" minute
        rate_set psc6 ipv6_addr "$PORTSCAN_RATE" "$PORTSCAN_BURST" minute
    fi
fi

# ─── SYNPROXY (опционально, done-right) ──────────────────────────────────────
# ⚠️ На VPN-relay (профиль connect-and-hold / PPS-флуд) SYNPROXY обычно ИЗБЫТОЧЕН:
# его единственный реальный плюс — анти-спуф SYN — уже закрыт tcp_syncookies=1 +
# per-IP ct-лимитами (CONN_LIMIT/SYN_RATE), а издержки (обязательный be_liberal=1,
# per-packet overhead, поломка TFO на защищённых портах) не оправданы. Против самого
# распространённого вектора (connect-and-hold / реальный PPS) он не помогает вовсе.
# Поэтому default OFF; включать ТОЛЬКО под подтверждённый спуфнутый SYN-флуд. Оставлен
# opt-in для не-relay сценариев (голый L4-фронт без syncookies-достаточности).
#
# notrack ТОЛЬКО для трафика к самому хосту (fib daddr type local): иначе правило в
# prerouting цепляет conntrack/NAT ТРАНЗИТА (Docker-контейнер панели → удалённая нода)
# и ломает его. Требует ядро ≥5.14 + модуль nft_synproxy (тянет nf_synproxy_core). Модуля
# с именем nf_synproxy в современных ядрах нет вовсе — до v4.2 проверка `modprobe nf_synproxy`
# проваливалась на любом ядре флота (сток 6.12, XanMod 6.18), и ENABLE_SYNPROXY=1 всегда
# уходил в degraded. Запрошен, но недоступен →
# fail-loud (маркер degraded + warn), БЕЗ тихой деградации; synproxy-правила не ставятся.
SYNPROXY_PRE=""; SYNPROXY_IN=""; SP_MODPROBE=""; SYNPROXY_OK=0
rm -f "$STATE_DIR/.synproxy-degraded" 2>/dev/null || true
if [[ "$ENABLE_SYNPROXY" == "1" ]]; then
    _kmaj="$(uname -r | cut -d. -f1)"; _kmin="$(uname -r | cut -d. -f2)"
    [[ "$_kmaj" =~ ^[0-9]+$ ]] || _kmaj=0; [[ "$_kmin" =~ ^[0-9]+$ ]] || _kmin=0
    if { [[ "$_kmaj" -gt 5 ]] || { [[ "$_kmaj" -eq 5 ]] && [[ "$_kmin" -ge 14 ]]; }; } && modprobe nft_synproxy 2>/dev/null; then
        SYNPROXY_OK=1
        SP_SET="$TCP_PORTS"
        # mss из MTU аплинка (−40Б IPv4+TCP), wscale 7 (дефолт Linux); клампим в 536..1460.
        _mtu="$(cat /sys/class/net/"$WAN"/mtu 2>/dev/null || echo 1500)"; [[ "$_mtu" =~ ^[0-9]+$ ]] || _mtu=1500
        SP_MSS=$(( _mtu - 40 )); { [[ "$SP_MSS" -gt 1460 ]] || [[ "$SP_MSS" -lt 536 ]]; } && SP_MSS=1460
        SP_MODPROBE="ExecStartPre=/bin/sh -c 'modprobe nft_synproxy 2>/dev/null || true'"
        SYNPROXY_PRE="    chain prerouting {
        type filter hook prerouting priority -300; policy accept;
        fib daddr type local tcp dport { ${SP_SET} } tcp flags syn notrack
    }"
        # Место правила — ДО `ct state invalid drop`: при nf_conntrack_tcp_loose=0 (обязателен для
        # synproxy, ставится ниже) третий ACK рукопожатия conntrack видит как invalid, и до
        # v4.2 его съедал invalid-drop раньше synproxy — новые TCP на TCP_PORTS не
        # устанавливались вовсе (а при loose=1 ACK шёл мимо synproxy в сокет и получал RST).
        # Забаненных режем раньше: иначе synproxy дописал бы им рукопожатие, а дальше
        # established прошёл бы мимо autoban.
        SYNPROXY_IN="        # SYNPROXY (до invalid-drop; забаненные — раньше него)
        tcp dport { ${SP_SET} } ip  saddr @autoban_v4 counter name c_autoban drop
        tcp dport { ${SP_SET} } ip6 saddr @autoban_v6 counter name c_autoban drop
        tcp dport { ${SP_SET} } ct state invalid,untracked synproxy mss ${SP_MSS} wscale 7 timestamp sack-perm"
        ok "SYNPROXY: ядро $(uname -r) ок, mss ${SP_MSS} wscale 7 (notrack только host-local)"
    else
        warn "SYNPROXY запрошен, но недоступен (нужно ядро ≥5.14 + модуль nft_synproxy). Защита БЕЗ synproxy."
        mkdir -p "$STATE_DIR"; echo "kernel=$(uname -r) reason=no_nft_synproxy at=$(date -Is)" > "$STATE_DIR/.synproxy-degraded"
    fi
fi

# ── Условные сеты/правила v3.0 (ban-once / blocklists / fleet) ────────────────
# suspect-сеты для ban-once (timeout + size-cap как у autoban).
SUSPECT_SETS=""
if [[ "$ENABLE_BANONCE" == "1" ]]; then
    SUSPECT_SETS="    set suspect_v4 { type ipv4_addr; flags timeout; size 65536; }
    set suspect_v6 { type ipv6_addr; flags timeout; size 65536; }"
fi

# blocklist-сеты (наполняет na-blocklist-update таймером) + drop-правило.
BLOCKLIST_SETS=""; BLOCKLIST_DROP=""
if [[ "$ENABLE_BLOCKLISTS" == "1" ]]; then
    BLOCKLIST_SETS="    set blocklist_v4 { type ipv4_addr; flags interval; auto-merge; }
    set blocklist_v6 { type ipv6_addr; flags interval; auto-merge; }"
    BLOCKLIST_DROP="        # статич-блоклисты (Spamhaus DROP / FireHOL L1 [/ Tor]) — обновляет na-blocklist-update
        ip  saddr @blocklist_v4 counter name c_blocklist drop
        ip6 saddr @blocklist_v6 counter name c_blocklist drop"
fi

# fleet-сеты (наполняет na-fleet-sync с панели Remnawave) + accept сразу после whitelist.
# FLEET_ON резолвится выше (до блока файрвола — нужен и в skip-режиме).
FLEET_SETS=""; FLEET_ACCEPT=""
if [[ "$FLEET_ON" == "1" ]]; then
    FLEET_SETS="    set na_fleet_v4 { type ipv4_addr; flags interval; auto-merge; }
    set na_fleet_v6 { type ipv6_addr; flags interval; auto-merge; }"
    FLEET_ACCEPT="        # ноды флота (авто-синк с панели) — свои серверы, обходят все лимиты
        ip  saddr @na_fleet_v4 accept
        ip6 saddr @na_fleet_v6 accept"
fi

# SSH connect-flood: превысил лимит → цепочка ssh_flood (ban-once: suspect→confirmed,
# иначе прямой бан), в пределах лимита → accept. Последний drop цепочки — страховка:
# если сет suspect/autoban полон и запись не легла, пакет сверх лимита всё равно не
# проходит (иначе он вернулся бы из цепочки и упал в accept ниже).
# В отличие от сервисных портов, SSH на ПОЛНОМ наборе не открываем: держать ssh4 полным
# дёшево (≈110 SYN/с со спуфнутых адресов на 10m timeout, для v6 хватает своей /64), и
# fail-open выключил бы защиту от перебора. Адрес, которому не нашлось записи, идёт под
# общий потолок без бана (админ из whitelist проходит выше, остальным хватит 30/мин).
SSH_RULES="        # SSH connect-flood: >${SSH_RATE}/мин новых с одного IP → цепочка ssh_flood
        tcp dport { ${SSH_NFT} } ct state new update @ssh4 { ip saddr limit rate over ${SSH_RATE}/minute burst ${SSH_BURST} packets } jump ssh_flood
        tcp dport { ${SSH_NFT} } ct state new update @ssh6 { ip6 saddr limit rate over ${SSH_RATE}/minute burst ${SSH_BURST} packets } jump ssh_flood
        tcp dport { ${SSH_NFT} } ct state new ip  saddr @ssh4 accept
        tcp dport { ${SSH_NFT} } ct state new ip6 saddr @ssh6 accept
        # набор переполнен (флуд со множества адресов) — общий потолок, без бана
        tcp dport { ${SSH_NFT} } ct state new limit rate 30/minute burst 30 packets accept
        tcp dport { ${SSH_NFT} } ct state new counter name c_sshflood drop"
rate_set ssh4 ipv4_addr "$SSH_RATE" "$SSH_BURST" minute
rate_set ssh6 ipv6_addr "$SSH_RATE" "$SSH_BURST" minute
if [[ "$ENABLE_BANONCE" == "1" ]]; then
    # Ban-once по-настоящему: «2-й раз» — это повторный ПЕРЕБОР, а не следующий пакет. До
    # v4.2 любой SYN сверх лимита от уже-suspect адреса банил на SSH_BAN_TIME — а клиент,
    # которому дропнули SYN, сам перешлёт его через ~1 с: CI/Ansible, открывшие на одно
    # соединение больше лимита, ловили суточный бан с первого превышения. Теперь suspect
    # банится, только когда его пакеты сверх лимита сами превышают втрое больший burst.
    _ssh_esc_burst=$(( SSH_BURST * 3 ))
    SSH_FLOOD_CHAIN="    # SSH сверх лимита (ban-once): 1-й раз suspect+drop; повторный перебор в окне ${SUSPECT_TIME} → бан ${SSH_BAN_TIME}
    chain ssh_flood {
        limit rate 5/second log prefix \"[na ssh-flood] \" level warn
        ip saddr @suspect_v4 update @sshs4 { ip saddr limit rate over ${SSH_RATE}/minute burst ${_ssh_esc_burst} packets } add @autoban_v4 { ip saddr timeout ${SSH_BAN_TIME} } counter name c_sshflood drop
        ip6 saddr @suspect_v6 update @sshs6 { ip6 saddr limit rate over ${SSH_RATE}/minute burst ${_ssh_esc_burst} packets } add @autoban_v6 { ip6 saddr timeout ${SSH_BAN_TIME} } counter name c_sshflood drop
        ip saddr @suspect_v4 counter name c_sshflood drop
        ip6 saddr @suspect_v6 counter name c_sshflood drop
        meta nfproto ipv4 add @suspect_v4 { ip saddr timeout ${SUSPECT_TIME} } counter name c_sshflood drop
        meta nfproto ipv6 add @suspect_v6 { ip6 saddr timeout ${SUSPECT_TIME} } counter name c_sshflood drop
        counter name c_sshflood drop
    }"
    rate_set sshs4 ipv4_addr "$SSH_RATE" "$_ssh_esc_burst" minute
    rate_set sshs6 ipv6_addr "$SSH_RATE" "$_ssh_esc_burst" minute
else
    SSH_FLOOD_CHAIN="    # SSH сверх лимита: бан ${SSH_BAN_TIME}
    chain ssh_flood {
        limit rate 5/second log prefix \"[na ssh-flood] \" level warn
        meta nfproto ipv4 add @autoban_v4 { ip saddr timeout ${SSH_BAN_TIME} } counter name c_sshflood drop
        meta nfproto ipv6 add @autoban_v6 { ip6 saddr timeout ${SSH_BAN_TIME} } counter name c_sshflood drop
        counter name c_sshflood drop
    }"
fi

WL4_LINE=""; [[ -n "$WL4" ]] && WL4_LINE="elements = { $WL4 }"
WL6_LINE=""; [[ -n "$WL6" ]] && WL6_LINE="elements = { $WL6 }"

# Финал input-цепочки по режиму: strict = policy drop + catch-all drop (всё не
# разрешённое блокируется); open = policy accept + catch-all: не перечисленные порты
# получают ТЕ ЖЕ per-IP флуд-лимиты, что и перечисленные выше (conn-limit / SYN-rate /
# UDP-rate; сверх лимита — транзитный drop пакета, НЕ бан IP), затем accept. Без этого
# динамические inbound'ы 3x-ui — ради которых open и существует — оставались бы совсем
# без анти-флуда. Прочие протоколы (ICMP отработан выше, GRE/ESP и т.п.) — accept.
FW_POLICY=drop
FW_CATCHALL="counter name c_catchall drop"
if [[ "$FW_MODE" == "open" ]]; then
    FW_POLICY=accept
    FW_CATCHALL="# FW_MODE=open: не перечисленные порты НЕ блокируются (динамические inbound'ы 3x-ui),
        # но per-IP лимиты им — те же, что перечисленным портам (drop сверх лимита ≠ бан)
        meta l4proto tcp ct state new meter occ4 { ip saddr ct count over ${CONN_LIMIT} } drop
        meta l4proto tcp ct state new meter occ6 { ip6 saddr ct count over ${CONN_LIMIT} } drop
        meta l4proto tcp ct state new update @osyn4 { ip saddr limit rate over ${SYN_RATE}/second burst ${SYN_BURST} packets } jump synflood_drop
        meta l4proto tcp ct state new update @osyn6 { ip6 saddr limit rate over ${SYN_RATE}/second burst ${SYN_BURST} packets } jump synflood_drop
        meta l4proto udp update @oudp4 { ip saddr limit rate over ${UDP_RATE}/second burst ${UDP_BURST} packets } counter name c_udpflood drop
        meta l4proto udp update @oudp6 { ip6 saddr limit rate over ${UDP_RATE}/second burst ${UDP_BURST} packets } counter name c_udpflood drop
        counter accept"
    rate_set osyn4 ipv4_addr "$SYN_RATE" "$SYN_BURST" second; rate_set osyn6 ipv6_addr "$SYN_RATE" "$SYN_BURST" second
    rate_set oudp4 ipv4_addr "$UDP_RATE" "$UDP_BURST" second; rate_set oudp6 ipv6_addr "$UDP_RATE" "$UDP_BURST" second
fi

# per-IP лимит ICMP echo — тоже набор с timeout (см. «Наборы per-IP лимитеров»)
rate_set icmp4 ipv4_addr "$ICMP_RATE" "$ICMP_BURST" second
rate_set icmp6 ipv6_addr "$ICMP_RATE" "$ICMP_BURST" second

# ─── Локальные правила оператора (na_filter.d) ───────────────────────────────
# Ручные правки na_filter.nft (свой сет фронт-прокси, лишний порт) молча стирал любой
# ре-ран, а диагностика их не видела. Свои фрагменты кладутся сюда и вклеиваются в КАЖДУЮ
# генерацию (проверяются общим nft -c: битый фрагмент = ничего не применено):
#   na_filter.d/table/*.nft — на уровне таблицы (set …, свои цепочки);
#   na_filter.d/input/*.nft — в цепочку input сразу после whitelist/fleet (accept-правила
#                             своих адресов идут раньше автобана и лимитов).
NA_INCLUDE_DIR="$CONF_DIR/na_filter.d"
INCLUDE_TABLE=""; INCLUDE_INPUT=""; INCLUDE_N=0
for _kind in table input; do
    for _f in "$NA_INCLUDE_DIR/$_kind"/*.nft; do
        [[ -f "$_f" && ! -L "$_f" ]] || continue
        _body="$(cat "$_f")"
        if [[ "$_kind" == table ]]; then
            INCLUDE_TABLE+=$'\n'"    # ── локальное: $_f"$'\n'"$_body"$'\n'
        else
            INCLUDE_INPUT+=$'\n'"        # ── локальное: $_f"$'\n'"$_body"$'\n'
        fi
        INCLUDE_N=$((INCLUDE_N+1))
    done
done
[[ "$INCLUDE_N" -gt 0 ]] && info "локальные правила оператора: $INCLUDE_N файл(ов) из $NA_INCLUDE_DIR"
unset _kind _f _body

# ─── Опубликованные Docker-порты (forward) ───────────────────────────────────
# Трафик к контейнеру с `-p` (bridge) после DNAT идёт через hook forward, а не input: на
# него не действовали ни autoban, ни блок-листы, ни анти-спуф, и strict не закрывал такие
# порты (аудит флота: Caddy панели и второй тенант на нодах — целиком мимо na_filter).
# Здесь — те же вердикты ПО ИСТОЧНИКУ для новых DNAT-соединений. Лимиты и список портов
# не трогаем: у контейнеров свой жизненный цикл и свои потребители (CDN, второй тенант).
DNAT_JUMP=""; DNAT_CHAIN=""
if [[ "$DNAT_GUARD" == "1" ]]; then
    DNAT_JUMP="        ct status dnat ct state new jump dnat_guard"
    _dnat_bogon=""
    [[ -n "$WAN" ]] && _dnat_bogon="        iifname \"${WAN}\" ip  saddr @bogon_v4 counter name c_dnat_guard drop
        iifname \"${WAN}\" ip6 saddr @bogon_v6 counter name c_dnat_guard drop"
    _dnat_fleet=""
    [[ "$FLEET_ON" == "1" ]] && _dnat_fleet="        ip  saddr @na_fleet_v4 return
        ip6 saddr @na_fleet_v6 return"
    _dnat_bl=""
    [[ "$ENABLE_BLOCKLISTS" == "1" ]] && _dnat_bl="        ip  saddr @blocklist_v4 counter name c_dnat_guard drop
        ip6 saddr @blocklist_v6 counter name c_dnat_guard drop"
    DNAT_CHAIN="    # новые соединения к опубликованным Docker-портам: вердикты по источнику (DNAT_GUARD=0 — выкл)
    chain dnat_guard {
        ip  saddr @whitelist_v4 return
        ip6 saddr @whitelist_v6 return
$_dnat_fleet
        ip  saddr @autoban_v4 counter name c_dnat_guard drop
        ip6 saddr @autoban_v6 counter name c_dnat_guard drop
$_dnat_bl
$_dnat_bogon
    }"
    unset _dnat_bogon _dnat_fleet _dnat_bl
fi

# Именованные счётчики отброшенного: объём атаки — в цифрах, а не в строках журнала
# (лог под rate-limit, на насыщении он молчит). Читает na-fw-status / na-diagnose.
COUNTERS=""
for _c in c_synflood c_udpflood c_udp_amp c_portscan c_autoban c_blocklist c_bogon c_badflags \
          c_nodeport c_catchall c_dnat_guard c_sshflood; do
    COUNTERS+="    counter $_c { packets 0 bytes 0 }"$'\n'
done
unset _c

# ─── Генерация nft-файла ─────────────────────────────────────────────────────
# NFT_FILE — файл автозагрузки (его грузит na-firewall.service). Кандидат пишется рядом
# (та же ФС → атомарный mv) и становится файлом автозагрузки только после `nft -c` И
# успешного `nft -f`. До v4.1.3 генерация шла прямо в файл автозагрузки: провал проверки
# печатал «ничего не применено», а битый файл уже лежал на месте рабочего — и первый же
# ребут поднимал ноду без файрвола. В DRY_RUN кандидат и есть результат (/tmp).
NFT_FILE="$CONF_DIR/na_filter.nft"
mkdir -p "$CONF_DIR"
if [[ "$DRY_RUN" == "1" ]]; then
    NFT_FILE="$(mktemp /tmp/na_filter.XXXXXX.nft)"; NFT_NEW="$NFT_FILE"
else
    NFT_NEW="$(mktemp "$CONF_DIR/.na_filter.nft.XXXXXX")"
    trap 'rm -f "$NFT_NEW" 2>/dev/null || true' EXIT
fi
NFT_REJECTED="$CONF_DIR/na_filter.nft.rejected"
title "Генерация nftables → $NFT_FILE"

cat > "$NFT_NEW" <<NFT
#!/usr/sbin/nft -f
# node-accelerator / protect.sh @ $(date -Is)
# FW_MODE=$FW_MODE
# Управляем ТОЛЬКО своей таблицей — НЕ flush ruleset (живём рядом с CrowdSec/Docker).

table inet na_filter {}
delete table inet na_filter

table inet na_filter {

$COUNTERS
    set whitelist_v4 { type ipv4_addr; flags interval; auto-merge; $WL4_LINE }
    set whitelist_v6 { type ipv6_addr; flags interval; auto-merge; $WL6_LINE }

    # size — потолок записей: portscan-бан ловит чистый SYN (тривиально спуфится),
    # без лимита спуф-флуд раздул бы set в памяти ядра. При переполнении новые баны
    # просто не добавляются (старые живут по timeout).
    set autoban_v4 { type ipv4_addr; flags timeout; size 65536; }
    set autoban_v6 { type ipv6_addr; flags timeout; size 65536; }
$SUSPECT_SETS
$BLOCKLIST_SETS
$FLEET_SETS
$NP_SETS

    # per-IP лимитеры: записи живут, пока адрес активен (timeout продлевается update'ом)
$RATE_SETS
$INCLUDE_TABLE

    # bogon/martian источники (RFC1918, CGNAT, loopback, link-local, TEST-NET, multicast)
    set bogon_v4 {
        type ipv4_addr; flags interval; auto-merge
        elements = {
            0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
            169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24,
            192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
            224.0.0.0/3
        }
    }

    # bogon-источники IPv6, которые НЕ могут легитимно прийти как saddr на WAN.
    # СОЗНАТЕЛЬНО без fe80::/10 (NDP/RA — link-local source), без ff00::/8 (multicast) и без
    # :: — неуказанного адреса: с него идут NS проверки дублей (DAD), до v4.2 он тут был и
    # ломал автоконфиг v6. Только однозначно поддельные диапазоны.
    set bogon_v6 {
        type ipv6_addr; flags interval; auto-merge
        elements = {
            ::1/128, ::ffff:0:0/96, 100::/64, 2001:db8::/32, fc00::/7
        }
    }

    # битые TCP-флаги / скан-пакеты → лог(rl) + drop
    chain scan_drop {
        limit rate 5/second log prefix "[na badflags] " level info
        counter name c_badflags drop
    }

    # новые TCP сверх per-IP SYN-rate → лог(rl) + drop
    chain synflood_drop {
        limit rate 5/second log prefix "[na synflood] " level info
        counter name c_synflood drop
    }

$SSH_FLOOD_CHAIN

$PORTSCAN_CHAINS

$DNAT_CHAIN

$SYNPROXY_PRE

    chain input {
        type filter hook input priority filter; policy ${FW_POLICY};

        iif lo accept
        ct state established,related accept
$SYNPROXY_IN
        ct state invalid drop

        # whitelist — всегда сверху (в т.ч. твой текущий SSH-IP)
        ip  saddr @whitelist_v4 accept
        ip6 saddr @whitelist_v6 accept
$FLEET_ACCEPT
$INCLUDE_INPUT
        # уже забаненные
        ip  saddr @autoban_v4 counter name c_autoban drop
        ip6 saddr @autoban_v6 counter name c_autoban drop
$BLOCKLIST_DROP

$ANTISPOOF

        # flag-drop: NULL, XMAS, SYN+FIN, SYN+RST, FIN+RST и прочие невалидные комбинации
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0                       jump scan_drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|syn|rst|psh|ack|urg) jump scan_drop
        tcp flags & (fin|psh|urg) == (fin|psh|urg)                         jump scan_drop
        tcp flags & (syn|fin) == (syn|fin)                                 jump scan_drop
        tcp flags & (syn|rst) == (syn|rst)                                 jump scan_drop
        tcp flags & (fin|rst) == (fin|rst)                                 jump scan_drop
        tcp flags & (fin|ack) == fin                                       jump scan_drop
        tcp flags & (psh|ack) == psh                                       jump scan_drop
        tcp flags & (ack|urg) == urg                                       jump scan_drop

        # ICMP: пинг работает, флуд режется. Лимит PER-IP (meter), НЕ глобальный — иначе
        # нода с сотнями пингующих клиентов упирается в общий потолок и пинг «пропадает».
        ip protocol icmp icmp type echo-request update @icmp4 { ip saddr limit rate over ${ICMP_RATE}/second burst ${ICMP_BURST} packets } drop
        ip protocol icmp icmp type echo-request accept
        ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
        icmpv6 type echo-request update @icmp6 { ip6 saddr limit rate over ${ICMP_RATE}/second burst ${ICMP_BURST} packets } drop
        icmpv6 type echo-request accept
        icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, packet-too-big, time-exceeded, parameter-problem, destination-unreachable, mld-listener-query, mld-listener-report, mld-listener-done } accept

$SSH_RULES

        # сервисные TCP-порты (per-IP лимиты)
$TCP_RULES

        # сервисные UDP-порты (per-IP лимиты)
$UDP_AMP
$UDP_RULES

$NODE_RULES

$PORTSCAN

        $FW_CATCHALL
    }

    chain forward {
        type filter hook forward priority filter; policy accept;
$DNAT_JUMP
    }
    chain output  { type filter hook output  priority filter; policy accept; }
}
NFT

# ─── Проверка синтаксиса ДО применения ───────────────────────────────────────
chmod 0644 "$NFT_NEW"
if ! nft -c -f "$NFT_NEW"; then
    if [[ "$DRY_RUN" == "1" ]]; then
        err "Сгенерированный ruleset не прошёл nft -c. Файл: $NFT_NEW (ничего не применено)."
    else
        mv -f "$NFT_NEW" "$NFT_REJECTED"
        err "Сгенерированный ruleset не прошёл nft -c — ничего не применено, файл автозагрузки $NFT_FILE не тронут. Отвергнутый ruleset: $NFT_REJECTED"
    fi
    exit 1
fi
ok "nft -c: синтаксис валиден"

# ─── Бюджет журнала под лог анти-скана (issue #35) ───────────────────────────
# Тулкит одной рукой включает поток `[na portscan]`, другой (optimize) ограничивает
# journald капом — и до v4.1 нигде не говорил, что вместе это даёт ретеншен меньше
# суток. Считаем ДО применения (в DRY_RUN тоже) и говорим вслух.
# ~500 Б — размер ЗАПИСИ journald, а не длины текста: сама строка «[na portscan] IN=…
# SRC=… DPT=…» это ~120 Б, но journald хранит её с заголовком и двумя десятками полей
# метаданных (_PID/_COMM/_BOOT_ID/_MACHINE_ID/…), а Compress=yes не сжимает записи
# мельче 512 Б. Замер флота даёт верхнюю границу ~700 Б/запись (405 822 строки при
# журнале 291.8 МБ) — берём 500 как срединную оценку.
NA_JOURNAL_LINE_BYTES=500
# Кап журнала в байтах. Порядок как у systemd: journald.conf, поверх — drop-in'ы
# journald.conf.d/*.conf (побеждает последний), закомментированные строки не в счёт.
# Не нашли — считаем 300M: столько ставит наш же optimize, и это худший реалистичный
# случай (на ноде без optimize кап по умолчанию — 10% от размера /var/log).
journald_cap_bytes() {
    local f v last="" n u
    for f in /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf; do
        [[ -f "$f" ]] || continue
        v="$(awk -F= '/^[[:space:]]*SystemMaxUse[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2}' "$f" 2>/dev/null | tail -1)"
        [[ -n "$v" ]] && last="$v"
    done
    [[ -n "$last" ]] || { echo $((300*1024*1024)); return 0; }
    n="$(printf '%s' "$last" | grep -oE '^[0-9]+')" || true
    [[ -n "$n" ]] || { echo $((300*1024*1024)); return 0; }
    u="$(printf '%s' "${last#"$n"}" | tr '[:lower:]' '[:upper:]')"
    case "$u" in
        K) echo $((n*1024));;
        M) echo $((n*1024*1024));;
        G) echo $((n*1024*1024*1024));;
        T) echo $((n*1024*1024*1024*1024));;
        *) echo "$n";;   # без суффикса systemd читает как байты
    esac
}
_hbytes() {   # байты → человекочитаемо (МБ/ГБ), без bc
    local b="$1"
    if   (( b >= 1024*1024*1024 )); then printf '%d.%02d ГБ' $((b/1024/1024/1024)) $(( (b*100/1024/1024/1024)%100 ))
    elif (( b >= 1024*1024 ));      then printf '%d МБ' $((b/1024/1024))
    else printf '%d КБ' $((b/1024)); fi
}
check_journal_budget() {
    [[ "$ENABLE_PORTSCAN_BAN" == "1" && "$FW_MODE" != "open" ]] || return 0
    (( PORTSCAN_LOG_RATE > 0 )) || return 0
    local cap day pct
    cap="$(journald_cap_bytes)"
    (( cap > 0 )) || return 0
    day=$(( PORTSCAN_LOG_RATE * 1440 * NA_JOURNAL_LINE_BYTES ))
    pct=$(( day * 100 / cap ))
    (( pct > 30 )) || return 0
    warn "журнал: лог анти-скана при PORTSCAN_LOG_RATE=$PORTSCAN_LOG_RATE даёт ~$(_hbytes "$day")/сутки при капе journald $(_hbytes "$cap") (${pct}% в сутки) — история в журнале проживёт меньше $(( 100 / pct )) суток и вытеснит логи входов/сервисов"
    warn "снизь PORTSCAN_LOG_RATE (0 = не логировать, на бан не влияет) или подними NA_JOURNAL_MAX_USE (optimize)"
    return 0
}
check_journal_budget

if [[ "$DRY_RUN" == "1" ]]; then
    ok "DRY-RUN: файл сгенерирован и проверен. Применение пропущено."
    info "Посмотреть: cat $NFT_FILE"
    exit 0
fi

# ─── Активные баны переживают ре-ран ─────────────────────────────────────────
# Ре-ран пересоздаёт таблицу целиком — до v4.2 вместе с ней обнулялись autoban и suspect:
# сканер, забаненный на час, возвращался сразу после любого ре-рана protect (а ре-раны
# на флоте делаются при каждой правке whitelist). Снимаем живые записи с ОСТАВШИМСЯ сроком
# и возвращаем их в новую таблицу. Best-effort: не вышло — новая таблица просто без них.
BAN_SNAP=""
snapshot_bans() {
    local set
    mkdir -p "$STATE_DIR" 2>/dev/null || return 0
    BAN_SNAP="$(mktemp "$STATE_DIR/.bans.XXXXXX")" || { BAN_SNAP=""; return 0; }
    for set in autoban_v4 autoban_v6 suspect_v4 suspect_v6; do
        [[ "$set" == suspect_* && "$ENABLE_BANONCE" != "1" ]] && continue
        nft list set inet na_filter "$set" 2>/dev/null | sed -n '/elements = {/,/^[[:space:]]*}/p' \
          | grep -oE '[0-9a-fA-F:.]+(/[0-9]+)? timeout [0-9dhms]+ expires [0-9dhms]+' \
          | awk -v set="$set" '{ e=$5; sub(/[0-9]+ms$/, "", e); if (e != "") print set, $1, e }' || true
    done | awk '
        { k=$1; v=$2 " timeout " $3
          n[k]++; buf[k]=buf[k] (buf[k]==""?"":", ") v
          if (n[k] % 500 == 0) { print "add element inet na_filter " k " { " buf[k] " }"; buf[k]="" } }
        END { for (k in buf) if (buf[k] != "") print "add element inet na_filter " k " { " buf[k] " }" }
    ' > "$BAN_SNAP"
    [[ -s "$BAN_SNAP" ]] || { rm -f "$BAN_SNAP"; BAN_SNAP=""; }
}
restore_bans() {
    [[ -n "$BAN_SNAP" && -s "$BAN_SNAP" ]] || return 0
    local n
    n="$(grep -oE 'timeout' "$BAN_SNAP" | wc -l | tr -d ' ')"
    if nft -f "$BAN_SNAP" 2>/dev/null; then
        ok "перенесено записей autoban/suspect из прошлой таблицы: $n (с оставшимся сроком)"
    else
        warn "не удалось перенести $n записей autoban/suspect — новая таблица начнёт с чистого листа"
    fi
    rm -f "$BAN_SNAP"; BAN_SNAP=""
}
snapshot_bans

# ─── Применяем (с сейфти-таймером) ───────────────────────────────────────────
# Был ли сейфти взведён ДО нас (прошлый неинтерактивный прогон без подтверждения):
# arm_safety его перевзводит, и при отказе nft -f его надо вернуть, а не снять.
SAFETY_PRE=0
{ systemctl is-active --quiet na-fw-safety.timer 2>/dev/null \
  || { [[ -f "$STATE_DIR/na-fw-safety.pid" ]] && kill -0 "$(cat "$STATE_DIR/na-fw-safety.pid" 2>/dev/null)" 2>/dev/null; }; } && SAFETY_PRE=1
arm_safety
if ! nft -f "$NFT_NEW"; then
    # Ядро отвергло транзакцию целиком — живая таблица осталась прежней. Взведённый сейфти
    # через SAFETY_DELAY снёс бы её И выключил автозагрузку: нода, которой ре-ран не
    # изменил ничего, осталась бы без защиты. Чужой (прошлого прогона) сейфти — оставляем.
    [[ "$SAFETY_PRE" == "1" ]] || disarm_safety
    [[ -n "$BAN_SNAP" ]] && rm -f "$BAN_SNAP"
    mv -f "$NFT_NEW" "$NFT_REJECTED"
    err "nft -f не применил ruleset (ядро отвергло транзакцию) — живые правила и файл автозагрузки прежние. Отвергнутый ruleset: $NFT_REJECTED"
    exit 1
fi
backup_file "$NFT_FILE" "$BACKUP"
mv -f "$NFT_NEW" "$NFT_FILE"
rm -f "$NFT_REJECTED" 2>/dev/null || true
# хэш файла автозагрузки: ручная правка na_filter.nft видна в na-diagnose (ре-ран её сотрёт)
NFT_SHA="$(sha256sum "$NFT_FILE" 2>/dev/null | awk '{print $1}')"
ok "nftables na_filter применён"
restore_bans
# новый руллсет применён → прошлое срабатывание сейфти больше не актуально
rm -f "$STATE_DIR/safety-fired.last" 2>/dev/null || true

# boot-persist через свой сервис (не трогаем /etc/nftables.conf и чужие таблицы)
# Порядок как у дистрибутивного nftables.service: правила встают ДО network-pre.target, то
# есть до подъёма сети. До v4.2 стояло After=network-pre.target без DefaultDependencies=no —
# окно, в котором сеть уже поднята, а na_filter ещё нет.
cat > /etc/systemd/system/na-firewall.service <<EOF
[Unit]
Description=node-accelerator nftables (na_filter)
DefaultDependencies=no
After=local-fs.target
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
$SP_MODPROBE
ExecStart=/usr/sbin/nft -f $NFT_FILE
ExecReload=/usr/sbin/nft -f $NFT_FILE

[Install]
WantedBy=multi-user.target
EOF
# nft_synproxy грузим на boot (и на стоковых, и на XanMod — модуль, CONFIG_NFT_SYNPROXY=m).
# SYNPROXY требует nf_conntrack_tcp_loose=0: при loose=1 conntrack «подхватывает» третий
# ACK как новое соединение, synproxy его не видит, и сокет отвечает RST. Плата: после
# сброса conntrack (ребут модуля, failover) уже установленные соединения не подхватываются.
if [[ "$SYNPROXY_OK" == "1" ]]; then
    echo "nft_synproxy" > /etc/modules-load.d/na-synproxy.conf
    printf '# node-accelerator: SYNPROXY (ENABLE_SYNPROXY=1)\nnet.netfilter.nf_conntrack_tcp_loose = 0\n' > /etc/sysctl.d/99-na-synproxy.conf
    sysctl -q -w net.netfilter.nf_conntrack_tcp_loose=0 2>/dev/null || warn "не смог выставить nf_conntrack_tcp_loose=0 — SYNPROXY не будет завершать рукопожатия"
else
    rm -f /etc/modules-load.d/na-synproxy.conf 2>/dev/null || true
    if [[ -f /etc/sysctl.d/99-na-synproxy.conf ]]; then
        rm -f /etc/sysctl.d/99-na-synproxy.conf
        sysctl -q -w net.netfilter.nf_conntrack_tcp_loose=1 2>/dev/null || true
    fi
fi
systemctl daemon-reload
systemctl enable na-firewall.service >/dev/null 2>&1 || true
# Дистрибутивный nftables.service НЕ включаем (до v4.1.2 включали «для персиста»):
# его конфиг /etc/nftables.conf тулкит не пишет, а дефолтный шаблон начинается с
# `flush ruleset` и ExecStop у юнита = `nft flush ruleset` — любой stop/restart/reload
# такого «ничейного» юнита снёс бы na_filter, таблицы CrowdSec и Docker. Персист даёт
# только na-firewall.service; состояние nftables.service — решение оператора, не трогаем
# ни на первом прогоне, ни на ре-ране.
ok "na-firewall.service включён (правила переживут reboot — если не сработает сейфти-таймер: он теперь снимает и автозагрузку)"

fi  # ═══ конец блока файрвола (FW_MODE=skip его пропускает) ═══

# ═══ v3.0 МОДУЛИ: fleet-sync · blocklists · ctguard ═══════════════════════════
# Зависимости только под включённые модули (jq — fleet/blocklists, conntrack — ctguard).
_dep_list=()
{ [[ "$FLEET_ON" == "1" ]] || [[ "$ENABLE_BLOCKLISTS" == "1" && "$FW_MODE" != "skip" ]]; } && _dep_list+=(jq)
[[ "$ENABLE_CTGUARD" == "1" ]] && _dep_list+=(conntrack)
if [[ "${#_dep_list[@]}" -gt 0 ]]; then
    apt_install "${_dep_list[@]}" || warn "не доустановил зависимости: ${_dep_list[*]}"
fi

# ── Fleet auto-sync: ноды флота из Remnawave-панели → nft-сет na_fleet_* ──────
if [[ "$FLEET_ON" == "1" ]]; then
    title "Fleet auto-sync (ноды флота → whitelist)"
    if [[ -n "$REMNAWAVE_NODES_URL" ]] || [[ -n "$REMNAWAVE_URL" && -n "$REMNAWAVE_TOKEN" ]]; then
        umask 077; mkdir -p "$CONF_DIR"
        # fleet.env хелпер подключает через `.` от root каждые 5 минут: до v4.2 значения
        # писались как есть, и токен вида `abc;cmd` исполнял cmd, а `abc def` молча давал
        # пустой токен (синк навсегда на last-known-good). Набор символов токена проверяем,
        # значения пишем в экранированном виде (%q).
        for _k in REMNAWAVE_TOKEN CADDY_AUTH_API_TOKEN; do
            [[ -z "${!_k}" || "${!_k}" =~ ^[A-Za-z0-9._~+/=:-]+$ ]] \
                || { err "$_k: недопустимые символы (ожидается base64/JWT/hex-подобный токен)"; exit 1; }
        done
        unset _k
        {
            [[ -z "$REMNAWAVE_URL"            ]] || printf 'REMNAWAVE_URL=%q\n' "$REMNAWAVE_URL"
            [[ -z "$REMNAWAVE_TOKEN"          ]] || printf 'REMNAWAVE_TOKEN=%q\n' "$REMNAWAVE_TOKEN"
            [[ -z "$REMNAWAVE_NODES_URL"      ]] || printf 'REMNAWAVE_NODES_URL=%q\n' "$REMNAWAVE_NODES_URL"
            [[ -z "$CADDY_AUTH_API_TOKEN"     ]] || printf 'CADDY_AUTH_API_TOKEN=%q\n' "$CADDY_AUTH_API_TOKEN"
        } > "$CONF_DIR/fleet.env"
        chmod 0600 "$CONF_DIR/fleet.env"; chown root:root "$CONF_DIR/fleet.env" 2>/dev/null || true
        if [[ -n "$REMNAWAVE_NODES_URL" ]]; then
            ok "источник нод сохранён в $CONF_DIR/fleet.env (NODES_URL — без API-токена на ноде)"
        else
            ok "токен панели сохранён в $CONF_DIR/fleet.env (root:root 0600, НЕ в protect.conf)"
        fi
    elif [[ -f "$CONF_DIR/fleet.env" ]]; then
        info "использую сохранённый $CONF_DIR/fleet.env"
    fi
    cat > /usr/local/sbin/na-fleet-sync <<'FSYNC'
#!/usr/bin/env bash
# na-fleet-sync — держит адреса нод флота в nft-сете na_fleet_v4/v6 (accept сразу
# после whitelist). Источник (из /etc/node-accelerator/fleet.env):
#   1) REMNAWAVE_NODES_URL — статический список БЕЗ токена панели на ноде: JSON того же
#      вида, что /api/nodes, ИЛИ plain-text «адрес на строку» (# — комментарий).
#   2) REMNAWAVE_URL + REMNAWAVE_TOKEN — GET /api/nodes по Bearer. Токен уходит ТОЛЬКО
#      на заданный оператором URL. CADDY_AUTH_API_TOKEN (опц.) → X-Api-Key для Caddy
#      Security / Tiny Auth перед панелью.
# Fail-safe: источник недоступен / кривой ответ / 0 валидных IP → текущий whitelist нод
# НЕ трогаем (last-known-good). Применение отдельной nft-транзакцией: битые данные не
# ломают na_filter. Успех отмечается в /var/lib/node-accelerator/fleet-sync.last —
# na-diagnose показывает возраст последнего синка (протухший токен виден, а не молчит).
set -u
TAG=na-fleet-sync
ENVF=/etc/node-accelerator/fleet.env
STAMP=/var/lib/node-accelerator/fleet-sync.last
[ -r "$ENVF" ] || { logger -t "$TAG" "нет $ENVF — выкл"; exit 0; }
# shellcheck disable=SC1090
. "$ENVF"
URL="${REMNAWAVE_URL:-}"; TOKEN="${REMNAWAVE_TOKEN:-}"; NURL="${REMNAWAVE_NODES_URL:-}"
CADDY="${CADDY_AUTH_API_TOKEN:-}"
{ [ -n "$NURL" ] || { [ -n "$URL" ] && [ -n "$TOKEN" ]; }; } || { logger -t "$TAG" "источник не задан — выкл"; exit 0; }
command -v curl >/dev/null 2>&1 || { logger -t "$TAG" "нет curl"; exit 1; }
nft list set inet na_filter na_fleet_v4 >/dev/null 2>&1 || { logger -t "$TAG" "сет na_fleet нет (protect без fleet) — выкл"; exit 0; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# Секреты уходят в ФАЙЛ заголовков (внутри 0700-каталога), а не в argv: аргументы
# процесса видны всей системе через /proc/<pid>/cmdline на всё время запроса.
HDRF="$TMP/hdr"
: > "$HDRF"; chmod 600 "$HDRF"
[ -n "$CADDY" ] && printf 'X-Api-Key: %s\n' "$CADDY" >> "$HDRF"
# В journald пишем URL без userinfo: README сам предлагает закрывать статический список
# basic-auth'ом (https://user:pass@host/nodes.json), а лог читает кто угодно с доступом
# к journalctl — пароль там жил бы вечно и повторялся каждый тик синка.
redact_url() { printf '%s' "$1" | sed -E 's#^([A-Za-z][A-Za-z0-9+.-]*://)[^/@]*@#\1***@#'; }
# curl срезает Authorization на кросс-хост редиректе, но кастомный X-Api-Key — НЕТ:
# с -L токен Caddy утёк бы на хост-цель редиректа. При заданном токене редиректы НЕ
# следуем (оператор задаёт финальный https-URL сам). Без токена -L оставляем, но
# --proto-redir '=https' не даёт редиректу увести фетч списка нод на cleartext http.
FS_REDIR=(-L --max-redirs 3)
[ -n "$CADDY" ] && FS_REDIR=(--max-redirs 0)
if [ -n "$NURL" ]; then
    SRC="$NURL"
    CURL_HDR=()
    [ -s "$HDRF" ] && CURL_HDR=(-H @"$HDRF")
    HTTP="$(curl -fsS "${FS_REDIR[@]}" --proto-redir '=https' --max-time 15 -o "$TMP/r" -w '%{http_code}' \
            "${CURL_HDR[@]}" "$NURL" 2>/dev/null || true)"
else
    command -v jq >/dev/null 2>&1 || { logger -t "$TAG" "нет jq (нужен для /api/nodes)"; exit 1; }
    URL="${URL%/}"; SRC="$URL/api/nodes"
    printf 'Authorization: Bearer %s\n' "$TOKEN" >> "$HDRF"
    printf 'Accept: application/json\n' >> "$HDRF"
    HTTP="$(curl -fsS --max-time 15 -o "$TMP/r" -w '%{http_code}' \
            -H @"$HDRF" "$SRC" 2>/dev/null || true)"
fi
[ "$HTTP" = "200" ] && [ -s "$TMP/r" ] || { logger -t "$TAG" "источник недоступен (HTTP=$HTTP) — last-known-good"; exit 0; }
: > "$TMP/addr"
if command -v jq >/dev/null 2>&1; then
    jq -r '.. | objects | .address? // empty' "$TMP/r" 2>/dev/null | awk 'NF' >> "$TMP/addr" || true
fi
if [ ! -s "$TMP/addr" ] && [ -n "$NURL" ]; then
    # plain-text режим NODES_URL: адрес/hostname на строку (валидация/резолв ниже).
    # s/\r$//: CRLF-файлы (Windows/панель/CDN) иначе оставляют \r в токене → 0 валидных
    # адресов навсегда. head -n 200: кэп на случай, если по URL прилетела HTML-страница
    # логина — не делать сотни getent-резолвов мусора каждый тик.
    sed -E 's/\r$//; s/#.*$//' "$TMP/r" | awk 'NF{print $1}' | head -n 200 >> "$TMP/addr"
fi
sort -u -o "$TMP/addr" "$TMP/addr"
[ -s "$TMP/addr" ] || { logger -t "$TAG" "в ответе нет адресов — last-known-good"; exit 0; }
: > "$TMP/v4"; : > "$TMP/v6"
while IFS= read -r a; do
    [ -n "$a" ] || continue
    if printf '%s' "$a" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then echo "$a" >> "$TMP/v4"; continue; fi
    if printf '%s' "$a" | grep -qE '^[0-9a-fA-F:]+$' && printf '%s' "$a" | grep -q ':'; then echo "$a" >> "$TMP/v6"; continue; fi
    getent ahostsv4 "$a" 2>/dev/null | awk '{print $1}' >> "$TMP/v4"
    getent ahostsv6 "$a" 2>/dev/null | awk '{print $1}' >> "$TMP/v6"
done < "$TMP/addr"
V4="$(grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$TMP/v4" 2>/dev/null | sort -u | paste -sd, -)"
V6="$(grep -E '^[0-9a-fA-F:]+$' "$TMP/v6" 2>/dev/null | grep ':' | sort -u | paste -sd, -)"
[ -n "$V4" ] || [ -n "$V6" ] || { logger -t "$TAG" "0 валидных IP — last-known-good"; exit 0; }
{
    echo "flush set inet na_filter na_fleet_v4"
    [ -n "$V4" ] && echo "add element inet na_filter na_fleet_v4 { $V4 }"
    echo "flush set inet na_filter na_fleet_v6"
    [ -n "$V6" ] && echo "add element inet na_filter na_fleet_v6 { $V6 }"
} > "$TMP/upd.nft"
n4=$(printf '%s' "$V4" | tr ',' '\n' | grep -c . || true)
n6=$(printf '%s' "$V6" | tr ',' '\n' | grep -c . || true)
if nft -f "$TMP/upd.nft" 2>/dev/null; then
    mkdir -p /var/lib/node-accelerator && date +%s > "$STAMP"
    logger -t "$TAG" "whitelist нод обновлён: ${n4} v4 + ${n6} v6 (из $(redact_url "$SRC"))"
else
    logger -t "$TAG" "nft apply не прошёл — last-known-good сохранён"
fi
FSYNC
    chmod +x /usr/local/sbin/na-fleet-sync
    cat > /etc/systemd/system/na-fleet-sync.service <<'EOF'
[Unit]
Description=node-accelerator fleet whitelist sync (Remnawave /api/nodes)
After=na-firewall.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/na-fleet-sync
EOF
    cat > /etc/systemd/system/na-fleet-sync.timer <<EOF
[Unit]
Description=node-accelerator fleet sync timer
[Timer]
OnBootSec=60s
OnUnitActiveSec=$FLEET_SYNC_INTERVAL
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now na-fleet-sync.timer >/dev/null 2>&1 || true
    /usr/local/sbin/na-fleet-sync >/dev/null 2>&1 || true
    ok "fleet-sync включён (интервал $FLEET_SYNC_INTERVAL). Лог: journalctl -t na-fleet-sync"
fi

# ── Статич-блоклисты: Spamhaus DROP + FireHOL L1 [+ Tor] → nft-сет blocklist_* ─
# (при FW_MODE=skip сеты blocklist_* не существуют — модуль пропускается, info выше)
if [[ "$ENABLE_BLOCKLISTS" == "1" && "$FW_MODE" != "skip" ]]; then
    title "Статич-блоклисты (Spamhaus DROP / FireHOL L1$([[ "$BLOCK_TOR" == "1" ]] && echo ' / Tor'))"
    cat > /usr/local/sbin/na-blocklist-update <<'BLUP'
#!/usr/bin/env bash
# na-blocklist-update — обновляет nft-сеты blocklist_v4/v6 из публичных threat-фидов.
# Источники: Spamhaus DROP (json v4+v6), FireHOL Level 1 (v4), опц. Tor exit-list.
# Плюс /etc/node-accelerator/custom-blocklist.txt (локальные дополнения оператора).
# Bogon/private-фильтр, валидация, отдельная nft-транзакция (битый фид не ломает
# na_filter), last-known-good при недоступности фидов.
set -u
TAG=na-blocklist
BLOCK_TOR_FLAG="${1:-0}"
CUSTOM=/etc/node-accelerator/custom-blocklist.txt
nft list set inet na_filter blocklist_v4 >/dev/null 2>&1 || { logger -t "$TAG" "сет blocklist нет — выкл"; exit 0; }
command -v curl >/dev/null 2>&1 || { logger -t "$TAG" "нет curl"; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fetch() { curl -fsSL --connect-timeout 10 --max-time 60 "$1" 2>/dev/null; }
: > "$TMP/v4.raw"; : > "$TMP/v6.raw"
# Spamhaus DROP (json). jq может не быть — тогда фид пропускается.
if command -v jq >/dev/null 2>&1; then
    fetch https://www.spamhaus.org/drop/drop_v4.json | jq -r '.cidr // empty' 2>/dev/null >> "$TMP/v4.raw"
    fetch https://www.spamhaus.org/drop/drop_v6.json | jq -r '.cidr // empty' 2>/dev/null >> "$TMP/v6.raw"
fi
# FireHOL Level 1 (v4, high-confidence)
fetch https://iplists.firehol.org/files/firehol_level1.netset | grep -vE '^#' >> "$TMP/v4.raw"
# Tor exit nodes (опц.)
[ "$BLOCK_TOR_FLAG" = "1" ] && fetch https://check.torproject.org/torbulkexitlist >> "$TMP/v4.raw"
# локальные дополнения оператора (v4 и v6 вперемешку)
[ -r "$CUSTOM" ] && grep -vE '^\s*#|^\s*$' "$CUSTOM" >> "$TMP/v4.raw" && grep ':' "$CUSTOM" 2>/dev/null >> "$TMP/v6.raw"
# v4: только валидные IP/CIDR, без приватных/CGNAT/loopback/0.0.0.0
grep -hoE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "$TMP/v4.raw" 2>/dev/null \
  | grep -vE '^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)' \
  | sort -u > "$TMP/v4.clean"
# Слишком широкие префиксы — отказ: одна строка `x.x.x.x/0` в custom-blocklist.txt или в
# испорченном фиде заблокировала бы весь интернет (v4 короче /8, v6 короче /19 не бывает
# в настоящих списках злоумышленников).
awk -F/ 'NF==1 || $2>=8' "$TMP/v4.clean" > "$TMP/v4.ok"
WIDE4=$(( $(grep -c . "$TMP/v4.clean" 2>/dev/null || true) - $(grep -c . "$TMP/v4.ok" 2>/dev/null || true) ))
mv -f "$TMP/v4.ok" "$TMP/v4.clean"
[ "$WIDE4" -gt 0 ] && logger -t "$TAG" "отброшено $WIDE4 v4-префиксов шире /8 (ошибка фида/опечатка в custom)"
# v6: из jq-чистых .cidr (+ кастомные), базовая sanity
grep -hE '^[0-9a-fA-F:/]+$' "$TMP/v6.raw" 2>/dev/null | grep ':' | awk -F/ 'NF==1 || $2>=19' | sort -u > "$TMP/v6.clean"
# `grep -c` на пустом файле САМ печатает 0 и возвращает rc=1, поэтому `|| echo 0` дописал бы
# второй ноль и превратил число в "0\n0" — арифметика ниже сломалась бы на ровном месте.
N4="$(grep -c . "$TMP/v4.clean" 2>/dev/null)"; N4="${N4:-0}"
N6="$(grep -c . "$TMP/v6.clean" 2>/dev/null)"; N6="${N6:-0}"
[ "$N4" -gt 0 ] || { logger -t "$TAG" "0 v4-записей (фиды недоступны?) — last-known-good"; exit 0; }
{
    echo "flush set inet na_filter blocklist_v4"
    echo "add element inet na_filter blocklist_v4 { $(paste -sd, "$TMP/v4.clean") }"
    if [ "$N6" -gt 0 ]; then
        echo "flush set inet na_filter blocklist_v6"
        echo "add element inet na_filter blocklist_v6 { $(paste -sd, "$TMP/v6.clean") }"
    fi
} > "$TMP/bl.nft"
if nft -f "$TMP/bl.nft" 2>/dev/null; then
    mkdir -p /var/lib/node-accelerator && date +%s > /var/lib/node-accelerator/blocklist.last
    logger -t "$TAG" "blocklist обновлён: ${N4} v4 + ${N6} v6"
else
    logger -t "$TAG" "nft apply не прошёл — last-known-good"
fi
BLUP
    chmod +x /usr/local/sbin/na-blocklist-update
    cat > /etc/systemd/system/na-blocklist.service <<EOF
[Unit]
Description=node-accelerator threat blocklist update
After=na-firewall.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/na-blocklist-update $BLOCK_TOR
EOF
    cat > /etc/systemd/system/na-blocklist.timer <<EOF
[Unit]
Description=node-accelerator blocklist refresh timer
[Timer]
OnBootSec=120s
OnUnitActiveSec=$BLOCKLIST_REFRESH
RandomizedDelaySec=300
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now na-blocklist.timer >/dev/null 2>&1 || true
    /usr/local/sbin/na-blocklist-update "$BLOCK_TOR" >/dev/null 2>&1 || true
    ok "блоклисты включены (обновление $BLOCKLIST_REFRESH). Лог: journalctl -t na-blocklist"
fi

# ── conntrack phantom-eviction (защита от distributed connect-and-hold) ───────
if [[ "$ENABLE_CTGUARD" == "1" ]]; then
    title "conntrack-guard (phantom-eviction)$([[ "$NA_CTG_ENFORCE" == "1" ]] && echo ' [ENFORCE]' || echo ' [observe]')"
    cat > "$CONF_DIR/ctguard.conf" <<EOF
# node-accelerator ctguard — детект distributed connect-and-hold по «живым» сокетам.
# Источник-фантом: conntrack ≫ живых сокетов (ss) → соединения брошены. CGNAT-safe:
# эвикт только концентрированный холдер с conntrack ≥ PHANTOM_MIN и live ≤ LIVE_FLOOR.
NA_CTG_ENFORCE=$NA_CTG_ENFORCE
NA_CTG_PHANTOM_MIN=${NA_CTG_PHANTOM_MIN:-4000}
NA_CTG_LIVE_FLOOR=${NA_CTG_LIVE_FLOOR:-2}
NA_CTG_BANTIME=${NA_CTG_BANTIME:-15m}
NA_CTG_COARSE_MULT=${NA_CTG_COARSE_MULT:-3}
EOF
    chmod 0640 "$CONF_DIR/ctguard.conf"
    cat > /usr/local/sbin/na-ctguard <<'CTG'
#!/usr/bin/env bash
# na-ctguard — liveness-aware защита от distributed connect-and-hold флуда. Класс атаки,
# который статичные rate-limit'ы не ловят: сотни IP открывают тысячи TCP, проходят
# handshake и БРОСАЮТ их — conntrack пухнет, приложение (xray) захлёбывается, но per-IP
# счётчики молчат (пик атаки пересекается с легит-CGNAT-потолком). Признак фантома:
# conntrack ≫ живых сокетов (ss). Дёшево: дорогой `conntrack -L` только если коарс-гейт
# (conntrack ≫ ss) сработал. CGNAT-safe: пропускаем источники с живыми сокетами,
# малым conntrack или в whitelist. observe-режим (NA_CTG_ENFORCE=0) — только лог.
set -u
TAG=na-ctguard
CONF=/etc/node-accelerator/ctguard.conf
# shellcheck disable=SC1090
[ -r "$CONF" ] && . "$CONF"
ENFORCE="${NA_CTG_ENFORCE:-0}"
PHANTOM_MIN="${NA_CTG_PHANTOM_MIN:-4000}"
LIVE_FLOOR="${NA_CTG_LIVE_FLOOR:-2}"
BANTIME="${NA_CTG_BANTIME:-15m}"
COARSE_MULT="${NA_CTG_COARSE_MULT:-3}"
command -v conntrack >/dev/null 2>&1 || { logger -t "$TAG" "нет conntrack-tools"; exit 0; }

# своя изолированная таблица (priority -5 → раньше na_filter); rollback = удалить таблицу
nft list table inet na_ctguard >/dev/null 2>&1 || nft -f - <<'NFTG'
table inet na_ctguard {
    set phantom_v4 { type ipv4_addr; flags timeout; size 131072; }
    set phantom_v6 { type ipv6_addr; flags timeout; size 131072; }
    chain input {
        type filter hook input priority -5; policy accept;
        ip  saddr @phantom_v4 drop
        ip6 saddr @phantom_v6 drop
    }
}
NFTG

CT_TOTAL="$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)"
SS_TOTAL="$(ss -tnH state established 2>/dev/null | wc -l)"
# коарс-гейт: дорогой дамп только если conntrack заметно больше живых сокетов И велик
[ "$CT_TOTAL" -ge "$PHANTOM_MIN" ] || exit 0
[ "$CT_TOTAL" -ge $((SS_TOTAL * COARSE_MULT)) ] || exit 0

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# Живые established по src-IP клиента.
# `::ffff:` снимаем обязательно: когда сервис слушает на `*:443` (v6-сокет принимает
# v4-mapped), ss печатает пиров как `[::ffff:1.2.3.4]`, а conntrack — голым `1.2.3.4`.
# Без нормализации лукап живых сокетов не матчится НИКОГДА, live всегда читается как 0,
# и LIVE_FLOOR — вся CGNAT-защита — не срабатывает: эвиктится любой холдер выше
# PHANTOM_MIN. Ровно та же нормализация давно стоит в harvest_node_port_peers().
ss -tnH state established 2>/dev/null | awk '{print $NF}' \
  | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//; s/^::ffff:([0-9.]+)$/\1/' | sort | uniq -c > "$TMP/live"
# Адреса, которые НЕ могут быть источником входящей атаки и потому не бывают кандидатами.
# Первый src= в записи conntrack — клиентский IP только для ВХОДЯЩИХ соединений; для
# исходящих (xray → сайт) это адрес самой ноды, а на relay исходящие доминируют. Без
# фильтра нода становится крупнейшим «фантом-холдером»: банит сама себя, и `conntrack -D`
# по своему адресу сносит состояние всех проксируемых сессий разом. Приватные диапазоны
# отсекаем по той же причине — там живут docker-бриджи и туннельные плечи.
SELF_RE="$( { ip -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1
              printf '127.0.0.1\n::1\n'; } | sed 's/\./\\./g' | paste -sd'|' - )"
PRIV_RE='^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|f[cd]|fe[89ab])'
# conntrack по ПЕРВОМУ src= — только tcp, без собственных и служебных адресов
# DNAT-потоки (опубликованные порты контейнеров, второй тенант на боксе) пропускаем:
# их живые сокеты — в netns контейнера, ss хоста их не видит, и клиент выглядел бы фантомом
# (бан на input отрезал бы его от сервисов ЭТОЙ ноды). DNAT = reply-src ≠ orig-dst.
conntrack -L -p tcp 2>/dev/null \
  | awk '{ s=""; d=""; rs="";
           for(i=1;i<=NF;i++){
               if($i ~ /^src=/){ if(s=="") s=substr($i,5); else if(rs=="") rs=substr($i,5) }
               else if($i ~ /^dst=/ && d=="") d=substr($i,5)
           }
           if (s != "" && (rs == "" || rs == d)) print s }' \
  | grep -Ev "^(${SELF_RE})$" | grep -Ev "$PRIV_RE" \
  | sort | uniq -c | sort -rn > "$TMP/ct"

is_white() {  # в whitelist na_filter или в fleet-сете?
    local ip="$1" s4 s6
    if printf '%s' "$ip" | grep -q ':'; then s4=whitelist_v6; s6=na_fleet_v6; else s4=whitelist_v4; s6=na_fleet_v4; fi
    nft get element inet na_filter "$s4" "{ $ip }" >/dev/null 2>&1 && return 0
    nft get element inet na_filter "$s6" "{ $ip }" >/dev/null 2>&1 && return 0
    return 1
}
cand=0; eict=0
while read -r cnt ip; do
    [ -n "${ip:-}" ] || continue
    [ "$cnt" -ge "$PHANTOM_MIN" ] || break   # отсортировано по убыванию → дальше только меньше
    is_white "$ip" && continue
    live="$(awk -v ip="$ip" '$2==ip{print $1; f=1} END{if(!f)print 0}' "$TMP/live")"
    [ "${live:-0}" -le "$LIVE_FLOOR" ] || continue   # есть живые сокеты → легит/shared-front, щадим
    cand=$((cand+1))
    if [ "$ENFORCE" = "1" ]; then
        if printf '%s' "$ip" | grep -q ':'; then setn=phantom_v6; else setn=phantom_v4; fi
        nft add element inet na_ctguard "$setn" "{ $ip timeout $BANTIME }" 2>/dev/null \
            && conntrack -D -s "$ip" >/dev/null 2>&1 && eict=$((eict+1))
        logger -t "$TAG" "evict $ip ct=$cnt live=$live (bantime $BANTIME)"
    else
        logger -t "$TAG" "[observe] phantom-кандидат $ip ct=$cnt live=$live (NA_CTG_ENFORCE=0 — без эвикта)"
    fi
done < "$TMP/ct"
[ "$cand" -gt 0 ] && logger -t "$TAG" "тик: ct_total=$CT_TOTAL ss=$SS_TOTAL кандидатов=$cand эвиктов=$eict enforce=$ENFORCE"
exit 0
CTG
    chmod +x /usr/local/sbin/na-ctguard
    cat > /etc/systemd/system/na-ctguard.service <<'EOF'
[Unit]
Description=node-accelerator conntrack phantom-eviction
After=na-firewall.service
[Service]
Type=oneshot
# не отбираем CPU у xray под атакой
Nice=10
IOSchedulingClass=idle
ExecStart=/usr/local/sbin/na-ctguard
EOF
    cat > /etc/systemd/system/na-ctguard.timer <<EOF
[Unit]
Description=node-accelerator ctguard timer
[Timer]
OnBootSec=90s
OnUnitActiveSec=${NA_CTG_INTERVAL:-20s}
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now na-ctguard.timer >/dev/null 2>&1 || true
    if [[ "$NA_CTG_ENFORCE" == "1" ]]; then
        ok "ctguard ENFORCE: фантом-холдеры эвиктятся. Лог: journalctl -t na-ctguard"
    else
        warn "ctguard в OBSERVE (только лог). Убедись по journalctl -t na-ctguard, что кандидаты = только атакеры (live≤$NA_CTG_LIVE_FLOOR), затем NA_CTG_ENFORCE=1 + ре-ран protect."
    fi
fi

# ctguard выключен, а от прошлого прогона остались таймер/таблица/конфиг (NA_CTG_ENFORCE=1
# эвиктил бы и дальше каждые 20с): до v4.2 ENABLE_CTGUARD=0 на ре-ране не снимал ничего.
if [[ "$ENABLE_CTGUARD" != "1" ]] && { [[ -f /etc/systemd/system/na-ctguard.timer ]] || nft list table inet na_ctguard >/dev/null 2>&1; }; then
    systemctl disable --now na-ctguard.timer na-ctguard.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/na-ctguard.timer /etc/systemd/system/na-ctguard.service \
          /usr/local/sbin/na-ctguard "$CONF_DIR/ctguard.conf"
    systemctl daemon-reload 2>/dev/null || true
    nft delete table inet na_ctguard 2>/dev/null || true
    ok "ctguard снят (ENABLE_CTGUARD=0): таймер, таблица na_ctguard и конфиг удалены"
fi

# ─── fw-status хелпер ────────────────────────────────────────────────────────
# Все счётчики наборов идут через nft_set_count из lib/common.sh, а тело функций
# ВШИВАЕТСЯ в хелпер через `declare -f`: na-fw-status — самостоятельный скрипт на ноде,
# и lib/common.sh рядом с ним может не лежать вовсе (curl|bash гоняет модули из
# временной папки, которой после установки уже нет).
# Почему не `grep -c` по выводу nft: в заголовке ЛЮБОГО динамического набора всегда есть
# строка `flags dynamic,timeout`, поэтому `grep -c timeout` рисовал «1» на ПУСТОМ наборе
# и +1 на непустом, а элементы nft переносит по несколько в строку — «строка = адрес» не
# выполняется в принципе. Один и тот же autoban считался в na-fw-status и в na-diagnose
# двумя разными способами, и команды расходились между собой на живой ноде (issue #32/#36).
write_fw_status() {
    {
        echo '#!/usr/bin/env bash'
        echo '# na-fw-status — сводка защиты (ставит protect.sh, снимает rollback).'
        echo '# Счётчики наборов — общий хелпер lib/common.sh, вшит сюда declare -f: скрипт'
        echo '# должен работать на ноде сам по себе, без каталога с библиотекой рядом.'
        declare -f nft_set_count nft_set_elems
        cat <<'STAT'
echo "── nft table inet na_filter ──"
# -t: без содержимого наборов — лимитеры держат десятки тысяч записей
nft -t list table inet na_filter 2>/dev/null | grep -E 'policy' | head -5
echo
echo "── отброшено (именованные счётчики, с загрузки таблицы) ──"
nft list counters table inet na_filter 2>/dev/null \
  | awk '/counter c_/{n=$2} /packets/{for(i=1;i<=NF;i++) if($i=="packets"){p=$(i+1); b=$(i+3)}; if(n!=""){printf "  %-14s %12s пакетов %14s байт\n", n, p, b; n=""}}'
echo
echo "── autoban (живые баны) ──"
echo "v4: $(nft_set_count inet na_filter autoban_v4)   v6: $(nft_set_count inet na_filter autoban_v6)"
# Кто именно забанен и до когда. Срез строго по блоку `elements = { … }`: вне его те же
# слова timeout/expires живут в заголовке набора.
nft list set inet na_filter autoban_v4 2>/dev/null | sed -n '/elements = {/,/^[[:space:]]*}/p' \
  | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3} (timeout|expires)[^,}]*' | head -15
if nft list set inet na_filter suspect_v4 >/dev/null 2>&1; then
    echo "suspect (наблюдение, ban-once) v4: $(nft_set_count inet na_filter suspect_v4)   v6: $(nft_set_count inet na_filter suspect_v6)"
fi
echo
if nft list set inet na_filter blocklist_v4 >/dev/null 2>&1; then
    echo "── threat-блоклисты ──"
    echo "v4: $(nft_set_count inet na_filter blocklist_v4)   v6: $(nft_set_count inet na_filter blocklist_v6)   (обновляет na-blocklist-update)"
    echo
fi
if nft list set inet na_filter na_fleet_v4 >/dev/null 2>&1; then
    echo "── fleet-sync (ноды флота → whitelist) ──"
    echo "v4: $(nft_set_count inet na_filter na_fleet_v4)   v6: $(nft_set_count inet na_filter na_fleet_v6)   (последний синк: $(journalctl -t na-fleet-sync -n1 --no-pager -o cat 2>/dev/null | head -c 80))"
    echo
fi
if nft list table inet na_ctguard >/dev/null 2>&1; then
    echo "── ctguard (phantom-eviction) ──"
    enf="$(awk -F= '/^NA_CTG_ENFORCE/{print $2}' /etc/node-accelerator/ctguard.conf 2>/dev/null)"
    echo "режим: $([ "${enf:-0}" = 1 ] && echo ENFORCE || echo observe)   фантомов в блоке v4: $(nft_set_count inet na_ctguard phantom_v4)   v6: $(nft_set_count inet na_ctguard phantom_v6)"
    journalctl -t na-ctguard -n3 --no-pager -o cat 2>/dev/null | sed 's/^/    /'
    echo
fi
if [ -f /var/lib/node-accelerator/.synproxy-degraded ]; then
    echo "⚠ SYNPROXY DEGRADED: $(cat /var/lib/node-accelerator/.synproxy-degraded)"
    echo
fi
if command -v cscli >/dev/null 2>&1; then
    echo "── CrowdSec ──"
    cscli decisions list 2>/dev/null | head -20
    echo
    cscli metrics 2>/dev/null | sed -n '1,25p'
fi
STAT
    } > /usr/local/sbin/na-fw-status
    chmod +x /usr/local/sbin/na-fw-status
}
write_fw_status

# ─── na-fw: whitelist и разбан одной командой ────────────────────────────────
# Whitelist живёт в четырёх местах (живой сет, na_filter.nft, WHITELIST= в protect.conf,
# CrowdSec-yaml), и до v4.2 штатного способа поменять его, кроме полного ре-рана, не было:
# на флоте их правили sed'ом по отдельности (сотни *.bak-*), слои расходились, а ре-ран
# молча возвращал старое. na-fw меняет все слои разом, файл проверяет nft -c до замены.
write_na_fw() {
    cat > /usr/local/sbin/na-fw <<'NAFW'
#!/usr/bin/env bash
# na-fw — whitelist и разбан для na_filter (ставит protect.sh, снимает rollback).
#   na-fw allow add <ip|cidr>…   — в whitelist: protect.conf, na_filter.nft, живой сет,
#                                  CrowdSec (парсер + правило CROWDSEC_SCOPE=ssh)
#   na-fw allow del <ip|cidr>…   — убрать оттуда же
#   na-fw allow list             — что сейчас в whitelist (живой сет и protect.conf)
#   na-fw unban <ip>…            — снять autoban/suspect и решения CrowdSec
set -euo pipefail
CONF_DIR=/etc/node-accelerator
STATE_DIR=/var/lib/node-accelerator
CONF="$CONF_DIR/protect.conf"
NFT_FILE="$CONF_DIR/na_filter.nft"
CS_YAML=/etc/crowdsec/parsers/s02-enrich/na-whitelist.yaml
SCOPE_NFT="$CONF_DIR/na-crowdsec-scope.nft"
die() { echo "[x] $*" >&2; exit 1; }
say() { echo "[+] $*"; }
[[ ${EUID:-$(id -u)} -eq 0 ]] || die "нужен root"
fam_of() {   # fam_of <адрес> → 4|6; rc=1 — не адрес
    if [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then echo 4
    elif [[ "$1" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ && "$1" == *:* ]]; then echo 6
    else return 1; fi
}
norm() { local a="$1"; a="${a%/32}"; [[ "$a" == *:* ]] && a="${a%/128}"; printf '%s' "$a"; }
conf_list() { sed -nE 's/^: "\$\{WHITELIST:?=([^}]*)\}".*/\1/p' "$CONF" 2>/dev/null | tail -1; }
conf_set() {   # conf_set <csv> — переписать WHITELIST= в protect.conf (none = пусто)
    local v="${1:-none}" tmp
    [[ -f "$CONF" ]] || { umask 077; : > "$CONF"; }
    tmp="$(mktemp "$CONF.XXXXXX")"
    if grep -qE '^: "\$\{WHITELIST:?=' "$CONF"; then
        sed -E "s|^: \"\\\$\\{WHITELIST(:?)=[^}]*\\}\"|: \"\\\${WHITELIST\\1=$v}\"|" "$CONF" > "$tmp"
    else
        cat "$CONF" > "$tmp"; printf ': "${WHITELIST:=%s}"\n' "$v" >> "$tmp"
    fi
    chmod 0600 "$tmp"; mv -f "$tmp" "$CONF"
}
file_elems() {   # file_elems 4|6 — элементы whitelist_vN из na_filter.nft
    sed -nE "s/.*set whitelist_v$1 \\{.*elements = \\{ ([^}]*) \\}.*/\\1/p" "$NFT_FILE" 2>/dev/null | tr -d ' ' | tr ',' '\n' | grep -v '^$' || true
}
file_set() {   # file_set 4|6 <элементы через перевод строки>
    local fam="$1" list="$2" typ=ipv4_addr line tmp
    [[ "$fam" == 6 ]] && typ=ipv6_addr
    list="$(printf '%s\n' "$list" | grep -v '^$' | sort -u | paste -sd, - | sed 's/,/, /g')"
    if [[ -n "$list" ]]; then line="    set whitelist_v$fam { type $typ; flags interval; auto-merge; elements = { $list } }"
    else line="    set whitelist_v$fam { type $typ; flags interval; auto-merge;  }"; fi
    tmp="$(mktemp "$NFT_FILE.XXXXXX")"
    awk -v fam="$fam" -v line="$line" '$0 ~ "^[[:space:]]*set whitelist_v" fam " \\{" {print line; next} {print}' "$NFT_FILE" > "$tmp"
    nft -c -f "$tmp" >/dev/null 2>&1 || { rm -f "$tmp"; die "изменённый na_filter.nft не прошёл nft -c — ничего не тронуто"; }
    chmod 0644 "$tmp"; mv -f "$tmp" "$NFT_FILE"
}
sync_aux() {   # CrowdSec-yaml, правило scope, хэш в маркере — из итогового файла
    local w4 w6 ip="" cidr="" x
    w4="$(file_elems 4)"; w6="$(file_elems 6)"
    for x in $w4 $w6; do
        if [[ "$x" == */* ]]; then cidr+="    - \"$x\""$'\n'; else ip+="    - \"$x\""$'\n'; fi
    done
    if [[ -d "$(dirname "$CS_YAML")" ]]; then
        if [[ -n "$ip$cidr" ]]; then
            { echo "name: node-accelerator/whitelist"; echo "description: never ban admin/panel"; echo "whitelist:"
              echo "  reason: node-accelerator trusted"
              [[ -n "$ip"   ]] && { echo "  ip:";   printf "%s" "$ip"; }
              [[ -n "$cidr" ]] && { echo "  cidr:"; printf "%s" "$cidr"; }; } > "$CS_YAML"
        else rm -f "$CS_YAML"; fi
        systemctl reload crowdsec >/dev/null 2>&1 || true
    fi
    if [[ -f "$SCOPE_NFT" ]]; then
        local l4="        # na-wl4 (whitelist пуст)" l6="        # na-wl6 (whitelist пуст)" tmp
        [[ -n "$w4" ]] && l4="        ip saddr { $(paste -sd, - <<<"$w4" | sed 's/,/, /g') } return # na-wl4"
        [[ -n "$w6" ]] && l6="        ip6 saddr { $(paste -sd, - <<<"$w6" | sed 's/,/, /g') } return # na-wl6"
        tmp="$(mktemp "$SCOPE_NFT.XXXXXX")"
        awk -v l4="$l4" -v l6="$l6" '/na-wl4/{print l4; next} /na-wl6/{print l6; next} {print}' "$SCOPE_NFT" > "$tmp"
        if nft -c -f "$tmp" >/dev/null 2>&1; then
            mv -f "$tmp" "$SCOPE_NFT"; nft -f "$SCOPE_NFT" 2>/dev/null || true
            systemctl restart crowdsec-firewall-bouncer >/dev/null 2>&1 || true
        else rm -f "$tmp"; echo "[!] правило CrowdSec scope не обновлено (nft -c)" >&2; fi
    fi
    if [[ -f "$STATE_DIR/protect.installed" ]]; then
        local sha; sha="$(sha256sum "$NFT_FILE" | awk '{print $1}')"
        sed -i.na-tmp -E "s/^nft_sha256=.*/nft_sha256=$sha/" "$STATE_DIR/protect.installed" && rm -f "$STATE_DIR/protect.installed.na-tmp"
    fi
}
cmd="${1:-}"; sub="${2:-}"
case "$cmd" in
    allow)
        [[ -f "$NFT_FILE" ]] || die "нет $NFT_FILE — protect не ставился (или FW_MODE=skip)"
        case "$sub" in
            list)
                echo "живой сет v4: $(nft list set inet na_filter whitelist_v4 2>/dev/null | sed -n '/elements = {/,/}/p' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?' | paste -sd' ' -)"
                echo "живой сет v6: $(nft list set inet na_filter whitelist_v6 2>/dev/null | sed -n '/elements = {/,/}/p' | grep -oE '[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}(/[0-9]+)?' | paste -sd' ' -)"
                echo "protect.conf: $(conf_list)"; exit 0 ;;
            add|del) ;;
            *) die "использование: na-fw allow add|del|list <ip|cidr>…" ;;
        esac
        shift 2; [[ $# -gt 0 ]] || die "не указан адрес"
        cur="$(conf_list)"; [[ "$cur" == none ]] && cur=""
        e4="$(file_elems 4)"; e6="$(file_elems 6)"
        for a in "$@"; do
            fam="$(fam_of "$a")" || die "'$a' — не IPv4/IPv6/CIDR"
            a="$(norm "$a")"
            if [[ "$sub" == add ]]; then
                [[ ",$cur," == *",$a,"* ]] || cur+="${cur:+,}$a"
                if [[ "$fam" == 4 ]]; then e4+=$'\n'"$a"; else e6+=$'\n'"$a"; fi
                nft add element inet na_filter "whitelist_v$fam" "{ $a }" 2>/dev/null || true
                nft delete element inet na_filter "autoban_v$fam" "{ $a }" 2>/dev/null || true
                say "allow $a"
            else
                cur="$(tr ',' '\n' <<<"$cur" | grep -vxF -- "$a" | paste -sd, - || true)"
                if [[ "$fam" == 4 ]]; then e4="$(grep -vxF -- "$a" <<<"$e4" || true)"; else e6="$(grep -vxF -- "$a" <<<"$e6" || true)"; fi
                nft delete element inet na_filter "whitelist_v$fam" "{ $a }" 2>/dev/null || true
                say "deny $a (снят из whitelist)"
            fi
        done
        file_set 4 "$e4"; file_set 6 "$e6"
        conf_set "$cur"
        sync_aux
        say "whitelist обновлён во всех слоях (сет, na_filter.nft, protect.conf, CrowdSec)" ;;
    unban)
        shift; [[ $# -gt 0 ]] || die "не указан адрес"
        for a in "$@"; do
            fam="$(fam_of "$a")" || die "'$a' — не IP"
            for st in autoban suspect; do nft delete element inet na_filter "${st}_v$fam" "{ $a }" 2>/dev/null || true; done
            command -v cscli >/dev/null 2>&1 && cscli decisions delete --ip "$a" >/dev/null 2>&1 || true
            say "unban $a (autoban/suspect/CrowdSec)"
        done ;;
    *) sed -n '2,7p' "$0"; exit 1 ;;
esac
NAFW
    chmod +x /usr/local/sbin/na-fw
}
write_na_fw

# ─── top-talkers хелпер ──────────────────────────────────────────────────────
# Если нода за реверс-прокси/балансировщиком/CDN — трафик идёт с горстки upstream-IP,
# и per-IP лимиты их режут. Хелпер показывает топ источников → кандидаты в WHITELIST=.
cat > /usr/local/sbin/na-fw-top-talkers <<'TT'
#!/usr/bin/env bash
# Топ удалённых IP по числу установленных TCP-соединений на сервисных портах.
# Если нода за реверс-прокси/балансировщиком/CDN — легитимный трафик приходит с
# небольшого набора upstream-адресов; их стоит занести в WHITELIST=, чтобы per-IP
# лимиты (CONN_LIMIT/SYN_RATE) их не резали. Хелпер показывает кандидатов.
#   na-fw-top-talkers [порт[,порт...]] [N]   (по умолчанию порты из protect, N=25)
set -u
DEF=443
if [ -r /var/lib/node-accelerator/protect.installed ]; then
    DEF="$(awk -F= '/^tcp_ports=/{print $2}' /var/lib/node-accelerator/protect.installed)"
fi
PORTS="${1:-${DEF:-443}}"
N="${2:-25}"
filt=""
for p in ${PORTS//,/ }; do
    [ -n "$p" ] || continue
    filt="${filt:+$filt or }sport = :$p"
done
[ -n "$filt" ] || { echo "нет портов для анализа"; exit 1; }
echo "── Топ-$N удалённых IP по established TCP на портах: $PORTS ──"
# при `state established` ss не печатает колонку State — адрес пира последний, а не 5-й
ss -Hnt state established "( $filt )" 2>/dev/null \
    | awk '{print $NF}' \
    | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//; s/^::ffff:([0-9.]+)$/\1/' \
    | sort | uniq -c | sort -rn | head -n "$N"
TT
chmod +x /usr/local/sbin/na-fw-top-talkers

# ─── Маркер ──────────────────────────────────────────────────────────────────
mkdir -p "$STATE_DIR"
cat > "$STATE_DIR/protect.installed" <<EOF
installed_at=$(date -Is)
na_version=$NA_VERSION
backup=$BACKUP
fw_mode=$FW_MODE
ssh_port=$SSH_EFF
tcp_ports=$TCP_PORTS
udp_ports=$UDP_PORTS
node_port=${NP_EFF:-none}
crowdsec=$ENABLE_CROWDSEC
nft_file=${NFT_FILE:-}
crowdsec_scope=${CROWDSEC_SCOPE_EFF:-}
dnat_guard=$([[ "$FW_MODE" != "skip" ]] && echo "$DNAT_GUARD" || echo 0)
nft_sha256=${NFT_SHA:-}
include_dir=$CONF_DIR/na_filter.d
include_files=${INCLUDE_N:-0}
EOF

# Персист эффективного конфига → ре-ран без ENV сохранит эти значения (ENV всё ещё
# переопределяет). WHITELIST хранит только заданный оператором список (без транзитного
# авто-IP текущей SSH-сессии — тот добавляется в WL4/WL6 отдельно).
# REMNAWAVE_URL/TOKEN сюда НЕ пишем — токен живёт в fleet.env (0600), fleet-режим
# восстанавливается по наличию fleet.env.
# none-ключи возвращаем словом none (иначе следующий прогон взял бы встроенный дефолт);
# SSH_PORT пишем, только если он задан оператором — автодетект каждый прогон делает заново.
for _k in $NA_NONE_KEYS; do printf -v "$_k" '%s' none; done
_ssh_key=""; [[ " $NA_EXPLICIT_KEYS " == *" SSH_PORT "* ]] && _ssh_key=SSH_PORT
export NA_EXPLICIT_KEYS
save_conf "$CONF_DIR/protect.conf" \
    FW_MODE $_ssh_key TCP_PORTS UDP_PORTS NODE_PORT WHITELIST CROWDSEC_SCOPE DNAT_GUARD UDP_AMP_DROP \
    SYN_RATE SYN_BURST UDP_RATE UDP_BURST UDP_BULK_PORTS UDP_BULK_RATE UDP_BULK_BURST CONN_LIMIT \
    ICMP_RATE ICMP_BURST SSH_RATE SSH_BURST SSH_BAN_TIME \
    PORTSCAN_BAN_TIME PORTSCAN_RATE PORTSCAN_BURST PORTSCAN_LOG_RATE PORTSCAN_LOG_BURST \
    ENABLE_PORTSCAN_BAN ENABLE_CROWDSEC CROWDSEC_STRICT ENABLE_SYNPROXY \
    ENABLE_BLOCKLISTS BLOCK_TOR BLOCKLIST_REFRESH ENABLE_BANONCE SUSPECT_TIME \
    FLEET_SYNC FLEET_SYNC_INTERVAL \
    NODE_PORT_WHITELIST_ONLY NODE_PORT_LAST NODE_PORT_AUTOWL NODE_PORT_PEERS SAFETY_DELAY \
    ENABLE_CTGUARD NA_CTG_ENFORCE NA_CTG_PHANTOM_MIN NA_CTG_LIVE_FLOOR \
    NA_CTG_COARSE_MULT NA_CTG_BANTIME NA_CTG_INTERVAL

# ─── Подтверждение работы ────────────────────────────────────────────────────
if [[ "$FW_MODE" == "skip" ]]; then
    # nftables не ставился — сейфти-таймер не взводился, самоблокировка невозможна.
    echo
    ok "Готово. Файрвол не ставился (FW_MODE=skip). Решишь закрыть порты — инструкция выше, либо ре-ран с FW_MODE=strict. Статус CrowdSec: na-fw-status"
else
    title "Подтверждение (защита от самоблокировки)"
    echo "  Открой НОВОЕ окно и проверь: ssh root@<этот сервер>"
    if [[ -n "$ADMIN_IP" ]]; then
        echo "  (твой текущий IP $ADMIN_IP уже в whitelist, но лучше убедиться.)"
    else
        echo "  (IP текущей сессии не определён — в whitelist его НЕТ: проверь обязательно.)"
    fi
    echo
    if [[ -t 0 && -z "${REMNAWAVE_NONINTERACTIVE:-}" ]]; then
        read -r -p "Соединение работает? [y/N]: " c
        if [[ "$c" =~ ^[yYдД] ]]; then
            disarm_safety
            # сейфти мог сработать, пока шли установки модулей: «защита активна» без таблицы — ложь
            if nft -t list table inet na_filter >/dev/null 2>&1; then
                ok "Сейфти-таймер снят. Защита активна."
            else
                err "Сейфти-таймер УЖЕ сработал (таблицы na_filter нет, автозагрузка выключена) — защиты сейчас нет. Прогони protect заново (SAFETY_DELAY=… побольше)."
            fi
        else
            warn "Сейфти оставлен: через ${SAFETY_DELAY}s na_filter удалится сам."
            warn "Если всё ок — сними: systemctl stop na-fw-safety.timer  (или kill \$(cat $STATE_DIR/na-fw-safety.pid))"
        fi
    else
        warn "Неинтерактивно: сейфти-таймер на ${SAFETY_DELAY}s АКТИВЕН."
        warn "Подтверди доступ и сними: systemctl stop na-fw-safety.timer"
    fi
    echo
    [[ "$FW_MODE" == "open" ]] && info "FW_MODE=open: не перечисленные порты открыты. Появится полный список — закрой всё ре-раном с FW_MODE=strict TCP_PORTS=… UDP_PORTS=…"
    ok "Готово. Статус: na-fw-status | топ источников (для WHITELIST за CDN/LB): na-fw-top-talkers"
fi
