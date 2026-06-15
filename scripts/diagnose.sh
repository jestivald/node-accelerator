#!/usr/bin/env bash
#
# diagnose.sh — 🩺 Диагностика ноды (read-only, ничего не меняет).
# Проверяет ядро/BBR, sysctl, лимиты, conntrack, MSS-коллапс, NIC/RPS, firewall,
# blocklists/fleet/ctguard, CrowdSec — печатает итог ✔/▲/✘ с рекомендациями.
#   diagnose.sh             — человекочитаемый отчёт
#   diagnose.sh --json      — один JSON-объект для флот-мониторинга (Zabbix/Prometheus)
#   diagnose.sh --retrans [--window N]  — глубокий разбор причин TCP-retransmits

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$SCRIPT_DIR/lib/common.sh"

OKC=0; WARNC=0; FAILC=0
pass() { status_line OK   "$*"; OKC=$((OKC+1)); }
wrn()  { status_line WARN "$*"; WARNC=$((WARNC+1)); }
bad()  { status_line FAIL "$*"; FAILC=$((FAILC+1)); }
val()  { sysctl -n "$1" 2>/dev/null; }

# diagnose read-only — должен работать и на не-Debian/чужой ОС, поэтому НЕ зовём
# фатальный detect_os (он exit'ит на не-Ubuntu/Debian), просто подтягиваем os-release
# для PRETTY_NAME, если есть.
[[ -f /etc/os-release ]] && { . /etc/os-release 2>/dev/null || true; }

# ─── JSON-режим (для флот-мониторинга: Zabbix/Prometheus/SSH-поллинг) ─────────
# `diagnose.sh --json` печатает один машинно-читаемый объект и выходит. Read-only.
emit_json() {
    local kern xanmod virt cc qd ctmax ctcnt ctpct uln minsnd mtuprobe collapsed
    local fw ab4 ab6 susp bl4 bl6 fl4 fl6 crowd ctg syndeg safety rebootn
    local u1 n1 s1 i1 w1 q1 sq1 st1 u2 n2 s2 i2 w2 q2 sq2 st2 dt steal out rtx rtxpct
    kern="$(uname -r)"; uname -r | grep -qi xanmod && xanmod=true || xanmod=false
    virt="$(detect_virt)"
    cc="$(val net.ipv4.tcp_congestion_control)"; qd="$(val net.core.default_qdisc)"
    ctmax="$(val net.netfilter.nf_conntrack_max)"; ctmax="${ctmax:-0}"
    ctcnt="$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)"
    ctpct=0; [[ "${ctmax:-0}" -gt 0 ]] && ctpct=$(( ctcnt * 100 / ctmax ))
    uln="$(ulimit -n 2>/dev/null || echo 0)"
    minsnd="$(val net.ipv4.tcp_min_snd_mss)"; minsnd="${minsnd:-0}"
    mtuprobe="$(val net.ipv4.tcp_mtu_probing)"; mtuprobe="${mtuprobe:-0}"
    collapsed="$(ss -tin 2>/dev/null | grep -oE 'mss:[0-9]+' | awk -F: '$2>0 && $2<256{c++} END{print c+0}')"
    # CPU steal (1с-сэмпл) — только если есть /proc/stat
    steal=0
    if [[ -r /proc/stat ]]; then
        read -r _ u1 n1 s1 i1 w1 q1 sq1 st1 _ < /proc/stat; sleep 1
        read -r _ u2 n2 s2 i2 w2 q2 sq2 st2 _ < /proc/stat
        dt=$(( (u2+n2+s2+i2+w2+q2+sq2+st2) - (u1+n1+s1+i1+w1+q1+sq1+st1) ))
        [[ "${dt:-0}" -gt 0 ]] && steal=$(( (st2 - st1) * 100 / dt ))
    fi
    out=0; rtx=0; rtxpct=0
    if [[ -r /proc/net/snmp ]]; then
        eval "$(awk '/^Tcp:/{ if(!h){for(i=2;i<=NF;i++)nm[i]=$i;h=1;next} for(i=2;i<=NF;i++){if(nm[i]=="OutSegs")print "out="$i;if(nm[i]=="RetransSegs")print "rtx="$i} }' /proc/net/snmp 2>/dev/null)"
        out="${out:-0}"; rtx="${rtx:-0}"; [[ "$out" -gt 0 ]] && rtxpct=$(( rtx * 100 / out ))
    fi
    nft list table inet na_filter >/dev/null 2>&1 && fw=true || fw=false
    ab4="$(nft list set inet na_filter autoban_v4 2>/dev/null | grep -c timeout)"
    ab6="$(nft list set inet na_filter autoban_v6 2>/dev/null | grep -c timeout)"
    susp="$(nft list set inet na_filter suspect_v4 2>/dev/null | grep -c timeout)"
    bl4="$(nft list set inet na_filter blocklist_v4 2>/dev/null | grep -coE '[0-9.]+')"
    bl6="$(nft list set inet na_filter blocklist_v6 2>/dev/null | grep -c ':')"
    fl4="$(nft list set inet na_filter na_fleet_v4 2>/dev/null | grep -coE '[0-9.]+')"
    fl6="$(nft list set inet na_filter na_fleet_v6 2>/dev/null | grep -c ':')"
    command -v cscli >/dev/null 2>&1 && { systemctl is-active --quiet crowdsec && crowd=true || crowd=false; } || crowd=false
    if nft list table inet na_ctguard >/dev/null 2>&1; then
        local enf; enf="$(awk -F= '/^NA_CTG_ENFORCE/{print $2}' /etc/node-accelerator/ctguard.conf 2>/dev/null)"
        [[ "${enf:-0}" == 1 ]] && ctg=enforce || ctg=observe
    else ctg=off; fi
    [[ -f "$STATE_DIR/.synproxy-degraded" ]] && syndeg=true || syndeg=false
    { systemctl is-active --quiet na-fw-safety.timer 2>/dev/null \
      || { [[ -f "$STATE_DIR/na-fw-safety.pid" ]] && kill -0 "$(cat "$STATE_DIR/na-fw-safety.pid" 2>/dev/null)" 2>/dev/null; }; } \
      && safety=true || safety=false
    rebootn=false; grep -q '^reboot_needed=1' "$STATE_DIR/optimize.installed" 2>/dev/null && rebootn=true
    printf '{'
    printf '"kernel":"%s","xanmod":%s,"virt":"%s","cpu_steal_pct":%s,"tcp_retrans_pct":%s,' "$kern" "$xanmod" "$virt" "$steal" "$rtxpct"
    printf '"congestion_control":"%s","qdisc":"%s","conntrack_max":%s,"conntrack_count":%s,"conntrack_pct":%s,' "${cc:-}" "${qd:-}" "$ctmax" "$ctcnt" "$ctpct"
    printf '"ulimit_n":%s,"min_snd_mss":%s,"mtu_probing":%s,"mss_collapsed_sockets":%s,' "${uln:-0}" "$minsnd" "$mtuprobe" "${collapsed:-0}"
    printf '"firewall":%s,"autoban_v4":%s,"autoban_v6":%s,"suspect":%s,"blocklist_v4":%s,"blocklist_v6":%s,' "$fw" "$ab4" "$ab6" "$susp" "$bl4" "$bl6"
    printf '"fleet_v4":%s,"fleet_v6":%s,"crowdsec":%s,"ctguard":"%s","synproxy_degraded":%s,' "$fl4" "$fl6" "$crowd" "$ctg" "$syndeg"
    printf '"safety_armed":%s,"reboot_needed":%s}\n' "$safety" "$rebootn"
}
if [[ "${1:-}" == "--json" ]]; then emit_json; exit 0; fi

# ─── Глубокий разбор retrans (`--retrans [--window N]`) ───────────────────────
# Панель/`--json` показывают tcp_retrans_pct и mss_collapsed — это инструмент
# «докопаться до причины»: TX vs RX, тип retrans, хвост сокетов, CC на проводе,
# дропы qdisc/ring/softirq, accept-queue, TCP-фичи + вердикт. Read-only. Все дельты
# снимаются за ОДНО окно (а не цепочкой sleep'ов).
_snmp()    { awk -v k="$1" '/^Tcp:/{if(!h){for(i=2;i<=NF;i++)n[i]=$i;h=1;next} for(i=2;i<=NF;i++) if(n[i]==k) print $i}' /proc/net/snmp 2>/dev/null; }
_tcpext()  { awk -v k="$1" '/^TcpExt:/{if(!h){for(i=2;i<=NF;i++)n[i]=$i;h=1;next} for(i=2;i<=NF;i++) if(n[i]==k) print $i}' /proc/net/netstat 2>/dev/null; }
_tcq()     { tc -s qdisc show dev "$1" 2>/dev/null | grep -oE "$2 [0-9]+" | head -1 | awk '{print $2+0}'; }
_softirq() { awk -v k="$1" '$1==k":"{s=0;for(i=2;i<=NF;i++)s+=$i;print s}' /proc/softirqs 2>/dev/null; }

retrans_deep() {
    local win=20 IFACE k v d
    [[ "${1:-}" == "--window" && -n "${2:-}" ]] && win="$2"
    [[ "$win" =~ ^[0-9]+$ && "$win" -ge 5 && "$win" -le 300 ]] || win=20
    IFACE="$(default_iface)"; IFACE="${IFACE:-eth0}"

    clear 2>/dev/null || true
    printf "%b" "$BOLD"
    cat <<'B'
  ┌────────────────────────────────────────────┐
  │   🔬  node-accelerator — разбор retrans     │
  └────────────────────────────────────────────┘
B
    printf "%b" "$NC"
    info "iface=$IFACE   окно семплинга=${win}s   (read-only)"

    # ── BEFORE
    local out0 rtx0 in0; out0="$(_snmp OutSegs)"; rtx0="$(_snmp RetransSegs)"; in0="$(_snmp InSegs)"
    local exts="TCPLostRetransmit TCPSlowStartRetrans TCPSynRetrans TCPTimeouts TCPSackRecovery TCPSpuriousRtxHostQueues TCPBacklogDrop TCPRcvQDrop"
    declare -A E0
    for k in $exts; do v="$(_tcpext "$k")"; E0[$k]="${v:-0}"; done
    local qd0 qo0 qr0 rx0 tx0 eth0f=""
    qd0="$(_tcq "$IFACE" dropped)"; qo0="$(_tcq "$IFACE" overlimits)"; qr0="$(_tcq "$IFACE" requeues)"
    rx0="$(_softirq NET_RX)"; tx0="$(_softirq NET_TX)"
    command -v ethtool >/dev/null 2>&1 && { eth0f="$(mktemp)"; ethtool -S "$IFACE" 2>/dev/null > "$eth0f"; }

    sleep "$win"

    # ── AFTER + дельты
    local out1 rtx1 in1 dout drtx din rate ratio
    out1="$(_snmp OutSegs)"; rtx1="$(_snmp RetransSegs)"; in1="$(_snmp InSegs)"
    dout=$(( ${out1:-0} - ${out0:-0} )); drtx=$(( ${rtx1:-0} - ${rtx0:-0} )); din=$(( ${in1:-0} - ${in0:-0} ))

    title "1) Retrans rate (за ${win}s)"
    if [[ "$dout" -gt 0 ]]; then
        rate="$(awk -v r="$drtx" -v o="$dout" 'BEGIN{printf "%.2f", r*100/o}')"
        status_line "$(awk -v x="$rate" 'BEGIN{print (x>=5?"FAIL":(x>=2?"WARN":"OK"))}')" "retrans = ${rate}%   (Retrans Δ=$drtx / OutSegs Δ=$dout)"
    else
        info "трафика за окно почти не было (OutSegs Δ=$dout) — увеличь --window"
    fi
    ratio="$(awk -v i="$din" -v o="$dout" 'BEGIN{if(i>0)printf "%.2f",o/i; else print "?"}')"
    info "InSegs Δ=$din  OutSegs Δ=$dout  out/in=$ratio   (>>1 = download через ноду; <1 = upload)"

    title "2) Тип retrans (Δ за ${win}s — что доминирует)"
    for k in $exts; do
        v="$(_tcpext "$k")"; v="${v:-0}"; d=$(( v - ${E0[$k]:-0} ))
        [[ "$d" -gt 0 ]] && printf "   %-28s +%d\n" "$k" "$d"
    done
    cat <<'I'
   ─ SackRecovery/SlowStartRetrans = реальные потери (SACK/dup-ACK)
   ─ Timeouts = RTO/stall (тяжёлые потери или залипание пути/таргета)
   ─ LostRetransmit = ретрансмит сам потерялся → плохой путь
   ─ SpuriousRtxHostQueues = буферизация в host-очередях (qdisc/ring)
   ─ BacklogDrop = переполнение accept-queue (приложение не успевает)
I

    title "3) Хвост по сокетам (top retrans)"
    if command -v ss >/dev/null 2>&1; then
        ss -tin state established 2>/dev/null \
          | awk '/retrans:/{ if(match($0,/retrans:[0-9]+\/[0-9]+/)){ s=substr($0,RSTART,RLENGTH); split(s,p,"/"); if(p[2]+0>0) print p[2] } }' \
          | sort -rn | head -8 | awk '{printf "   retrans=%s\n",$1}'
        ss -tin state established 2>/dev/null | grep -oE 'retrans:[0-9]+/[0-9]+' | awk -F/ '{print $2}' \
          | awk '{t++; if($1==0)b["0"]++; else if($1<5)b["1-4"]++; else if($1<20)b["5-19"]++; else if($1<100)b["20-99"]++; else b["100+"]++}
                 END{ if(t){printf "   распределение по %d сокетам → ",t; for(x in b) printf "%s:%d  ",x,b[x]; print ""} }'
    else warn "ss недоступен"; fi

    title "4) Congestion control на проводе"
    info "настройка: cc=$(val net.ipv4.tcp_congestion_control)  qdisc=$(val net.core.default_qdisc)"
    if command -v ss >/dev/null 2>&1; then
        local ccdist; ccdist="$(ss -tin state established 2>/dev/null | grep -oE ' (bbr|cubic|reno|htcp|vegas|dctcp) ' | sort | uniq -c | sort -rn | awk '{printf "%s:%s  ",$2,$1}')"
        [[ -n "$ccdist" ]] && info "на сокетах: $ccdist" || info "на сокетах: (нет ESTAB или старый ss)"
        if ss -tin state established 2>/dev/null | grep -qE ' cubic ' && [[ "$(val net.ipv4.tcp_congestion_control)" == "bbr" ]]; then
            warn "часть сокетов на cubic при cc=bbr — это коннекты ДО смены CC (или приложение задаёт своё)"
        fi
    fi

    title "5) Дропы TX-тракта (Δ за ${win}s)"
    local qd1 qo1 qr1 rx1 tx1
    qd1="$(_tcq "$IFACE" dropped)"; qo1="$(_tcq "$IFACE" overlimits)"; qr1="$(_tcq "$IFACE" requeues)"
    printf "   qdisc: dropped +%s  overlimits +%s  requeues +%s\n" "$(( ${qd1:-0}-${qd0:-0} ))" "$(( ${qo1:-0}-${qo0:-0} ))" "$(( ${qr1:-0}-${qr0:-0} ))"
    rx1="$(_softirq NET_RX)"; tx1="$(_softirq NET_TX)"
    printf "   softirq: NET_RX +%s  NET_TX +%s\n" "$(( ${rx1:-0}-${rx0:-0} ))" "$(( ${tx1:-0}-${tx0:-0} ))"
    if [[ -n "$eth0f" ]]; then
        local eth1f; eth1f="$(mktemp)"; ethtool -S "$IFACE" 2>/dev/null > "$eth1f"
        awk 'NR==FNR{a[$1]=$2;next}{if($2+0>a[$1]+0 && (($1) in a)) printf "   nic: %-30s +%d\n",$1,$2-a[$1]}' "$eth0f" "$eth1f" \
          | grep -iE 'drop|err|miss|fifo|nobuf|over' | head -8
        rm -f "$eth0f" "$eth1f"
    fi

    title "6) Очереди и TCP-фичи"
    if command -v ss >/dev/null 2>&1; then
        info "состояния: $(ss -tan 2>/dev/null | awk 'NR>1{c[$1]++}END{for(s in c)printf "%s:%d ",s,c[s]}')"
        local lq; lq="$(ss -tlnH 2>/dev/null | awk '$2+0>0{print $4"(rq="$2")"}' | head -5 | tr '\n' ' ')"
        [[ -n "$lq" ]] && warn "listen-очереди с backlog: $lq" || info "listen-очереди: пусто (accept успевает)"
    fi
    info "sack=$(val net.ipv4.tcp_sack) dsack=$(val net.ipv4.tcp_dsack) ts=$(val net.ipv4.tcp_timestamps) frto=$(val net.ipv4.tcp_frto) recovery=$(val net.ipv4.tcp_recovery)"
    local msnd mtup collapsed
    msnd="$(val net.ipv4.tcp_min_snd_mss)"; mtup="$(val net.ipv4.tcp_mtu_probing)"
    collapsed="$(ss -tin 2>/dev/null | grep -oE 'mss:[0-9]+' | awk -F: '$2>0 && $2<256{c++}END{print c+0}')"
    info "min_snd_mss=${msnd:-?} mtu_probing=${mtup:-?} collapsed_sockets=${collapsed:-0}"

    title "Вердикт"
    local said=0
    [[ "$(( ${qd1:-0}-${qd0:-0} ))" -gt 0 ]] && { warn "qdisc дропает на TX — переполнение исходящей очереди (burst/линия медленнее ядра)"; said=1; }
    [[ "${collapsed:-0}" -gt 0 && "${msnd:-0}" -le 64 ]] && { warn "MSS-коллапс: min_snd_mss=${msnd:-?} + collapsed=${collapsed} → send-MSS схлопывается на лоссовом плече (mtu_probing=${mtup:-?}); floor 512 + mtu_probing=0 лечит"; said=1; }
    [[ "$said" -eq 0 ]] && ok "явных TX-узких мест за окно не видно — смотри тип retrans выше (Timeouts=путь/таргет, SackRecovery=потери к клиенту)"
    echo
}
if [[ "${1:-}" == "--retrans" ]]; then shift; retrans_deep "$@"; exit 0; fi

clear 2>/dev/null || true
printf "%b" "$BOLD"
cat <<'B'
  ┌────────────────────────────────────────────┐
  │   🩺  node-accelerator — диагностика ноды   │
  └────────────────────────────────────────────┘
B
printf "%b" "$NC"

# ─── Система ─────────────────────────────────────────────────────────────────
title "Система"
VIRT="$(detect_virt)"
CORES="$(nproc 2>/dev/null || echo '?')"
MEM="$(free -h 2>/dev/null | awk '/Mem:/{print $2}')"
info "OS:     ${PRETTY_NAME:-$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")}"
info "Kernel: $(uname -r)   Arch: $(arch)"
info "Virt:   $VIRT   CPU: ${CORES} ядер   RAM: ${MEM:-?}"
info "Uptime: $(uptime -p 2>/dev/null || uptime)"
# CPU steal: сколько CPU у нашей VPS отбирает гипервизор — главный скрытый потолок,
# не виден в load/governor. Дельта за 1 секунду по агрегату /proc/stat.
read -r _ u1 n1 s1 i1 w1 q1 sq1 st1 _ < /proc/stat
sleep 1
read -r _ u2 n2 s2 i2 w2 q2 sq2 st2 _ < /proc/stat
DT=$(( (u2+n2+s2+i2+w2+q2+sq2+st2) - (u1+n1+s1+i1+w1+q1+sq1+st1) ))
if [[ "${DT:-0}" -gt 0 ]]; then
    STEAL=$(( (st2 - st1) * 100 / DT ))
    if   [[ "$STEAL" -ge 10 ]]; then bad  "CPU steal = ${STEAL}% — гипервизор активно отбирает CPU (оверселл/шумный сосед)"
    elif [[ "$STEAL" -ge 3  ]]; then wrn  "CPU steal = ${STEAL}% (заметный — под пиками может проседать)"
    else                             pass "CPU steal = ${STEAL}% (CPU ноды не отбирают)"
    fi
fi

# ─── Ядро / BBR ──────────────────────────────────────────────────────────────
title "Ядро и congestion control"
if uname -r | grep -qi xanmod; then
    pass "XanMod-ядро активно ($(uname -r)) → BBRv3 доступен"
else
    if can_install_kernel; then
        wrn "Ядро не XanMod — BBRv3 нет. Поставь оптимизатор (XanMod), будет +скорость."
    else
        [[ "$VIRT" != none && "$VIRT" != kvm && "$VIRT" != unknown ]] \
            && info "Контейнер ($VIRT): кастомное ядро невозможно, BBRv3 недоступен — это норма." \
            || info "Стоковое ядро."
    fi
fi
CC="$(val net.ipv4.tcp_congestion_control)"
AVAIL="$(val net.ipv4.tcp_available_congestion_control)"
[[ "$CC" == "bbr" ]] && pass "congestion_control = bbr$(uname -r | grep -qi xanmod && echo ' (BBRv3)')" \
                     || wrn "congestion_control = ${CC:-?} (ожидалось bbr). Доступно: ${AVAIL:-?}"
QD="$(val net.core.default_qdisc)"
[[ "$QD" == "fq" || "$QD" == "fq_codel" || "$QD" == "cake" ]] && pass "default_qdisc = $QD" \
                     || wrn "default_qdisc = ${QD:-?} (для BBR-пейсинга лучше fq)"
if [[ "$(arch)" == "x86_64" ]]; then
    LVL="$(cpu_psabi_level)"
    info "CPU psABI: поддерживает до x86-64-v${LVL} (выбор сборки XanMod)"
fi
# Реальность поверх sysctl: сколько живых TCP-сокетов реально на BBR + доля ретрансмитов.
BBRN="$(ss -tin 2>/dev/null | grep -c bbr || true)"
[[ "${BBRN:-0}" -gt 0 ]] && info "Живых TCP-сокетов на BBR сейчас: $BBRN"
eval "$(awk '
  /^Tcp:/ { if (!h){for(i=2;i<=NF;i++)nm[i]=$i; h=1; next}
            for(i=2;i<=NF;i++){ if(nm[i]=="OutSegs")print "OUT="$i; if(nm[i]=="RetransSegs")print "RTX="$i } }
  ' /proc/net/snmp 2>/dev/null)"
if [[ -n "${OUT:-}" && "${OUT:-0}" -gt 0 ]]; then
    PCT=$(( ${RTX:-0} * 100 / OUT ))
    [[ "$PCT" -ge 5 ]] && wrn  "TCP-ретрансмиты ${PCT}% (${RTX:-0}/${OUT}, с загрузки) — потери/перегруз на аплинке" \
                       || pass "TCP-ретрансмиты ${PCT}% (${RTX:-0}/${OUT}, с загрузки) — линк чистый"
fi

# ─── Sysctl-ключи ────────────────────────────────────────────────────────────
title "Sysctl"
chk() { # chk key min "human"
    local k="$1" want="$2" cur; cur="$(val "$k")"
    if [[ -z "$cur" ]]; then wrn "$k не задан"; return; fi
    if [[ "$cur" -ge "$want" ]] 2>/dev/null; then pass "$k = $cur"; else wrn "$k = $cur (рекоменд. ≥ $want)"; fi
}
chk net.core.somaxconn 32768
chk net.core.rmem_max 33554432
chk net.core.wmem_max 33554432
chk net.ipv4.tcp_max_syn_backlog 16384
chk fs.file-max 1000000
chk fs.nr_open 1000000
[[ "$(val net.ipv4.tcp_syncookies)" == "1" ]] && pass "tcp_syncookies = 1 (анти-SYN-flood)" || wrn "tcp_syncookies выкл."
[[ "$(val net.ipv4.tcp_fastopen)" == "3" ]] && pass "tcp_fastopen = 3" || info "tcp_fastopen = $(val net.ipv4.tcp_fastopen)"
RPF="$(val net.ipv4.conf.all.rp_filter)"
[[ "$RPF" == "2" ]] && pass "rp_filter = 2 (loose, ок для host-network)" \
    || { [[ "$RPF" == "1" ]] && wrn "rp_filter = 1 (strict) — может рубить асимметричный трафик VPN" || info "rp_filter = ${RPF:-?}"; }

# ─── Лимиты ──────────────────────────────────────────────────────────────────
title "Лимиты"
ULN="$(ulimit -n 2>/dev/null)"
[[ "$ULN" -ge 524288 ]] 2>/dev/null && pass "ulimit -n (текущая сессия) = $ULN" \
    || wrn "ulimit -n = $ULN — для shell-сессий применится после перелогина"
if command -v systemctl >/dev/null; then
    DLN="$(systemctl show -p DefaultLimitNOFILE --value 2>/dev/null)"
    [[ "$DLN" -ge 524288 ]] 2>/dev/null && pass "systemd DefaultLimitNOFILE = $DLN" || wrn "systemd DefaultLimitNOFILE = ${DLN:-?}"
fi

# ─── Conntrack ───────────────────────────────────────────────────────────────
title "Conntrack"
CTMAX="$(val net.netfilter.nf_conntrack_max)"
CTCNT="$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)"
if [[ -n "$CTMAX" ]]; then
    pass "nf_conntrack_max = $CTMAX (сейчас занято: ${CTCNT:-0})"
    if [[ -n "$CTCNT" && "$CTMAX" -gt 0 ]]; then
        PCT=$(( CTCNT * 100 / CTMAX ))
        [[ "$PCT" -ge 80 ]] && wrn "conntrack заполнен на ${PCT}% — близко к потолку!"
    fi
else
    info "nf_conntrack ещё не загружен (появится при первом пакете через firewall)"
fi
# Разбивка дропов (если есть conntrack-tools): early_drop=давление по памяти,
# insert_failed=хеш-коллизии, drop=таблица переполнена. Decimal — mawk-safe.
if command -v conntrack >/dev/null 2>&1; then
    read -r CT_IF CT_DR CT_ED < <(conntrack -S 2>/dev/null | awk '
        {for(i=1;i<=NF;i++){split($i,kv,"="); if(kv[1]=="insert_failed")f+=kv[2]; else if(kv[1]=="drop")d+=kv[2]; else if(kv[1]=="early_drop")e+=kv[2]}}
        END{printf "%d %d %d", f+0, d+0, e+0}')
    if [[ "$(( ${CT_IF:-0} + ${CT_DR:-0} + ${CT_ED:-0} ))" -gt 0 ]]; then
        wrn "conntrack дропы: insert_failed=${CT_IF:-0} drop=${CT_DR:-0} early_drop=${CT_ED:-0} (early_drop=память, insert_failed=хеш, drop=таблица полна)"
    else
        pass "conntrack без дропов (insert_failed/drop/early_drop = 0)"
    fi
fi

# ─── MSS (анти-коллапс) ──────────────────────────────────────────────────────
# Ловит ровно тот прод-инцидент, что чинит v2.4: при mtu_probing=1 на лоссовом плече
# ядро ужимает send-MSS к полу (дефолт 48Б) → throughput коллапсирует. Проверяем пол
# и считаем ЖИВЫЕ сокеты с обрезанным MSS (реальность поверх sysctl).
title "MSS (анти-коллапс на туннелях)"
MINSND="$(val net.ipv4.tcp_min_snd_mss)"
MTUPROBE="$(val net.ipv4.tcp_mtu_probing)"
if [[ "${MINSND:-0}" -ge 512 ]] 2>/dev/null; then pass "tcp_min_snd_mss = $MINSND (пол против коллапса)"
else wrn "tcp_min_snd_mss = ${MINSND:-?} (при mtu_probing=1 рекоменд. ≥512 — иначе MSS-коллапс)"; fi
[[ -n "$MTUPROBE" ]] && info "tcp_mtu_probing = $MTUPROBE"
COLLAPSED="$(ss -tin 2>/dev/null | grep -oE 'mss:[0-9]+' | awk -F: '$2>0 && $2<256{c++} END{print c+0}')"
if [[ "${COLLAPSED:-0}" -gt 0 ]]; then
    bad "живых сокетов с обрезанным MSS (<256): $COLLAPSED — ИДЁТ MSS-коллапс на лоссовом плече (см. tcp_min_snd_mss)"
else
    pass "сокетов с обрезанным MSS нет (коллапса не видно)"
fi

# ─── NIC / RPS ───────────────────────────────────────────────────────────────
title "Сетевая карта"
NIC="$(default_iface || true)"
if [[ -n "$NIC" ]]; then
    DRV="$(ethtool -i "$NIC" 2>/dev/null | awk '/^driver:/{print $2}')"
    info "NIC: $NIC   driver: ${DRV:-?}   txqueuelen: $(cat /sys/class/net/$NIC/tx_queue_len 2>/dev/null || echo '?')"
    RXQ=$(ls -d /sys/class/net/"$NIC"/queues/rx-* 2>/dev/null | wc -l)
    RPS_ON=0
    for q in /sys/class/net/"$NIC"/queues/rx-*/rps_cpus; do
        [[ -f "$q" ]] && grep -qvE '^0+$' "$q" 2>/dev/null && RPS_ON=1
    done
    [[ "$RXQ" -gt 1 ]] && info "RX-очередей: $RXQ (multi-queue)" || info "RX-очередей: $RXQ (single-queue — RPS критичен)"
    if [[ "$RPS_ON" == "1" ]]; then pass "RPS включён (приём размазан по ядрам)"; else
        [[ "$CORES" -gt 1 ]] && wrn "RPS выключен — на $CORES ядрах приём может висеть на cpu0" || info "1 ядро — RPS не нужен"
    fi
    if command -v ethtool >/dev/null; then
        OFF="$(ethtool -k "$NIC" 2>/dev/null | awk '/generic-receive-offload:|tcp-segmentation-offload:|generic-segmentation-offload:/{print $1$2}' | tr '\n' ' ')"
        [[ -n "$OFF" ]] && info "offloads: $OFF"
    fi
    # RX/TX drops/errors (накопительно с загрузки) — индикатор качества линка/ring-буфера
    read -r RXE RXD TXE TXD < <(ip -s link show dev "$NIC" 2>/dev/null | awk '
        /RX:/{getline; e=$3; d=$4} /TX:/{getline; te=$3; td=$4} END{printf "%d %d %d %d", e+0, d+0, te+0, td+0}')
    if [[ "$(( ${RXD:-0} + ${TXD:-0} + ${RXE:-0} + ${TXE:-0} ))" -gt 0 ]]; then
        info "NIC drops/errors (с загрузки): RXdrop=${RXD:-0} RXerr=${RXE:-0} TXdrop=${TXD:-0} TXerr=${TXE:-0}"
    else
        pass "NIC без drop/error счётчиков"
    fi
    systemctl is-active --quiet na-rps.service 2>/dev/null && pass "na-rps.service активен" || info "na-rps.service не запущен (ставится оптимизатором)"
else
    wrn "Основной интерфейс не определён"
fi

# ─── Память / прочее ─────────────────────────────────────────────────────────
title "Память, swap, THP, governor"
if swapon --show 2>/dev/null | grep -q .; then pass "swap: $(swapon --show=NAME,SIZE --noheadings 2>/dev/null | tr '\n' ' ')"; else wrn "swap отсутствует"; fi
THP="$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null | grep -oE '\[.*\]' | tr -d '[]')"
[[ "$THP" == "never" ]] && pass "THP = never" || wrn "THP = ${THP:-?} (для сетевых нагрузок лучше never)"
GOV="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null)"
[[ -n "$GOV" ]] && { [[ "$GOV" == "performance" ]] && pass "governor = performance" || info "governor = $GOV"; } || info "cpufreq недоступен (VPS) — норма"
systemctl is-active --quiet irqbalance 2>/dev/null && pass "irqbalance активен" || info "irqbalance не запущен"

# ─── Firewall / защита ───────────────────────────────────────────────────────
title "Firewall и защита"
if nft list table inet na_filter >/dev/null 2>&1; then
    pass "nftables na_filter активна (policy drop на input)"
    AB4=$(nft list set inet na_filter autoban_v4 2>/dev/null | grep -c 'timeout\|expires')
    AB6=$(nft list set inet na_filter autoban_v6 2>/dev/null | grep -c 'timeout\|expires')
    info "autoban: v4=$AB4  v6=$AB6"
    WLN=$(nft list set inet na_filter whitelist_v4 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
    [[ "$WLN" -gt 0 ]] && pass "whitelist_v4: $WLN адрес(ов)" || wrn "whitelist пуст — твой IP не защищён от автобана!"
    # датчик: насколько близко самый «жирный» источник к CONN_LIMIT (виден ли per-IP потолок)
    CLIM=$(nft list chain inet na_filter input 2>/dev/null | grep -oE 'ct count over [0-9]+' | head -1 | grep -oE '[0-9]+')
    if [[ -n "$CLIM" ]]; then
        MAXIP=$(ss -tnH state established 2>/dev/null | awk '{print $NF}' | sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//' | sort | uniq -c | sort -rn | head -1 | awk '{print $1+0}')
        if [[ "${MAXIP:-0}" -ge $((CLIM*80/100)) ]]; then
            wrn "макс. конн. с одного IP = ${MAXIP:-0} при CONN_LIMIT=$CLIM (≥80%) — за CGNAT возможны дропы, подними CONN_LIMIT"
        else
            pass "макс. конн. с одного IP = ${MAXIP:-0} / CONN_LIMIT $CLIM (запас есть)"
        fi
    fi
    # v3.0 компоненты
    if nft list set inet na_filter suspect_v4 >/dev/null 2>&1; then
        SUSP=$(nft list set inet na_filter suspect_v4 2>/dev/null | grep -c timeout)
        info "ban-once: suspect (наблюдение) v4=$SUSP"
    fi
    if nft list set inet na_filter blocklist_v4 >/dev/null 2>&1; then
        BL4=$(nft list set inet na_filter blocklist_v4 2>/dev/null | grep -coE '[0-9.]+')
        [[ "$BL4" -gt 0 ]] && pass "threat-блоклисты: v4=$BL4 записей (na-blocklist-update)" \
            || wrn "blocklist_v4 пуст — фиды не подтянулись? journalctl -t na-blocklist"
    fi
    if nft list set inet na_filter na_fleet_v4 >/dev/null 2>&1; then
        FL4=$(nft list set inet na_filter na_fleet_v4 2>/dev/null | grep -coE '[0-9.]+')
        [[ "$FL4" -gt 0 ]] && pass "fleet-sync: $FL4 нод флота в whitelist" \
            || wrn "na_fleet пуст — панель/токен? journalctl -t na-fleet-sync"
    fi
else
    wrn "na_filter не активна — защита не стоит (запусти 🛡 protect)"
fi
# ctguard (отдельная таблица)
if nft list table inet na_ctguard >/dev/null 2>&1; then
    ENF=$(awk -F= '/^NA_CTG_ENFORCE/{print $2}' /etc/node-accelerator/ctguard.conf 2>/dev/null)
    PH4=$(nft list set inet na_ctguard phantom_v4 2>/dev/null | grep -c timeout)
    [[ "${ENF:-0}" == 1 ]] && pass "ctguard ENFORCE активен (фантомов в блоке: $PH4)" \
        || info "ctguard в observe-режиме (только лог; NA_CTG_ENFORCE=1 для эвикта)"
fi
# synproxy degraded-маркер
if [[ -f "$STATE_DIR/.synproxy-degraded" ]]; then
    bad "SYNPROXY DEGRADED: $(cat "$STATE_DIR/.synproxy-degraded") — защита без synproxy"
fi
# Взведённый сейфти-таймер: protect в неинтерактиве оставляет na-fw-safety активным.
# Если не снять — na_filter САМОУДАЛИТСЯ через SAFETY_DELAY. Ловим это громко.
if systemctl is-active --quiet na-fw-safety.timer 2>/dev/null \
   || { [[ -f "$STATE_DIR/na-fw-safety.pid" ]] && kill -0 "$(cat "$STATE_DIR/na-fw-safety.pid" 2>/dev/null)" 2>/dev/null; } \
   || { [[ -f /tmp/na-fw-safety.pid ]] && kill -0 "$(cat /tmp/na-fw-safety.pid 2>/dev/null)" 2>/dev/null; }; then
    bad "ВЗВЕДЁН сейфти-таймер na-fw-safety — na_filter СКОРО САМОУДАЛИТСЯ! Сними после проверки доступа: systemctl stop na-fw-safety.timer"
fi
if command -v cscli >/dev/null 2>&1; then
    systemctl is-active --quiet crowdsec && pass "CrowdSec агент активен" || wrn "CrowdSec установлен, но не active"
    systemctl is-active --quiet crowdsec-firewall-bouncer && pass "firewall-bouncer активен" || wrn "bouncer не active"
    DEC=$(cscli decisions list -o raw 2>/dev/null | grep -vc '^$' || echo 0)
    info "CrowdSec decisions (активные баны): $DEC"
    nft list table ip crowdsec >/dev/null 2>&1 && info "таблица bouncer'а ip crowdsec присутствует (priority -10, раньше na_filter)"
else
    info "CrowdSec не установлен (ставится модулем 🛡 protect)"
fi

# ─── Слушающие порты ─────────────────────────────────────────────────────────
title "Слушающие порты"
ss -tulnH 2>/dev/null | awk '{print $1, $5}' | sort -u | sed 's/^/  /' | head -25

# ─── Сеть (быстрый тест) ─────────────────────────────────────────────────────
title "Сеть"
EXTIP="$(curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"
[[ -n "$EXTIP" ]] && info "Внешний IPv4: $EXTIP"
if command -v ping >/dev/null; then
    RTT="$(ping -c2 -W2 1.1.1.1 2>/dev/null | awk -F'/' '/rtt|round-trip/{print $5" ms"}')"
    [[ -n "$RTT" ]] && info "RTT до 1.1.1.1: avg $RTT" || info "ICMP-тест не прошёл (возможно ICMP режется аптайм-провайдером)"
fi

# ─── Здоровье: давление, диск, инциденты ─────────────────────────────────────
title "Здоровье: давление, диск, инциденты"
# PSI — стол ядра под нагрузкой (avg10 по 'some'); современные ядра
if [[ -r /proc/pressure/cpu ]]; then
    for r in cpu memory io; do
        A="$(awk '/^some/{for(i=1;i<=NF;i++) if($i ~ /^avg10=/){sub(/avg10=/,"",$i); print $i}}' "/proc/pressure/$r" 2>/dev/null)"; A="${A:-0}"
        if awk -v x="$A" 'BEGIN{exit !(x+0>=10)}'; then wrn "PSI $r some avg10=${A}% — заметный стол ядра"; else info "PSI $r some avg10=${A}%"; fi
    done
else info "PSI недоступен (старое ядро)"; fi
# Диск + inodes (лог-флуд жрёт inodes раньше места)
DSP="$(df -P / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5);print $5}')"
DIN="$(df -Pi / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5);print $5}')"
if [[ "${DSP:-0}" -ge 85 ]] 2>/dev/null; then wrn "/ занят на ${DSP}%"; else info "/ занят на ${DSP:-?}%"; fi
if [[ "${DIN:-0}" -ge 85 ]] 2>/dev/null; then wrn "inodes / заняты на ${DIN}% (лог-флуд?)"; else info "inodes /: ${DIN:-?}%"; fi
# Инциденты ядра/сервисов
OOM="$(journalctl -k --since '-24h' --no-pager 2>/dev/null | grep -ciE 'out of memory|oom-killer|soft lockup|hung task')"
if [[ "${OOM:-0}" -gt 0 ]]; then wrn "kern-лог за 24ч: $OOM строк OOM/lockup/hung — память/перегруз"; else pass "kern-лог чист (OOM/lockup/hung за 24ч нет)"; fi
FAILED="$(systemctl --failed --no-legend 2>/dev/null | grep -c .)"
if [[ "${FAILED:-0}" -gt 0 ]]; then wrn "упавших systemd-юнитов: $FAILED (см. systemctl --failed)"; else pass "упавших systemd-юнитов нет"; fi

# ─── Итог ────────────────────────────────────────────────────────────────────
hr
printf "  Итог:  %b✔ %d%b   %b▲ %d%b   %b✘ %d%b\n" "$GREEN" "$OKC" "$NC" "$YELLOW" "$WARNC" "$NC" "$RED" "$FAILC" "$NC"
if [[ "$FAILC" -gt 0 ]]; then
    echo "  → Есть критические пункты (✘). Запусти ⚡ оптимизатор и 🛡 защиту."
elif [[ "$WARNC" -gt 0 ]]; then
    echo "  → Базово ок, но есть, что докрутить (▲ выше)."
else
    echo "  → Нода затюнена и защищена. 🚀"
fi
hr
