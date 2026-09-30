#!/usr/bin/env bash
#
# snapshot.sh - capture the state of a Linux host in the first minutes of an incident.
#
# Read-only: it reads /proc and runs read-only commands, and writes only to its
# own output directory. A missing tool or permission skips that one check instead
# of stopping the run.
#
# Usage:       ./snapshot.sh [-i seconds] [-d hostname] [-o dir] [-t] [-h]
# Exit status: 0 = nothing above thresholds, 1 = findings, 2 = usage error.

set -uo pipefail   # no "set -e": one failed probe must not end the whole snapshot
export LC_ALL=C

# Defaults. Each can also be set from the environment.
INTERVAL=${INTERVAL:-5}                # seconds between the two TCP counter samples (0 = skip rates)
DNS_NAME=${DNS_NAME-example.com}       # name to time a lookup for (empty = skip)
OUT_DIR=${OUT_DIR:-}                   # where the report goes (default: ./snapshot-<host>-<time>)
DISK_WARN=${DISK_WARN:-90}             # % of space or inodes used
MEM_WARN=${MEM_WARN:-10}               # % of memory still available
PSI_WARN=${PSI_WARN:-10}               # % of the last 10s that tasks spent stalled
RETRANS_WARN=${RETRANS_WARN:-1}        # % of TCP segments retransmitted during the sample
CONNTRACK_WARN=${CONNTRACK_WARN:-80}   # % of the connection-tracking table in use
DNS_WARN=${DNS_WARN:-500}              # ms for one lookup

BODY=/dev/null   # report body; main() points this at a file
FINDINGS=()      # one line per threshold crossed

usage() {
  cat <<'EOF'
Usage: snapshot.sh [-i seconds] [-d hostname] [-o dir] [-t] [-h]

  -i seconds   sample TCP counters over this many seconds (default 5, 0 = totals only)
  -d hostname  name to time a DNS lookup for (default example.com, '' = skip)
  -o dir       output directory (default ./snapshot-<host>-<utc time>)
  -t           also pack the output directory into a .tar.gz
  -h           show this help

Thresholds come from the environment: DISK_WARN, MEM_WARN, PSI_WARN,
RETRANS_WARN, CONNTRACK_WARN, DNS_WARN.
EOF
}

# ---- helpers ----------------------------------------------------------------

have()    { command -v "$1" > /dev/null 2>&1; }
section() { printf '\n== %s ==\n' "$1" >> "$BODY"; }
say()     { printf '%s\n' "$*" >> "$BODY"; }
warn()    { FINDINGS+=("$*"); }
gt()      { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 > b + 0) }'; }   # a > b, floats allowed

# /proc/net/snmp and /proc/net/netstat store counters as pairs of lines: one line
# of names, then one line of values. Flatten them to "Group.Counter value" lines,
# for example "TcpExt.ListenOverflows 12".
net_counters() {
  awk '
    $1 != group { group = $1; for (i = 2; i <= NF; i++) name[i] = $i; next }
    { g = $1; sub(":", "", g); for (i = 2; i <= NF; i++) print g "." name[i], $i; group = "" }
  ' "$@" 2> /dev/null
}

# ---- checks -----------------------------------------------------------------

check_load() {
  section "Load and pressure"
  local load1 cpus res avg
  read -r load1 _ < /proc/loadavg
  cpus=$(nproc 2> /dev/null || grep -c '^processor' /proc/cpuinfo)
  say "loadavg: $(cat /proc/loadavg)   cpus: $cpus"
  gt "$load1" "$cpus" && warn "load average $load1 is above the $cpus CPUs available"

  # Pressure stall information (kernel 4.20+): share of time tasks waited on a resource.
  for res in cpu memory io; do
    avg=$(awk '/^some/ { sub("avg10=", "", $2); print $2 }' "/proc/pressure/$res" 2> /dev/null)
    if [ -z "$avg" ]; then
      say "pressure/$res: not available"
      continue
    fi
    say "pressure/$res: tasks stalled ${avg}% of the last 10s"
    gt "$avg" "$PSI_WARN" && warn "$res pressure: tasks stalled ${avg}% of the last 10s"
  done
}

check_memory() {
  section "Memory"
  local total avail swap_total swap_free pct ooms
  total=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)
  avail=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)
  swap_total=$(awk '/^SwapTotal:/ { print $2 }' /proc/meminfo)
  swap_free=$(awk '/^SwapFree:/ { print $2 }' /proc/meminfo)
  total=${total:-1}
  avail=${avail:-0}
  pct=$((avail * 100 / total))
  say "available: $((avail / 1024)) of $((total / 1024)) MiB (${pct}%)"
  say "swap used: $(((${swap_total:-0} - ${swap_free:-0}) / 1024)) of $((${swap_total:-0} / 1024)) MiB"
  [ "$pct" -lt "$MEM_WARN" ] && warn "only ${pct}% of memory is still available"

  ooms=$(awk '$1 == "oom_kill" { print $2 }' /proc/vmstat 2> /dev/null)
  say "OOM kills since boot: ${ooms:-unknown}"
  [ "${ooms:-0}" -gt 0 ] && warn "${ooms} OOM kill(s) since boot"
}

check_processes() {
  section "Top processes"
  if ! have ps; then
    say "skipped: ps is not installed"
    return
  fi
  # ps reports CPU averaged over each process's lifetime, not the last few seconds.
  # The awk filter drops the ps process itself, which always tops its own list.
  say "-- by CPU (lifetime average) --"
  ps -eo pid,user,pcpu,pmem,rss,etime,comm --sort=-pcpu 2> /dev/null |
    awk 'NR == 1 || $NF != "ps"' | head -n 6 >> "$BODY"
  say "-- by memory --"
  ps -eo pid,user,pcpu,pmem,rss,etime,comm --sort=-rss 2> /dev/null |
    awk 'NR == 1 || $NF != "ps"' | head -n 6 >> "$BODY"
}

check_disk() {
  section "Disk"
  local pct mount skip=(-x tmpfs -x devtmpfs -x squashfs)
  df -hP "${skip[@]}" >> "$BODY" 2> /dev/null
  while read -r pct mount; do
    warn "filesystem $mount is ${pct}% full"
  done < <(df -P "${skip[@]}" 2> /dev/null |
    awk -v t="$DISK_WARN" 'NR > 1 { p = $5; sub("%", "", p); if (p + 0 >= t) print p, $6 }')
  while read -r pct mount; do
    warn "filesystem $mount has used ${pct}% of its inodes"
  done < <(df -iP "${skip[@]}" 2> /dev/null |
    awk -v t="$DISK_WARN" 'NR > 1 && $5 != "-" { p = $5; sub("%", "", p); if (p + 0 >= t) print p, $6 }')
}

check_interfaces() {
  section "Network interfaces"
  if have ip; then
    ip -brief addr >> "$BODY" 2> /dev/null
    say "default route: $(ip route show default 2> /dev/null | head -n 1)"
  else
    say "addresses and routes skipped: ip (iproute2) is not installed"
  fi
  say "-- errors and drops since boot --"
  awk 'NR > 2 { sub(":", " ")
       printf "%-12s rx_errs=%s rx_drop=%s tx_errs=%s tx_drop=%s\n", $1, $4, $5, $12, $13 }' \
    /proc/net/dev >> "$BODY" 2> /dev/null
}

# Counters worth watching during an incident. Totals since boot say little on a
# long-lived host, so the report also shows how much each moved during the sample.
TCP_COUNTERS="Tcp.ActiveOpens Tcp.PassiveOpens Tcp.AttemptFails Tcp.EstabResets
Tcp.OutSegs Tcp.RetransSegs TcpExt.TCPTimeouts TcpExt.TCPSynRetrans
TcpExt.ListenOverflows TcpExt.ListenDrops TcpExt.TCPBacklogDrop"

check_tcp() {
  section "TCP"
  local -A before=() after=()
  local k v
  say "sockets: $(grep '^TCP:' /proc/net/sockstat 2> /dev/null)"

  while read -r k v; do before[$k]=$v; done < <(net_counters /proc/net/snmp /proc/net/netstat)
  if [ "$INTERVAL" -gt 0 ]; then
    echo "sampling TCP counters for ${INTERVAL}s..." >&2
    sleep "$INTERVAL"
    while read -r k v; do after[$k]=$v; done < <(net_counters /proc/net/snmp /proc/net/netstat)
    say "-- counters: total since boot, change in ${INTERVAL}s --"
  else
    say "-- counters: total since boot (rates skipped, interval is 0) --"
  fi
  for k in $TCP_COUNTERS; do
    [ -n "${before[$k]:-}" ] || continue
    if [ "$INTERVAL" -gt 0 ]; then
      printf '%-24s %14s %+8d\n' "$k" "${after[$k]:-0}" "$((${after[$k]:-0} - ${before[$k]}))" >> "$BODY"
    else
      printf '%-24s %14s\n' "$k" "${before[$k]}" >> "$BODY"
    fi
  done

  if [ "$INTERVAL" -gt 0 ] && [ -n "${before[Tcp.OutSegs]:-}" ]; then
    # OutSegs counts new segments only, so retransmits are compared against it.
    local sent retrans overflows
    sent=$((${after[Tcp.OutSegs]:-0} - ${before[Tcp.OutSegs]}))
    retrans=$((${after[Tcp.RetransSegs]:-0} - ${before[Tcp.RetransSegs]:-0}))
    overflows=$((${after[TcpExt.ListenOverflows]:-0} - ${before[TcpExt.ListenOverflows]:-0}))
    say "retransmits: $retrans against $sent new segments sent in ${INTERVAL}s"
    # Needs at least 10 retransmits: on a near-idle host one lost packet is a large percentage.
    awk -v r="$retrans" -v s="$sent" -v t="$RETRANS_WARN" 'BEGIN { exit !(r >= 10 && r * 100 > t * s) }' &&
      warn "TCP retransmits: $retrans against $sent new segments sent in ${INTERVAL}s (threshold ${RETRANS_WARN}%)"
    [ "$overflows" -gt 0 ] &&
      warn "accept queue overflowed $overflows time(s) in ${INTERVAL}s: a listener is not accepting fast enough"
  fi

  local count max pct
  count=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2> /dev/null)
  max=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2> /dev/null)
  if [ -n "$count" ] && [ "${max:-0}" -gt 0 ]; then
    pct=$((count * 100 / max))
    say "conntrack: $count of $max entries (${pct}%)"
    [ "$pct" -ge "$CONNTRACK_WARN" ] &&
      warn "conntrack table is ${pct}% full: new connections are dropped once it fills"
  else
    say "conntrack: not in use"
  fi

  if ! have ss; then
    say "per-connection detail skipped: ss (iproute2) is not installed"
    return
  fi
  say "-- connections by state --"
  ss -tan 2> /dev/null | awk 'NR > 1 { n[$1]++ } END { for (s in n) printf "%8d %s\n", n[s], s }' |
    sort -rn >> "$BODY"
  say "-- top remote peers (established) --"
  ss -tn state established 2> /dev/null |
    awk 'NR > 1 { p = $4; sub(/:[^:]*$/, "", p); n[p]++ } END { for (p in n) printf "%8d %s\n", n[p], p }' |
    sort -rn | head -n 5 >> "$BODY"

  # For a listening socket, Recv-Q is the number of connections waiting to be
  # accepted and Send-Q is the backlog limit.
  say "-- listeners with connections waiting to be accepted --"
  local addr queued backlog any=0
  while read -r addr queued backlog; do
    any=1
    say "$addr: $queued waiting, backlog $backlog"
    [ "$queued" -ge "$backlog" ] && warn "accept queue is full on $addr ($queued waiting, backlog $backlog)"
  done < <(ss -ltn 2> /dev/null | awk 'NR > 1 && $2 > 0 { print $4, $2, $3 }')
  [ "$any" -eq 0 ] && say "none"
}

check_dns() {
  section "DNS"
  say "resolvers: $(awk '/^nameserver/ { printf "%s ", $2 }' /etc/resolv.conf 2> /dev/null)"
  if [ -z "$DNS_NAME" ]; then
    say "lookup skipped"
    return
  fi
  if ! have getent; then
    say "lookup skipped: getent is not installed"
    return
  fi
  local lookup=(getent hosts "$DNS_NAME") start ms
  have timeout && lookup=(timeout 5 "${lookup[@]}")
  start=$(date +%s%N)
  if "${lookup[@]}" > /dev/null 2>&1; then
    ms=$((($(date +%s%N) - start) / 1000000))
    say "lookup of $DNS_NAME took ${ms} ms"
    [ "$ms" -ge "$DNS_WARN" ] && warn "DNS lookup of $DNS_NAME took ${ms} ms"
  else
    say "lookup of $DNS_NAME FAILED"
    warn "DNS lookup of $DNS_NAME failed or timed out"
  fi
}

check_kernel_log() {
  section "Kernel log"
  local log hits
  if log=$(dmesg -T --level=emerg,alert,crit,err 2> /dev/null); then
    :
  elif have journalctl && log=$(journalctl -k -p err -q --no-pager 2> /dev/null); then
    :
  else
    say "skipped: the kernel log is not readable here (no dmesg, or root is required)"
    return
  fi
  if [ -z "$log" ]; then
    say "no messages at error level or above"
    return
  fi
  say "-- last 20 messages at error level or above --"
  printf '%s\n' "$log" | tail -n 20 >> "$BODY"
  hits=$(printf '%s\n' "$log" | grep -ciE 'out of memory|oom-kill|i/o error|link is down|soft lockup|hung_task')
  [ "$hits" -gt 0 ] && warn "$hits kernel log line(s) mention OOM, I/O errors, link down or lockups"
}

check_services() {
  section "Failed services"
  if [ ! -d /run/systemd/system ] || ! have systemctl; then
    say "skipped: systemd is not running here"
    return
  fi
  local failed
  failed=$(systemctl --failed --no-legend --plain 2> /dev/null | awk '{ print $1 }')
  if [ -z "$failed" ]; then
    say "none"
    return
  fi
  say "$failed"
  warn "failed systemd units: $(printf '%s' "$failed" | tr '\n' ' ')"
}

# Keep the raw kernel counters next to the report, for whoever writes the review later.
save_raw() {
  mkdir -p "$OUT_DIR/raw" || return
  local f
  for f in loadavg meminfo vmstat net/dev net/snmp net/netstat net/sockstat \
    pressure/cpu pressure/memory pressure/io; do
    cat "/proc/$f" > "$OUT_DIR/raw/${f//\//_}" 2> /dev/null || rm -f "$OUT_DIR/raw/${f//\//_}"
  done
  have ss && ss -tan > "$OUT_DIR/raw/ss_tan" 2> /dev/null
}

# ---- main -------------------------------------------------------------------

main() {
  local opt make_tar=0
  while getopts ':i:d:o:th' opt; do
    case "$opt" in
      i) INTERVAL=$OPTARG ;;
      d) DNS_NAME=$OPTARG ;;
      o) OUT_DIR=$OPTARG ;;
      t) make_tar=1 ;;
      h) usage; exit 0 ;;
      *) usage >&2; exit 2 ;;
    esac
  done
  case "$INTERVAL" in
    '' | *[!0-9]*) echo "snapshot.sh: -i needs a whole number of seconds" >&2; exit 2 ;;
  esac

  local host stamp report
  host=$(hostname 2> /dev/null || cat /proc/sys/kernel/hostname)
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  OUT_DIR=${OUT_DIR:-snapshot-$host-$stamp}
  mkdir -p "$OUT_DIR" || { echo "snapshot.sh: cannot create $OUT_DIR" >&2; exit 2; }
  report=$OUT_DIR/report.txt
  BODY=$OUT_DIR/body.tmp
  : > "$BODY"

  check_load
  check_memory
  check_processes
  check_disk
  check_interfaces
  check_tcp
  check_dns
  check_kernel_log
  check_services
  save_raw

  {
    echo "Host:    $host"
    echo "Time:    $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "Kernel:  $(uname -r)"
    echo "Uptime:  $(awk '{ printf "%dd %dh %dm", $1 / 86400, $1 % 86400 / 3600, $1 % 3600 / 60 }' /proc/uptime)"
    echo "Run as:  $(id -un 2> /dev/null || id -u)"
    echo
    if [ "${#FINDINGS[@]}" -eq 0 ]; then
      echo "FINDINGS: nothing above thresholds"
    else
      echo "FINDINGS (${#FINDINGS[@]}):"
      printf '  ! %s\n' "${FINDINGS[@]}"
    fi
    cat "$BODY"
  } > "$report"
  rm -f "$BODY"

  cat "$report"
  echo
  echo "Saved to $OUT_DIR/"
  if [ "$make_tar" -eq 1 ]; then
    tar -czf "$OUT_DIR.tar.gz" -C "$(dirname "$OUT_DIR")" "$(basename "$OUT_DIR")" &&
      echo "Packed as $OUT_DIR.tar.gz"
  fi

  [ "${#FINDINGS[@]}" -eq 0 ]
}

# Run only when executed, so the tests can source this file and call single functions.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
