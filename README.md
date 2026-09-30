# incident-snapshot

[![ci](https://github.com/apn006/incident-snapshot/actions/workflows/ci.yml/badge.svg)](https://github.com/apn006/incident-snapshot/actions/workflows/ci.yml)

One command that captures the state of a Linux host in the first minutes of an incident. It checks load, memory, disk, TCP health, DNS, the kernel log and failed services, and lists anything above a threshold at the top of the report.

## Why

The first minutes of an incident usually go to typing the same dozen commands on each affected host, and the output scrolls away before anyone can compare it. This script runs those checks in one pass and saves the report, together with the raw kernel counters, in a directory you can attach to the incident.

## Quick start

```bash
git clone https://github.com/apn006/incident-snapshot.git
cd incident-snapshot
./snapshot.sh
```

Root is not required. Without it, the kernel log is skipped on hosts that restrict `dmesg`.

## Example

This run was taken while a test listener on port 8080, with a backlog of 1, had stopped accepting connections and 12 clients were trying to connect:

```text
Host:    vm
Time:    2026-09-30 06:14:58 UTC
Kernel:  6.18.44-fc-v50
Uptime:  0d 0h 4m
Run as:  root

FINDINGS (3):
  ! TCP retransmits: 50 against 0 new segments sent in 5s (threshold 1%)
  ! accept queue overflowed 50 time(s) in 5s: a listener is not accepting fast enough
  ! accept queue is full on 127.0.0.1:8080 (2 waiting, backlog 1)

[...]

== TCP ==
sockets: TCP: inuse 17 orphan 0 tw 0 alloc 17 mem 0
-- counters: total since boot, change in 5s --
Tcp.ActiveOpens                      41       +0
Tcp.PassiveOpens                      9       +0
Tcp.AttemptFails                      0       +0
Tcp.EstabResets                       4       +0
Tcp.OutSegs                         645       +0
Tcp.RetransSegs                     170      +50
TcpExt.TCPTimeouts                  170      +50
TcpExt.TCPSynRetrans                170      +50
TcpExt.ListenOverflows              200      +50
TcpExt.ListenDrops                  200      +50
TcpExt.TCPBacklogDrop                 0       +0
retransmits: 50 against 0 new segments sent in 5s
conntrack: 0 of 65536 entries (0%)
-- connections by state --
      10 SYN-SENT
       4 ESTAB
       3 LISTEN
-- top remote peers (established) --
       4 127.0.0.1
-- listeners with connections waiting to be accepted --
127.0.0.1:8080: 2 waiting, backlog 1
```

The report and the raw data are saved side by side:

```text
snapshot-<host>-<utc time>/
  report.txt   the report, findings first
  raw/         copies of the /proc counters and the socket list, for the review afterwards
```

## What it checks

| Check | Where it looks | Flags when |
| --- | --- | --- |
| Load and pressure | `/proc/loadavg`, `/proc/pressure` | load is above the CPU count, or tasks were stalled more than 10% of the last 10s |
| Memory | `/proc/meminfo`, `/proc/vmstat` | less than 10% is available, or there was an OOM kill since boot |
| Top processes | `ps` | information only |
| Disk | `df` | a filesystem has used 90% of its space or inodes |
| Network interfaces | `ip`, `/proc/net/dev` | information only |
| TCP | `/proc/net/snmp`, `/proc/net/netstat`, `ss`, conntrack | retransmits exceed 1% of new segments (at least 10 of them), an accept queue overflowed or is full, or conntrack is 80% full |
| DNS | `getent` | a lookup fails or takes 500 ms or more |
| Kernel log | `dmesg`, or `journalctl -k` | lines mention OOM, I/O errors, link down or lockups |
| Failed services | `systemctl --failed` | any unit has failed |

## Options

| Flag | Meaning | Default |
| --- | --- | --- |
| `-i seconds` | how long to sample the TCP counters; `0` reports totals only | `5` |
| `-d hostname` | name to time a DNS lookup for; `''` skips the lookup | `example.com` |
| `-o dir` | output directory | `./snapshot-<host>-<utc time>` |
| `-t` | also pack the output directory as a `.tar.gz` | off |

Thresholds are read from the environment:

| Variable | Default | Meaning |
| --- | --- | --- |
| `DISK_WARN` | `90` | % of space or inodes used |
| `MEM_WARN` | `10` | % of memory still available |
| `PSI_WARN` | `10` | % of the last 10s that tasks spent stalled |
| `RETRANS_WARN` | `1` | retransmits as a % of new segments sent during the sample |
| `CONNTRACK_WARN` | `80` | % of the connection-tracking table in use |
| `DNS_WARN` | `500` | milliseconds for one lookup |

```bash
DISK_WARN=80 ./snapshot.sh -i 10 -d db.internal -t
```

The exit status is `0` when nothing crossed a threshold, `1` when something did, and `2` for a usage error, so the script can also run from cron or a deploy hook.

## Design notes

- **Read-only.** It reads `/proc` and runs read-only commands. The only thing it writes is its own output directory.
- **Rates, not just totals.** Kernel counters count from boot, so on a host that has been up for months a large number says little about the present. The script samples the TCP counters twice and reports how far each one moved in between.
- **A failed check never stops the run.** There is no `set -e`. If `ss`, `ip`, `ps`, `getent`, `dmesg` or systemd is missing, that check is skipped and the report says so. This matters in minimal containers.
- **Few dependencies.** bash 4 or newer, awk, GNU coreutils and `/proc`. Everything else is used only when present.

## Limitations

- It is a snapshot of the present, not monitoring. Trends belong in Prometheus and Grafana.
- The thresholds are starting points and are not tuned for any particular workload.
- `ps` reports CPU averaged over each process's lifetime, so a process that only just became busy ranks lower than it should.
- The accept-queue checks cover TCP listeners only.
- Linux only, and the DNS timing needs GNU `date`. Tested on Ubuntu 24.04 with bash 5.2.
- The report contains IP addresses and process names. Treat it as internal.

## Tests

```bash
bash tests/smoke.sh
```

The smoke test checks the counter parser against a fixture, runs the script on the current host and confirms every section was written, and checks the exit status for bad usage. CI runs ShellCheck and the smoke test on every push.

## Adding a check

Each check is one function that uses three helpers: `section` starts a block in the report, `say` writes a line, and `warn` adds a finding. For example, a check for file handle exhaustion:

```bash
check_file_handles() {
  section "File handles"
  local used max pct
  read -r used _ max < /proc/sys/fs/file-nr
  pct=$((used * 100 / max))
  say "open file handles: $used of $max (${pct}%)"
  [ "$pct" -ge 80 ] && warn "file handle table is ${pct}% full"
}
```

Add the function next to the others and call it from `main`.

## License

MIT
