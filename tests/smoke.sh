#!/usr/bin/env bash
# Smoke tests: the counter parser against a fixture, then a real run on this host.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "FAIL: $*" >&2; exit 1; }

# 1. The parser must pair every counter name with its own value, across groups.
# shellcheck source=snapshot.sh
source ./snapshot.sh
out=$(net_counters tests/fixtures/netstat.txt)
grep -qxF 'TcpExt.ListenOverflows 7' <<< "$out" || fail "ListenOverflows not parsed"
grep -qxF 'TcpExt.TCPTimeouts 3' <<< "$out" || fail "last counter of a group not parsed"
grep -qxF 'IpExt.InOctets 123456' <<< "$out" || fail "second group not parsed"
[ "$(wc -l <<< "$out")" -eq 8 ] || fail "expected 8 counters, got $(wc -l <<< "$out")"

# 2. A real run must finish, exit 0 (clean) or 1 (findings), and write every section.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
status=0
bash ./snapshot.sh -i 1 -d '' -o "$tmp/snap" > "$tmp/stdout" 2> /dev/null || status=$?
[ "$status" -le 1 ] || fail "unexpected exit status $status"
for name in 'Load and pressure' 'Memory' 'Top processes' 'Disk' 'Network interfaces' \
  'TCP' 'DNS' 'Kernel log' 'Failed services'; do
  grep -qF "== $name ==" "$tmp/snap/report.txt" || fail "section missing: $name"
done
grep -q '^FINDINGS' "$tmp/snap/report.txt" || fail "findings summary missing"
[ -s "$tmp/snap/raw/net_netstat" ] || fail "raw counters were not saved"

# 3. Bad usage must exit 2.
status=0
bash ./snapshot.sh -x > /dev/null 2>&1 || status=$?
[ "$status" -eq 2 ] || fail "an unknown flag should exit 2, got $status"
status=0
bash ./snapshot.sh -i abc > /dev/null 2>&1 || status=$?
[ "$status" -eq 2 ] || fail "a non-numeric interval should exit 2, got $status"

echo "ok"
