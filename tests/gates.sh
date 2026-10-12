#!/usr/bin/env bash
# Step 1 gates against a running responder (venv/bin/python -m responder).
# Usage: tests/gates.sh [port]
set -u
PORT=${1:-5300}
cd "$(dirname "$0")/.."
ANCHOR=zones/nsec.test.anchor
D="dig -p $PORT @127.0.0.1"
fail=0

check() {  # check <name> <output> <regex>
    if grep -qE "$3" <<<"$2"; then echo "PASS  $1"; else echo "FAIL  $1"; echo "$2" | sed 's/^/    /'; fail=1; fi
}

out=$($D +dnssec +norec www.nsec.test A)
check "1 udp: flags qr aa, no ra" "$out" 'flags: qr aa;'
check "1 udp: DO echoed"          "$out" 'EDNS: version: 0, flags: do;'
check "1 udp: RRSIG A alg 13"     "$out" 'RRSIG[[:space:]]+A 13 3 '

out=$($D +tcp +dnssec www.nsec.test A)
check "2 tcp: answer over TCP"    "$out" '\(TCP\)'
check "2 tcp: rd copied, no ra"   "$out" 'flags: qr aa rd;'

out=$($D +dnssec nsec.test DNSKEY)
check "3 DNSKEY 257 3 13"         "$out" 'DNSKEY[[:space:]]+257 3 13 '
check "3 RRSIG DNSKEY"            "$out" 'RRSIG[[:space:]]+DNSKEY 13 2 '

for q in "www.nsec.test A" "www.nsec.test TXT" "nsec.test SOA" "nsec.test DNSKEY"; do
    out=$(delv -p "$PORT" @127.0.0.1 -a "$ANCHOR" +root=nsec.test $q 2>&1)
    check "4 delv $q" "$out" '^; fully validated'
done

exit $fail
