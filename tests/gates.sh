#!/usr/bin/env bash
# Step 1 and step 2 gates against a running responder (venv/bin/python -m responder).
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
check "s1.1 udp: flags qr aa, no ra" "$out" 'flags: qr aa;'
check "s1.1 udp: DO echoed"          "$out" 'EDNS: version: 0, flags: do;'
check "s1.1 udp: RRSIG A alg 13"     "$out" 'RRSIG[[:space:]]+A 13 3 '

out=$($D +tcp +dnssec www.nsec.test A)
check "s1.2 tcp: answer over TCP"    "$out" '\(TCP\)'
check "s1.2 tcp: rd copied, no ra"   "$out" 'flags: qr aa rd;'

out=$($D +dnssec nsec.test DNSKEY)
check "s1.3 DNSKEY 257 3 13"         "$out" 'DNSKEY[[:space:]]+257 3 13 '
check "s1.3 RRSIG DNSKEY"            "$out" 'RRSIG[[:space:]]+DNSKEY 13 2 '

for q in "www.nsec.test A" "www.nsec.test TXT" "nsec.test SOA" "nsec.test DNSKEY"; do
    out=$(delv -p "$PORT" @127.0.0.1 -a "$ANCHOR" +root=nsec.test $q 2>&1)
    check "s1.4 delv $q" "$out" '^; fully validated'
done

# Step 2: vanilla NSEC. Structure via dig, then independent validation via delv.
out=$($D +dnssec +norec nope.nsec.test A)
check "s2 nxdomain: rcode, aa"          "$out" 'status: NXDOMAIN'
check "s2 nxdomain: SOA + 2 NSEC + sigs" "$out" 'AUTHORITY: 6,'
out=$($D +dnssec +norec www.nsec.test AAAA)
check "s2 nodata: NSEC at qname"        "$out" '^www\.nsec\.test\.[[:space:]]+60[[:space:]]+IN[[:space:]]+NSEC'
out=$($D +dnssec +norec x.wild.nsec.test A)
check "s2 wildcard: RRSIG labels 3"     "$out" 'RRSIG[[:space:]]+A 13 3 '
out=$($D +dnssec +norec foo.secure.nsec.test A)
check "s2 referral: no aa"              "$out" 'flags: qr;'
check "s2 referral: DS in authority"    "$out" '^secure\.nsec\.test\..*[[:space:]]DS[[:space:]]'
out=$($D +dnssec +norec insecure.nsec.test A)
check "s2 insecure referral: NSEC, no DS" "$out" 'NSEC[[:space:]]+ns1\.nsec\.test\. NS RRSIG NSEC'

for q in "nope.nsec.test A" "zzz.nsec.test A" "www.nsec.test AAAA" "ent.nsec.test A" \
         "a.b.wild.nsec.test TXT" "insecure.nsec.test DS"; do
    out=$(delv -p "$PORT" @127.0.0.1 -a "$ANCHOR" +root=nsec.test $q 2>&1)
    check "s2 delv $q" "$out" '^; negative response, fully validated'
done
for q in "x.wild.nsec.test A" "secure.nsec.test DS" "nsec.test NSEC"; do
    out=$(delv -p "$PORT" @127.0.0.1 -a "$ANCHOR" +root=nsec.test $q 2>&1)
    check "s2 delv $q" "$out" '^; fully validated'
done

exit $fail
