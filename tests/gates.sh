#!/usr/bin/env bash
# Step 1-4 gates against a running responder (venv/bin/python -m responder).
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

# Step 3: vanilla NSEC3 (zone nsec3.test).
A3=zones/nsec3.test.anchor
out=$($D +dnssec +norec nsec3.test NSEC3PARAM)
check "s3 NSEC3PARAM 1 0 0 - at apex"     "$out" 'NSEC3PARAM[[:space:]]+1 0 0 -'
out=$($D +dnssec +norec c.nsec3.test A)
check "s3 nxdomain: rcode"               "$out" 'status: NXDOMAIN'
check "s3 nxdomain: SOA + 3 NSEC3 + sigs" "$out" 'AUTHORITY: 8,'
check "s3 nxdomain: 3 NSEC3 records"      "$(grep -c 'IN[[:space:]]NSEC3[[:space:]]' <<<"$out")" '^3$'
out=$($D +dnssec +norec ent.nsec3.test A)
check "s3 ENT: matching NSEC3, empty bitmap" "$out" 'NSEC3 1 0 0 - [0-9A-V]+$'
for q in "c.nsec3.test A" "zzz.nsec3.test A" "www.nsec3.test AAAA" "ent.nsec3.test A" \
         "foo.bar.ent.nsec3.test A" "a.b.wild.nsec3.test TXT" "insecure.nsec3.test DS"; do
    out=$(delv -p "$PORT" @127.0.0.1 -a "$A3" +root=nsec3.test $q 2>&1)
    check "s3 delv $q" "$out" '^; negative response, fully validated'
done
for q in "x.wild.nsec3.test A" "secure.nsec3.test DS" "nsec3.test NSEC3PARAM"; do
    out=$(delv -p "$PORT" @127.0.0.1 -a "$A3" +root=nsec3.test $q 2>&1)
    check "s3 delv $q" "$out" '^; fully validated'
done

# Step 4: online-signed variants (docs/VARIANTS.md). Same zone content in each.
out=$($D +dnssec +norec nope.minnsec.test A)
check "s4 minnsec: NXDOMAIN, 2 NSEC + sigs"  "$out" 'AUTHORITY: 6,'
check "s4 minnsec: cover next is nope\\000"  "$out" 'NSEC[[:space:]]+nope\\000\.minnsec\.test\. RRSIG NSEC'
out=$($D +dnssec +norec c.minnsec3.test A)
check "s4 white lies: NXDOMAIN, 3 NSEC3"     "$(grep -c 'IN[[:space:]]NSEC3[[:space:]]' <<<"$out")" '^3$'
out=$($D +dnssec +norec nope.cdoe-nsec.test A)
check "s4 compact: NOERROR for nonexistent" "$out" 'status: NOERROR'
check "s4 compact: NXNAME bitmap"           "$out" 'NSEC[[:space:]]+\\000\.nope\.cdoe-nsec\.test\. RRSIG NSEC (TYPE128|NXNAME)'
out=$($D +dnssec +norec +coflag nope.cdoe-nsec.test A)
check "s4 compact: CO restores NXDOMAIN"    "$out" 'status: NXDOMAIN'
check "s4 compact: CO echoed"               "$out" 'flags: do co;'
out=$($D +dnssec +norec nope.cdoe-nsec.test TYPE128)
check "s4 NXNAME query: FORMERR"            "$out" 'status: FORMERR'
out=$($D +dnssec +norec nope.cdoe-nsec3.test A)
check "s4 compact NSEC3: one NSEC3, NXNAME" "$out" 'NSEC3 1 0 0 - [0-9A-V]+ (TYPE128|NXNAME)$'

# delv on every variant (a DS query at the apex is left out: it needs the
# parent zone, which an island trust anchor cannot provide).
for z in minnsec.test minnsec3.test cdoe-nsec.test cdoe-nsec3.test; do
    for q in "nope A" "zzz A" "c A" "foo.bar.ent A" "www AAAA" "ent A" "wild A" \
             "x.wild TXT" "a.b.wild TXT" "insecure DS"; do
        set -- $q
        out=$(delv -p "$PORT" @127.0.0.1 -a "zones/$z.anchor" +root=$z "$1.$z" "$2" 2>&1)
        check "s4 delv $z $q" "$out" '^; negative response, fully validated'
    done
    for q in "www A" "x.wild A" "deep.er.wild A" "secure DS"; do
        set -- $q
        out=$(delv -p "$PORT" @127.0.0.1 -a "zones/$z.anchor" +root=$z "$1.$z" "$2" 2>&1)
        check "s4 delv $z $q" "$out" '^; fully validated'
    done
done

exit $fail
