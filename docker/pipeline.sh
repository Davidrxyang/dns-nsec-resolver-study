#!/usr/bin/env bash
# Local resolver pipeline: client -> resolvers (BIND, Knot, PowerDNS) -> responder (see compose.yml).
# Usage: docker/pipeline.sh up | check | experiments [args] | down
set -u
cd "$(dirname "$0")/.."
DC="docker compose"
RLOG=logs/queries.jsonl

# Resolvers under test: name, lab address, cache flush (same as experiments/harness.py).
RESOLVERS="bind knot pdns"
ip_of() { case $1 in bind) echo 172.30.0.20 ;; knot) echo 172.30.0.21 ;; pdns) echo 172.30.0.22 ;; esac; }
flush() {
    case $1 in
        bind) $DC exec -T bind rndc flush ;;
        knot) $DC exec -T knot kresctl cache clear >/dev/null ;;
        pdns) $DC exec -T pdns rec_control wipe-cache '.$' >/dev/null ;;
    esac
}

up() {
    # BIND runs as uid 53 in its container and must write here; a dir the
    # host user owns is not writable by it, and Docker would create a
    # missing one as root.
    mkdir -p logs/bind && chmod 777 logs/bind
    # Write every zone's trust anchor before BIND starts and includes them.
    $DC build responder || exit 1
    $DC run --rm --no-deps responder --addr 0.0.0.0 --port 53 --anchors-only || exit 1
    # Knot wants zone-format trust anchors (one DNSKEY line per file).
    for f in zones/*.anchor; do
        sed -nE 's/^[[:space:]]*([^[:space:]]+) static-key ([0-9]+) ([0-9]+) ([0-9]+) "([^"]+)";.*/\1 300 IN DNSKEY \2 \3 \4 \5/p' \
            "$f" > "${f%.anchor}.dnskey"
    done
    # PowerDNS wants DS records (RDATA only) in YAML; derive them with BIND's dnssec-dsfromkey.
    pdns_anchors
    $DC up -d --build || exit 1
    for r in $RESOLVERS; do
        for _ in $(seq 30); do
            $DC exec -T client dig @"$(ip_of $r)" +short +time=1 +tries=1 nsec.test SOA >/dev/null 2>&1 && continue 2
            sleep 1
        done
        echo "$r did not answer; see '$DC logs $r'"; exit 1
    done
    echo "pipeline up"
}

pdns_anchors() {
    local out=docker/pdns/recursor.d/anchors.yml img
    img=$(sed -nE 's/^[[:space:]]+(internetsystemsconsortium\/bind9@sha256:[0-9a-f]+).*/\1/p' compose.yml | head -1)
    {
        echo "# Generated from zones/*.dnskey by docker/pipeline.sh up; do not edit."
        echo "dnssec:"
        echo "  trustanchors:"
        for f in zones/*.dnskey; do
            z=$(basename "$f" .dnskey)
            ds=$(docker run --rm -v "$PWD/zones:/z:ro" --entrypoint dnssec-dsfromkey "$img" -2 -f "/z/$z.dnskey" "$z" | awk '{print $4, $5, $6, $7}')
            echo "    - { name: $z, dsrecords: ['$ds'] }"
        done
    } > "$out"
}

fail=0
check() {  # check <name> <output> <regex>
    if grep -qE "$3" <<<"$2"; then echo "PASS  $1"; else echo "FAIL  $1"; echo "$2" | sed 's/^/    /'; fail=1; fi
}
seen() {   # seen <qname> <resolver ip>: responder log lines for qname sent by that resolver
    grep -i "\"qname\": \"$1\"" "$RLOG" 2>/dev/null | grep -c "\"src\": \"$2\""
}

checks() {
    out=$($DC exec -T client dig @172.30.0.10 +dnssec +norec www.nsec.test A)
    check "1 client -> responder directly (network)"      "$out" 'flags: qr aa;'

    tag=m$RANDOM$RANDOM
    for r in $RESOLVERS; do
        ip=$(ip_of $r)
        dig_r() { $DC exec -T client dig @"$ip" +dnssec "$@"; }

        out=$(dig_r www.nsec.test A)
        check "$r 2 validates positive answer (ad)"       "$out" 'flags: qr rd ra ad;'

        flush $r
        # Two fresh names in the same NSEC gap (insecure < m... < ns1).
        a="${tag}${r}a.nsec.test."; b="${tag}${r}b.nsec.test."
        out=$(dig_r "$a" A)
        check "$r 3 client -> resolver: NXDOMAIN"         "$out" 'status: NXDOMAIN'
        check "$r 3 client -> resolver: validated (ad)"   "$out" 'flags: qr rd ra ad;'
        sleep 0.5
        n=$(seen "$a" "$ip")
        check "$r 3 responder saw the query (RD=0, DO=1)" "$(grep -i "\"qname\": \"$a\"" "$RLOG" | grep "\"src\": \"$ip\"")" '"rd": false.*"do": true'

        dig_r "$a" A >/dev/null
        sleep 0.5
        check "$r 4 repeat answered from cache"           "$(seen "$a" "$ip")" "^$n\$"

        out=$(dig_r "$b" A)
        sleep 0.5
        check "$r 5 same-gap name: NXDOMAIN"              "$out" 'status: NXDOMAIN'
        check "$r 5 same-gap name: validated (ad)"        "$out" 'flags: qr rd ra ad;'
        if [ "$(seen "$b" "$ip")" -eq 0 ]; then
            echo "OBS   $r 5 ANC: synthesized $b from the cached NSEC (responder saw nothing)"
        elif [ "$r" = pdns ]; then
            echo "OBS   $r 5 no ANC: expected in this lab, PowerDNS skips its aggressive cache for forward_zones"
        else
            echo "OBS   $r 5 no ANC: asked the responder for $b"
        fi

        # Every variant zone: a validated answer for a nonexistent name.
        # Compact denial answers NOERROR (RFC 9824), the others NXDOMAIN.
        for z in nsec3.test minnsec.test minnsec3.test cdoe-nsec.test cdoe-nsec3.test; do
            case $z in cdoe-*) want=NOERROR ;; *) want=NXDOMAIN ;; esac
            out=$(dig_r "c${tag}${r}.$z." A)
            check "$r 5b $z: $want"                       "$out" "status: $want"
            check "$r 5b $z: validated (ad)"              "$out" 'flags: qr rd ra ad;'
        done
    done

    # 6. Negative control: with the responder stopped, every resolver must fail
    # rather than answer. Flush first and use another gap (ns1 < p... < secure);
    # otherwise the cached insecure->ns1 NSEC would allow synthesis.
    for r in $RESOLVERS; do flush $r; done
    $DC stop responder >/dev/null 2>&1
    for r in $RESOLVERS; do
        out=$($DC exec -T client dig @"$(ip_of $r)" +dnssec +time=30 +tries=1 "p${tag}${r}.nsec.test." A)
        check "$r 6 negative control: responder stopped, correctly returns SERVFAIL" "$out" 'status: SERVFAIL'
    done
    $DC start responder >/dev/null 2>&1
    exit $fail
}

case "${1:-}" in
    up) up ;;
    check) checks ;;
    experiments) shift; venv/bin/python -m experiments run "$@" ;;
    down) $DC down ;;
    *) echo "usage: $0 up | check | experiments [--resolver bind|knot|pdns|all] [--only IDs] [--slow] | down"; exit 2 ;;
esac
