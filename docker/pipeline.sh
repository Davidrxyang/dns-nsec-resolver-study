#!/usr/bin/env bash
# Local resolver pipeline: client -> BIND -> responder (see compose.yml).
# Usage: docker/pipeline.sh up | check | experiments [args] | down
set -u
cd "$(dirname "$0")/.."
DC="docker compose"
RLOG=logs/queries.jsonl

up() {
    # BIND runs as uid 53 in its container and must write here; a dir the
    # host user owns is not writable by it, and Docker would create a
    # missing one as root.
    mkdir -p logs/bind && chmod 777 logs/bind
    $DC up -d --build || exit 1
    for _ in $(seq 20); do
        $DC exec -T bind dig @127.0.0.1 +short +time=1 +tries=1 nsec.test SOA >/dev/null 2>&1 && { echo "pipeline up"; return; }
        sleep 1
    done
    echo "BIND did not answer; see logs/bind/default.log and '$DC logs bind'"; exit 1
}

fail=0
check() {  # check <name> <output> <regex>
    if grep -qE "$3" <<<"$2"; then echo "PASS  $1"; else echo "FAIL  $1"; echo "$2" | sed 's/^/    /'; fail=1; fi
}
seen() {   # number of responder log lines for a qname sent by BIND
    grep -i "\"qname\": \"$1\"" "$RLOG" 2>/dev/null | grep -c '"src": "172.30.0.20"'
}

checks() {
    out=$($DC exec -T bind dig @172.30.0.10 +dnssec +norec www.nsec.test A)
    check "1 BIND host -> responder directly (network)" "$out" 'flags: qr aa;'

    out=$($DC exec -T bind dig @127.0.0.1 +dnssec www.nsec.test A)
    check "2 BIND validates positive answer (ad)"        "$out" 'flags: qr rd ra ad;'

    $DC exec -T bind rndc flush
    # Two fresh names in the same NSEC gap (insecure < m... < ns1).
    tag=m$RANDOM$RANDOM
    a="${tag}a.nsec.test."; b="${tag}b.nsec.test."

    out=$($DC exec -T client dig @172.30.0.20 +dnssec "$a" A)
    check "3 client -> BIND: NXDOMAIN"                   "$out" 'status: NXDOMAIN'
    check "3 client -> BIND: validated (ad)"             "$out" 'flags: qr rd ra ad;'
    sleep 0.5
    n=$(seen "$a")
    check "3 responder saw BIND's query (RD=0, DO=1)"    "$(grep -i "\"qname\": \"$a\"" "$RLOG")" '"rd": false.*"do": true'

    $DC exec -T client dig @172.30.0.20 +dnssec "$a" A >/dev/null
    sleep 0.5
    check "4 repeat answered from cache"                 "$(seen "$a")" "^$n\$"

    out=$($DC exec -T client dig @172.30.0.20 +dnssec "$b" A)
    sleep 0.5
    check "5 same-gap name: NXDOMAIN"                    "$out" 'status: NXDOMAIN'
    check "5 same-gap name: validated (ad)"              "$out" 'flags: qr rd ra ad;'
    if [ "$(seen "$b")" -eq 0 ]; then
        echo "OBS   5 ANC: BIND synthesized $b from the cached NSEC (responder saw nothing)"
    else
        echo "OBS   5 no ANC: BIND asked the responder for $b"
    fi

    # 6. Negative control: with the responder stopped, BIND must fail rather
    # than answer. Flush first and use another gap (ns1 < p... < secure);
    # otherwise the cached insecure->ns1 NSEC would let BIND synthesize.
    $DC exec -T bind rndc flush
    $DC stop responder >/dev/null 2>&1
    out=$($DC exec -T client dig @172.30.0.20 +dnssec +time=30 +tries=1 "p${tag}.nsec.test." A)
    $DC start responder >/dev/null 2>&1
    check "6 responder down: SERVFAIL"                   "$out" 'status: SERVFAIL'
    exit $fail
}

case "${1:-}" in
    up) up ;;
    check) checks ;;
    experiments) shift; venv/bin/python -m experiments run "$@" ;;
    down) $DC down ;;
    *) echo "usage: $0 up | check | experiments [--only IDs] [--slow] | down"; exit 2 ;;
esac
