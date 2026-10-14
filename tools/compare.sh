#!/usr/bin/env bash
# Ask the same question in every variant zone and show the answers side by side.
#
# Usage: tools/compare.sh [--bind] LABEL [QTYPE] [extra dig options...]
#   tools/compare.sh nope                 # nonexistent name, all six zones
#   tools/compare.sh ent A                # empty non-terminal
#   tools/compare.sh nope A +coflag       # compact denial with CO set
#   tools/compare.sh --bind nope          # through BIND (Docker pipeline) instead
#
# Shows rcode, flags, and the denial records (NSEC/NSEC3) of each answer,
# with long \255 runs shortened. Label "@" means the zone apex.
set -u
server=127.0.0.1 port=5300 rd=+norec via="responder 127.0.0.1:5300"
if [ "${1:-}" = "--bind" ]; then
    server=172.30.0.20 port=53 rd=+rec via="BIND 172.30.0.20 (resolver view)"; shift
fi
label=${1:?usage: tools/compare.sh [--bind] LABEL [QTYPE] [dig options...]}
qtype=${2:-A}
shift; [ $# -gt 0 ] && shift

echo "query: $label.<zone> $qtype ${*:-}   via $via"
for z in nsec nsec3 minnsec minnsec3 cdoe-nsec cdoe-nsec3; do
    name="$label.$z.test"; [ "$label" = "@" ] && name="$z.test"
    printf '\n== %s.test\n' "$z"
    dig -p "$port" @"$server" +dnssec "$rd" +nocmd +nostats +noquestion +nottlid "$@" "$name" "$qtype" \
        | awk '/status:/ { sub(/.*status: /, ""); sub(/,.*/, ""); st = $0 }
               /^;; flags:/ { sub(/^;; flags: /, ""); sub(/;.*/, ""); print st "   flags: " $0 }
               /^; EDNS:/ && /flags: do co/ { print "   (CO echoed)" }
               $2 == "IN" && $3 != "RRSIG" && $3 != "SOA" && $3 != "OPT" {
                   $2 = ""; print "  " $0 }' \
        | sed -E 's/(\\255){4,}/\\255…/g; s/  +/ /g'
done
