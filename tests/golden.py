"""Compare response structure against golden dig captures in tests/golden/.

Both a dig text capture and a live dns.message.Message reduce to the same
"shape": RCODE, flags, section layout, and the role each denial record
plays. Signatures, serials, and names are deliberately left out.
"""

import base64
import hashlib
import re
from pathlib import Path

import dns.flags
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype

GOLDEN = Path(__file__).parent / "golden"
SECTIONS = {"ANSWER": "answer", "AUTHORITY": "authority", "ADDITIONAL": "additional"}


def parse_dig(text):
    """Parse dig output into {rcode, flags, do, answer/authority/additional}."""
    out = {"answer": [], "authority": [], "additional": []}
    section = None
    for line in text.splitlines():
        if m := re.search(r"status: (\w+)", line):
            out["rcode"] = m.group(1)
        if m := re.match(r";; flags: ([a-z ]*);", line):
            out["flags"] = set(m.group(1).split())
        if line.startswith("; EDNS:"):
            out["do"] = "flags: do" in line
        if m := re.match(r";; (\w+) SECTION:", line):
            section = SECTIONS.get(m.group(1))
            continue
        if section and line and not line.startswith(";"):
            name, ttl, cls, typ, rdata = line.split(None, 4)
            rd = dns.rdata.from_text(cls, typ, rdata)
            out[section].append((dns.name.from_text(name), int(ttl), rd))
    return out


def from_message(msg):
    out = {
        "rcode": dns.rcode.to_text(msg.rcode()),
        "flags": set(dns.flags.to_text(msg.flags).lower().split()),
        "do": bool(msg.ednsflags & dns.flags.DO),
    }
    for sec in ("answer", "authority", "additional"):
        out[sec] = [(rrset.name, rrset.ttl, rd) for rrset in getattr(msg, sec) for rd in rrset]
    return out


def covers(owner, nxt, name):
    """NSEC (owner, next) span contains name, including the wrap-around span."""
    if owner < nxt:
        return owner < name < nxt
    return name > owner or name < nxt


def nsec_types(rd):
    """Decode an NSEC/NSEC3 type bitmap (RFC 4034 §4.1.2) into rdtype ints."""
    types = set()
    for window, bitmap in rd.windows:
        for i, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    types.add(window * 256 + i * 8 + bit)
    return types


def _role(rd):
    types = nsec_types(rd)
    if dns.rdatatype.SOA in types:
        return "apex"
    if dns.rdatatype.NS in types:
        return "delegation+ds" if dns.rdatatype.DS in types else "delegation"
    return "name"


def nxdomain_shape(parsed, qname):
    qname = dns.name.from_text(qname)
    auth = parsed["authority"]
    soa = next(rd for _, _, rd in auth if rd.rdtype == dns.rdatatype.SOA)
    soa_ttl = next(ttl for _, ttl, rd in auth if rd.rdtype == dns.rdatatype.SOA)
    apex = next(n for n, _, rd in auth if rd.rdtype == dns.rdatatype.SOA)
    wildcard = dns.name.Name((b"*",) + apex.labels)
    neg_ttl = min(soa_ttl, soa.minimum)

    def kind(rd):
        t = dns.rdatatype.to_text(rd.rdtype)
        return f"RRSIG {dns.rdatatype.to_text(rd.type_covered)}" if t == "RRSIG" else t

    return {
        "rcode": parsed["rcode"],
        "flags": sorted(parsed["flags"]),
        "do": parsed["do"],
        "answer": len(parsed["answer"]),
        "authority": [kind(rd) for _, _, rd in auth],
        "nsec": [
            (_role(rd), covers(n, rd.next, qname), covers(n, rd.next, wildcard))
            for n, _, rd in auth if rd.rdtype == dns.rdatatype.NSEC
        ],
        "ttls_are_negative_ttl": all(ttl == neg_ttl for _, ttl, _ in auth),
        "rrsig_labels_match_owner": all(
            rd.labels == len(n) - 1 for n, _, rd in auth if rd.rdtype == dns.rdatatype.RRSIG
        ),
    }


# --- NSEC3 -------------------------------------------------------------------

def nsec3_hash(name, salt=b"", iterations=0):
    """RFC 5155 §5, written independently of dnspython's nsec3_hash."""
    if isinstance(name, str):
        name = dns.name.from_text(name)
    wire = name.canonicalize().to_wire()
    h = hashlib.sha1(wire + salt).digest()
    for _ in range(iterations):
        h = hashlib.sha1(h + salt).digest()
    return base64.b32hexencode(h).decode().rstrip("=").upper()


def nsec3_spans(records):
    """[(owner_hash, next_hash, rdata)] for NSEC3 records [(name, ttl, rdata)]."""
    out = []
    for name, _, rd in records:
        if rd.rdtype == dns.rdatatype.NSEC3:
            nxt = base64.b32hexencode(rd.next).decode().rstrip("=").upper()
            out.append((name.labels[0].decode().upper(), nxt, rd))
    return out


def hash_covers(owner, nxt, h):
    if owner < nxt:
        return owner < h < nxt
    return h > owner or h < nxt


def nsec3_nxdomain_shape(parsed, qname):
    """Role of each NSEC3 in an NXDOMAIN: closest-encloser match, next-closer
    cover, wildcard cover (RFC 5155 §7.2.2). The closest encloser is the
    longest ancestor of qname whose hash matches an NSEC3 owner."""
    qname = dns.name.from_text(qname)
    auth = parsed["authority"]
    spans = nsec3_spans(auth)
    rd0 = spans[0][2]
    salt, it = rd0.salt, rd0.iterations
    owners = {o for o, _, _ in spans}
    ce = qname.parent()
    while nsec3_hash(ce, salt, it) not in owners:
        ce = ce.parent()
    nc = dns.name.Name(qname.labels[-(len(ce.labels) + 1):])
    wc = dns.name.Name((b"*",) + ce.labels)
    roles = []
    for o, n, _ in spans:
        r = []
        if o == nsec3_hash(ce, salt, it):
            r.append("ce-match")
        if hash_covers(o, n, nsec3_hash(nc, salt, it)):
            r.append("nc-cover")
        if hash_covers(o, n, nsec3_hash(wc, salt, it)):
            r.append("wc-cover")
        roles.append("+".join(r))
    soa = next(rd for _, _, rd in auth if rd.rdtype == dns.rdatatype.SOA)
    soa_ttl = next(ttl for _, ttl, rd in auth if rd.rdtype == dns.rdatatype.SOA)

    def kind(rd):
        t = dns.rdatatype.to_text(rd.rdtype)
        return f"RRSIG {dns.rdatatype.to_text(rd.type_covered)}" if t == "RRSIG" else t

    return {
        "rcode": parsed["rcode"],
        "flags": sorted(parsed["flags"]),
        "do": parsed["do"],
        "answer": len(parsed["answer"]),
        "authority": [kind(rd) for _, _, rd in auth],
        "nsec3_roles": roles,
        "hash_alg": rd0.algorithm,
        "ttls_are_negative_ttl": all(ttl == min(soa_ttl, soa.minimum) for _, ttl, _ in auth),
        "rrsig_labels_match_owner": all(
            rd.labels == len(n) - 1 for n, _, rd in auth if rd.rdtype == dns.rdatatype.RRSIG),
    }
