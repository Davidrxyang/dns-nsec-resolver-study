"""Denial-of-existence builders, one class per variant.

Each class builds its pre-signed records into the zone before signing
(prepare) and, per response, says which records prove a denial. Proof
methods return a list of items for the authority section, in order and
without duplicates. Each item is either
  - a Name: the owner of a pre-signed denial RRset (vanilla NSEC/NSEC3), or
  - an RRset: a record built for this response and signed online
    (minimally covering NSEC, NSEC3 white lies, compact denial).

Class attributes tell the lookup flow (answer.py) how a variant differs:
  online          builds records per response
  compact         RFC 9824: NOERROR for nonexistent names, CO signaling
  wildcard_exact  wildcard answers signed as exact matches (RFC 9824 §3.3)

Implementation decisions where an RFC is silent are labelled Dn and
explained in docs/VARIANTS.md.
"""

import base64
import bisect

import dns.dnssec
import dns.name
import dns.rcode
import dns.rrset
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype


def _dedup(names):
    out = []
    for n in names:
        if n not in out:
            out.append(n)
    return out


def next_closer(qname, ce):
    """The child of the closest encloser on the path to qname (RFC 5155 §1.3)."""
    return dns.name.Name(qname.labels[-(len(ce.labels) + 1):])


class Denial:
    """Defaults shared by all variants: pre-signed, standard rcodes."""

    online = False
    compact = False
    wildcard_exact = False

    def nxdomain_rcode(self, do, co):
        return dns.rcode.NXDOMAIN


class NsecDenial(Denial):
    """Vanilla NSEC (RFC 4034 §4, RFC 4035 §2.3 and §3.1.3): a pre-built chain."""

    rdtype = dns.rdatatype.NSEC

    def prepare(self, zone) -> None:
        # dns.name.Name orders canonically (RFC 4034 §6.1).
        self.owners = sorted(zone.authoritative_names())
        for i, owner in enumerate(self.owners):
            nxt = self.owners[(i + 1) % len(self.owners)]  # last wraps to apex
            node = zone.zone.get_node(owner)
            types = {
                rds.rdtype for rds in node.rdatasets
                if zone.is_authoritative(owner, rds.rdtype)
                or rds.rdtype == dns.rdatatype.NS  # delegation NS is listed (§2.3)
            }
            types |= {dns.rdatatype.NSEC, dns.rdatatype.RRSIG}
            text = " ".join([nxt.to_text()] + [dns.rdatatype.to_text(t) for t in sorted(types)])
            rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NSEC, text)
            node.replace_rdataset(dns.rdataset.from_rdata(zone.neg_ttl, rdata))

    def covering(self, name):
        """Owner of the NSEC whose span (owner, next) contains a nonexistent name."""
        i = bisect.bisect_right(self.owners, name) - 1
        return self.owners[i]  # i >= 0: the apex sorts before every in-zone name

    def nodata(self, zone, qname):
        """§3.1.3.1. For an empty non-terminal there is no matching NSEC;
        the NSEC covering the name proves it has no types."""
        return [qname] if zone.has_node(qname) else [self.covering(qname)]

    def nxdomain(self, zone, qname, ce):
        """§3.1.3.2: no exact match, and no wildcard at the closest encloser."""
        wildcard = dns.name.Name((b"*",) + ce.labels)
        return _dedup([self.covering(qname), self.covering(wildcard)])

    def wildcard_answer(self, zone, qname, ce):
        """§3.1.3.3: prove no closer match than the wildcard."""
        return [self.covering(qname)]

    def wildcard_nodata(self, zone, qname, wildcard):
        """§3.1.3.4: no closer match, and the wildcard lacks the type."""
        return _dedup([self.covering(qname), wildcard])

    def no_ds(self, zone, cut):
        """§3.1.4: the NSEC at the delegation point shows no DS."""
        return [cut]


class Nsec3Denial(Denial):
    """Vanilla NSEC3 (RFC 5155 §7.1 and §7.2): a pre-built hashed chain.

    NSEC3 records live in zone.extra, outside the name tree, so their hashed
    owner names do not exist for queries (§7.2.8). Defaults follow RFC 9276:
    SHA-1, 0 extra iterations, empty salt, no opt-out.
    """

    rdtype = dns.rdatatype.NSEC3
    ALGORITHM = 1  # SHA-1, the only defined NSEC3 hash

    def __init__(self, iterations=0, salt="", opt_out=False):
        self.iterations = iterations
        self.salt = salt          # hex; "" means no salt
        self.opt_out = opt_out

    def _hash(self, name) -> str:
        return dns.dnssec.nsec3_hash(name, self.salt or None, self.iterations, self.ALGORITHM)

    def _params(self, flags) -> str:
        return f"{self.ALGORITHM} {flags} {self.iterations} {self.salt or '-'}"

    def prepare(self, zone) -> None:
        self.origin = zone.origin
        names = set(zone.authoritative_names())
        if self.opt_out:
            # §7.1: unsigned delegations may be left out of an Opt-Out chain.
            names -= {c for c in zone.cuts if zone.zone.get_rdataset(c, dns.rdatatype.DS) is None}
        # §7.1: empty non-terminals get NSEC3 RRs (with empty bitmaps).
        ents = set()
        for n in names:
            a = n.parent() if n != self.origin else self.origin
            while a != self.origin:
                if a not in names:
                    ents.add(a)
                a = a.parent()

        apex = zone.zone.find_node(self.origin)
        param = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NSEC3PARAM, self._params(0))
        # Flags MUST be 0 (§4.1.2). RFC 5155 sets no TTL; 0 as dnssec-signzone does.
        apex.replace_rdataset(dns.rdataset.from_rdata(0, param))

        entries = sorted((self._hash(n), n) for n in names | ents)
        self.hashes = [h for h, _ in entries]  # base32hex preserves hash byte order
        if len(set(self.hashes)) != len(self.hashes):
            raise ValueError("NSEC3 hash collision between zone names; change the salt")
        self.hashset = set(self.hashes)
        flags = 1 if self.opt_out else 0
        for i, (h, name) in enumerate(entries):
            nxt = self.hashes[(i + 1) % len(self.hashes)]
            types = " ".join(dns.rdatatype.to_text(t) for t in sorted(self._bitmap(zone, name)))
            rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NSEC3,
                                        f"{self._params(flags)} {nxt} {types}")
            zone.extra[(self._owner(h), dns.rdatatype.NSEC3)] = dns.rdataset.from_rdata(zone.neg_ttl, rdata)

    @staticmethod
    def _bitmap(zone, name):
        """Types at the original name (§7.1); never NSEC3 itself; empty for ENTs."""
        node = zone.zone.get_node(name)
        if node is None:
            return set()
        signed = {r.rdtype for r in node.rdatasets if zone.is_authoritative(name, r.rdtype)}
        types = signed | {r.rdtype for r in node.rdatasets if r.rdtype == dns.rdatatype.NS}
        return types | ({dns.rdatatype.RRSIG} if signed else set())

    def _owner(self, h):
        return dns.name.from_text(h, self.origin)

    def match(self, name):
        h = self._hash(name)
        return self._owner(h) if h in self.hashset else None

    def covering(self, name):
        """Owner of the NSEC3 whose hash span contains a nonexistent name's hash."""
        h = self._hash(name)
        if h in self.hashset:
            # §7.2.9: non-existence cannot be proven; the server turns this into SERVFAIL.
            raise RuntimeError(f"NSEC3 hash collision for nonexistent {name}")
        i = bisect.bisect_right(self.hashes, h) - 1  # -1 wraps to the last hash
        return self._owner(self.hashes[i])

    next_closer = staticmethod(next_closer)

    def _ce_proof(self, qname, ce):
        """§7.2.1: NSEC3 matching the closest encloser + one covering the next closer."""
        return [self.match(ce), self.covering(self.next_closer(qname, ce))]

    def _provable_ce_proof(self, qname):
        """§7.2.1 with Opt-Out: walk up to the closest encloser that has an NSEC3."""
        ce = qname.parent()
        while self.match(ce) is None:
            ce = ce.parent()
        return self._ce_proof(qname, ce)

    def nxdomain(self, zone, qname, ce):
        """§7.2.2: closest encloser proof + cover for the wildcard at the CE."""
        wildcard = dns.name.Name((b"*",) + ce.labels)
        return _dedup(self._ce_proof(qname, ce) + [self.covering(wildcard)])

    def nodata(self, zone, qname):
        """§7.2.3 / §7.2.4: the matching NSEC3; for a DS query at an opted-out
        delegation, a closest provable encloser proof instead."""
        m = self.match(qname)
        return [m] if m is not None else self._provable_ce_proof(qname)

    def wildcard_answer(self, zone, qname, ce):
        """§7.2.6: only the cover for the next closer name."""
        return [self.covering(self.next_closer(qname, ce))]

    def wildcard_nodata(self, zone, qname, wildcard):
        """§7.2.5: closest encloser proof + the NSEC3 matching the wildcard."""
        return _dedup(self._ce_proof(qname, wildcard.parent()) + [self.match(wildcard)])

    def no_ds(self, zone, cut):
        """§7.2.7: NSEC3 matching the cut, or an Opt-Out closest provable encloser proof."""
        return self.nodata(zone, cut)


# --- helpers for online variants ------------------------------------------

MAX_LABEL, MAX_NAME = 63, 255


def _wire_len(labels):
    return sum(len(l) + 1 for l in labels)  # labels include the root b""


def successor(name):
    """Immediate canonical successor: prepend a \000 label (RFC 4470 §4,
    RFC 9824 §3.1). Fallback if that exceeds 255 octets: append \000 to the
    first label, the smallest name after the whole subtree (D6)."""
    name = name.canonicalize()
    if _wire_len((b"\x00",) + name.labels) <= MAX_NAME:
        return dns.name.Name((b"\x00",) + name.labels)
    return subtree_successor(name)


def subtree_successor(name):
    """Smallest name after name and all its descendants: append \000 to the
    first label (RFC 9824 §3.4, used for delegations; D5)."""
    name = name.canonicalize()
    first = name.labels[0]
    if len(first) >= MAX_LABEL or _wire_len(name.labels) + 1 > MAX_NAME:
        raise RuntimeError(f"no successor fits the length limits for {name}")  # -> SERVFAIL
    return dns.name.Name((first + b"\x00",) + name.labels[1:])


def predecessor(name):
    """Close canonical predecessor per RFC 4470 §4: decrement the last octet
    of the first label and pad that label with \377 to 63 octets.

    - A trailing \000 is removed instead; an emptied label is dropped, giving
      the parent name, which immediately precedes \000.parent.
    - Octets A-Z compare as a-z (RFC 4034 §6.1), so a decrement landing on
      A-Z would sort high; it is lowered to "@" (0x40), the largest octet
      sorting below them (D7).
    - Padding is shortened to respect the 255-octet name limit (D6).
    """
    name = name.canonicalize()
    first, rest = name.labels[0], name.labels[1:]
    last = first[-1]
    if last == 0:
        first = first[:-1]
        return dns.name.Name(rest) if not first else dns.name.Name((first,) + rest)
    dec = last - 1
    if 0x41 <= dec <= 0x5A:
        dec = 0x40
    label = first[:-1] + bytes([dec])
    room = min(MAX_LABEL - len(label), MAX_NAME - _wire_len((label,) + rest))
    return dns.name.Name((label + b"\xff" * max(room, 0),) + rest)


def _types_text(types):
    return " ".join(dns.rdatatype.to_text(t) for t in sorted(types))


def _real_nsec_types(zone, name):
    """Types an NSEC owned by an existing name lists (RFC 4035 §2.3)."""
    node = zone.zone.get_node(name)
    types = set()
    if node is not None:
        types = {r.rdtype for r in node.rdatasets
                 if zone.is_authoritative(name, r.rdtype) or r.rdtype == dns.rdatatype.NS}
    return types | {dns.rdatatype.NSEC, dns.rdatatype.RRSIG}


def _nsec(zone, owner, nxt, types):
    rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NSEC,
                             f"{nxt.to_text()} {_types_text(types)}")
    return dns.rrset.from_rdata(owner, zone.neg_ttl, rd)


def _next_for(zone, owner):
    """Next name for an online NSEC owned by an existing name: the immediate
    successor, or for a delegation the subtree successor, since \000.cut
    would lie inside the child zone (RFC 9824 §3.4; D5)."""
    return subtree_successor(owner) if owner in zone.cuts else successor(owner)


def _existing_names(zone):
    """Sorted existing names in the parent zone: authoritative names, cuts, ENTs."""
    names = set(zone.authoritative_names())
    for n in list(names):
        a = n
        while a != zone.origin:
            a = a.parent()
            names.add(a)
    return sorted(names)


_HASH_BITS = 160


def _hash_int(h):
    return int.from_bytes(base64.b32hexdecode(h.upper()), "big")  # 32 chars = 160 bits, no padding


def _hash_str(i):
    i %= 1 << _HASH_BITS
    return base64.b32hexencode(i.to_bytes(20, "big")).decode().rstrip("=").upper()


def _hash_add(h, delta):
    return _hash_str(_hash_int(h) + delta)


class _OnlineNsec3(Nsec3Denial):
    """Shared machinery for online NSEC3 variants: hashes of existing names,
    NSEC3PARAM at the apex (D9), records built per response, never opt-out (D10)."""

    online = True

    def __init__(self, iterations=0, salt=""):
        super().__init__(iterations=iterations, salt=salt, opt_out=False)

    def prepare(self, zone) -> None:
        self.origin = zone.origin
        apex = zone.zone.find_node(self.origin)
        param = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NSEC3PARAM, self._params(0))
        apex.replace_rdataset(dns.rdataset.from_rdata(0, param))
        self.by_hash = {self._hash(n): n for n in _existing_names(zone)}

    def record(self, zone, owner_hash, types, next_hash=None):
        nxt = next_hash or _hash_add(owner_hash, 1)
        rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NSEC3,
                                 f"{self._params(0)} {nxt} {_types_text(types)}")
        return dns.rrset.from_rdata(self._owner(owner_hash), zone.neg_ttl, rd)

    def match(self, zone, name):
        """Hash(name) -> hash(name)+1, with the name's real types (RFC 7129 App. B, RFC 9824 §4)."""
        return self.record(zone, self._hash(name), self._bitmap(zone, name))

    def _nonexistent_hash(self, name):
        h = self._hash(name)
        if h in self.by_hash:
            raise RuntimeError(f"NSEC3 hash collision for nonexistent {name}")  # RFC 5155 §7.2.9
        return h


# --- minimally covering NSEC (RFC 4470) -------------------------------------

class MinimalNsecDenial(Denial):
    """Online-signed minimally covering NSEC (RFC 4470).

    Covers: owner = predecessor(name), next = successor(name), bitmap RRSIG
    NSEC (§3: "MUST include RRSIG and NSEC ... SHOULD NOT include any other").
    If an existing name falls between predecessor(name) and name, it becomes
    the owner with its real bitmap (§3). Existing names get NSECs with their
    real bitmaps and a minimal next name (§3 relaxes RFC 4034 §4.1.1).
    """

    rdtype = dns.rdatatype.NSEC
    online = True

    def __init__(self, cover_next="subtree"):
        # Next name of covers for nonexistent names (D14):
        #   "subtree": name with \000 appended to its first label, the smallest
        #              name after the name's whole subtree (RFC 4470 §3 example
        #              style; erratum 6734). Validates in BIND.
        #   "child":   \000.name, RFC 4470 §4's increment taken literally. Per
        #              erratum 6734 this proves "no data", not non-existence, and
        #              BIND rejects such NXDOMAINs. Kept as an experiment knob.
        if cover_next not in ("subtree", "child"):
            raise ValueError("cover_next must be 'subtree' or 'child'")
        self.cover_next = cover_next

    def prepare(self, zone) -> None:
        self.existing = _existing_names(zone)

    def nsec_at(self, zone, name):
        return _nsec(zone, name, _next_for(zone, name), _real_nsec_types(zone, name))

    def cover(self, zone, name, ent=False):
        owner = predecessor(name)
        i = bisect.bisect_left(self.existing, name) - 1
        types = {dns.rdatatype.NSEC, dns.rdatatype.RRSIG}
        if i >= 0 and self.existing[i] > owner:
            owner = self.existing[i]                      # §3 collision rule (D8)
            types = _real_nsec_types(zone, owner)
        if ent or self.cover_next == "child":
            nxt = successor(name)                         # \000.name: name exists (ENT)
        else:
            try:
                nxt = subtree_successor(name)
            except RuntimeError:                          # 63-octet first label (D6)
                nxt = successor(name)
        return _nsec(zone, owner, nxt, types)

    def nodata(self, zone, qname):
        # ENT: an NSEC may not be the only RRset at a name (RFC 4035 §2.3), so
        # cover the ENT; the next name \000.ent lies below it, which proves
        # the ENT exists, as with a pre-signed chain (D4).
        if zone.has_node(qname):
            return [self.nsec_at(zone, qname)]
        return [self.cover(zone, qname, ent=True)]

    # Covers span the next closer name, not the QNAME (D15): a minimal span
    # around a QNAME two labels below the closest encloser would sit inside
    # the next closer's subtree and never prove the next closer absent.

    def nxdomain(self, zone, qname, ce):
        wildcard = dns.name.Name((b"*",) + ce.labels)
        nc = next_closer(qname, ce)
        return _dedup_rrsets([self.cover(zone, nc), self.cover(zone, wildcard)])

    def wildcard_answer(self, zone, qname, ce):
        return [self.cover(zone, next_closer(qname, ce))]

    def wildcard_nodata(self, zone, qname, wildcard):
        nc = next_closer(qname, wildcard.parent())
        return _dedup_rrsets([self.cover(zone, nc), self.nsec_at(zone, wildcard)])

    def no_ds(self, zone, cut):
        return [self.nsec_at(zone, cut)]


# --- minimally covering NSEC3, "white lies" (RFC 7129 Appendix B) ----------

class Nsec3WhiteLiesDenial(_OnlineNsec3):
    """Online NSEC3 "white lies" (RFC 7129 App. B; PowerDNS "narrow" mode).

    Every record is a white lie, as in the RFC's example: a match is
    hash(name) -> hash(name)+1 with the real bitmap; a cover is
    hash(name)-1 -> hash(name)+1 with an empty bitmap (or, if hash-1 is an
    existing name's hash, that name's types). Proof structure is RFC 5155 §7.2.
    """

    def cover(self, zone, name):
        h = self._nonexistent_hash(name)
        below = _hash_add(h, -1)
        types = self._bitmap(zone, self.by_hash[below]) if below in self.by_hash else set()
        return self.record(zone, below, types, next_hash=_hash_add(h, 1))

    def _ce_proof(self, zone, qname, ce):
        return [self.match(zone, ce), self.cover(zone, self.next_closer(qname, ce))]

    def nxdomain(self, zone, qname, ce):
        wildcard = dns.name.Name((b"*",) + ce.labels)
        return _dedup_rrsets(self._ce_proof(zone, qname, ce) + [self.cover(zone, wildcard)])

    def nodata(self, zone, qname):
        return [self.match(zone, qname)]

    def wildcard_answer(self, zone, qname, ce):
        return [self.cover(zone, self.next_closer(qname, ce))]

    def wildcard_nodata(self, zone, qname, wildcard):
        return _dedup_rrsets(self._ce_proof(zone, qname, wildcard.parent()) + [self.match(zone, wildcard)])

    def no_ds(self, zone, cut):
        return [self.match(zone, cut)]


# --- compact denial of existence (RFC 9824) --------------------------------

class _Compact:
    """RFC 9824 behavior common to the NSEC and NSEC3 forms."""

    online = True
    compact = True
    wildcard_exact = True       # §3.3: wildcard answers look like exact matches

    def nxdomain_rcode(self, do, co):
        # §5.1: with CO set, NXDOMAIN is restored. Without DO there is no
        # proof to keep consistent; §5 says servers should try to preserve
        # NXDOMAIN where possible, so DO=0 gets NXDOMAIN (D11).
        return dns.rcode.NXDOMAIN if (co or not do) else dns.rcode.NOERROR

    def wildcard_answer(self, zone, qname, ce):
        return []               # §3.3: no closer-match proof needed


class CompactNsecDenial(_Compact, Denial):
    """RFC 9824 §3: one NSEC owned by the QNAME, next = immediate successor."""

    rdtype = dns.rdatatype.NSEC

    def prepare(self, zone) -> None:
        pass

    def nsec_at(self, zone, name, types=None):
        types = types if types is not None else _real_nsec_types(zone, name)
        return _nsec(zone, name, _next_for(zone, name), types)

    def nxdomain(self, zone, qname, ce):
        # §3.1: bitmap MUST be exactly RRSIG NSEC NXNAME.
        return [self.nsec_at(zone, qname.canonicalize(),
                             {dns.rdatatype.RRSIG, dns.rdatatype.NSEC, dns.rdatatype.NXNAME})]

    def nodata(self, zone, qname):
        # §3.2: real types; an ENT gets RRSIG NSEC only (no NXNAME).
        return [self.nsec_at(zone, qname.canonicalize())]

    def wildcard_nodata(self, zone, qname, wildcard):
        # §3.3: "akin to a non-wildcard NODATA": owner QNAME, wildcard's types.
        return [self.nsec_at(zone, qname.canonicalize(), _real_nsec_types(zone, wildcard))]

    def no_ds(self, zone, cut):
        return [self.nsec_at(zone, cut)]  # §3.4: NS RRSIG NSEC, next sub\000


class CompactNsec3Denial(_Compact, _OnlineNsec3):
    """RFC 9824 §4: one NSEC3 matching hash(QNAME), next = hash + 1."""

    def nxdomain(self, zone, qname, ce):
        # §4: bitmap is NXNAME only.
        return [self.record(zone, self._nonexistent_hash(qname), {dns.rdatatype.NXNAME})]

    def nodata(self, zone, qname):
        return [self.match(zone, qname)]       # ENT: empty bitmap (§4)

    def wildcard_nodata(self, zone, qname, wildcard):
        return [self.record(zone, self._nonexistent_hash(qname), self._bitmap(zone, wildcard))]

    def no_ds(self, zone, cut):
        return [self.match(zone, cut)]


def _dedup_rrsets(rrsets):
    out = []
    for r in rrsets:
        if all(r.name != o.name for o in out):
            out.append(r)
    return out


VARIANTS = {
    "nsec": NsecDenial,
    "nsec3": Nsec3Denial,
    "minimal-nsec": MinimalNsecDenial,
    "nsec3-white-lies": Nsec3WhiteLiesDenial,
    "compact-nsec": CompactNsecDenial,
    "compact-nsec3": CompactNsec3Denial,
}
