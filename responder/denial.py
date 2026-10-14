"""Denial-of-existence builders, one class per variant.

Each class builds its records into the zone before signing (prepare) and,
per response, names which of those records prove a denial. The proof
methods return owner names whose denial RRset (plus RRSIG) goes in the
authority section, in order and without duplicates.
"""

import bisect

import dns.dnssec
import dns.name
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


class NsecDenial:
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


class Nsec3Denial:
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
        soa_ttl = apex.get_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA).ttl
        param = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NSEC3PARAM, self._params(0))
        apex.replace_rdataset(dns.rdataset.from_rdata(soa_ttl, param))  # flags MUST be 0 (§4.1.2)

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

    @staticmethod
    def next_closer(qname, ce):
        return dns.name.Name(qname.labels[-(len(ce.labels) + 1):])

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


VARIANTS = {"nsec": NsecDenial, "nsec3": Nsec3Denial}
