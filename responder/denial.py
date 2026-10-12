"""Denial-of-existence builders, one class per variant.

Each class builds its records into the zone before signing (prepare) and,
per response, names which of those records prove a denial. The proof
methods return owner names whose denial RRset (plus RRSIG) goes in the
authority section, in order and without duplicates.
"""

import bisect

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


VARIANTS = {"nsec": NsecDenial}
