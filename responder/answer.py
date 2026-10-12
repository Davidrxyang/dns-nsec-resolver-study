"""Authoritative lookup: fills a response for a query inside one zone.

Order follows RFC 1034 §4.3.2 with RFC 4035 §3.1 DNSSEC additions:
referral, exact match (answer / NODATA), wildcard (answer / NODATA),
otherwise NXDOMAIN. Which denial records prove a negative comes from
zone.denial, so variants plug in without touching this flow.
"""

import dns.flags
import dns.name
import dns.rcode
import dns.rdatatype

ADDRESS_TYPES = (dns.rdatatype.A, dns.rdatatype.AAAA)


def _add(section, found, do):
    rrset, sig = found
    section.append(rrset)
    if do and sig is not None:
        section.append(sig)


def _add_denial(response, zone, owners, do):
    if not do:
        return
    for owner in owners:
        _add(response.authority, zone.get(owner, zone.denial.rdtype), do)


def _negative(response, zone, owners, do, rcode):
    response.set_rcode(rcode)
    _add(response.authority, zone.get(zone.origin, dns.rdatatype.SOA, ttl=zone.neg_ttl), do)
    _add_denial(response, zone, owners, do)


def _referral(response, zone, cut, do):
    response.flags &= ~dns.flags.AA
    ns = zone.get(cut, dns.rdatatype.NS)
    response.authority.append(ns[0])
    if do:
        ds = zone.get(cut, dns.rdatatype.DS)
        if ds is not None:
            _add(response.authority, ds, do)
        else:
            _add_denial(response, zone, zone.denial.no_ds(zone, cut), do)
    # Glue for in-zone nameserver names.
    for rdata in ns[0]:
        target = rdata.target
        if not target.is_subdomain(zone.origin):
            continue
        for t in ADDRESS_TYPES:
            glue = zone.get(target, t)
            if glue is not None:
                response.additional.append(glue[0])


def _positive(response, zone, name, qtype, owner, do) -> bool:
    """Answer from the RRsets at name (renamed to owner). False if none match."""
    if qtype == dns.rdatatype.RRSIG:
        sigs = zone.sigs_at(name, owner)
        response.answer.extend(sigs)
        return bool(sigs)
    found = zone.get(name, qtype, owner)
    if found is None and qtype != dns.rdatatype.CNAME:
        found = zone.get(name, dns.rdatatype.CNAME, owner)  # returned, not chased
    if found is None:
        return False
    _add(response.answer, found, do)
    return True


def answer(response, zone, qname, qtype, do) -> None:
    cut = zone.find_cut(qname, qtype)
    if cut is not None:
        _referral(response, zone, cut, do)
        return

    if zone.name_exists(qname):
        if not _positive(response, zone, qname, qtype, qname, do):
            _negative(response, zone, zone.denial.nodata(zone, qname), do, dns.rcode.NOERROR)
        return

    ce = zone.closest_encloser(qname)
    wildcard = dns.name.Name((b"*",) + ce.labels)
    if zone.has_node(wildcard):
        if _positive(response, zone, wildcard, qtype, qname, do):
            _add_denial(response, zone, zone.denial.wildcard_answer(zone, qname, ce), do)
        else:
            owners = zone.denial.wildcard_nodata(zone, qname, wildcard)
            _negative(response, zone, owners, do, dns.rcode.NOERROR)
        return

    _negative(response, zone, zone.denial.nxdomain(zone, qname, ce), do, dns.rcode.NXDOMAIN)
