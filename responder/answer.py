"""Authoritative lookup: fills a response for a query inside one zone.

Order follows RFC 1034 §4.3.2 with RFC 4035 §3.1 DNSSEC additions:
referral, exact match (answer / NODATA), wildcard (answer / NODATA),
otherwise NXDOMAIN. Which denial records prove a negative comes from
zone.denial, so variants plug in without touching this flow. Variant
switches (see responder/denial.py): denial items may be pre-signed owner
names or per-response RRsets; compact denial changes the NXDOMAIN rcode,
signs wildcard answers as exact matches, and echoes CO (RFC 9824 §5.1).
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


def _add_denial(response, zone, items, do):
    if not do:
        return
    for item in items:
        if isinstance(item, dns.name.Name):          # pre-signed record
            _add(response.authority, zone.get(item, zone.denial.rdtype), do)
        else:                                        # built for this response
            _add(response.authority, (item, zone.sign_online(item)), do)


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
    _add_ns_addresses(response, zone, ns[0], do)


def _add_ns_addresses(response, zone, ns_rrset, do):
    """Additional-section addresses for in-zone nameserver names: unsigned
    glue in referrals, signed authoritative data for the apex NS RRset."""
    for rdata in ns_rrset:
        target = rdata.target
        if not target.is_subdomain(zone.origin):
            continue
        for t in ADDRESS_TYPES:
            found = zone.get(target, t)
            if found is not None:
                _add(response.additional, found, do)


def _online_nsec_at(zone, name):
    """The NSEC an online NSEC variant would show for an existing name."""
    for item in zone.denial.nodata(zone, name):
        if not isinstance(item, dns.name.Name) and item.name == name:
            return item
    return None


def _positive(response, zone, name, qtype, owner, do, exact=False) -> bool:
    """Answer from the RRsets at name (renamed to owner). False if none match.

    exact: sign the (wildcard-expanded) answer online as if owner existed,
    so its RRSIG label count is the owner's (RFC 9824 §3.3).
    """
    online_nsec = zone.denial.online and zone.denial.rdtype == dns.rdatatype.NSEC
    if qtype == dns.rdatatype.RRSIG:
        sigs = zone.sigs_at(name, owner)
        if online_nsec and name == owner and (nsec := _online_nsec_at(zone, name)) is not None:
            sigs.append(zone.sign_online(nsec))      # D12
        response.answer.extend(sigs)
        return bool(sigs)
    found = zone.get(name, qtype, owner)
    if found is None and qtype != dns.rdatatype.CNAME:
        found = zone.get(name, dns.rdatatype.CNAME, owner)  # returned, not chased
    if found is None and online_nsec and qtype == dns.rdatatype.NSEC and name == owner:
        nsec = _online_nsec_at(zone, name)           # D12: the NSEC the bitmap advertises
        found = (nsec, zone.sign_online(nsec)) if nsec is not None else None
    if found is None:
        return False
    if exact:
        found = (found[0], zone.sign_online(found[0]))
    _add(response.answer, found, do)
    if found[0].rdtype == dns.rdatatype.NS:
        _add_ns_addresses(response, zone, found[0], do)
    return True


def answer(response, zone, qname, qtype, do, co=False) -> None:
    denial = zone.denial
    if denial.compact and co:
        response.ednsflags |= dns.flags.CO           # RFC 9824 §5.1
    cut = zone.find_cut(qname, qtype)
    if cut is not None:
        _referral(response, zone, cut, do)
        return

    if zone.name_exists(qname):
        if not _positive(response, zone, qname, qtype, qname, do):
            _negative(response, zone, denial.nodata(zone, qname), do, dns.rcode.NOERROR)
        return

    ce = zone.closest_encloser(qname)
    wildcard = dns.name.Name((b"*",) + ce.labels)
    if zone.has_node(wildcard):
        if _positive(response, zone, wildcard, qtype, qname, do, exact=denial.wildcard_exact):
            _add_denial(response, zone, denial.wildcard_answer(zone, qname, ce), do)
        else:
            items = denial.wildcard_nodata(zone, qname, wildcard)
            _negative(response, zone, items, do, dns.rcode.NOERROR)
        return

    _negative(response, zone, denial.nxdomain(zone, qname, ce), do, denial.nxdomain_rcode(do, co))
