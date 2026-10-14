"""Zone loading, key management, and signing.

One SignedZone per variant zone. Keys persist under zones/keys/ so the trust
anchor stays stable across restarts. The zone's denial object adds its
denial records (e.g. the NSEC chain) before everything is signed.
"""

import time
from pathlib import Path

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
import dns.zone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .denial import NsecDenial

ALGORITHM = dns.dnssec.Algorithm.ECDSAP256SHA256  # 13
DNSKEY_FLAGS = 257  # ZONE | SEP: single key acting as KSK and ZSK
# Inception in the past and expiration far ahead so clock skew cannot interfere.
INCEPTION_SKEW = 3600
SIG_LIFETIME = 30 * 86400


def load_or_create_key(path: Path) -> ec.EllipticCurvePrivateKey:
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return key


class SignedZone:
    def __init__(self, zone_file: Path, key_dir: Path, denial=None):
        self.zone = dns.zone.from_file(str(zone_file), relativize=False)
        self.origin = self.zone.origin
        name = self.origin.to_text(omit_final_dot=True)
        self.key = load_or_create_key(key_dir / f"{name}.pem")
        self.dnskey = dns.dnssec.make_dnskey(self.key.public_key(), ALGORITHM, DNSKEY_FLAGS)
        self.key_tag = dns.dnssec.key_id(self.dnskey)

        apex = self.zone.find_node(self.origin)
        soa = apex.get_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        # DNSKEY at the zone's TTL, as dnssec-signzone does for a key without one.
        apex.replace_rdataset(dns.rdataset.from_rdata(soa.ttl, self.dnskey))

        # RFC 2308 / RFC 9077: negative TTL = min(SOA TTL, SOA MINIMUM).
        self.neg_ttl = min(soa.ttl, soa[0].minimum)

        # Delegation points: non-apex names holding NS. Names below them are
        # occluded (glue): not authoritative, never signed, no NSEC.
        self.cuts = {
            n for n, node in self.zone.nodes.items()
            if n != self.origin and node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NS)
        }

        # Signed records that live outside the zone's name tree, e.g. NSEC3 at
        # hashed owner names: queries for those names must behave as if the
        # names did not exist (RFC 5155 §7.2.8). (owner, rdtype) -> rdataset
        self.extra: dict[tuple[dns.name.Name, int], dns.rdataset.Rdataset] = {}

        self.denial = denial if denial is not None else NsecDenial()
        self.denial.prepare(self)

        # (owner, rdtype) -> RRset of RRSIGs covering that RRset
        self.rrsigs: dict[tuple[dns.name.Name, int], dns.rrset.RRset] = {}
        self.sign_all()

    # --- zone structure -------------------------------------------------

    def is_occluded(self, name) -> bool:
        return any(name != c and name.is_subdomain(c) for c in self.cuts)

    def is_authoritative(self, name, rdtype) -> bool:
        """RFC 4035 §2.2: delegation NS and glue are not signed."""
        if self.is_occluded(name):
            return False
        if name in self.cuts:
            return rdtype in (dns.rdatatype.DS, dns.rdatatype.NSEC)
        return True

    def authoritative_names(self):
        """Owner names that get denial records: authoritative names and cuts."""
        return [
            n for n, node in self.zone.nodes.items()
            if node.rdatasets and not self.is_occluded(n)
        ]

    def find_cut(self, qname, qtype):
        """Delegation point at or above qname, if the query must be referred.

        A DS query for the cut itself is answered by the parent (us).
        """
        for cut in sorted(self.cuts, key=len):
            if qname.is_subdomain(cut) and not (qname == cut and qtype == dns.rdatatype.DS):
                return cut
        return None

    def has_node(self, name) -> bool:
        node = self.zone.get_node(name)
        return node is not None and bool(node.rdatasets)

    def name_exists(self, name) -> bool:
        """True if name has data or is an empty non-terminal."""
        if self.has_node(name):
            return True
        return any(n != name and n.is_subdomain(name) for n in self.zone.nodes)

    def closest_encloser(self, qname):
        name = qname.parent()
        while not self.name_exists(name):
            name = name.parent()
        return name

    # --- signing and retrieval -----------------------------------------

    def sign_all(self) -> None:
        now = int(time.time())
        inception = now - INCEPTION_SKEW
        expiration = now + SIG_LIFETIME
        # Online-signed records reuse this window (docs/VARIANTS.md D3).
        self.sig_window = (inception, expiration)
        self._online_sigs = {}
        rrsets = [(owner, rds) for owner, node in self.zone.nodes.items() for rds in node.rdatasets
                  if rds.rdtype != dns.rdatatype.RRSIG and self.is_authoritative(owner, rds.rdtype)]
        rrsets += [(owner, rds) for (owner, _), rds in self.extra.items()]
        for owner, rds in rrsets:
            rrset = dns.rrset.RRset(owner, rds.rdclass, rds.rdtype)
            rrset.update(rds)
            sig = dns.dnssec.sign(
                rrset,
                self.key,
                self.origin,
                self.dnskey,
                inception=inception,
                expiration=expiration,
            )
            self.rrsigs[(owner, rds.rdtype)] = dns.rrset.from_rdata(owner, rds.ttl, sig)

    def sign_online(self, rrset):
        """Sign a record built per response (online signing variants).

        ECDSA signing here is deterministic (RFC 6979) and the window is fixed,
        so identical records get identical signatures and are cached.
        """
        key = (rrset.name.canonicalize(), rrset.rdtype, rrset.ttl,
               tuple(sorted(rd.to_digestable(self.origin) for rd in rrset)))
        sig = self._online_sigs.get(key)
        if sig is None:
            inception, expiration = self.sig_window
            rd = dns.dnssec.sign(rrset, self.key, self.origin, self.dnskey,
                                 inception=inception, expiration=expiration)
            sig = dns.rrset.from_rdata(rrset.name, rrset.ttl, rd)
            if len(self._online_sigs) < 100_000:
                self._online_sigs[key] = sig
        return sig

    def get(self, name, rdtype, owner=None, ttl=None):
        """Return (rrset, rrsig_rrset or None) for an existing RRset, else None.

        owner renames the result (wildcard expansion, or echoing the query's
        case); ttl lowers the served TTL (negative-response SOA). Signatures
        stay valid either way: validators canonicalize names and cap TTLs at
        the RRSIG's original TTL.
        """
        rds = self.extra.get((name, rdtype)) or self.zone.get_rdataset(name, rdtype)
        if rds is None:
            return None
        owner = owner if owner is not None else name
        rrset = dns.rrset.RRset(owner, dns.rdataclass.IN, rdtype)
        rrset.update(rds)
        sig = self.rrsigs.get((name, rdtype))
        if sig is not None:
            sig_copy = dns.rrset.RRset(owner, dns.rdataclass.IN, dns.rdatatype.RRSIG, rdtype)
            sig_copy.update(sig)
            sig = sig_copy
        if ttl is not None:
            rrset.ttl = min(rrset.ttl, ttl)
            if sig is not None:
                sig.ttl = min(sig.ttl, ttl)
        return rrset, sig

    def sigs_at(self, name, owner=None):
        """All RRSIGs at a name (for qtype RRSIG), one RRset per covered type.

        dnspython keeps RRSIGs with different covered types in separate
        RRsets; on the wire they are simply consecutive records.
        """
        owner = owner if owner is not None else name
        out = []
        for (n, covered), sig in self.rrsigs.items():
            if n == name:
                rrset = dns.rrset.RRset(owner, dns.rdataclass.IN, dns.rdatatype.RRSIG, covered)
                rrset.update(sig)
                out.append(rrset)
        return out

    def anchor_text(self) -> str:
        """Trust anchor in named.conf syntax, as read by `delv -a`."""
        _, _, _, key_b64 = self.dnskey.to_text().split(" ", 3)
        return (
            "trust-anchors {\n"
            f'    {self.origin.to_text()} static-key {self.dnskey.flags} '
            f'{self.dnskey.protocol} {self.dnskey.algorithm} "{key_b64.replace(" ", "")}";\n'
            "};\n"
        )

    def ds_text(self) -> str:
        ds = dns.dnssec.make_ds(self.origin, self.dnskey, "SHA256")
        return f"{self.origin} IN DS {ds}"
