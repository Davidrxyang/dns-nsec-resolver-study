"""Zone loading, key management, and signing.

One SignedZone per variant zone. Keys persist under zones/keys/ so the trust
anchor stays stable across restarts.
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

ALGORITHM = dns.dnssec.Algorithm.ECDSAP256SHA256  # 13
DNSKEY_FLAGS = 257  # ZONE | SEP: single key acting as KSK and ZSK
DNSKEY_TTL = 3600
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
    def __init__(self, zone_file: Path, key_dir: Path):
        self.zone = dns.zone.from_file(str(zone_file), relativize=False)
        self.origin = self.zone.origin
        name = self.origin.to_text(omit_final_dot=True)
        self.key = load_or_create_key(key_dir / f"{name}.pem")
        self.dnskey = dns.dnssec.make_dnskey(self.key.public_key(), ALGORITHM, DNSKEY_FLAGS)
        self.key_tag = dns.dnssec.key_id(self.dnskey)

        apex = self.zone.find_node(self.origin)
        apex.replace_rdataset(
            dns.rdataset.from_rdata(DNSKEY_TTL, self.dnskey)
        )

        # (owner, rdtype) -> RRset of RRSIGs covering that RRset
        self.rrsigs: dict[tuple[dns.name.Name, int], dns.rrset.RRset] = {}
        self.sign_all()

    def sign_all(self) -> None:
        now = int(time.time())
        inception = now - INCEPTION_SKEW
        expiration = now + SIG_LIFETIME
        for owner, node in self.zone.nodes.items():
            for rds in node.rdatasets:
                if rds.rdtype == dns.rdatatype.RRSIG:
                    continue
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
                sigset = dns.rrset.from_rdata(owner, rds.ttl, sig)
                self.rrsigs[(owner, rds.rdtype)] = sigset

    def get(self, name: dns.name.Name, rdtype: int):
        """Return (rrset, rrsig_rrset) for an existing RRset, else None."""
        rds = self.zone.get_rdataset(name, rdtype)
        if rds is None:
            return None
        rrset = dns.rrset.RRset(name, dns.rdataclass.IN, rdtype)
        rrset.update(rds)
        return rrset, self.rrsigs[(name, rdtype)]

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
