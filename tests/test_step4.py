"""Step 4: online-signed variants, over one live server with all four zones.

  minnsec.test     minimally covering NSEC   (RFC 4470)
  minnsec3.test    NSEC3 white lies          (RFC 7129 App. B)
  cdoe-nsec.test   compact denial, NSEC      (RFC 9824 §3)
  cdoe-nsec3.test  compact denial, NSEC3     (RFC 9824 §4)

Proofs are checked independently of the responder: NSEC3 hashes with the
hashlib implementation in tests/golden.py, spans with canonical ordering.
Decision IDs (Dn) refer to docs/VARIANTS.md.

Run: venv/bin/python -m unittest discover -s tests -t .
"""

import tempfile
import unittest
from pathlib import Path

import dns.dnssec
import dns.edns
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

from responder.denial import (CompactNsec3Denial, CompactNsecDenial, MinimalNsecDenial,
                              Nsec3WhiteLiesDenial)
from responder.server import Responder, start
from responder.zone import SignedZone
from tests import golden

REPO = Path(__file__).resolve().parent.parent
N = dns.name.from_text
H = golden.nsec3_hash
NSEC, NSEC3, RRSIG = dns.rdatatype.NSEC, dns.rdatatype.NSEC3, dns.rdatatype.RRSIG
ZONES = {
    "minnsec.test.": MinimalNsecDenial,
    "minnsec3.test.": Nsec3WhiteLiesDenial,
    "cdoe-nsec.test.": CompactNsecDenial,
    "cdoe-nsec3.test.": CompactNsec3Denial,
}


def types(rd):
    return {dns.rdatatype.to_text(t) for t in golden.nsec_types(rd)}


def child(name, label=b"\x00"):
    return dns.name.Name((label,) + N(name).labels)


def append0(name):
    n = N(name)
    return dns.name.Name((n.labels[0] + b"\x00",) + n.labels[1:])


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.zones = {o: SignedZone(REPO / "zones" / f"{o}zone", Path(cls.tmp.name), d())
                     for o, d in ZONES.items()}
        cls.udp, cls.tcp = start(Responder(list(cls.zones.values())), "127.0.0.1", 0)
        cls.port = cls.udp.server_address[1]

    @classmethod
    def tearDownClass(cls):
        for srv in (cls.udp, cls.tcp):
            srv.shutdown()
            srv.server_close()
        cls.tmp.cleanup()

    def ask(self, qname, qtype, do=True, co=False):
        q = dns.message.make_query(qname, qtype, want_dnssec=do, use_edns=0)
        q.flags &= ~dns.flags.RD
        if co:
            q.ednsflags |= dns.flags.CO
        return dns.query.udp(q, "127.0.0.1", port=self.port, timeout=2)

    def assert_signed(self, r, origin):
        keys = {N(origin): self.zones[origin].zone.get_rdataset(N(origin), dns.rdatatype.DNSKEY)}
        for section in (r.answer, r.authority):
            sigs = {(x.name, x.covers): x for x in section if x.rdtype == RRSIG}
            for rrset in section:
                if rrset.rdtype != RRSIG:
                    dns.dnssec.validate(rrset, sigs[(rrset.name, rrset.rdtype)], keys)

    def denial(self, r, rdtype):
        return [(x.name, x[0]) for x in r.authority if x.rdtype == rdtype]

    def spans3(self, r):
        recs = [(x.name, x.ttl, rd) for x in r.authority if x.rdtype == NSEC3 for rd in x]
        return golden.nsec3_spans(recs)


class MinimalNsec(Base):
    Z = "minnsec.test."

    def test_nxdomain_two_minimal_covers(self):
        r = self.ask("nope." + self.Z, "A")
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)
        self.assert_signed(r, self.Z)
        (o1, n1), (o2, n2) = self.denial(r, NSEC)
        q, w = N("nope." + self.Z), N("*." + self.Z)
        self.assertTrue(o1 < q < n1.next and n1.next == append0("nope." + self.Z))   # D14
        self.assertTrue(o2 < w < n2.next and n2.next == append0("*." + self.Z))
        self.assertEqual(types(n1), {"RRSIG", "NSEC"})                             # RFC 4470 §3
        self.assertFalse(n1.next.is_subdomain(q))                                  # erratum 6734

    def test_nxdomain_deep_name_covers_next_closer(self):
        r = self.ask("foo.bar.ent." + self.Z, "A")                                 # D15
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)
        (o1, n1), (o2, n2) = self.denial(r, NSEC)
        nc = N("bar.ent." + self.Z)
        self.assertTrue(o1 < nc < n1.next and n1.next == append0("bar.ent." + self.Z))
        self.assertTrue(o2 < N("*.ent." + self.Z) < n2.next)

    def test_nodata_existing_name_minimal_next(self):
        r = self.ask("www." + self.Z, "AAAA")
        (o, n), = self.denial(r, NSEC)
        self.assertEqual((o, n.next), (N("www." + self.Z), child("www." + self.Z)))
        self.assertEqual(types(n), {"A", "TXT", "RRSIG", "NSEC"})

    def test_ent_covered_with_child_next(self):
        r = self.ask("ent." + self.Z, "A")                                         # D4
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        (o, n), = self.denial(r, NSEC)
        self.assertTrue(o < N("ent." + self.Z) < n.next)
        self.assertEqual(n.next, child("ent." + self.Z))

    def test_delegation_nsec_next_is_subtree_successor(self):
        r = self.ask("foo.insecure." + self.Z, "A")                                # D5
        (o, n), = self.denial(r, NSEC)
        self.assertEqual((o, n.next), (N("insecure." + self.Z), append0("insecure." + self.Z)))
        self.assertEqual(types(n), {"NS", "RRSIG", "NSEC"})

    def test_wildcard_answer_and_nodata(self):
        r = self.ask("deep.er.wild." + self.Z, "A")
        self.assertEqual(r.answer[1][0].labels, 3)          # expanded from *.wild, as RFC 4470 allows
        (o, n), = self.denial(r, NSEC)
        self.assertTrue(o < N("er.wild." + self.Z) < n.next)
        r = self.ask("a.b.wild." + self.Z, "TXT")
        owners = [o for o, _ in self.denial(r, NSEC)]
        self.assertIn(N("*.wild." + self.Z), owners)

    def test_qtype_nsec_returns_online_record(self):
        r = self.ask("www." + self.Z, "NSEC")                                      # D12
        self.assertEqual(r.answer[0].rdtype, NSEC)
        self.assert_signed(r, self.Z)

    def test_cover_next_child_knob(self):
        z = SignedZone(REPO / "zones" / "minnsec.test.zone", Path(self.tmp.name),
                       MinimalNsecDenial(cover_next="child"))
        rrset = z.denial.cover(z, N("nope." + self.Z))
        self.assertEqual(rrset[0].next, child("nope." + self.Z))                   # RFC 4470 §4 literal


class WhiteLies(Base):
    Z = "minnsec3.test."

    @staticmethod
    def width(owner_hash, next_hash):
        """Span of an NSEC3 record in hash space (next - owner, mod 2^160)."""
        num = lambda h: int.from_bytes(golden.base64.b32hexdecode(h), "big")
        return (num(next_hash) - num(owner_hash)) % (1 << 160)

    def test_nxdomain_three_white_lies(self):
        r = self.ask("c." + self.Z, "A")
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)
        self.assert_signed(r, self.Z)
        spans = {o: (n, rd) for o, n, rd in self.spans3(r)}
        apex = H(self.Z)
        self.assertEqual(self.width(apex, spans[apex][0]), 1)                      # match: hash -> hash+1
        self.assertEqual(types(spans[apex][1]), {"NS", "SOA", "RRSIG", "DNSKEY", "NSEC3PARAM"})
        for name in ("c." + self.Z, "*." + self.Z):                               # covers: h-1 -> h+1
            h = H(name)
            cover = [(o, n, rd) for o, (n, rd) in spans.items() if golden.hash_covers(o, n, h)]
            self.assertEqual(len(cover), 1)
            o, n, rd = cover[0]
            self.assertEqual(self.width(o, n), 2)
            self.assertEqual(types(rd), set())

    def test_nodata_and_ent_matches(self):
        r = self.ask("www." + self.Z, "AAAA")
        (o, n, rd), = self.spans3(r)
        self.assertEqual((o, self.width(o, n)), (H("www." + self.Z), 1))
        self.assertEqual(types(rd), {"A", "TXT", "RRSIG"})
        r = self.ask("ent." + self.Z, "A")
        (o, n, rd), = self.spans3(r)
        self.assertEqual((o, types(rd)), (H("ent." + self.Z), set()))

    def test_flags_never_opt_out(self):
        r = self.ask("c." + self.Z, "A")
        self.assertTrue(all(rd.flags == 0 for _, _, rd in self.spans3(r)))         # D10


class CompactNsec(Base):
    Z = "cdoe-nsec.test."

    def test_nonexistent_is_noerror_with_nxname(self):
        r = self.ask("nope." + self.Z, "A")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assert_signed(r, self.Z)
        (o, n), = self.denial(r, NSEC)
        self.assertEqual((o, n.next), (N("nope." + self.Z), child("nope." + self.Z)))
        self.assertEqual(types(n), {"RRSIG", "NSEC", "NXNAME"})                    # §3.1 MUST
        self.assertFalse(r.ednsflags & dns.flags.CO)

    def test_co_restores_nxdomain(self):
        r = self.ask("nope." + self.Z, "A", co=True)                               # §5.1
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)
        self.assertTrue(r.ednsflags & dns.flags.CO)
        self.assertEqual(types(self.denial(r, NSEC)[0][1]), {"RRSIG", "NSEC", "NXNAME"})

    def test_no_do_gets_nxdomain(self):
        r = self.ask("nope." + self.Z, "A", do=False)                              # D11
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)
        self.assertEqual([x.rdtype for x in r.authority], [dns.rdatatype.SOA])

    def test_ent_and_nodata_have_no_nxname(self):
        r = self.ask("ent." + self.Z, "A")
        self.assertEqual(types(self.denial(r, NSEC)[0][1]), {"RRSIG", "NSEC"})     # §3.2
        r = self.ask("www." + self.Z, "AAAA")
        self.assertEqual(types(self.denial(r, NSEC)[0][1]), {"A", "TXT", "RRSIG", "NSEC"})

    def test_wildcard_answer_signed_as_exact_match(self):
        r = self.ask("deep.er.wild." + self.Z, "A")
        sig = r.find_rrset(r.answer, N("deep.er.wild." + self.Z), 1, RRSIG, dns.rdatatype.A)
        self.assertEqual(sig[0].labels, 5)                                         # §3.3
        self.assertEqual(self.denial(r, NSEC), [])
        self.assert_signed(r, self.Z)

    def test_wildcard_nodata(self):
        r = self.ask("x.wild." + self.Z, "TXT")
        (o, n), = self.denial(r, NSEC)
        self.assertEqual(o, N("x.wild." + self.Z))
        self.assertEqual(types(n), {"A", "RRSIG", "NSEC"})                         # wildcard's types

    def test_unsigned_delegation_and_ds(self):
        for q, t in (("foo.insecure." + self.Z, "A"), ("insecure." + self.Z, "DS")):
            r = self.ask(q, t)
            (o, n), = self.denial(r, NSEC)
            self.assertEqual(n.next, append0("insecure." + self.Z))                # §3.4
            self.assertEqual(types(n), {"NS", "RRSIG", "NSEC"})

    def test_nxname_query_is_formerr_with_ede30(self):
        r = self.ask("nope." + self.Z, "TYPE128")                                  # §3.5
        self.assertEqual(r.rcode(), dns.rcode.FORMERR)
        self.assertIn(dns.edns.EDECode.INVALID_QUERY_TYPE,
                      [o.code for o in r.options if o.otype == dns.edns.OptionType.EDE])

    def test_matches_cloudflare_fixture_shape(self):
        fixture = golden.parse_dig((golden.GOLDEN / "cloudflare-cdoe-nsec.txt").read_text())
        want = golden.compact_nsec_shape(fixture, "nosuchname-12345.cloudflare.com.")
        got = golden.compact_nsec_shape(golden.from_message(self.ask("nope." + self.Z, "A")),
                                        "nope." + self.Z)
        self.assertEqual(got, want)


class CompactNsec3(Base):
    Z = "cdoe-nsec3.test."

    def test_nonexistent_single_matching_nsec3_nxname_only(self):
        r = self.ask("nope." + self.Z, "A")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assert_signed(r, self.Z)
        (o, n, rd), = self.spans3(r)
        self.assertEqual(o, H("nope." + self.Z))
        self.assertEqual(WhiteLies.width(o, n), 1)                                 # §4: hash+1
        self.assertEqual(types(rd), {"NXNAME"})
        self.assertEqual((rd.flags, rd.iterations, rd.salt), (0, 0, b""))

    def test_ent_empty_bitmap_and_delegation(self):
        r = self.ask("ent." + self.Z, "A")
        self.assertEqual(types(self.spans3(r)[0][2]), set())
        r = self.ask("foo.insecure." + self.Z, "A")
        (o, _, rd), = self.spans3(r)
        self.assertEqual((o, types(rd)), (H("insecure." + self.Z), {"NS"}))

    def test_co_and_wildcard(self):
        r = self.ask("nope." + self.Z, "A", co=True)
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)
        r = self.ask("x.wild." + self.Z, "A")
        sig = r.find_rrset(r.answer, N("x.wild." + self.Z), 1, RRSIG, dns.rdatatype.A)
        self.assertEqual(sig[0].labels, 4)

    def test_nsec3param_published(self):
        r = self.ask(self.Z, "NSEC3PARAM")                                         # D9
        self.assertEqual(r.answer[0][0].to_text(), "1 0 0 -")


if __name__ == "__main__":
    unittest.main()
