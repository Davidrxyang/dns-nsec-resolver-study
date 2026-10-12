"""Step 2: vanilla NSEC denial, over a live server using zones/nsec.test.zone.

Run: venv/bin/python -m unittest discover -s tests -t .
"""

import tempfile
import unittest
from pathlib import Path

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

from responder.server import Responder, start
from responder.zone import SignedZone
from tests import golden

REPO = Path(__file__).resolve().parent.parent
N = dns.name.from_text
NSEC = dns.rdatatype.NSEC
ORIGIN = N("nsec.test.")


class Step2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.zone = SignedZone(REPO / "zones" / "nsec.test.zone", Path(cls.tmp.name))
        cls.udp, cls.tcp = start(Responder([cls.zone]), "127.0.0.1", 0)
        cls.port = cls.udp.server_address[1]
        cls.keys = {ORIGIN: cls.zone.zone.get_rdataset(ORIGIN, dns.rdatatype.DNSKEY)}

    @classmethod
    def tearDownClass(cls):
        for srv in (cls.udp, cls.tcp):
            srv.shutdown()
            srv.server_close()
        cls.tmp.cleanup()

    def ask(self, qname, qtype, do=True):
        q = dns.message.make_query(qname, qtype, want_dnssec=do, use_edns=0)
        q.flags &= ~dns.flags.RD
        return dns.query.udp(q, "127.0.0.1", port=self.port, timeout=2)

    def assert_signed(self, section):
        """Every non-RRSIG RRset in the section validates with its RRSIG."""
        sigs = {(r.name, r.covers): r for r in section if r.rdtype == dns.rdatatype.RRSIG}
        for rrset in section:
            if rrset.rdtype != dns.rdatatype.RRSIG:
                dns.dnssec.validate(rrset, sigs[(rrset.name, rrset.rdtype)], self.keys)

    def nsecs(self, r):
        return [(rr.name, rr[0]) for rr in r.authority if rr.rdtype == NSEC]

    # --- the chain itself ---------------------------------------------

    def test_chain_order_wrap_and_ttl(self):
        owners = self.zone.denial.owners
        self.assertEqual(owners, [N(x) for x in (
            "nsec.test.", "host.ent.nsec.test.", "insecure.nsec.test.", "ns1.nsec.test.",
            "secure.nsec.test.", "*.wild.nsec.test.", "www.nsec.test.")])
        for i, owner in enumerate(owners):
            rds = self.zone.zone.get_rdataset(owner, NSEC)
            self.assertEqual(rds[0].next, owners[(i + 1) % len(owners)])
            self.assertEqual(rds.ttl, 60)  # min(SOA TTL 300, SOA MINIMUM 60)

    def test_bitmaps(self):
        def types(name):
            rd = self.zone.zone.get_rdataset(N(name), NSEC)[0]
            return {dns.rdatatype.to_text(t) for t in golden.nsec_types(rd)}
        self.assertEqual(types("nsec.test."), {"NS", "SOA", "DNSKEY", "NSEC", "RRSIG"})
        self.assertEqual(types("www.nsec.test."), {"A", "TXT", "NSEC", "RRSIG"})
        self.assertEqual(types("secure.nsec.test."), {"NS", "DS", "NSEC", "RRSIG"})
        self.assertEqual(types("insecure.nsec.test."), {"NS", "NSEC", "RRSIG"})

    def test_glue_and_delegation_ns_unsigned(self):
        for name, t in [("secure.nsec.test.", "NS"), ("ns.secure.nsec.test.", "A"),
                        ("insecure.nsec.test.", "NS"), ("ns.insecure.nsec.test.", "A")]:
            self.assertNotIn((N(name), dns.rdatatype.from_text(t)), self.zone.rrsigs)
        self.assertIsNone(self.zone.zone.get_rdataset(N("ns.secure.nsec.test."), NSEC))

    # --- responses ----------------------------------------------------

    def test_nxdomain(self):
        r = self.ask("nope.nsec.test.", "A")
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)
        self.assertTrue(r.flags & dns.flags.AA)
        self.assert_signed(r.authority)
        (o1, n1), (o2, n2) = self.nsecs(r)
        self.assertTrue(golden.covers(o1, n1.next, N("nope.nsec.test.")))
        self.assertTrue(golden.covers(o2, n2.next, N("*.nsec.test.")))

    def test_nxdomain_wraparound(self):
        r = self.ask("zzz.nsec.test.", "A")
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)
        self.assertEqual([o for o, _ in self.nsecs(r)], [N("www.nsec.test."), ORIGIN])

    def test_nxdomain_without_do_is_soa_only(self):
        r = self.ask("nope.nsec.test.", "A", do=False)
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)
        self.assertEqual([rr.rdtype for rr in r.authority], [dns.rdatatype.SOA])
        self.assertEqual(r.authority[0].ttl, 60)

    def test_nodata(self):
        r = self.ask("www.nsec.test.", "AAAA")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(r.answer), 0)
        self.assert_signed(r.authority)
        self.assertEqual([o for o, _ in self.nsecs(r)], [N("www.nsec.test.")])

    def test_empty_non_terminal(self):
        r = self.ask("ent.nsec.test.", "A")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        (owner, rd), = self.nsecs(r)
        self.assertTrue(golden.covers(owner, rd.next, N("ent.nsec.test.")))
        self.assertTrue(rd.next.is_subdomain(N("ent.nsec.test.")))

    def test_wildcard_answer(self):
        r = self.ask("x.wild.nsec.test.", "A")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        a = r.find_rrset(r.answer, N("x.wild.nsec.test."), 1, dns.rdatatype.A)
        sig = r.find_rrset(r.answer, a.name, 1, dns.rdatatype.RRSIG, dns.rdatatype.A)
        self.assertEqual(sig[0].labels, 3)  # of *.wild.nsec.test., marks expansion
        dns.dnssec.validate(a, sig, self.keys)
        (owner, rd), = self.nsecs(r)
        self.assertTrue(golden.covers(owner, rd.next, N("x.wild.nsec.test.")))

    def test_wildcard_nodata(self):
        r = self.ask("a.b.wild.nsec.test.", "TXT")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(r.answer), 0)
        # One NSEC both covers the qname and matches the wildcard (no TXT).
        self.assertEqual([o for o, _ in self.nsecs(r)], [N("*.wild.nsec.test.")])

    def test_referral_signed(self):
        r = self.ask("foo.secure.nsec.test.", "A")
        self.assertFalse(r.flags & dns.flags.AA)
        self.assertEqual([(rr.rdtype, rr.covers) for rr in r.authority], [
            (dns.rdatatype.NS, 0), (dns.rdatatype.DS, 0),
            (dns.rdatatype.RRSIG, dns.rdatatype.DS)])
        self.assert_signed(r.authority[1:])
        self.assertEqual(r.additional[0].name, N("ns.secure.nsec.test."))

    def test_referral_insecure(self):
        r = self.ask("insecure.nsec.test.", "A")
        self.assertFalse(r.flags & dns.flags.AA)
        self.assertEqual([o for o, _ in self.nsecs(r)], [N("insecure.nsec.test.")])
        self.assert_signed(r.authority[1:])

    def test_ds_at_delegation_answered_by_parent(self):
        r = self.ask("secure.nsec.test.", "DS")
        self.assertTrue(r.flags & dns.flags.AA)
        self.assert_signed(r.answer)
        r = self.ask("insecure.nsec.test.", "DS")
        self.assertTrue(r.flags & dns.flags.AA)
        self.assertEqual(len(r.answer), 0)
        self.assertEqual([o for o, _ in self.nsecs(r)], [N("insecure.nsec.test.")])

    def test_nsec_query(self):
        r = self.ask("nsec.test.", "NSEC")
        self.assertEqual(r.answer[0].rdtype, NSEC)
        self.assert_signed(r.answer)

    def test_any_notimp_without_aa(self):
        r = self.ask("nsec.test.", "ANY")
        self.assertEqual(r.rcode(), dns.rcode.NOTIMP)
        self.assertFalse(r.flags & dns.flags.AA)

    def test_rrsig_query(self):
        r = self.ask("www.nsec.test.", "RRSIG")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertEqual({rr.covers for rr in r.answer},
                         {dns.rdatatype.A, dns.rdatatype.TXT, NSEC})

    # --- golden fixture -----------------------------------------------

    def test_nxdomain_matches_root_fixture_shape(self):
        fixture = golden.parse_dig((golden.GOLDEN / "root-nsec-nxdomain.txt").read_text())
        want = golden.nxdomain_shape(fixture, "nosuchtld-12345.")
        # Pick a qname that, like the root case, falls after a signed delegation.
        r = self.ask("sz-nosuch.nsec.test.", "A")
        got = golden.nxdomain_shape(golden.from_message(r), "sz-nosuch.nsec.test.")
        self.assertEqual(got, want)


if __name__ == "__main__":
    unittest.main()
