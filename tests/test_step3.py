"""Step 3: vanilla NSEC3 denial, over a live server using zones/nsec3.test.zone.

Proofs are checked with an independent NSEC3 hash (tests/golden.nsec3_hash,
hashlib-based) rather than the responder's dnspython-based one.

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

from responder.denial import Nsec3Denial
from responder.server import Responder, start
from responder.zone import SignedZone
from tests import golden

REPO = Path(__file__).resolve().parent.parent
ZONE_FILE = REPO / "zones" / "nsec3.test.zone"
N = dns.name.from_text
NSEC3 = dns.rdatatype.NSEC3
ORIGIN = N("nsec3.test.")
H = golden.nsec3_hash


def types(rd):
    return {dns.rdatatype.to_text(t) for t in golden.nsec_types(rd)}


class Step3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.zone = SignedZone(ZONE_FILE, Path(cls.tmp.name), Nsec3Denial())
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

    def spans(self, r):
        """{owner_hash: (next_hash, rdata)} for the NSEC3 records in authority."""
        recs = [(rr.name, rr.ttl, rd) for rr in r.authority if rr.rdtype == NSEC3 for rd in rr]
        return {o: (n, rd) for o, n, rd in golden.nsec3_spans(recs)}

    def assert_signed(self, section):
        sigs = {(r.name, r.covers): r for r in section if r.rdtype == dns.rdatatype.RRSIG}
        for rrset in section:
            if rrset.rdtype != dns.rdatatype.RRSIG:
                dns.dnssec.validate(rrset, sigs[(rrset.name, rrset.rdtype)], self.keys)

    def assert_matches(self, spans, name):
        self.assertIn(H(name), spans, f"no NSEC3 matching {name}")
        return spans[H(name)][1]

    def assert_covered(self, spans, name):
        h = H(name)
        self.assertTrue(any(golden.hash_covers(o, n, h) for o, (n, _) in spans.items()),
                        f"no NSEC3 covering {name}")

    # --- hashing against real data -----------------------------------------

    def test_hash_reproduces_com_fixture(self):
        self.assertEqual(H("com."), "CK0POJMG874LJREF7EFN8430QVIT8BSM")
        self.assertEqual(dns.dnssec.nsec3_hash("com.", None, 0, 1), H("com."))

    # --- the chain itself --------------------------------------------------

    def test_chain_names_order_wrap_ttl_params(self):
        names = ["nsec3.test.", "ns1.nsec3.test.", "www.nsec3.test.", "host.ent.nsec3.test.",
                 "ent.nsec3.test.", "wild.nsec3.test.", "*.wild.nsec3.test.",
                 "secure.nsec3.test.", "insecure.nsec3.test."]   # incl. the two ENTs
        recs = [(o, rds.ttl, rds[0]) for (o, t), rds in self.zone.extra.items() if t == NSEC3]
        spans = golden.nsec3_spans(recs)
        self.assertEqual(sorted(o for o, _, _ in spans), sorted(H(n) for n in names))
        order = sorted(spans)
        for i, (o, n, rd) in enumerate(order):
            self.assertEqual(n, order[(i + 1) % len(order)][0])
            self.assertEqual((rd.algorithm, rd.flags, rd.iterations, rd.salt), (1, 0, 0, b""))
        self.assertTrue(all(ttl == 60 for _, ttl, _ in recs))
        param = self.zone.zone.get_rdataset(ORIGIN, dns.rdatatype.NSEC3PARAM)
        self.assertEqual(param[0].to_text(), "1 0 0 -")

    def test_bitmaps(self):
        def bm(name):
            return types(self.zone.extra[(N(H(name), ORIGIN), NSEC3)][0])
        self.assertEqual(bm("nsec3.test."), {"NS", "SOA", "RRSIG", "DNSKEY", "NSEC3PARAM"})
        self.assertEqual(bm("www.nsec3.test."), {"A", "TXT", "RRSIG"})
        self.assertEqual(bm("ent.nsec3.test."), set())           # ENT: empty (§7.1, §8.5)
        self.assertEqual(bm("wild.nsec3.test."), set())
        self.assertEqual(bm("secure.nsec3.test."), {"NS", "DS", "RRSIG"})
        self.assertEqual(bm("insecure.nsec3.test."), {"NS"})     # nothing signed there

    def test_hashed_owner_name_does_not_exist(self):
        r = self.ask(f"{H('nsec3.test.')}.nsec3.test.", "NSEC3")   # §7.2.8
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)

    def test_collision_raises(self):
        with self.assertRaises(RuntimeError):                      # §7.2.9 -> SERVFAIL
            self.zone.denial.covering(N("www.nsec3.test."))

    # --- responses -----------------------------------------------------------

    def test_nxdomain_at_apex(self):
        r = self.ask("nope.nsec3.test.", "A")
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)
        self.assert_signed(r.authority)
        s = self.spans(r)
        self.assert_matches(s, "nsec3.test.")
        self.assert_covered(s, "nope.nsec3.test.")
        self.assert_covered(s, "*.nsec3.test.")

    def test_nxdomain_below_ent(self):
        r = self.ask("foo.bar.ent.nsec3.test.", "A")
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)
        s = self.spans(r)
        self.assert_matches(s, "ent.nsec3.test.")       # closest encloser is the ENT
        self.assert_covered(s, "bar.ent.nsec3.test.")   # next closer
        self.assert_covered(s, "*.ent.nsec3.test.")

    def test_nodata(self):
        r = self.ask("www.nsec3.test.", "AAAA")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(r.answer), 0)
        self.assert_signed(r.authority)
        s = self.spans(r)
        self.assertEqual(len(s), 1)
        self.assertFalse({"AAAA", "CNAME"} & types(self.assert_matches(s, "www.nsec3.test.")))

    def test_empty_non_terminal(self):
        r = self.ask("ent.nsec3.test.", "A")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertEqual(types(self.assert_matches(self.spans(r), "ent.nsec3.test.")), set())

    def test_wildcard_answer(self):
        r = self.ask("x.wild.nsec3.test.", "A")
        a = r.find_rrset(r.answer, N("x.wild.nsec3.test."), 1, dns.rdatatype.A)
        sig = r.find_rrset(r.answer, a.name, 1, dns.rdatatype.RRSIG, dns.rdatatype.A)
        self.assertEqual(sig[0].labels, 3)
        dns.dnssec.validate(a, sig, self.keys)
        s = self.spans(r)
        self.assertEqual(len(s), 1)                      # §7.2.6: next-closer cover only
        self.assert_covered(s, "x.wild.nsec3.test.")

    def test_wildcard_nodata(self):
        r = self.ask("a.b.wild.nsec3.test.", "TXT")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        s = self.spans(r)
        self.assert_matches(s, "wild.nsec3.test.")       # closest encloser
        self.assert_covered(s, "b.wild.nsec3.test.")     # next closer
        self.assertNotIn("TXT", types(self.assert_matches(s, "*.wild.nsec3.test.")))

    def test_ds_nodata_at_insecure_delegation(self):
        r = self.ask("insecure.nsec3.test.", "DS")
        self.assertTrue(r.flags & dns.flags.AA)
        self.assertEqual(types(self.assert_matches(self.spans(r), "insecure.nsec3.test.")), {"NS"})

    def test_referrals(self):
        r = self.ask("foo.secure.nsec3.test.", "A")
        self.assertFalse(r.flags & dns.flags.AA)
        self.assertIn(dns.rdatatype.DS, [rr.rdtype for rr in r.authority])
        r = self.ask("foo.insecure.nsec3.test.", "A")
        self.assertFalse(r.flags & dns.flags.AA)
        self.assertNotIn("DS", types(self.assert_matches(self.spans(r), "insecure.nsec3.test.")))
        self.assert_signed(r.authority[1:])

    # --- golden fixture ------------------------------------------------------

    def test_nxdomain_matches_com_fixture_shape(self):
        fixture = golden.parse_dig((golden.GOLDEN / "com-nsec3-nxdomain.txt").read_text())
        want = golden.nsec3_nxdomain_shape(fixture, "nosuchdomain-12345.com.")
        # "c" puts the next-closer and wildcard covers in different NSEC3s, as in .com.
        r = self.ask("c.nsec3.test.", "A")
        got = golden.nsec3_nxdomain_shape(golden.from_message(r), "c.nsec3.test.")
        self.assertEqual(got, want)


class Step3OptOut(unittest.TestCase):
    """Opt-Out (RFC 5155 §6, §7.2.4, §7.2.7): unsigned delegations leave the chain."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.zone = SignedZone(ZONE_FILE, Path(cls.tmp.name), Nsec3Denial(opt_out=True))
        cls.udp, cls.tcp = start(Responder([cls.zone]), "127.0.0.1", 0)
        cls.port = cls.udp.server_address[1]

    @classmethod
    def tearDownClass(cls):
        for srv in (cls.udp, cls.tcp):
            srv.shutdown()
            srv.server_close()
        cls.tmp.cleanup()

    def ask(self, qname, qtype):
        q = dns.message.make_query(qname, qtype, want_dnssec=True, use_edns=0)
        q.flags &= ~dns.flags.RD
        return dns.query.udp(q, "127.0.0.1", port=self.port, timeout=2)

    def test_chain_excludes_insecure_and_sets_flag(self):
        owners = {o.labels[0].decode().upper(): rds[0] for (o, t), rds in self.zone.extra.items()
                  if t == NSEC3}
        self.assertNotIn(H("insecure.nsec3.test."), owners)
        self.assertIn(H("secure.nsec3.test."), owners)       # signed delegations stay
        self.assertTrue(all(rd.flags == 1 for rd in owners.values()))
        param = self.zone.zone.get_rdataset(ORIGIN, dns.rdatatype.NSEC3PARAM)
        self.assertEqual(param[0].flags, 0)                  # §4.1.2

    def _assert_provable_ce_proof(self, r):
        recs = [(rr.name, rr.ttl, rd) for rr in r.authority if rr.rdtype == NSEC3 for rd in rr]
        spans = {o: (n, rd) for o, n, rd in golden.nsec3_spans(recs)}
        self.assertIn(H("nsec3.test."), spans)               # closest provable encloser
        h = H("insecure.nsec3.test.")
        cover = [rd for o, (n, rd) in spans.items() if golden.hash_covers(o, n, h)]
        self.assertTrue(cover and cover[0].flags & 1)        # Opt-Out set on the cover

    def test_referral_uses_opt_out_proof(self):
        r = self.ask("foo.insecure.nsec3.test.", "A")
        self.assertFalse(r.flags & dns.flags.AA)
        self._assert_provable_ce_proof(r)

    def test_ds_query_uses_opt_out_proof(self):
        r = self.ask("insecure.nsec3.test.", "DS")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self._assert_provable_ce_proof(r)


if __name__ == "__main__":
    unittest.main()
