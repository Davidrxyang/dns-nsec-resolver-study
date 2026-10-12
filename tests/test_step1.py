"""Step 1: signing and positive answers, over a live UDP/TCP server.

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

ZONE = dns.name.from_text("nsec.test.")
ZONE_TEXT = """$ORIGIN nsec.test.
$TTL 300
@    SOA ns1 hostmaster 1 3600 600 86400 60
@    NS  ns1
ns1  A   127.0.0.1
www  A   192.0.2.1
www  TXT "hello"
"""
# 20 x ~100 bytes of TXT, plus RRSIG: well over 512 bytes.
BIG_TXT = "".join(f'big TXT "{i:02d}{"x" * 96}"\n' for i in range(20))


class Step1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        (d / "z.zone").write_text(ZONE_TEXT + BIG_TXT)
        cls.zone = SignedZone(d / "z.zone", d / "keys")
        cls.udp, cls.tcp = start(Responder([cls.zone]), "127.0.0.1", 0)
        cls.port = cls.udp.server_address[1]

    @classmethod
    def tearDownClass(cls):
        for srv in (cls.udp, cls.tcp):
            srv.shutdown()
            srv.server_close()
        cls.tmp.cleanup()

    def ask(self, qname, qtype, tcp=False, **kw):
        q = dns.message.make_query(qname, qtype, **kw)
        if tcp:
            return dns.query.tcp(q, "127.0.0.1", port=self.port, timeout=2)
        return dns.query.udp(q, "127.0.0.1", port=self.port, timeout=2)

    def keys(self):
        return {ZONE: self.zone.zone.get_rdataset(ZONE, dns.rdatatype.DNSKEY)}

    def test_every_rrset_validates(self):
        for (owner, rdtype), sigs in self.zone.rrsigs.items():
            rrset, _ = self.zone.get(owner, rdtype)
            dns.dnssec.validate(rrset, sigs, self.keys())

    def test_flags_and_sigs_with_do(self):
        r = self.ask("www.nsec.test.", "A", want_dnssec=True)
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertTrue(r.flags & dns.flags.QR and r.flags & dns.flags.AA)
        self.assertFalse(r.flags & (dns.flags.RA | dns.flags.AD))
        self.assertTrue(r.flags & dns.flags.RD)  # make_query sets RD; it is copied
        self.assertTrue(r.ednsflags & dns.flags.DO)
        a = r.find_rrset(r.answer, dns.name.from_text("www.nsec.test."), 1, dns.rdatatype.A)
        sig = r.find_rrset(r.answer, a.name, 1, dns.rdatatype.RRSIG, dns.rdatatype.A)
        dns.dnssec.validate(a, sig, self.keys())

    def test_no_sigs_without_do(self):
        r = self.ask("www.nsec.test.", "A", use_edns=0)
        self.assertFalse(r.ednsflags & dns.flags.DO)
        self.assertEqual([rr.rdtype for rr in r.answer], [dns.rdatatype.A])

    def test_no_edns_no_opt(self):
        r = self.ask("www.nsec.test.", "A", use_edns=False)
        self.assertEqual(r.edns, -1)

    def test_refused(self):
        for name in ("nope.nsec.test.", "example.com."):
            r = self.ask(name, "A", want_dnssec=True)
            self.assertEqual(r.rcode(), dns.rcode.REFUSED)

    def test_udp_truncation_and_tcp_fallback(self):
        r = self.ask("big.nsec.test.", "TXT", want_dnssec=True, payload=512)
        self.assertTrue(r.flags & dns.flags.TC)
        self.assertEqual(len(r.answer), 0)
        self.assertEqual(len(r.question), 1)
        r = self.ask("big.nsec.test.", "TXT", tcp=True, want_dnssec=True)
        self.assertFalse(r.flags & dns.flags.TC)
        self.assertEqual(len(r.answer[0]), 20)

    def test_badvers(self):
        r = self.ask("www.nsec.test.", "A", use_edns=1)
        self.assertEqual(r.rcode(), dns.rcode.BADVERS)
        self.assertFalse(r.flags & dns.flags.AA)


if __name__ == "__main__":
    unittest.main()
