"""Catalog of resolver-behavior experiments (vanilla NSEC zone nsec.test).

Each entry states the question, the method, what is expected and why
(with sources), and the code that runs it. `python -m experiments catalog`
renders this file into experiments/CATALOG.md, so the catalog and the code
cannot drift. Entries with run=None are planned and need responder changes.

IDs: Nxx run against nsec.test (vanilla NSEC); N3-xx against nsec3.test
(vanilla NSEC3, same zone content), as counterparts of the Nxx with the same
number. Online variants (same zone content, docs/VARIANTS.md): MN-xx
minnsec.test (minimal NSEC), WL-xx minnsec3.test (NSEC3 white lies), CN-xx
cdoe-nsec.test (compact NSEC), C3-xx cdoe-nsec3.test (compact NSEC3). NSEC3 "gaps" are hash intervals, so same-gap names are found by
hashing candidates against the zone's real chain (nsec3_same_gap).

Gaps in nsec.test used below (canonical order, zones/nsec.test.zone):
  insecure -> ns1     labels starting with "m"   ("m..." sorts between them)
  ns1      -> secure  labels starting with "p"
The apex NSEC (nsec.test -> host.ent) covers *.nsec.test for every NXDOMAIN.
"""

import bisect
import functools
import random
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import dns.dnssec

RFC8198 = "RFC 8198"
BIND_ARM = "BIND ARM synth-from-dnssec (NSEC only)"


@dataclass
class Experiment:
    id: str
    title: str
    question: str
    method: str
    expected: str               # for BIND, and for any resolver not listed in expected_by
    sources: str
    run: Callable | None = None
    slow: bool = False
    expected_by: dict = field(default_factory=dict)   # resolver name -> its own expectation text
    anc: bool = True            # tests aggressive negative caching (a second name from cache)


CATALOG: list[Experiment] = []


def experiment(**meta):
    def register(fn):
        CATALOG.append(Experiment(run=fn, **meta))
        return fn
    return register


def planned(**meta):
    CATALOG.append(Experiment(**meta))


def synth_outcome(second, expect_synth):
    """Classify the second probe: synthesized from cache, or fetched upstream.
    expect_synth None means no expectation (observation only)."""
    if second.error:
        return f"error: {second.error}", None
    outcome = "upstream" if second.went_upstream else "synthesized"
    if expect_synth is None:
        return outcome, None
    return outcome, (outcome == "synthesized") == expect_synth


# --- aggressive negative caching (ANC) ------------------------------------

@experiment(
    id="N01", title="NXDOMAIN synthesis, same NSEC gap",
    question="After one validated NXDOMAIN, does BIND answer a different name in the same gap without asking the responder? Does the synthesized answer carry the remaining TTL of the cached NSEC/SOA, or a fresh one?",
    method="flush; m<tag>a A (prime); wait 10 s; m<tag>b A. Compare upstream queries and authority TTLs.",
    expected="Synthesized NXDOMAIN with AD, with TTLs about 50 (60 minus the 10 s wait), not reset to 60.",
    sources=f"{RFC8198} §5.1, §5.4; {BIND_ARM}",
)
def n01(ctx):
    wait = 10
    a = ctx.probe(ctx.label("m") + "a.nsec.test.")
    time.sleep(wait)
    b = ctx.probe(ctx.label("m") + "b.nsec.test.")
    outcome, ok = synth_outcome(b, True)
    ttls = lambda p: sorted({r["ttl"] for r in p.authority})
    first, second = ttls(a), ttls(b)
    # Remaining TTL: second <= first - wait (+1 for whole-second rounding).
    remaining = bool(first and second) and max(second) <= max(first) - wait + 1
    ok = ok and b.rcode == "NXDOMAIN" and b.ad and remaining
    kind = "remaining TTL" if remaining else "TTL not decremented"
    return outcome, ok, f"prime TTLs {first}, after {wait}s {second} ({kind})"


@experiment(
    id="N02", title="No synthesis across gaps",
    question="Does BIND avoid synthesizing for a name whose covering NSEC it has not cached, even though the wildcard proof (apex NSEC) is cached?",
    method="flush; m<tag>a A (prime, caches insecure->ns1 and apex NSEC); p<tag>a A (gap ns1->secure).",
    expected="Upstream query for the second name (no covering NSEC cached).",
    sources=f"{RFC8198} §5.1",
)
def n02(ctx):
    ctx.probe(ctx.label("m") + "a.nsec.test.")
    b = ctx.probe(ctx.label("p") + "a.nsec.test.")
    return synth_outcome(b, False) + ("",)


@experiment(
    id="N03", title="NODATA synthesis, other type at an existing name",
    question="After NODATA for www AAAA (NSEC at www lists A TXT), does BIND synthesize NODATA for www MX?",
    method="flush; www AAAA (prime); www MX.",
    expected="Synthesized NODATA (the matching NSEC proves MX is absent). BIND support unknown.",
    sources=f"{RFC8198} §5.1",
)
def n03(ctx):
    ctx.probe("www.nsec.test.", "AAAA")
    b = ctx.probe("www.nsec.test.", "MX")
    return synth_outcome(b, True) + (f"rcode {b.rcode}, AD {b.ad}",)


@experiment(
    id="N04", title="NODATA synthesis at an empty non-terminal",
    question="After NODATA for ent A (proved by the covering NSEC nsec.test -> host.ent), does BIND synthesize NODATA for ent AAAA?",
    method="flush; ent.nsec.test A (prime); ent.nsec.test AAAA.",
    expected="Synthesized NODATA. BIND support unknown (ENT proofs use a covering, not matching, NSEC).",
    sources=f"{RFC8198} §5.1; RFC 4035 §5.4",
)
def n04(ctx):
    ctx.probe("ent.nsec.test.", "A")
    b = ctx.probe("ent.nsec.test.", "AAAA")
    return synth_outcome(b, True) + (f"rcode {b.rcode}, AD {b.ad}",)


@experiment(
    id="N05", title="NXDOMAIN below a cached NXDOMAIN",
    question="After NXDOMAIN for m<tag>a, is sub.m<tag>a answered without the responder? (Provable from the cached NSECs; also the RFC 8020 NXDOMAIN cut.)",
    method="flush; m<tag>a A (prime); sub.m<tag>a A.",
    expected="Synthesized NXDOMAIN.",
    sources=f"{RFC8198} §5.1; RFC 8020",
)
def n05(ctx):
    base = ctx.label("m") + "a.nsec.test."
    ctx.probe(base)
    b = ctx.probe("sub." + base)
    return synth_outcome(b, True) + (f"rcode {b.rcode}, AD {b.ad}",)


# --- wildcards ------------------------------------------------------------

@experiment(
    id="N06", title="Positive wildcard synthesis",
    question="After a wildcard-expanded answer for x<tag>.wild A, does BIND synthesize y<tag>.wild A from the cached wildcard and NSEC?",
    method="flush; x<tag>.wild A (prime); y<tag>.wild A.",
    expected="Synthesized positive answer with AD (RFC SHOULD). BIND support unknown.",
    sources=f"{RFC8198} §5.3",
)
def n06(ctx):
    ctx.probe(ctx.label("x") + ".wild.nsec.test.")
    b = ctx.probe(ctx.label("y") + ".wild.nsec.test.")
    return synth_outcome(b, True) + (f"rcode {b.rcode}, AD {b.ad}, answers {[r['type'] for r in b.answer]}",)


@experiment(
    id="N07", title="Wildcard NODATA synthesis",
    question="After wildcard NODATA for x<tag>.wild TXT, does BIND synthesize NODATA for y<tag>.wild TXT?",
    method="flush; x<tag>.wild TXT (prime); y<tag>.wild TXT.",
    expected="Synthesized NODATA (RFC SHOULD). BIND support unknown.",
    sources=f"{RFC8198} §5.3",
)
def n07(ctx):
    ctx.probe(ctx.label("x") + ".wild.nsec.test.", "TXT")
    b = ctx.probe(ctx.label("y") + ".wild.nsec.test.", "TXT")
    return synth_outcome(b, True) + (f"rcode {b.rcode}, AD {b.ad}",)


# --- client flags -----------------------------------------------------------

@experiment(
    id="N08", title="CD=1 disables synthesis",
    question="With the cache primed, does a client query with CD=1 (checking disabled) for a same-gap name go upstream?",
    method="flush; m<tag>a A (prime, CD=0); m<tag>b A with CD=1.",
    expected="Upstream: RFC 8198's implementation notes say synthesis applies 'unless the CD bit was set'. The RFC body never mentions CD, so this is guidance, not a requirement.",
    sources=f"{RFC8198} Appendix A (Detailed Implementation Notes)",
)
def n08(ctx):
    ctx.probe(ctx.label("m") + "a.nsec.test.")
    b = ctx.probe(ctx.label("m") + "b.nsec.test.", cd=True)
    return synth_outcome(b, False) + (f"rcode {b.rcode}, AD {b.ad}",)


@experiment(
    id="N09", title="DO=0 client still gets synthesis",
    question="Is synthesis independent of the client's DO bit, and what does a DO=0 client receive?",
    method="flush; m<tag>a A (prime, DO=1); m<tag>b A with DO=0.",
    expected="Synthesized NXDOMAIN; no NSEC/RRSIG in the response (client did not ask for DNSSEC).",
    sources=f"{RFC8198} §5 (silent on DO); RFC 4035 §3.2.1",
)
def n09(ctx):
    ctx.probe(ctx.label("m") + "a.nsec.test.")
    b = ctx.probe(ctx.label("m") + "b.nsec.test.", do=False)
    outcome, ok = synth_outcome(b, True)
    types = [r["type"] for r in b.authority]
    return outcome, ok and not any(t.startswith(("NSEC", "RRSIG")) for t in types), f"authority {types}"


@experiment(
    id="N10", title="Priming from a DO=0 client",
    question="If the first query comes from a DO=0 client, does BIND still fetch, validate, and cache the NSECs so a later DO=1 query is synthesized?",
    method="flush; m<tag>a A with DO=0 (prime); m<tag>b A with DO=1.",
    expected="Synthesized (the resolver validates regardless of the client's DO).",
    sources=f"{RFC8198} §5; RFC 4035 §4",
)
def n10(ctx):
    ctx.probe(ctx.label("m") + "a.nsec.test.", do=False)
    b = ctx.probe(ctx.label("m") + "b.nsec.test.")
    return synth_outcome(b, True) + (f"rcode {b.rcode}, AD {b.ad}",)


# --- upstream query shape -------------------------------------------------

@experiment(
    id="N11", title="Upstream queries for a deep nonexistent name",
    question="Which queries does BIND send to the responder for a nonexistent name three labels below the apex, and does it stop at the validated NXDOMAIN for the minimised name?",
    method="flush; d1.d2.m<tag>.nsec.test A; record the upstream query sequence.",
    expected="Relaxed QNAME minimisation (BIND default): NS query for m<tag>.nsec.test, then on NXDOMAIN a fallback full query for d1.d2.m<tag>, although the cached NSEC already proves it. Plus a DNSKEY fetch after the flush.",
    sources="BIND ARM qname-minimization (relaxed: falls back on NXDOMAIN); RFC 9156; RFC 8020",
    expected_by={"knot": "Unknown (observation): Knot's minimisation strategy is not documented in the same terms.",
                 "pdns": "Unknown (observation): qname_minimization is on by default (relaxed RFC 9156); nothing_below_nxdomain=dnssec may stop at the validated NXDOMAIN."},
    anc=False,
)
def n11(ctx):
    mid = ctx.label("m") + ".nsec.test."
    b = ctx.probe("d1.d2." + mid)
    ok = ctx.expect(f"{mid} NS" in b.upstream and f"d1.d2.{mid} A" in b.upstream, knot=None, pdns=None)
    return f"{len(b.upstream)} upstream", ok, "; ".join(b.upstream)


@experiment(
    id="N12", title="Synthesis stops after the NSEC TTL",
    question="Once the primed NSEC records expire (TTL 60 s), does a same-gap query go upstream again?",
    method="flush; m<tag>a A (prime); wait 65 s; m<tag>b A.",
    expected="Upstream.",
    sources=f"{RFC8198} §5.4; RFC 9077",
    slow=True,
)
def n12(ctx):
    ctx.probe(ctx.label("m") + "a.nsec.test.")
    time.sleep(65)
    b = ctx.probe(ctx.label("m") + "b.nsec.test.")
    return synth_outcome(b, False) + ("",)


# --- NSEC3 counterparts (zone nsec3.test) --------------------------------

NSEC3_ZONE = Path(__file__).resolve().parent.parent / "zones" / "nsec3.test.zone"


@functools.cache
def _nsec3_chain():
    """Sorted owner hashes of nsec3.test, built from the zone file by the responder."""
    from responder.denial import Nsec3Denial
    from responder.zone import SignedZone
    with tempfile.TemporaryDirectory() as d:  # throwaway key: only hashes are needed
        return tuple(SignedZone(NSEC3_ZONE, Path(d), Nsec3Denial()).denial.hashes)


def nsec3_same_gap(suffix, count=2, prefix="r"):
    """`count` fresh labels whose <label>.<suffix> hashes fall in one NSEC3 gap."""
    chain = _nsec3_chain()
    gap = lambda name: chain[bisect.bisect_right(chain, dns.dnssec.nsec3_hash(name, None, 0, 1)) - 1]
    want, out = None, []
    while len(out) < count:
        label = f"{prefix}{random.randrange(10**9)}"
        g = gap(f"{label}.{suffix}")
        want = want or g
        if g == want:
            out.append(label)
    return out


@experiment(
    id="N3-01", title="NSEC3: NXDOMAIN, same hash gap (counterpart of N01)",
    question="After one validated NSEC3 NXDOMAIN, is a different name whose hash falls in the same NSEC3 gap answered without the responder?",
    method="flush; two labels chosen so their hashes share one NSEC3 gap; <l1>.nsec3.test A (prime); <l2>.nsec3.test A.",
    expected="Upstream: BIND synthesizes from NSEC only; NSEC3 synthesis is 'planned for the future'. RFC 8198 §5.2 would allow it.",
    sources=f"{BIND_ARM}; {RFC8198} §5.2",
    expected_by={"knot": 'Unknown (observation): RFC 8198 §5.2 allows NSEC3 synthesis; Knot\'s docs say only "aggressive caching for DNSSEC-validated data" without restricting it to NSEC.'},
)
def n3_01(ctx):
    l1, l2 = nsec3_same_gap("nsec3.test.")
    ctx.probe(f"{l1}.nsec3.test.")
    b = ctx.probe(f"{l2}.nsec3.test.")
    return synth_outcome(b, ctx.expect(False, knot=None)) + (f"rcode {b.rcode}, AD {b.ad}",)


@experiment(
    id="N3-03", title="NSEC3: NODATA, other type at an existing name (counterpart of N03)",
    question="After NODATA for www AAAA (matching NSEC3 lists A TXT RRSIG), is www MX answered without the responder?",
    method="flush; www.nsec3.test AAAA (prime); www.nsec3.test MX.",
    expected="Upstream (no NSEC3 synthesis in BIND).",
    sources=f"{BIND_ARM}; {RFC8198} §5.2",
    expected_by={"knot": 'Unknown (observation): RFC 8198 §5.2 allows NSEC3 synthesis; Knot\'s docs say only "aggressive caching for DNSSEC-validated data" without restricting it to NSEC.'},
)
def n3_03(ctx):
    ctx.probe("www.nsec3.test.", "AAAA")
    b = ctx.probe("www.nsec3.test.", "MX")
    return synth_outcome(b, ctx.expect(False, knot=None)) + (f"rcode {b.rcode}, AD {b.ad}",)


@experiment(
    id="N3-06", title="NSEC3: positive wildcard (counterpart of N06)",
    question="After a wildcard answer for <l1>.wild.nsec3.test (proved by an NSEC3 covering the next closer name), is <l2>.wild, whose hash falls in the same gap, answered without the responder?",
    method="flush; two labels whose <label>.wild.nsec3.test hashes share one NSEC3 gap; query both, A.",
    expected="Upstream (no NSEC3-based wildcard synthesis in BIND). RFC 8198 §5.3 would allow it.",
    sources=f"{BIND_ARM}; {RFC8198} §5.3",
    expected_by={"knot": 'Unknown (observation): RFC 8198 §5.2 allows NSEC3 synthesis; Knot\'s docs say only "aggressive caching for DNSSEC-validated data" without restricting it to NSEC.'},
)
def n3_06(ctx):
    l1, l2 = nsec3_same_gap("wild.nsec3.test.")
    ctx.probe(f"{l1}.wild.nsec3.test.")
    b = ctx.probe(f"{l2}.wild.nsec3.test.")
    return synth_outcome(b, ctx.expect(False, knot=None)) + (f"rcode {b.rcode}, AD {b.ad}, answers {[r['type'] for r in b.answer]}",)


# --- online variants (docs/VARIANTS.md) -------------------------------------

RFC4470 = "RFC 4470"
RFC9824 = "RFC 9824"


def rcode_ad(p):
    return f"rcode {p.rcode}, AD {p.ad}" + (", CO" if "CO" in p.flags else "")


@experiment(
    id="MN-01", title="Minimal NSEC: second name beside a cached NXDOMAIN (counterpart of N01)",
    question="After a validated minimal-NSEC NXDOMAIN for m<tag>a, is m<tag>b (adjacent, but outside the one-name span) answered without the responder?",
    method="flush; m<tag>a.minnsec.test A (prime); m<tag>b.minnsec.test A.",
    expected="Upstream: the cover spans only m<tag>a's subtree, which defeats ANC by design.",
    sources=f"{RFC4470} §1; {RFC8198} §5.1",
)
def mn_01(ctx):
    ctx.probe(ctx.label("m") + "a.minnsec.test.")
    b = ctx.probe(ctx.label("m") + "b.minnsec.test.")
    return synth_outcome(b, False) + (rcode_ad(b),)


@experiment(
    id="MN-02", title="Minimal NSEC: name below a cached NXDOMAIN (counterpart of N05)",
    question="Is sub.m<tag>a answered from the cached cover for m<tag>a? The cover predecessor(m<tag>a) -> m<tag>a\\000 spans m<tag>a's whole subtree (decision D14).",
    method="flush; m<tag>a.minnsec.test A (prime); sub.m<tag>a.minnsec.test A.",
    expected="Synthesized (the cached cover and wildcard cover prove it). Depends on D14; with cover_next='child' the span would not reach sub.m<tag>a.",
    sources=f"{RFC8198} §5.1; {RFC4470} erratum 6734; docs/VARIANTS.md D14",
    expected_by={"knot": "Upstream: Knot's release notes (4.1.0, 2019) say aggressive caching is disabled for minimal ranges (CLAUDE.md §6); not re-verified for 6.x."},
)
def mn_02(ctx):
    base = ctx.label("m") + "a.minnsec.test."
    ctx.probe(base)
    b = ctx.probe("sub." + base)
    return synth_outcome(b, ctx.expect(True, knot=False)) + (rcode_ad(b),)


@experiment(
    id="MN-03", title="Minimal NSEC: NODATA, other type at an existing name (counterpart of N03)",
    question="After NODATA for www AAAA (online NSEC at www with the full bitmap), is www MX answered without the responder?",
    method="flush; www.minnsec.test AAAA (prime); www.minnsec.test MX.",
    expected="Synthesized: the NSEC at www lists every type, so it proves MX absent.",
    sources=f"{RFC8198} §5.1; {RFC4470} §3",
    expected_by={"knot": "Upstream: Knot's release notes (4.1.0, 2019) say aggressive caching is disabled for minimal ranges (CLAUDE.md §6); not re-verified for 6.x."},
)
def mn_03(ctx):
    ctx.probe("www.minnsec.test.", "AAAA")
    b = ctx.probe("www.minnsec.test.", "MX")
    return synth_outcome(b, ctx.expect(True, knot=False)) + (rcode_ad(b),)


@experiment(
    id="WL-01", title="NSEC3 white lies: second name (counterpart of N3-01)",
    question="After a white-lies NXDOMAIN, is a second nonexistent name answered without the responder?",
    method="flush; r<tag>a.minnsec3.test A (prime); r<tag>b.minnsec3.test A.",
    expected="Upstream: BIND does no NSEC3 synthesis, and the covers span only hash±1.",
    sources=f"{BIND_ARM}; RFC 7129 App. B",
)
def wl_01(ctx):
    ctx.probe(ctx.label("r") + "a.minnsec3.test.")
    b = ctx.probe(ctx.label("r") + "b.minnsec3.test.")
    return synth_outcome(b, False) + (rcode_ad(b),)


@experiment(
    id="CN-01", title="Compact NSEC: rcode the client sees for a nonexistent name",
    question="What rcode and AD does a client without CO get from BIND for a compact-denied name?",
    method="flush; nx<tag>.cdoe-nsec.test A (DO=1, CO=0).",
    expected="NOERROR with AD: RFC 9824 §5.1 says resolvers reset to NOERROR for queriers without CO; BIND 9.20 has no CO support anyway (FINDINGS INFRA.4).",
    sources=f"{RFC9824} §3.1, §5.1",
    anc=False,
)
def cn_01(ctx):
    p = ctx.probe(ctx.label("nx") + ".cdoe-nsec.test.")
    return p.rcode, p.rcode == "NOERROR" and p.ad, rcode_ad(p) + f"; upstream {p.upstream}"


@experiment(
    id="CN-02", title="Compact NSEC: client sets CO",
    question="Does BIND restore NXDOMAIN for a client that sets CO, and does it send CO upstream?",
    method="flush; nx<tag>.cdoe-nsec.test A with CO=1; check the response and BIND's upstream queries.",
    expected="No: NOERROR without CO and no CO upstream, since BIND's compact-denial support is dig-only. A CO-aware resolver would return NXDOMAIN with CO (RFC 9824 §5.1).",
    sources=f"{RFC9824} §5.1; FINDINGS INFRA.4",
    expected_by={"knot": 'Unknown (observation): Knot\'s documentation does not mention CO or RFC 9824.',
                 "pdns": "Unknown (observation): PowerDNS Recursor documentation does not mention CO or RFC 9824."},
    anc=False,
)
def cn_02(ctx):
    p = ctx.probe(ctx.label("nx") + ".cdoe-nsec.test.", co=True)
    co_up = any(u.endswith(" CO") for u in p.upstream)
    ok = ctx.expect(p.rcode == "NOERROR" and "CO" not in p.flags and not co_up, knot=None, pdns=None)
    return p.rcode + (" +CO" if "CO" in p.flags else ""), ok, rcode_ad(p) + f"; CO sent upstream: {co_up}"


@experiment(
    id="CN-03", title="Compact NSEC: same name again is cached",
    question="Is a repeated query for a compact-denied name answered from the (NODATA) negative cache?",
    method="flush; nx<tag>.cdoe-nsec.test A twice.",
    expected="Second query from cache (no upstream).",
    sources=f"{RFC9824} §3.1; RFC 2308",
    anc=False,
)
def cn_03(ctx):
    name = ctx.label("nx") + ".cdoe-nsec.test."
    ctx.probe(name)
    b = ctx.probe(name)
    return synth_outcome(b, True) + (rcode_ad(b),)


@experiment(
    id="CN-04", title="Compact NSEC: second name (counterpart of N01)",
    question="After a compact denial for m<tag>a, is m<tag>b answered without the responder?",
    method="flush; m<tag>a.cdoe-nsec.test A (prime); m<tag>b.cdoe-nsec.test A.",
    expected="Upstream: each NSEC spans only its owner (RFC 9824 §6: RFC 8198 synthesis not supported).",
    sources=f"{RFC9824} §6",
)
def cn_04(ctx):
    ctx.probe(ctx.label("m") + "a.cdoe-nsec.test.")
    b = ctx.probe(ctx.label("m") + "b.cdoe-nsec.test.")
    return synth_outcome(b, False) + (rcode_ad(b),)


@experiment(
    id="CN-05", title="Compact NSEC: name below a compact-denied name (counterpart of N05)",
    question="After a compact denial for m<tag>a (an NSEC saying m<tag>a 'exists' with only NXNAME), is sub.m<tag>a answered without the responder?",
    method="flush; m<tag>a.cdoe-nsec.test A (prime); sub.m<tag>a.cdoe-nsec.test A.",
    expected="Upstream: the NSEC proves nothing about names below its owner, and RFC 8020 NXDOMAIN cuts do not apply (no NXDOMAIN).",
    sources=f"{RFC9824} §6; RFC 8020",
)
def cn_05(ctx):
    base = ctx.label("m") + "a.cdoe-nsec.test."
    ctx.probe(base)
    b = ctx.probe("sub." + base)
    return synth_outcome(b, False) + (rcode_ad(b),)


@experiment(
    id="C3-01", title="Compact NSEC3: rcode the client sees for a nonexistent name",
    question="What rcode and AD does a client get from BIND for a compact-denied NSEC3 name?",
    method="flush; nx<tag>.cdoe-nsec3.test A.",
    expected="NOERROR with AD (as CN-01).",
    sources=f"{RFC9824} §4, §5.1",
    anc=False,
)
def c3_01(ctx):
    p = ctx.probe(ctx.label("nx") + ".cdoe-nsec3.test.")
    return p.rcode, p.rcode == "NOERROR" and p.ad, rcode_ad(p)


@experiment(
    id="C3-02", title="Compact NSEC3: second name",
    question="After a compact NSEC3 denial, is a second nonexistent name answered without the responder?",
    method="flush; m<tag>a.cdoe-nsec3.test A (prime); m<tag>b.cdoe-nsec3.test A.",
    expected="Upstream (no NSEC3 synthesis in BIND; single-hash spans).",
    sources=f"{BIND_ARM}; {RFC9824} §6",
)
def c3_02(ctx):
    ctx.probe(ctx.label("m") + "a.cdoe-nsec3.test.")
    b = ctx.probe(ctx.label("m") + "b.cdoe-nsec3.test.")
    return synth_outcome(b, False) + (rcode_ad(b),)


# --- planned: need deliberately odd responder output (responder knobs) ----

planned(
    id="P01", title="NSEC TTL above SOA MINIMUM",
    question="If NSEC TTL > min(SOA TTL, MINIMUM), does BIND cap it, and for how long does it synthesize?",
    method="Zone knob for NSEC TTL; prime; probe same gap past MINIMUM but before NSEC TTL.",
    expected="Capped at the negative TTL.",
    sources=f"{RFC8198} §5.4; RFC 9077 §3.4",
)
planned(
    id="P02", title="NSEC TTL above 3 hours",
    question="Does BIND cap the effective NSEC TTL at 10800 s?",
    method="Zone knob for a long NSEC and SOA MINIMUM; inspect cache TTL via rndc dumpdb.",
    expected="Capped (RECOMMENDED), or at max-ncache-ttl.",
    sources=f"{RFC8198} §5.4; BIND ARM max-ncache-ttl",
)
planned(
    id="P03", title="Broken proof is not cached or reused",
    question="With the wildcard NSEC omitted from NXDOMAIN, does BIND return SERVFAIL, and does it still cache and reuse the qname-covering NSEC?",
    method="Per-response knob to drop the wildcard NSEC; probe; then a same-gap name with a correct responder.",
    expected="SERVFAIL; no synthesis from the incomplete proof.",
    sources="RFC 4035 §5.4; BIND CVE-2026-11721 fix notes",
)
planned(
    id="P04", title="Expired RRSIG on a cached NSEC",
    question="How does BIND treat an NSEC whose RRSIG expires while cached?",
    method="Sign with a short validity window; prime; probe after expiry within the TTL.",
    expected="No synthesis from an NSEC whose signature has expired.",
    sources="RFC 4035 §5.3.1",
)
planned(
    id="P05", title="Strict QNAME minimisation and the NXDOMAIN cut",
    question="With qname-minimization strict, does BIND stop at the minimised NXDOMAIN (RFC 8020) instead of re-asking the full name (contrast with N11)?",
    method="BIND config variant (qname-minimization strict); rerun N11.",
    expected="One NS query, no full-name query.",
    sources="BIND ARM qname-minimization; RFC 9156; RFC 8020",
)
