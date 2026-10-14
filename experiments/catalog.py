"""Catalog of resolver-behavior experiments (vanilla NSEC zone nsec.test).

Each entry states the question, the method, what is expected and why
(with sources), and the code that runs it. `python -m experiments catalog`
renders this file into experiments/CATALOG.md, so the catalog and the code
cannot drift. Entries with run=None are planned and need responder changes.

Gaps in nsec.test used below (canonical order, zones/nsec.test.zone):
  insecure -> ns1     labels starting with "m"   ("m..." sorts between them)
  ns1      -> secure  labels starting with "p"
The apex NSEC (nsec.test -> host.ent) covers *.nsec.test for every NXDOMAIN.
"""

import time
from dataclasses import dataclass
from typing import Callable

RFC8198 = "RFC 8198"
BIND_ARM = "BIND ARM synth-from-dnssec (NSEC only)"


@dataclass
class Experiment:
    id: str
    title: str
    question: str
    method: str
    expected: str
    sources: str
    run: Callable | None = None
    slow: bool = False


CATALOG: list[Experiment] = []


def experiment(**meta):
    def register(fn):
        CATALOG.append(Experiment(run=fn, **meta))
        return fn
    return register


def planned(**meta):
    CATALOG.append(Experiment(**meta))


def synth_outcome(second, expect_synth: bool):
    """Classify the second probe: synthesized from cache, or fetched upstream."""
    if second.error:
        return f"error: {second.error}", None
    outcome = "upstream" if second.went_upstream else "synthesized"
    return outcome, (outcome == "synthesized") == expect_synth


# --- aggressive negative caching (ANC) ------------------------------------

@experiment(
    id="N01", title="NXDOMAIN synthesis, same NSEC gap",
    question="After one validated NXDOMAIN, does BIND answer a different name in the same gap without asking the responder? What TTLs does the synthesized answer carry?",
    method="flush; m<tag>a A (prime); m<tag>b A. Compare upstream queries and authority TTLs.",
    expected="Synthesized NXDOMAIN with AD; TTLs no higher than the primed NSEC's remaining TTL.",
    sources=f"{RFC8198} §5.1, §5.4; {BIND_ARM}",
)
def n01(ctx):
    a = ctx.probe(ctx.label("m") + "a.nsec.test.")
    b = ctx.probe(ctx.label("m") + "b.nsec.test.")
    outcome, ok = synth_outcome(b, True)
    ok = ok and b.rcode == "NXDOMAIN" and b.ad
    ttl = lambda p: sorted({r["ttl"] for r in p.authority})
    return outcome, ok, f"prime TTLs {ttl(a)}, second TTLs {ttl(b)}"


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
)
def n11(ctx):
    mid = ctx.label("m") + ".nsec.test."
    b = ctx.probe("d1.d2." + mid)
    ok = f"{mid} NS" in b.upstream and f"d1.d2.{mid} A" in b.upstream
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
