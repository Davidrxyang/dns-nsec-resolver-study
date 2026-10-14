# Experiment catalog

Generated from `experiments/catalog.py` by `venv/bin/python -m experiments catalog`; edit that file, not this one.
Zone: `nsec.test` (vanilla NSEC). Resolver: BIND in the local Docker pipeline. Results are diagnostics, written to `results/<time>/` (gitignored).

| ID | Status | Title | Expected | Sources |
|---|---|---|---|---|
| N01 | runnable | NXDOMAIN synthesis, same NSEC gap | Synthesized NXDOMAIN with AD, with TTLs about 50 (60 minus the 10 s wait), not reset to 60. | RFC 8198 §5.1, §5.4; BIND ARM synth-from-dnssec (NSEC only) |
| N02 | runnable | No synthesis across gaps | Upstream query for the second name (no covering NSEC cached). | RFC 8198 §5.1 |
| N03 | runnable | NODATA synthesis, other type at an existing name | Synthesized NODATA (the matching NSEC proves MX is absent). BIND support unknown. | RFC 8198 §5.1 |
| N04 | runnable | NODATA synthesis at an empty non-terminal | Synthesized NODATA. BIND support unknown (ENT proofs use a covering, not matching, NSEC). | RFC 8198 §5.1; RFC 4035 §5.4 |
| N05 | runnable | NXDOMAIN below a cached NXDOMAIN | Synthesized NXDOMAIN. | RFC 8198 §5.1; RFC 8020 |
| N06 | runnable | Positive wildcard synthesis | Synthesized positive answer with AD (RFC SHOULD). BIND support unknown. | RFC 8198 §5.3 |
| N07 | runnable | Wildcard NODATA synthesis | Synthesized NODATA (RFC SHOULD). BIND support unknown. | RFC 8198 §5.3 |
| N08 | runnable | CD=1 disables synthesis | Upstream: RFC 8198's implementation notes say synthesis applies 'unless the CD bit was set'. The RFC body never mentions CD, so this is guidance, not a requirement. | RFC 8198 Appendix A (Detailed Implementation Notes) |
| N09 | runnable | DO=0 client still gets synthesis | Synthesized NXDOMAIN; no NSEC/RRSIG in the response (client did not ask for DNSSEC). | RFC 8198 §5 (silent on DO); RFC 4035 §3.2.1 |
| N10 | runnable | Priming from a DO=0 client | Synthesized (the resolver validates regardless of the client's DO). | RFC 8198 §5; RFC 4035 §4 |
| N11 | runnable | Upstream queries for a deep nonexistent name | Relaxed QNAME minimisation (BIND default): NS query for m<tag>.nsec.test, then on NXDOMAIN a fallback full query for d1.d2.m<tag>, although the cached NSEC already proves it. Plus a DNSKEY fetch after the flush. | BIND ARM qname-minimization (relaxed: falls back on NXDOMAIN); RFC 9156; RFC 8020 |
| N12 | runnable (slow) | Synthesis stops after the NSEC TTL | Upstream. | RFC 8198 §5.4; RFC 9077 |
| N3-01 | runnable | NSEC3: NXDOMAIN, same hash gap (counterpart of N01) | Upstream: BIND synthesizes from NSEC only; NSEC3 synthesis is 'planned for the future'. RFC 8198 §5.2 would allow it. | BIND ARM synth-from-dnssec (NSEC only); RFC 8198 §5.2 |
| N3-03 | runnable | NSEC3: NODATA, other type at an existing name (counterpart of N03) | Upstream (no NSEC3 synthesis in BIND). | BIND ARM synth-from-dnssec (NSEC only); RFC 8198 §5.2 |
| N3-06 | runnable | NSEC3: positive wildcard (counterpart of N06) | Upstream (no NSEC3-based wildcard synthesis in BIND). RFC 8198 §5.3 would allow it. | BIND ARM synth-from-dnssec (NSEC only); RFC 8198 §5.3 |
| P01 | planned | NSEC TTL above SOA MINIMUM | Capped at the negative TTL. | RFC 8198 §5.4; RFC 9077 §3.4 |
| P02 | planned | NSEC TTL above 3 hours | Capped (RECOMMENDED), or at max-ncache-ttl. | RFC 8198 §5.4; BIND ARM max-ncache-ttl |
| P03 | planned | Broken proof is not cached or reused | SERVFAIL; no synthesis from the incomplete proof. | RFC 4035 §5.4; BIND CVE-2026-11721 fix notes |
| P04 | planned | Expired RRSIG on a cached NSEC | No synthesis from an NSEC whose signature has expired. | RFC 4035 §5.3.1 |
| P05 | planned | Strict QNAME minimisation and the NXDOMAIN cut | One NS query, no full-name query. | BIND ARM qname-minimization; RFC 9156; RFC 8020 |

## N01: NXDOMAIN synthesis, same NSEC gap

- **Question:** After one validated NXDOMAIN, does BIND answer a different name in the same gap without asking the responder? Does the synthesized answer carry the remaining TTL of the cached NSEC/SOA, or a fresh one?
- **Method:** flush; m<tag>a A (prime); wait 10 s; m<tag>b A. Compare upstream queries and authority TTLs.
- **Expected:** Synthesized NXDOMAIN with AD, with TTLs about 50 (60 minus the 10 s wait), not reset to 60.
- **Sources:** RFC 8198 §5.1, §5.4; BIND ARM synth-from-dnssec (NSEC only)

## N02: No synthesis across gaps

- **Question:** Does BIND avoid synthesizing for a name whose covering NSEC it has not cached, even though the wildcard proof (apex NSEC) is cached?
- **Method:** flush; m<tag>a A (prime, caches insecure->ns1 and apex NSEC); p<tag>a A (gap ns1->secure).
- **Expected:** Upstream query for the second name (no covering NSEC cached).
- **Sources:** RFC 8198 §5.1

## N03: NODATA synthesis, other type at an existing name

- **Question:** After NODATA for www AAAA (NSEC at www lists A TXT), does BIND synthesize NODATA for www MX?
- **Method:** flush; www AAAA (prime); www MX.
- **Expected:** Synthesized NODATA (the matching NSEC proves MX is absent). BIND support unknown.
- **Sources:** RFC 8198 §5.1

## N04: NODATA synthesis at an empty non-terminal

- **Question:** After NODATA for ent A (proved by the covering NSEC nsec.test -> host.ent), does BIND synthesize NODATA for ent AAAA?
- **Method:** flush; ent.nsec.test A (prime); ent.nsec.test AAAA.
- **Expected:** Synthesized NODATA. BIND support unknown (ENT proofs use a covering, not matching, NSEC).
- **Sources:** RFC 8198 §5.1; RFC 4035 §5.4

## N05: NXDOMAIN below a cached NXDOMAIN

- **Question:** After NXDOMAIN for m<tag>a, is sub.m<tag>a answered without the responder? (Provable from the cached NSECs; also the RFC 8020 NXDOMAIN cut.)
- **Method:** flush; m<tag>a A (prime); sub.m<tag>a A.
- **Expected:** Synthesized NXDOMAIN.
- **Sources:** RFC 8198 §5.1; RFC 8020

## N06: Positive wildcard synthesis

- **Question:** After a wildcard-expanded answer for x<tag>.wild A, does BIND synthesize y<tag>.wild A from the cached wildcard and NSEC?
- **Method:** flush; x<tag>.wild A (prime); y<tag>.wild A.
- **Expected:** Synthesized positive answer with AD (RFC SHOULD). BIND support unknown.
- **Sources:** RFC 8198 §5.3

## N07: Wildcard NODATA synthesis

- **Question:** After wildcard NODATA for x<tag>.wild TXT, does BIND synthesize NODATA for y<tag>.wild TXT?
- **Method:** flush; x<tag>.wild TXT (prime); y<tag>.wild TXT.
- **Expected:** Synthesized NODATA (RFC SHOULD). BIND support unknown.
- **Sources:** RFC 8198 §5.3

## N08: CD=1 disables synthesis

- **Question:** With the cache primed, does a client query with CD=1 (checking disabled) for a same-gap name go upstream?
- **Method:** flush; m<tag>a A (prime, CD=0); m<tag>b A with CD=1.
- **Expected:** Upstream: RFC 8198's implementation notes say synthesis applies 'unless the CD bit was set'. The RFC body never mentions CD, so this is guidance, not a requirement.
- **Sources:** RFC 8198 Appendix A (Detailed Implementation Notes)

## N09: DO=0 client still gets synthesis

- **Question:** Is synthesis independent of the client's DO bit, and what does a DO=0 client receive?
- **Method:** flush; m<tag>a A (prime, DO=1); m<tag>b A with DO=0.
- **Expected:** Synthesized NXDOMAIN; no NSEC/RRSIG in the response (client did not ask for DNSSEC).
- **Sources:** RFC 8198 §5 (silent on DO); RFC 4035 §3.2.1

## N10: Priming from a DO=0 client

- **Question:** If the first query comes from a DO=0 client, does BIND still fetch, validate, and cache the NSECs so a later DO=1 query is synthesized?
- **Method:** flush; m<tag>a A with DO=0 (prime); m<tag>b A with DO=1.
- **Expected:** Synthesized (the resolver validates regardless of the client's DO).
- **Sources:** RFC 8198 §5; RFC 4035 §4

## N11: Upstream queries for a deep nonexistent name

- **Question:** Which queries does BIND send to the responder for a nonexistent name three labels below the apex, and does it stop at the validated NXDOMAIN for the minimised name?
- **Method:** flush; d1.d2.m<tag>.nsec.test A; record the upstream query sequence.
- **Expected:** Relaxed QNAME minimisation (BIND default): NS query for m<tag>.nsec.test, then on NXDOMAIN a fallback full query for d1.d2.m<tag>, although the cached NSEC already proves it. Plus a DNSKEY fetch after the flush.
- **Sources:** BIND ARM qname-minimization (relaxed: falls back on NXDOMAIN); RFC 9156; RFC 8020

## N12: Synthesis stops after the NSEC TTL

- **Question:** Once the primed NSEC records expire (TTL 60 s), does a same-gap query go upstream again?
- **Method:** flush; m<tag>a A (prime); wait 65 s; m<tag>b A.
- **Expected:** Upstream.
- **Sources:** RFC 8198 §5.4; RFC 9077

## N3-01: NSEC3: NXDOMAIN, same hash gap (counterpart of N01)

- **Question:** After one validated NSEC3 NXDOMAIN, is a different name whose hash falls in the same NSEC3 gap answered without the responder?
- **Method:** flush; two labels chosen so their hashes share one NSEC3 gap; <l1>.nsec3.test A (prime); <l2>.nsec3.test A.
- **Expected:** Upstream: BIND synthesizes from NSEC only; NSEC3 synthesis is 'planned for the future'. RFC 8198 §5.2 would allow it.
- **Sources:** BIND ARM synth-from-dnssec (NSEC only); RFC 8198 §5.2

## N3-03: NSEC3: NODATA, other type at an existing name (counterpart of N03)

- **Question:** After NODATA for www AAAA (matching NSEC3 lists A TXT RRSIG), is www MX answered without the responder?
- **Method:** flush; www.nsec3.test AAAA (prime); www.nsec3.test MX.
- **Expected:** Upstream (no NSEC3 synthesis in BIND).
- **Sources:** BIND ARM synth-from-dnssec (NSEC only); RFC 8198 §5.2

## N3-06: NSEC3: positive wildcard (counterpart of N06)

- **Question:** After a wildcard answer for <l1>.wild.nsec3.test (proved by an NSEC3 covering the next closer name), is <l2>.wild, whose hash falls in the same gap, answered without the responder?
- **Method:** flush; two labels whose <label>.wild.nsec3.test hashes share one NSEC3 gap; query both, A.
- **Expected:** Upstream (no NSEC3-based wildcard synthesis in BIND). RFC 8198 §5.3 would allow it.
- **Sources:** BIND ARM synth-from-dnssec (NSEC only); RFC 8198 §5.3

## P01: NSEC TTL above SOA MINIMUM

- **Question:** If NSEC TTL > min(SOA TTL, MINIMUM), does BIND cap it, and for how long does it synthesize?
- **Method:** Zone knob for NSEC TTL; prime; probe same gap past MINIMUM but before NSEC TTL.
- **Expected:** Capped at the negative TTL.
- **Sources:** RFC 8198 §5.4; RFC 9077 §3.4

## P02: NSEC TTL above 3 hours

- **Question:** Does BIND cap the effective NSEC TTL at 10800 s?
- **Method:** Zone knob for a long NSEC and SOA MINIMUM; inspect cache TTL via rndc dumpdb.
- **Expected:** Capped (RECOMMENDED), or at max-ncache-ttl.
- **Sources:** RFC 8198 §5.4; BIND ARM max-ncache-ttl

## P03: Broken proof is not cached or reused

- **Question:** With the wildcard NSEC omitted from NXDOMAIN, does BIND return SERVFAIL, and does it still cache and reuse the qname-covering NSEC?
- **Method:** Per-response knob to drop the wildcard NSEC; probe; then a same-gap name with a correct responder.
- **Expected:** SERVFAIL; no synthesis from the incomplete proof.
- **Sources:** RFC 4035 §5.4; BIND CVE-2026-11721 fix notes

## P04: Expired RRSIG on a cached NSEC

- **Question:** How does BIND treat an NSEC whose RRSIG expires while cached?
- **Method:** Sign with a short validity window; prime; probe after expiry within the TTL.
- **Expected:** No synthesis from an NSEC whose signature has expired.
- **Sources:** RFC 4035 §5.3.1

## P05: Strict QNAME minimisation and the NXDOMAIN cut

- **Question:** With qname-minimization strict, does BIND stop at the minimised NXDOMAIN (RFC 8020) instead of re-asking the full name (contrast with N11)?
- **Method:** BIND config variant (qname-minimization strict); rerun N11.
- **Expected:** One NS query, no full-name query.
- **Sources:** BIND ARM qname-minimization; RFC 9156; RFC 8020
