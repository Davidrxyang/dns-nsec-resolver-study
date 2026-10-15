# Experiment catalog

Generated from `experiments/catalog.py` by `venv/bin/python -m experiments catalog`; edit that file, not this one.
Zones: see the ID prefixes in `experiments/catalog.py`. Resolvers: BIND, Knot Resolver and PowerDNS Recursor in the local Docker pipeline (`run --resolver bind|knot|pdns|all`). Results are diagnostics, written to `results/<time>/` (gitignored).

Expected applies to every resolver unless a resolver-specific expectation is listed. ANC experiments are reported as lab artifacts for resolvers whose lab routing disables aggressive caching (see `RESOLVERS` in experiments/harness.py).

| ID | Status | Title | Expected | Resolver-specific | ANC | Sources |
|---|---|---|---|---|---|---|
| N01 | runnable | NXDOMAIN synthesis, same NSEC gap | Synthesized NXDOMAIN with AD, with TTLs about 50 (60 minus the 10 s wait), not reset to 60. | — | yes | RFC 8198 §5.1, §5.4; BIND ARM synth-from-dnssec (NSEC only) |
| N02 | runnable | No synthesis across gaps | Upstream query for the second name (no covering NSEC cached). | — | yes | RFC 8198 §5.1 |
| N03 | runnable | NODATA synthesis, other type at an existing name | Synthesized NODATA (the matching NSEC proves MX is absent). BIND support unknown. | — | yes | RFC 8198 §5.1 |
| N04 | runnable | NODATA synthesis at an empty non-terminal | Synthesized NODATA. BIND support unknown (ENT proofs use a covering, not matching, NSEC). | — | yes | RFC 8198 §5.1; RFC 4035 §5.4 |
| N05 | runnable | NXDOMAIN below a cached NXDOMAIN | Synthesized NXDOMAIN. | — | yes | RFC 8198 §5.1; RFC 8020 |
| N06 | runnable | Positive wildcard synthesis | Synthesized positive answer with AD (RFC SHOULD). BIND support unknown. | — | yes | RFC 8198 §5.3 |
| N07 | runnable | Wildcard NODATA synthesis | Synthesized NODATA (RFC SHOULD). BIND support unknown. | — | yes | RFC 8198 §5.3 |
| N08 | runnable | CD=1 disables synthesis | Upstream: RFC 8198's implementation notes say synthesis applies 'unless the CD bit was set'. The RFC body never mentions CD, so this is guidance, not a requirement. | — | yes | RFC 8198 Appendix A (Detailed Implementation Notes) |
| N09 | runnable | DO=0 client still gets synthesis | Synthesized NXDOMAIN; no NSEC/RRSIG in the response (client did not ask for DNSSEC). | — | yes | RFC 8198 §5 (silent on DO); RFC 4035 §3.2.1 |
| N10 | runnable | Priming from a DO=0 client | Synthesized (the resolver validates regardless of the client's DO). | — | yes | RFC 8198 §5; RFC 4035 §4 |
| N11 | runnable | Upstream queries for a deep nonexistent name | Relaxed QNAME minimisation (BIND default): NS query for m<tag>.nsec.test, then on NXDOMAIN a fallback full query for d1.d2.m<tag>, although the cached NSEC already proves it. Plus a DNSKEY fetch after the flush. | **knot**: Unknown (observation): Knot's minimisation strategy is not documented in the same terms.; **pdns**: Unknown (observation): qname_minimization is on by default (relaxed RFC 9156); nothing_below_nxdomain=dnssec may stop at the validated NXDOMAIN. | no | BIND ARM qname-minimization (relaxed: falls back on NXDOMAIN); RFC 9156; RFC 8020 |
| N12 | runnable (slow) | Synthesis stops after the NSEC TTL | Upstream. | — | yes | RFC 8198 §5.4; RFC 9077 |
| N3-01 | runnable | NSEC3: NXDOMAIN, same hash gap (counterpart of N01) | Upstream: BIND synthesizes from NSEC only; NSEC3 synthesis is 'planned for the future'. RFC 8198 §5.2 would allow it. | **knot**: Unknown (observation): RFC 8198 §5.2 allows NSEC3 synthesis; Knot's docs say only "aggressive caching for DNSSEC-validated data" without restricting it to NSEC. | yes | BIND ARM synth-from-dnssec (NSEC only); RFC 8198 §5.2 |
| N3-03 | runnable | NSEC3: NODATA, other type at an existing name (counterpart of N03) | Upstream (no NSEC3 synthesis in BIND). | **knot**: Unknown (observation): RFC 8198 §5.2 allows NSEC3 synthesis; Knot's docs say only "aggressive caching for DNSSEC-validated data" without restricting it to NSEC. | yes | BIND ARM synth-from-dnssec (NSEC only); RFC 8198 §5.2 |
| N3-06 | runnable | NSEC3: positive wildcard (counterpart of N06) | Upstream (no NSEC3-based wildcard synthesis in BIND). RFC 8198 §5.3 would allow it. | **knot**: Unknown (observation): RFC 8198 §5.2 allows NSEC3 synthesis; Knot's docs say only "aggressive caching for DNSSEC-validated data" without restricting it to NSEC. | yes | BIND ARM synth-from-dnssec (NSEC only); RFC 8198 §5.3 |
| MN-01 | runnable | Minimal NSEC: second name beside a cached NXDOMAIN (counterpart of N01) | Upstream: the cover spans only m<tag>a's subtree, which defeats ANC by design. | — | yes | RFC 4470 §1; RFC 8198 §5.1 |
| MN-02 | runnable | Minimal NSEC: name below a cached NXDOMAIN (counterpart of N05) | Synthesized (the cached cover and wildcard cover prove it). Depends on D14; with cover_next='child' the span would not reach sub.m<tag>a. | **knot**: Upstream: Knot's release notes (4.1.0, 2019) say aggressive caching is disabled for minimal ranges (CLAUDE.md §6); not re-verified for 6.x. | yes | RFC 8198 §5.1; RFC 4470 erratum 6734; docs/VARIANTS.md D14 |
| MN-03 | runnable | Minimal NSEC: NODATA, other type at an existing name (counterpart of N03) | Synthesized: the NSEC at www lists every type, so it proves MX absent. | **knot**: Upstream: Knot's release notes (4.1.0, 2019) say aggressive caching is disabled for minimal ranges (CLAUDE.md §6); not re-verified for 6.x. | yes | RFC 8198 §5.1; RFC 4470 §3 |
| WL-01 | runnable | NSEC3 white lies: second name (counterpart of N3-01) | Upstream: BIND does no NSEC3 synthesis, and the covers span only hash±1. | — | yes | BIND ARM synth-from-dnssec (NSEC only); RFC 7129 App. B |
| CN-01 | runnable | Compact NSEC: rcode the client sees for a nonexistent name | NOERROR with AD: RFC 9824 §5.1 says resolvers reset to NOERROR for queriers without CO; BIND 9.20 has no CO support anyway (FINDINGS INFRA.4). | — | no | RFC 9824 §3.1, §5.1 |
| CN-02 | runnable | Compact NSEC: client sets CO | No: NOERROR without CO and no CO upstream, since BIND's compact-denial support is dig-only. A CO-aware resolver would return NXDOMAIN with CO (RFC 9824 §5.1). | **knot**: Unknown (observation): Knot's documentation does not mention CO or RFC 9824.; **pdns**: Unknown (observation): PowerDNS Recursor documentation does not mention CO or RFC 9824. | no | RFC 9824 §5.1; FINDINGS INFRA.4 |
| CN-03 | runnable | Compact NSEC: same name again is cached | Second query from cache (no upstream). | — | no | RFC 9824 §3.1; RFC 2308 |
| CN-04 | runnable | Compact NSEC: second name (counterpart of N01) | Upstream: each NSEC spans only its owner (RFC 9824 §6: RFC 8198 synthesis not supported). | — | yes | RFC 9824 §6 |
| CN-05 | runnable | Compact NSEC: name below a compact-denied name (counterpart of N05) | Upstream: the NSEC proves nothing about names below its owner, and RFC 8020 NXDOMAIN cuts do not apply (no NXDOMAIN). | — | yes | RFC 9824 §6; RFC 8020 |
| C3-01 | runnable | Compact NSEC3: rcode the client sees for a nonexistent name | NOERROR with AD (as CN-01). | — | no | RFC 9824 §4, §5.1 |
| C3-02 | runnable | Compact NSEC3: second name | Upstream (no NSEC3 synthesis in BIND; single-hash spans). | — | yes | BIND ARM synth-from-dnssec (NSEC only); RFC 9824 §6 |
| P01 | planned | NSEC TTL above SOA MINIMUM | Capped at the negative TTL. | — | yes | RFC 8198 §5.4; RFC 9077 §3.4 |
| P02 | planned | NSEC TTL above 3 hours | Capped (RECOMMENDED), or at max-ncache-ttl. | — | yes | RFC 8198 §5.4; BIND ARM max-ncache-ttl |
| P03 | planned | Broken proof is not cached or reused | SERVFAIL; no synthesis from the incomplete proof. | — | yes | RFC 4035 §5.4; BIND CVE-2026-11721 fix notes |
| P04 | planned | Expired RRSIG on a cached NSEC | No synthesis from an NSEC whose signature has expired. | — | yes | RFC 4035 §5.3.1 |
| P05 | planned | Strict QNAME minimisation and the NXDOMAIN cut | One NS query, no full-name query. | — | yes | BIND ARM qname-minimization; RFC 9156; RFC 8020 |

## N01: NXDOMAIN synthesis, same NSEC gap

- **Question:** After one validated NXDOMAIN, does BIND answer a different name in the same gap without asking the responder? Does the synthesized answer carry the remaining TTL of the cached NSEC/SOA, or a fresh one?
- **Method:** flush; m<tag>a A (prime); wait 10 s; m<tag>b A. Compare upstream queries and authority TTLs.
- **Expected:** Synthesized NXDOMAIN with AD, with TTLs about 50 (60 minus the 10 s wait), not reset to 60.
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 8198 §5.1, §5.4; BIND ARM synth-from-dnssec (NSEC only)

## N02: No synthesis across gaps

- **Question:** Does BIND avoid synthesizing for a name whose covering NSEC it has not cached, even though the wildcard proof (apex NSEC) is cached?
- **Method:** flush; m<tag>a A (prime, caches insecure->ns1 and apex NSEC); p<tag>a A (gap ns1->secure).
- **Expected:** Upstream query for the second name (no covering NSEC cached).
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 8198 §5.1

## N03: NODATA synthesis, other type at an existing name

- **Question:** After NODATA for www AAAA (NSEC at www lists A TXT), does BIND synthesize NODATA for www MX?
- **Method:** flush; www AAAA (prime); www MX.
- **Expected:** Synthesized NODATA (the matching NSEC proves MX is absent). BIND support unknown.
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 8198 §5.1

## N04: NODATA synthesis at an empty non-terminal

- **Question:** After NODATA for ent A (proved by the covering NSEC nsec.test -> host.ent), does BIND synthesize NODATA for ent AAAA?
- **Method:** flush; ent.nsec.test A (prime); ent.nsec.test AAAA.
- **Expected:** Synthesized NODATA. BIND support unknown (ENT proofs use a covering, not matching, NSEC).
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 8198 §5.1; RFC 4035 §5.4

## N05: NXDOMAIN below a cached NXDOMAIN

- **Question:** After NXDOMAIN for m<tag>a, is sub.m<tag>a answered without the responder? (Provable from the cached NSECs; also the RFC 8020 NXDOMAIN cut.)
- **Method:** flush; m<tag>a A (prime); sub.m<tag>a A.
- **Expected:** Synthesized NXDOMAIN.
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 8198 §5.1; RFC 8020

## N06: Positive wildcard synthesis

- **Question:** After a wildcard-expanded answer for x<tag>.wild A, does BIND synthesize y<tag>.wild A from the cached wildcard and NSEC?
- **Method:** flush; x<tag>.wild A (prime); y<tag>.wild A.
- **Expected:** Synthesized positive answer with AD (RFC SHOULD). BIND support unknown.
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 8198 §5.3

## N07: Wildcard NODATA synthesis

- **Question:** After wildcard NODATA for x<tag>.wild TXT, does BIND synthesize NODATA for y<tag>.wild TXT?
- **Method:** flush; x<tag>.wild TXT (prime); y<tag>.wild TXT.
- **Expected:** Synthesized NODATA (RFC SHOULD). BIND support unknown.
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 8198 §5.3

## N08: CD=1 disables synthesis

- **Question:** With the cache primed, does a client query with CD=1 (checking disabled) for a same-gap name go upstream?
- **Method:** flush; m<tag>a A (prime, CD=0); m<tag>b A with CD=1.
- **Expected:** Upstream: RFC 8198's implementation notes say synthesis applies 'unless the CD bit was set'. The RFC body never mentions CD, so this is guidance, not a requirement.
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 8198 Appendix A (Detailed Implementation Notes)

## N09: DO=0 client still gets synthesis

- **Question:** Is synthesis independent of the client's DO bit, and what does a DO=0 client receive?
- **Method:** flush; m<tag>a A (prime, DO=1); m<tag>b A with DO=0.
- **Expected:** Synthesized NXDOMAIN; no NSEC/RRSIG in the response (client did not ask for DNSSEC).
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 8198 §5 (silent on DO); RFC 4035 §3.2.1

## N10: Priming from a DO=0 client

- **Question:** If the first query comes from a DO=0 client, does BIND still fetch, validate, and cache the NSECs so a later DO=1 query is synthesized?
- **Method:** flush; m<tag>a A with DO=0 (prime); m<tag>b A with DO=1.
- **Expected:** Synthesized (the resolver validates regardless of the client's DO).
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 8198 §5; RFC 4035 §4

## N11: Upstream queries for a deep nonexistent name

- **Question:** Which queries does BIND send to the responder for a nonexistent name three labels below the apex, and does it stop at the validated NXDOMAIN for the minimised name?
- **Method:** flush; d1.d2.m<tag>.nsec.test A; record the upstream query sequence.
- **Expected:** Relaxed QNAME minimisation (BIND default): NS query for m<tag>.nsec.test, then on NXDOMAIN a fallback full query for d1.d2.m<tag>, although the cached NSEC already proves it. Plus a DNSKEY fetch after the flush.
- **Expected (knot):** Unknown (observation): Knot's minimisation strategy is not documented in the same terms.
- **Expected (pdns):** Unknown (observation): qname_minimization is on by default (relaxed RFC 9156); nothing_below_nxdomain=dnssec may stop at the validated NXDOMAIN.
- **Tests aggressive negative caching:** no
- **Sources:** BIND ARM qname-minimization (relaxed: falls back on NXDOMAIN); RFC 9156; RFC 8020

## N12: Synthesis stops after the NSEC TTL

- **Question:** Once the primed NSEC records expire (TTL 60 s), does a same-gap query go upstream again?
- **Method:** flush; m<tag>a A (prime); wait 65 s; m<tag>b A.
- **Expected:** Upstream.
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 8198 §5.4; RFC 9077

## N3-01: NSEC3: NXDOMAIN, same hash gap (counterpart of N01)

- **Question:** After one validated NSEC3 NXDOMAIN, is a different name whose hash falls in the same NSEC3 gap answered without the responder?
- **Method:** flush; two labels chosen so their hashes share one NSEC3 gap; <l1>.nsec3.test A (prime); <l2>.nsec3.test A.
- **Expected:** Upstream: BIND synthesizes from NSEC only; NSEC3 synthesis is 'planned for the future'. RFC 8198 §5.2 would allow it.
- **Expected (knot):** Unknown (observation): RFC 8198 §5.2 allows NSEC3 synthesis; Knot's docs say only "aggressive caching for DNSSEC-validated data" without restricting it to NSEC.
- **Tests aggressive negative caching:** yes
- **Sources:** BIND ARM synth-from-dnssec (NSEC only); RFC 8198 §5.2

## N3-03: NSEC3: NODATA, other type at an existing name (counterpart of N03)

- **Question:** After NODATA for www AAAA (matching NSEC3 lists A TXT RRSIG), is www MX answered without the responder?
- **Method:** flush; www.nsec3.test AAAA (prime); www.nsec3.test MX.
- **Expected:** Upstream (no NSEC3 synthesis in BIND).
- **Expected (knot):** Unknown (observation): RFC 8198 §5.2 allows NSEC3 synthesis; Knot's docs say only "aggressive caching for DNSSEC-validated data" without restricting it to NSEC.
- **Tests aggressive negative caching:** yes
- **Sources:** BIND ARM synth-from-dnssec (NSEC only); RFC 8198 §5.2

## N3-06: NSEC3: positive wildcard (counterpart of N06)

- **Question:** After a wildcard answer for <l1>.wild.nsec3.test (proved by an NSEC3 covering the next closer name), is <l2>.wild, whose hash falls in the same gap, answered without the responder?
- **Method:** flush; two labels whose <label>.wild.nsec3.test hashes share one NSEC3 gap; query both, A.
- **Expected:** Upstream (no NSEC3-based wildcard synthesis in BIND). RFC 8198 §5.3 would allow it.
- **Expected (knot):** Unknown (observation): RFC 8198 §5.2 allows NSEC3 synthesis; Knot's docs say only "aggressive caching for DNSSEC-validated data" without restricting it to NSEC.
- **Tests aggressive negative caching:** yes
- **Sources:** BIND ARM synth-from-dnssec (NSEC only); RFC 8198 §5.3

## MN-01: Minimal NSEC: second name beside a cached NXDOMAIN (counterpart of N01)

- **Question:** After a validated minimal-NSEC NXDOMAIN for m<tag>a, is m<tag>b (adjacent, but outside the one-name span) answered without the responder?
- **Method:** flush; m<tag>a.minnsec.test A (prime); m<tag>b.minnsec.test A.
- **Expected:** Upstream: the cover spans only m<tag>a's subtree, which defeats ANC by design.
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 4470 §1; RFC 8198 §5.1

## MN-02: Minimal NSEC: name below a cached NXDOMAIN (counterpart of N05)

- **Question:** Is sub.m<tag>a answered from the cached cover for m<tag>a? The cover predecessor(m<tag>a) -> m<tag>a\000 spans m<tag>a's whole subtree (decision D14).
- **Method:** flush; m<tag>a.minnsec.test A (prime); sub.m<tag>a.minnsec.test A.
- **Expected:** Synthesized (the cached cover and wildcard cover prove it). Depends on D14; with cover_next='child' the span would not reach sub.m<tag>a.
- **Expected (knot):** Upstream: Knot's release notes (4.1.0, 2019) say aggressive caching is disabled for minimal ranges (CLAUDE.md §6); not re-verified for 6.x.
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 8198 §5.1; RFC 4470 erratum 6734; docs/VARIANTS.md D14

## MN-03: Minimal NSEC: NODATA, other type at an existing name (counterpart of N03)

- **Question:** After NODATA for www AAAA (online NSEC at www with the full bitmap), is www MX answered without the responder?
- **Method:** flush; www.minnsec.test AAAA (prime); www.minnsec.test MX.
- **Expected:** Synthesized: the NSEC at www lists every type, so it proves MX absent.
- **Expected (knot):** Upstream: Knot's release notes (4.1.0, 2019) say aggressive caching is disabled for minimal ranges (CLAUDE.md §6); not re-verified for 6.x.
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 8198 §5.1; RFC 4470 §3

## WL-01: NSEC3 white lies: second name (counterpart of N3-01)

- **Question:** After a white-lies NXDOMAIN, is a second nonexistent name answered without the responder?
- **Method:** flush; r<tag>a.minnsec3.test A (prime); r<tag>b.minnsec3.test A.
- **Expected:** Upstream: BIND does no NSEC3 synthesis, and the covers span only hash±1.
- **Tests aggressive negative caching:** yes
- **Sources:** BIND ARM synth-from-dnssec (NSEC only); RFC 7129 App. B

## CN-01: Compact NSEC: rcode the client sees for a nonexistent name

- **Question:** What rcode and AD does a client without CO get from BIND for a compact-denied name?
- **Method:** flush; nx<tag>.cdoe-nsec.test A (DO=1, CO=0).
- **Expected:** NOERROR with AD: RFC 9824 §5.1 says resolvers reset to NOERROR for queriers without CO; BIND 9.20 has no CO support anyway (FINDINGS INFRA.4).
- **Tests aggressive negative caching:** no
- **Sources:** RFC 9824 §3.1, §5.1

## CN-02: Compact NSEC: client sets CO

- **Question:** Does BIND restore NXDOMAIN for a client that sets CO, and does it send CO upstream?
- **Method:** flush; nx<tag>.cdoe-nsec.test A with CO=1; check the response and BIND's upstream queries.
- **Expected:** No: NOERROR without CO and no CO upstream, since BIND's compact-denial support is dig-only. A CO-aware resolver would return NXDOMAIN with CO (RFC 9824 §5.1).
- **Expected (knot):** Unknown (observation): Knot's documentation does not mention CO or RFC 9824.
- **Expected (pdns):** Unknown (observation): PowerDNS Recursor documentation does not mention CO or RFC 9824.
- **Tests aggressive negative caching:** no
- **Sources:** RFC 9824 §5.1; FINDINGS INFRA.4

## CN-03: Compact NSEC: same name again is cached

- **Question:** Is a repeated query for a compact-denied name answered from the (NODATA) negative cache?
- **Method:** flush; nx<tag>.cdoe-nsec.test A twice.
- **Expected:** Second query from cache (no upstream).
- **Tests aggressive negative caching:** no
- **Sources:** RFC 9824 §3.1; RFC 2308

## CN-04: Compact NSEC: second name (counterpart of N01)

- **Question:** After a compact denial for m<tag>a, is m<tag>b answered without the responder?
- **Method:** flush; m<tag>a.cdoe-nsec.test A (prime); m<tag>b.cdoe-nsec.test A.
- **Expected:** Upstream: each NSEC spans only its owner (RFC 9824 §6: RFC 8198 synthesis not supported).
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 9824 §6

## CN-05: Compact NSEC: name below a compact-denied name (counterpart of N05)

- **Question:** After a compact denial for m<tag>a (an NSEC saying m<tag>a 'exists' with only NXNAME), is sub.m<tag>a answered without the responder?
- **Method:** flush; m<tag>a.cdoe-nsec.test A (prime); sub.m<tag>a.cdoe-nsec.test A.
- **Expected:** Upstream: the NSEC proves nothing about names below its owner, and RFC 8020 NXDOMAIN cuts do not apply (no NXDOMAIN).
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 9824 §6; RFC 8020

## C3-01: Compact NSEC3: rcode the client sees for a nonexistent name

- **Question:** What rcode and AD does a client get from BIND for a compact-denied NSEC3 name?
- **Method:** flush; nx<tag>.cdoe-nsec3.test A.
- **Expected:** NOERROR with AD (as CN-01).
- **Tests aggressive negative caching:** no
- **Sources:** RFC 9824 §4, §5.1

## C3-02: Compact NSEC3: second name

- **Question:** After a compact NSEC3 denial, is a second nonexistent name answered without the responder?
- **Method:** flush; m<tag>a.cdoe-nsec3.test A (prime); m<tag>b.cdoe-nsec3.test A.
- **Expected:** Upstream (no NSEC3 synthesis in BIND; single-hash spans).
- **Tests aggressive negative caching:** yes
- **Sources:** BIND ARM synth-from-dnssec (NSEC only); RFC 9824 §6

## P01: NSEC TTL above SOA MINIMUM

- **Question:** If NSEC TTL > min(SOA TTL, MINIMUM), does BIND cap it, and for how long does it synthesize?
- **Method:** Zone knob for NSEC TTL; prime; probe same gap past MINIMUM but before NSEC TTL.
- **Expected:** Capped at the negative TTL.
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 8198 §5.4; RFC 9077 §3.4

## P02: NSEC TTL above 3 hours

- **Question:** Does BIND cap the effective NSEC TTL at 10800 s?
- **Method:** Zone knob for a long NSEC and SOA MINIMUM; inspect cache TTL via rndc dumpdb.
- **Expected:** Capped (RECOMMENDED), or at max-ncache-ttl.
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 8198 §5.4; BIND ARM max-ncache-ttl

## P03: Broken proof is not cached or reused

- **Question:** With the wildcard NSEC omitted from NXDOMAIN, does BIND return SERVFAIL, and does it still cache and reuse the qname-covering NSEC?
- **Method:** Per-response knob to drop the wildcard NSEC; probe; then a same-gap name with a correct responder.
- **Expected:** SERVFAIL; no synthesis from the incomplete proof.
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 4035 §5.4; BIND CVE-2026-11721 fix notes

## P04: Expired RRSIG on a cached NSEC

- **Question:** How does BIND treat an NSEC whose RRSIG expires while cached?
- **Method:** Sign with a short validity window; prime; probe after expiry within the TTL.
- **Expected:** No synthesis from an NSEC whose signature has expired.
- **Tests aggressive negative caching:** yes
- **Sources:** RFC 4035 §5.3.1

## P05: Strict QNAME minimisation and the NXDOMAIN cut

- **Question:** With qname-minimization strict, does BIND stop at the minimised NXDOMAIN (RFC 8020) instead of re-asking the full name (contrast with N11)?
- **Method:** BIND config variant (qname-minimization strict); rerun N11.
- **Expected:** One NS query, no full-name query.
- **Tests aggressive negative caching:** yes
- **Sources:** BIND ARM qname-minimization; RFC 9156; RFC 8020
