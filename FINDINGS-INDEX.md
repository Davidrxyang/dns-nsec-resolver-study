# Findings index

One-line view of [FINDINGS.md](FINDINGS.md); each ID links to the full entry, which has the evidence and reasoning. When you add or change a finding, update both files.

Status: **diag** = local pipeline only, re-measure in production · **doc** = documented behavior, reproduced · **conf** = confirmed in production · **fixed** = our tooling, resolved.
Resolver: BIND 9.20.29 unless noted.

## All findings

| ID | Finding | Status | Evidence | Next |
|---|---|---|---|---|
| [A1](FINDINGS.md#a1-bind-synthesizes-negative-answers-even-when-the-client-sets-cd1) | Synthesizes even when client sets **CD=1** (RFC 8198 App. A says not to) | diag | N08 | other resolvers |
| [A2](FINDINGS.md#a2-relaxed-qname-minimisation-re-asks-the-full-name-after-a-validated-nxdomain) | Relaxed QNAME-min **re-asks the full name** after a validated NXDOMAIN | doc | N11 | P05 (strict) |
| [A3](FINDINGS.md#a3-bind-never-synthesizes-from-nsec3-it-fully-synthesizes-from-nsec) | **No synthesis from NSEC3**; full synthesis from NSEC | doc | N01/03/06 vs N3-01/03/06 | baseline for variants |
| [A4](FINDINGS.md#a4-binds-synthesis-covers-every-nsec-case-rfc-8198-allows) | NSEC synthesis covers NXDOMAIN, NODATA, ENT, wildcard (+NODATA) | diag | N01, N03–N07 | — |
| [A5](FINDINGS.md#a5-synthesized-answers-carry-the-remaining-ttl-and-synthesis-stays-inside-what-the-cache-proves) | Synthesized answers carry **remaining TTL**; stop at expiry; no cross-gap | diag | N01, N02, N12 | — |
| [A6](FINDINGS.md#a6-the-clients-do-bit-does-not-affect-priming-or-synthesis) | Client **DO bit irrelevant** to priming and synthesis | diag | N09, N10 | — |
| [A7](FINDINGS.md#a7-synthesized-names-leave-no-trace-of-their-own-in-the-cache-dump) | Synthesized names **leave no cache entry**; only the NSECs are stored | diag (1 obs.) | cache dump | repeat; cache sizes |
| [A8](FINDINGS.md#a8-with-the-authoritative-server-down-bind-takes-more-than-5-s-to-return-servfail) | SERVFAIL takes **> 5 s** with the authority down | diag (1 obs.) | manual control | set probe timeouts |
| [A9](FINDINGS.md#a9-bind-does-not-keep-minimally-covering-nsec-records-for-synthesis) | BIND **does not keep minimal-NSEC records for synthesis** (only attached to negative entries) | diag | MN-02, MN-03, cache dump | find the trigger; BIND source |
| [A10](FINDINGS.md#a10-bind-neither-sends-nor-honors-co-so-clients-see-noerror-for-compact-denied-names) | BIND neither sends nor honors **CO**; clients see **NOERROR** for compact-denied names | diag | CN-01..05, C3-01 | CO-aware resolvers |
| [B1](FINDINGS.md#b1-ldns-drill-rejects-a-correct-nsec-nodata-proof-for-an-empty-non-terminal) | **drill rejects a correct ENT NODATA** proof (delv and BIND accept) | diag | tests/reference.py | Unbound, Knot, PowerDNS |
| [B2](FINDINGS.md#b2-a-broken-nsec3-proof-is-still-valid-when-one-record-covers-two-names) | A "broken" NSEC3 proof can still be valid (one record covers two names) | doc | broken-proof test | pick names for P03 |
| [B3](FINDINGS.md#b3-the-literal-rfc-4470-4-increment-produces-nxdomain-proofs-bind-rejects-and-drill-accepts) | Literal RFC 4470 §4 cover (`\000.q`) **rejected by BIND, accepted by drill** (erratum 6734) | doc | delv vtrace, drill | other resolvers (`cover_next="child"`) |
| [B4](FINDINGS.md#b4-drill-rejects-every-minimal-nsec-ent-proof) | drill rejects **every** minimal-NSEC ENT proof (as B1) | diag | tests/reference.py | — |
| [C1](FINDINGS.md#c1-the-chains-and-all-denial-responses-match-bind-exactly) | Our chains and 81 responses **match BIND exactly** | fixed | tests/reference.py | — |
| [C2](FINDINGS.md#c2-three-non-denial-differences-found-and-aligned-to-bind) | 3 non-denial diffs (NS additional, DNSKEY TTL, NSEC3PARAM TTL) aligned | fixed | tests/reference.py | — |
| [D1](FINDINGS.md#d1-the-com-nsec3-nxdomain-orders-its-proof-as-closest-encloser-match-next-closer-cover-wildcard-cover) | `.com` NSEC3 proof order: CE match, next-closer, wildcard | doc | golden fixture | — |
| [D2](FINDINGS.md#d2-nsec3-nxdomain-size-depends-on-the-qname-because-records-are-reused) | NSEC3 NXDOMAIN has **2 or 3** records depending on the qname | doc | nsec3.test | classifier design |
| [E1](FINDINGS.md#e1-binds-compact-denial-support-is-in-dig-only) | BIND **compact-denial support is dig-only** | doc | release notes | — |
| [E2](FINDINGS.md#e2-several-bind-920x-fixes-touch-exactly-the-paths-under-study) | 9.20.x fixes touch these paths; **version is a variable** | doc | release notes | record digest per run |
| [E3](FINDINGS.md#e3-dig-sends-any-queries-over-tcp-by-default) | dig sends ANY over TCP by default | doc | manual test | — |
| [E4](FINDINGS.md#e4-minimally-covering-nsec3-is-not-rfc-4470-it-is-rfc-7129s-white-lies-deployed-as-powerdns-narrow-mode) | Minimal NSEC3 = RFC 7129 **white lies** (PowerDNS narrow), not RFC 4470; a 6th setup | doc | RFCs, PowerDNS docs | build `minnsec3.test` |

## By theme

- **Leads, possibly publishable:** A1 (CD=1), A9 (BIND silently excludes minimal NSEC from synthesis), B3 (validators split on the literal RFC 4470 form), B1/B4 (validator disagreement on ENT NODATA), A7 (cache footprint of synthesis).
- **Baseline for the variant comparison:** A3, A4, A5, A6, A10.
- **Affects measurement design:** A2 (extra upstream queries), A8 (timeouts), B2 (broken-proof name choice), D2 (record counts), E2 (pin versions), E4 (sixth variant; one-response classifier).
- **Our tooling, settled:** C1, C2.

## Open follow-ups

- [ ] A1, B1: repeat on Unbound, Knot Resolver, PowerDNS Recursor
- [ ] A1: check BIND source or GitLab for intent; does CD=1 change upstream validation?
- [ ] A2: run P05 (strict QNAME minimisation)
- [ ] A7: repeat with several synthesized names; compare cache sizes across variants
- [ ] A8: set experiment probe timeouts above BIND's upstream retry time
- [ ] B1: check the NSEC3 counterpart (passes in drill) and ldns bug reports
- [ ] B2: choose distinct-record names when building P03
- [ ] A9: discriminating experiment for what makes BIND skip minimal NSEC; read BIND's cache/synth code
- [ ] B3: run `cover_next = "child"` against other validators and resolvers
- [ ] A10: find a CO-aware resolver (RFC 9824 §5.1)
- [ ] All diag entries: re-measure in the production setup
