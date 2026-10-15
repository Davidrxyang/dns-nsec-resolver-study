# Findings index

Resolver matrix of [FINDINGS.md](FINDINGS.md): one row per finding, one column per resolver; each ID links to the full entry with evidence and status. When you add a finding or test a resolver, update both files.

Resolvers: BIND 9.20.29 · Knot Resolver 6.5.0 · PowerDNS Recursor 5.4.7 · Unbound not deployed yet (—). **Bold** marks a difference between resolvers or a key result. *lab artifact* = not measurable in the local lab for that resolver (INFRA.7). `n/a` rows are not resolver behavior.

## ALL: Across all variants

| ID | Finding | BIND | Knot | Unbound | PowerDNS | Next |
|---|---|---|---|---|---|---|
| [ALL.1](FINDINGS.md#all1-every-resolver-validates-every-variant) | Every resolver validates all six variants | ✓ all AD | ✓ all AD | — | ✓ all AD | — |
| [ALL.2](FINDINGS.md#all2-synthesized-answers-carry-the-remaining-ttl-and-synthesis-stops-at-expiry-and-at-the-edge-of-what-the-cache-proves) | Synthesis uses remaining TTL; stops at expiry and gap edges | ✓ | ✓ | — | *lab artifact* | — |
| [ALL.3](FINDINGS.md#all3-the-clients-do-bit-does-not-affect-priming-or-synthesis) | Client DO bit doesn't affect priming or synthesis | ✓ | ✓ | — | *lab artifact* | — |
| [ALL.4](FINDINGS.md#all4-resolvers-synthesize-even-when-the-client-sets-cd1-and-differ-on-ad) | Synthesis despite CD=1 (RFC 8198 App. A says no) | synth, **AD=1** | synth, **AD=0** | — | *lab artifact* | sources; RFC 6840 |
| [ALL.5](FINDINGS.md#all5-relaxed-qname-minimisation-re-asks-the-full-name-after-a-validated-nxdomain) | Relaxed QNAME-min re-asks the full name after NXDOMAIN | yes (NS, ARM) | yes (NS) | — | yes (**qtype A**) | P05 strict |
| [ALL.6](FINDINGS.md#all6-upstream-query-name-casing-0x20) | Upstream qname case randomization (0x20) | no | **yes** | — | no | — |
| [ALL.7](FINDINGS.md#all7-resolver-initiated-upstream-queries) | Resolver-initiated upstream queries | none seen | **`_ta-*` NULL** (RFC 8145) | — | none seen | — |
| [ALL.8](FINDINGS.md#all8-time-to-servfail-when-the-authoritative-server-is-down) | Time to SERVFAIL with the authority down | > 5 s | < 30 s | — | < 30 s | measure |

## NSEC: Vanilla NSEC

| ID | Finding | BIND | Knot | Unbound | PowerDNS | Next |
|---|---|---|---|---|---|---|
| [NSEC.1](FINDINGS.md#nsec1-aggressive-synthesis-covers-every-nsec-case-rfc-8198-allows) | Synthesizes every RFC 8198 NSEC case | ✓ all six | ✓ all six | — | *lab artifact* | — |
| [NSEC.2](FINDINGS.md#nsec2-synthesized-names-leave-no-per-name-cache-entry) | Synthesized names leave no per-name cache entry | yes (1 dump) | — | — | — | repeat; Knot/PowerDNS cache dumps |
| [NSEC.3](FINDINGS.md#nsec3-validators-disagree-on-an-ent-nodata-proved-by-a-covering-nsec) | Validators split on ENT NODATA via covering NSEC (drill rejects) | delv ✓ | — | — | — | add `wild` experiment |

## NSEC3: Vanilla NSEC3

| ID | Finding | BIND | Knot | Unbound | PowerDNS | Next |
|---|---|---|---|---|---|---|
| [NSEC3.1](FINDINGS.md#nsec31-synthesis-from-nsec3-splits-the-resolvers) | **Synthesis from NSEC3** | **never** (ARM) | **yes**; wildcard variable (2/8) | — | *lab artifact* | opt-out; TTL; Knot N3-06 |
| [NSEC3.2](FINDINGS.md#nsec32-nsec3-nxdomain-has-2-or-3-records-depending-on-the-name) | NXDOMAIN has 2 or 3 NSEC3 depending on name | n/a (zone property) | | | | classifier |
| [NSEC3.3](FINDINGS.md#nsec33-a-broken-nsec3-proof-is-still-valid-when-one-record-covers-two-names) | A 'broken' proof can still be valid | n/a (methodology) | | | | P03 names |
| [NSEC3.4](FINDINGS.md#nsec34-real-world-reference-com-orders-its-proof-as-closest-encloser-match-next-closer-cover-wildcard-cover) | `.com` proof order: CE match, next closer, wildcard | n/a (reference data) | | | | — |

## MINNSEC: Minimally covering NSEC (RFC 4470)

| ID | Finding | BIND | Knot | Unbound | PowerDNS | Next |
|---|---|---|---|---|---|---|
| [MINNSEC.1](FINDINGS.md#minnsec1-no-resolver-synthesizes-from-minimally-covering-nsec) | **No synthesis from minimal NSEC**, even where provable | none (undocumented; not cached standalone) | none (documented) | — | *lab artifact* | find BIND trigger |
| [MINNSEC.2](FINDINGS.md#minnsec2-the-literal-rfc-4470-4-cover-is-rejected-by-some-validators-and-accepted-by-others) | Literal RFC 4470 §4 cover (`\000.q`): validators split | delv ✗; drill ✓ | — | — | — | `cover_next=child` on all |
| [MINNSEC.3](FINDINGS.md#minnsec3-drill-rejects-every-minimal-nsec-ent-proof) | drill rejects every minimal-NSEC ENT proof | delv ✓ | — | — | — | ENT experiments |

## WL: NSEC3 white lies (RFC 7129 App. B)

| ID | Finding | BIND | Knot | Unbound | PowerDNS | Next |
|---|---|---|---|---|---|---|
| [WL.1](FINDINGS.md#wl1-minimally-covering-nsec3-is-rfc-7129s-white-lies-not-rfc-4470) | Minimal NSEC3 = RFC 7129 white lies (PowerDNS narrow) | n/a (documentation) | | | | — |
| [WL.2](FINDINGS.md#wl2-no-resolver-synthesizes-from-white-lies) | No synthesis from white lies | none | none (despite NSEC3.1) | — | *lab artifact*; documented: none |  |

## CDOE: Compact denial (RFC 9824)

| ID | Finding | BIND | Knot | Unbound | PowerDNS | Next |
|---|---|---|---|---|---|---|
| [CDOE.1](FINDINGS.md#cdoe1-clients-see-noerror-for-nonexistent-names-and-no-resolver-sends-or-honors-co) | Clients see NOERROR; CO neither sent nor honored | NOERROR, no CO | NOERROR, no CO | — | NOERROR, no CO | CO-aware resolver |
| [CDOE.2](FINDINGS.md#cdoe2-compact-answers-are-cached-per-name-and-never-synthesized-for-other-names) | Cached per name, never synthesized for other names | ✓ | ✓ | — | ✓ | — |

## INFRA: Validators, responder, environment

| ID | Finding | BIND | Knot | Unbound | PowerDNS | Next |
|---|---|---|---|---|---|---|
| [INFRA.1](FINDINGS.md#infra1-our-chains-and-denial-responses-match-binds-signer-and-server-exactly) | Our chains and responses match BIND's signer/server | n/a (resolved) | | | | — |
| [INFRA.2](FINDINGS.md#infra2-three-non-denial-differences-from-bind-were-found-and-aligned) | 3 non-denial diffs aligned to BIND | n/a (resolved) | | | | — |
| [INFRA.3](FINDINGS.md#infra3-several-bind-920x-fixes-touch-exactly-the-paths-under-study) | BIND 9.20.x fixes touch our paths: version is a variable | n/a (documentation) | | | | record digests |
| [INFRA.4](FINDINGS.md#infra4-binds-compact-denial-support-is-in-dig-only) | BIND's compact-denial support is dig-only | n/a (documentation) | | | | — |
| [INFRA.5](FINDINGS.md#infra5-the-official-knot-resolver-v650-image-reports-a-development-version) | Knot image tagged v6.5.0 reports 6.5.0.dev1+928fe2 | n/a (environment) | | | | record version |
| [INFRA.6](FINDINGS.md#infra6-dig-sends-any-queries-over-tcp-by-default) | dig sends ANY over TCP by default | n/a (tooling) | | | | — |
| [INFRA.7](FINDINGS.md#infra7-the-labs-zone-routing-static-stub--forward-is-not-neutral-powerdns-disables-aggressive-caching-for-forwarded-zones) | **Lab routing isn't neutral: PowerDNS skips ANC for forwarded zones** | n/a (methodology; affects PowerDNS) | | | | **local delegation setup** |

## Where resolvers differ so far

- **NSEC3.1:** Knot synthesizes from NSEC3 (wildcard case variable); BIND never does; PowerDNS can't be measured in the lab.
- **ALL.4:** both BIND and Knot synthesize for CD=1 queries, but BIND sets AD and Knot clears it.
- **ALL.5:** all three re-ask the full name; PowerDNS minimises with qtype A, BIND and Knot with NS.
- **ALL.6 / ALL.7:** only Knot randomizes qname case and sends RFC 8145 signalling queries.
- **INFRA.7:** PowerDNS disables aggressive caching for forwarded zones, so the lab's routing method itself differs in effect per resolver.

## Leads, possibly publishable

- **NSEC3.1:** NSEC3 synthesis splits resolvers.
- **MINNSEC.1:** BIND and Knot skip minimal NSEC; BIND's is undocumented.
- **MINNSEC.2:** validators split on the literal RFC 4470 form (erratum 6734).
- **NSEC.3 / MINNSEC.3:** validator disagreement on ENT NODATA.
- **ALL.4:** CD=1 and AD.
- **INFRA.7:** forwarding disables ANC in PowerDNS, relevant to operators who forward internal zones.

## Open follow-ups

- [ ] **INFRA.7: local delegation setup** (signed local root or `test.` parent, root hints, root trust anchor) so all resolvers, PowerDNS included, resolve as on the Internet; then rerun the catalogue
- [ ] Deploy Unbound; fill its column
- [ ] MINNSEC.1: discriminating experiment for what makes BIND skip minimal NSEC; BIND source
- [ ] MINNSEC.2: run a `cover_next = "child"` zone through every resolver
- [ ] NSEC.3 / MINNSEC.3: add ENT-NODATA experiments (`wild`, `ent` in nsec/minnsec zones) for every resolver
- [ ] NSEC3.1: NSEC3 opt-out zone, NSEC3 TTL expiry, and Knot's N3-06 variability
- [ ] ALL.4: check BIND and Knot sources; RFC 6840 reading of AD on CD=1
- [ ] ALL.5: P05 (strict QNAME minimisation)
- [ ] ALL.8: measure time to SERVFAIL per resolver
- [ ] NSEC.2: repeat cache-footprint observation; Knot and PowerDNS cache dumps
- [ ] CDOE.1: find a CO-aware resolver
- [ ] NSEC3.3: choose distinct-record names when building P03
- [ ] All diag entries: re-measure in the production setup
