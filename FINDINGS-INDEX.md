# Findings index

Resolver matrix of [FINDINGS.md](FINDINGS.md): one row per finding, one column per resolver; each ID links to the full entry with evidence and status. When you add a finding or test a resolver, update both files.

Resolvers: BIND 9.20.29 · Knot Resolver 6.5.0 · Unbound 1.26.1 · PowerDNS Recursor 5.4.7. All reach the zones by delegation from the lab's local root; lab-only exemptions from resolver defaults are listed in INFRA.8. **Bold** marks a difference between resolvers or a key result. `n/a` rows are not resolver behavior.

## ALL: Across all variants

| ID | Finding | BIND | Knot | Unbound | PowerDNS | Next |
|---|---|---|---|---|---|---|
| [ALL.1](FINDINGS.md#all1-every-resolver-validates-every-variant) | Every resolver validates all six variants | ✓ all AD | ✓ all AD | ✓ all AD | ✓ all AD | — |
| [ALL.2](FINDINGS.md#all2-synthesized-answers-carry-the-remaining-ttl-and-synthesis-stops-at-expiry-and-at-the-edge-of-what-the-cache-proves) | Synthesis uses remaining TTL; stops at expiry and gap edges | ✓ | ✓ | ✓ | ✓ | — |
| [ALL.3](FINDINGS.md#all3-the-clients-do-bit-does-not-affect-priming-or-synthesis) | Client DO bit doesn't affect priming or synthesis | ✓ | ✓ | ✓ | ✓ | — |
| [ALL.4](FINDINGS.md#all4-resolvers-synthesize-even-when-the-client-sets-cd1-and-differ-on-ad) | Synthesis despite CD=1 (RFC 8198 App. A says no) | synth, **AD=1** | synth, **AD=0** | synth, **AD=1** | synth, **AD=1** | sources (intent) |
| [ALL.5](FINDINGS.md#all5-the-upstream-query-pattern-for-a-deep-nonexistent-name-differs-by-resolver-and-by-routing) | Deep-name upstream pattern (delegation) | NS min., +NS AAAA, full name (4) | **no min.**, full name (2) | A min., **stops** (RFC 8020) (2) | A min., **stops** (RFC 8020) (2) | P05 strict |
| [ALL.6](FINDINGS.md#all6-upstream-query-name-casing-0x20) | Upstream qname case randomization (0x20) | no | **yes** | no | no | — |
| [ALL.7](FINDINGS.md#all7-resolver-initiated-upstream-queries) | Resolver-initiated upstream queries | none seen | `_ta-*` NULL (RFC 8145) | `_ta-*` **type A** (RFC 8145 says NULL) | none seen | — |
| [ALL.8](FINDINGS.md#all8-time-to-servfail-when-the-authoritative-server-is-down) | Time to SERVFAIL when the authority is down | ~10 s | ~7 s | **never over UDP** (discard-timeout); ~25 s internally | ~2 s | repeat over UDP |
| [ALL.9](FINDINGS.md#all9-resolvers-may-answer-test-names-themselves-rfc-6761-special-use-handling) | Answers `.test` itself (RFC 6761) | no | **yes, NXDOMAIN with AD** | **yes, NXDOMAIN with aa, no AD** | no | — |
| [ALL.10](FINDINGS.md#all10-resolvers-may-refuse-to-query-nameservers-at-private-or-special-purpose-addresses) | Refuses to query private nameserver addresses by default | no | no | no | **yes** (`dont_query` incl. 172.16/12) | — |

## NSEC: Vanilla NSEC

| ID | Finding | BIND | Knot | Unbound | PowerDNS | Next |
|---|---|---|---|---|---|---|
| [NSEC.1](FINDINGS.md#nsec1-aggressive-synthesis-covers-every-nsec-case-rfc-8198-allows) | Synthesizes every RFC 8198 NSEC case | ✓ all six | ✓ all six | ✓ all six | ✓ all six | — |
| [NSEC.2](FINDINGS.md#nsec2-what-synthesis-stores-differs-bind-keeps-no-per-name-entry-unbound-does) | What synthesis stores (per-name entry?) | no entry (1 dump) | — | **message entry per synthesized name** (1 dump) | — | repeat; Knot/PowerDNS cache dumps |
| [NSEC.3](FINDINGS.md#nsec3-validators-disagree-on-an-ent-nodata-proved-by-a-covering-nsec) | Validators split on ENT NODATA via covering NSEC (drill rejects) | accepts | accepts | accepts | accepts | catalogue experiment |

## NSEC3: Vanilla NSEC3

| ID | Finding | BIND | Knot | Unbound | PowerDNS | Next |
|---|---|---|---|---|---|---|
| [NSEC3.1](FINDINGS.md#nsec31-synthesis-from-nsec3-splits-the-resolvers) | **Synthesis from NSEC3** | **never** (ARM) | **yes**; wildcard variable (4/10) | **never** (docs: NSEC chain) | **yes**; wildcard no (2 runs) | opt-out; TTL; wildcard |
| [NSEC3.2](FINDINGS.md#nsec32-nsec3-nxdomain-has-2-or-3-records-depending-on-the-name) | NXDOMAIN has 2 or 3 NSEC3 depending on name | n/a (zone property) | | | | classifier |
| [NSEC3.3](FINDINGS.md#nsec33-a-broken-nsec3-proof-is-still-valid-when-one-record-covers-two-names) | A 'broken' proof can still be valid | n/a (methodology) | | | | P03 names |
| [NSEC3.4](FINDINGS.md#nsec34-real-world-reference-com-orders-its-proof-as-closest-encloser-match-next-closer-cover-wildcard-cover) | `.com` proof order: CE match, next closer, wildcard | n/a (reference data) | | | | — |

## MINNSEC: Minimally covering NSEC (RFC 4470)

| ID | Finding | BIND | Knot | Unbound | PowerDNS | Next |
|---|---|---|---|---|---|---|
| [MINNSEC.1](FINDINGS.md#minnsec1-resolvers-mostly-keep-minimally-covering-nsec-out-of-synthesis-unbound-uses-it-for-nodata) | **Synthesis from minimal NSEC** | none (source: `is_minimal_nsec`, `has_000_label`) | none (source; documented) | **NODATA synthesized (MN-03, 5/5)**; MN-02 via RFC 8020 | none (MN-02 via RFC 8020) | why Unbound; encoding knob |
| [MINNSEC.2](FINDINGS.md#minnsec2-the-literal-rfc-4470-4-cover-is-rejected-by-some-validators-and-accepted-by-others) | Literal RFC 4470 §4 cover (`\000.q`): validators split | delv ✗; drill ✓ | — | — | — | `cover_next=child` on all |
| [MINNSEC.3](FINDINGS.md#minnsec3-drill-rejects-every-minimal-nsec-ent-proof) | drill rejects every minimal-NSEC ENT proof | accepts | accepts | accepts | accepts | — |
| [MINNSEC.4](FINDINGS.md#minnsec4-resolvers-recognize-minimal-nsec-by-its-shape-a-heuristic) | **Minimal NSEC recognized by shape** (heuristic) | bitmap = `RRSIG NSEC`, or next starts with `\000` | zero byte in next-name label; NSEC3 hash+1 | none (no filter) | next = `\000.`owner only | encoding knob

## WL: NSEC3 white lies (RFC 7129 App. B)

| ID | Finding | BIND | Knot | Unbound | PowerDNS | Next |
|---|---|---|---|---|---|---|
| [WL.1](FINDINGS.md#wl1-minimally-covering-nsec3-is-rfc-7129s-white-lies-not-rfc-4470) | Minimal NSEC3 = RFC 7129 white lies (PowerDNS narrow) | n/a (documentation) | | | |  |
| [WL.2](FINDINGS.md#wl2-no-resolver-synthesizes-from-white-lies) | No synthesis from white lies | none | none (despite NSEC3.1) | none | none (documented filter) |  |

## CDOE: Compact denial (RFC 9824)

| ID | Finding | BIND | Knot | Unbound | PowerDNS | Next |
|---|---|---|---|---|---|---|
| [CDOE.1](FINDINGS.md#cdoe1-clients-see-noerror-for-nonexistent-names-and-no-resolver-sends-or-honors-co) | Clients see NOERROR; CO neither sent nor honored | NOERROR, no CO | NOERROR, no CO | NOERROR, no CO | NOERROR, no CO | CO-aware resolver; NXDOMAIN restoration (§5) |
| [CDOE.2](FINDINGS.md#cdoe2-compact-answers-are-cached-per-name-and-never-synthesized-for-other-names) | Cached per name, never synthesized for other names | ✓ | ✓ | ✓ | ✓ | — |

## INFRA: Validators, responder, environment

| ID | Finding | BIND | Knot | Unbound | PowerDNS | Next |
|---|---|---|---|---|---|---|
| [INFRA.1](FINDINGS.md#infra1-our-chains-and-denial-responses-match-binds-signer-and-server-exactly) | Our chains and responses match BIND's signer/server | n/a (resolved) | | | | — |
| [INFRA.2](FINDINGS.md#infra2-three-non-denial-differences-from-bind-were-found-and-aligned) | 3 non-denial diffs aligned to BIND | n/a (resolved) | | | | — |
| [INFRA.3](FINDINGS.md#infra3-several-bind-920x-fixes-touch-exactly-the-paths-under-study) | BIND 9.20.x fixes touch our paths: version is a variable | n/a (documentation) | | | | record digests |
| [INFRA.4](FINDINGS.md#infra4-binds-compact-denial-support-is-in-dig-only) | BIND's compact-denial support is dig-only | n/a (documentation) | | | | — |
| [INFRA.5](FINDINGS.md#infra5-the-official-knot-resolver-v650-image-reports-a-development-version) | Knot image tagged v6.5.0 reports 6.5.0.dev1+928fe2 | n/a (environment) | | | | record version |
| [INFRA.6](FINDINGS.md#infra6-dig-sends-any-queries-over-tcp-by-default) | dig sends ANY over TCP by default | n/a (tooling) | | | | — |
| [INFRA.7](FINDINGS.md#infra7-the-labs-zone-routing-static-stub--forward-is-not-neutral-powerdns-disables-aggressive-caching-for-forwarded-zones) | PowerDNS skips ANC for forwarded zones (lab routing not neutral) | n/a (methodology; resolved by INFRA.8) | | | | — |
| [INFRA.8](FINDINGS.md#infra8-local-delegation-setup-resolvers-reach-the-zones-from-a-signed-local-root) | **Local delegation setup**: signed local root, hints, root anchor; lab-only exemptions | n/a (lab infrastructure) | | | | remove exemptions in the wild |
| [INFRA.9](FINDINGS.md#infra9-unbound-built-from-source-and-its-cache-flush-needs-two-commands) | Unbound built from the signed tarball; flush = reload + flush_infra | n/a (environment) | | | | — |

## Where resolvers differ so far

- **NSEC3.1:** Knot and PowerDNS synthesize from NSEC3; BIND and Unbound never do.
- **MINNSEC.1:** only Unbound synthesizes from a minimal NSEC (NODATA at an existing name); the others keep minimal NSEC out of synthesis, because online-signed bitmaps are untrusted. This exposes Unbound to wrong bitmaps (inferred, not observed).
- **MINNSEC.4:** BIND, Knot and PowerDNS recognize minimal NSEC by three different shape rules (BIND alone uses the bitmap); misses, not false positives, are the risk.
- **ALL.4:** all four synthesize for CD=1 queries; BIND, PowerDNS and Unbound set AD, Knot clears it. Both conform to RFC 4035/6840, which tie AD to authenticity, not to CD.
- **ALL.5:** deep-name query patterns differ: BIND minimises with NS and falls back to the full name; PowerDNS and Unbound minimise with A and stop at the NXDOMAIN (RFC 8020); Knot doesn't minimise below the cut.
- **ALL.8:** Unbound never delivers SERVFAIL over UDP for a dead authority (discard-timeout); the others do.
- **ALL.9:** Knot and Unbound answer `.test` themselves, Knot with AD, Unbound with aa and no AD.
- **ALL.6 / ALL.7:** only Knot randomizes qname case; Knot and Unbound send RFC 8145 signalling, Unbound with the wrong qtype (A).
- **ALL.10:** only PowerDNS refuses private nameserver addresses by default.
- **NSEC.2:** Unbound stores a message-cache entry per synthesized name; BIND doesn't.
- **INFRA.7:** PowerDNS disables aggressive caching for forwarded zones (resolved in the lab by INFRA.8).

## Leads, possibly publishable

- **NSEC3.1:** NSEC3 synthesis splits resolvers two against two.
- **MINNSEC.1 / MINNSEC.4:** Unbound alone synthesizes from minimal NSEC; the others filter by shape (BIND's filter is undocumented, found in source), so behavior depends on the signer's encoding.
- **ALL.8:** Unbound clients never see SERVFAIL over UDP when an authority is dead, only timeouts.
- **MINNSEC.2:** validators split on the literal RFC 4470 form (erratum 6734).
- **ALL.4:** CD=1 and AD.
- **ALL.9:** Knot answers `.test` locally with AD.
- **ALL.7:** Unbound's RFC 8145 queries use type A, not NULL.
- **INFRA.7:** forwarding disables ANC in PowerDNS, relevant to operators who forward internal zones.

## Open follow-ups

- [ ] MINNSEC.1: why Unbound synthesizes NODATA from minimal NSEC and the others don't (source: Unbound `validator/val_neg.c`); separate RFC 8020 from synthesis for MN-02
- [ ] MINNSEC.1: bad-bitmap knob (omit an existing type) to test Unbound's exposure
- [x] MINNSEC.4: BIND's detection rule from source (`resolver.c`: `is_minimal_nsec`, `has_000_label`)
- [ ] MINNSEC.4: encoding knob (`\000.www` vs `www\000`); predicted: BIND and PowerDNS synthesize MN-03 under `www\000`, Knot doesn't
- [ ] MINNSEC.2: run a `cover_next = "child"` zone through every resolver
- [ ] NSEC.3 / MINNSEC.3: make the ENT-NODATA queries catalogue experiments
- [ ] NSEC3.1: NSEC3 opt-out zone, NSEC3 TTL expiry, and NSEC3 wildcard synthesis (Knot variable, PowerDNS not seen)
- [x] ALL.4: RFC 4035/6840 reading of AD on CD=1 (both behaviors conform; recorded in ALL.4)
- [ ] ALL.4: check sources for intent (synthesis despite RFC 8198 App. A; AD derivation)
- [ ] ALL.5: P05 (strict QNAME minimisation)
- [ ] ALL.7: confirm Unbound's `_ta-` qtype in its source
- [ ] ALL.8: repeat SERVFAIL timing over UDP with several runs (current numbers: one TCP query each); Unbound over TCP (connection closed at ~30 s)
- [ ] NSEC.2: repeat cache-footprint observation; Knot and PowerDNS cache dumps
- [ ] CDOE.1: find a CO-aware resolver
- [ ] NSEC3.3: choose distinct-record names when building P03
- [ ] AWS/wild setup: remove every lab-only exemption in the INFRA.8 table
- [ ] All diag entries: re-measure in the production setup
