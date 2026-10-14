# Findings log

A running record of every observation worth revisiting, for later analysis. One-line overview: [FINDINGS-INDEX.md](FINDINGS-INDEX.md). Add new entries at the end of the relevant section, never renumber, and update an entry's **Status** rather than deleting it.

**Status values**
- **diagnostic**: seen in the local Docker pipeline only. Must be re-measured in the production setup before it counts as a result.
- **documented**: the behavior is stated in vendor documentation or an RFC, and we reproduced it.
- **confirmed**: reproduced in the production setup (none yet).
- **resolved**: was an issue in our own tooling and has been fixed.

**Environment for everything below unless noted** (2026-10-14):
- Variant zones and decisions: docs/VARIANTS.md.
- BIND 9.20.29, `internetsystemsconsortium/bind9@sha256:071465f8…41ad0`, default options plus `synth-from-dnssec yes`.
- Static-stub zones with local trust anchors, in the Docker lab 172.30.0.0/24.
- Responder at commit `6a672b7` (+ working tree).
- Zones `nsec.test` (vanilla NSEC) and `nsec3.test` (vanilla NSEC3, same content).

**Reproduce:**
- Experiments: `docker/pipeline.sh up && docker/pipeline.sh experiments --slow`. IDs refer to `experiments/CATALOG.md`.
- Validator and reference checks: `venv/bin/python -m tests.reference`.

---

## A. Resolver behavior (BIND 9.20.29)

### A1. BIND synthesizes negative answers even when the client sets CD=1
- **Status:** diagnostic (stable across 5+ runs).
- **Evidence:** experiment **N08**. With the cache primed by `m<tag>a`, a CD=1 query for `m<tag>b` (same NSEC gap) returned NXDOMAIN with AD, and the responder saw no query.
- **Expected:** no synthesis. RFC 8198 Appendix A ("Detailed Implementation Notes") says validators synthesize "unless the CD bit was set on the incoming query".
- **Interpretation:** a deviation from the RFC's implementation notes, not from a normative requirement; the RFC body never mentions CD. The response also carries AD on a CD=1 query.
- **Follow-up:** run on Unbound, Knot Resolver and PowerDNS Recursor; check BIND's source or GitLab for intent; check whether CD=1 queries also skip validation of upstream data.

### A2. Relaxed QNAME minimisation re-asks the full name after a validated NXDOMAIN
- **Status:** documented (BIND ARM `qname-minimization`: relaxed mode "falls back to normal (non-minimized) query mode when it receives either NXDOMAIN or other unexpected responses").
- **Evidence:** experiment **N11**. For `d1.d2.m<tag>.nsec.test A` after a flush, BIND sent `m<tag>.nsec.test NS`, then `nsec.test DNSKEY`, then the full `d1.d2.m<tag>.nsec.test A`, although the validated NXDOMAIN for `m<tag>` already proved the full name absent (RFC 8020 cut, and RFC 8198 synthesis).
- **Interpretation:** the fallback ignores the resolver's own validated denial.
- **Measurement impact:** the first query for a deep nonexistent name costs 2 upstream queries plus DNSKEY. Count it correctly, so it is not mistaken for missing ANC.
- **Follow-up:** planned **P05** (strict mode); compare with other resolvers.

### A3. BIND never synthesizes from NSEC3; it fully synthesizes from NSEC
- **Status:** documented (BIND ARM `synth-from-dnssec`: NSEC only; NSEC3 synthesis "planned for the future").
- **Evidence:**

  | Case | NSEC | NSEC3 |
  |---|---|---|
  | NXDOMAIN, same gap | synthesized (**N01**) | upstream (**N3-01**) |
  | NODATA, other type | synthesized (**N03**) | upstream (**N3-03**) |
  | Positive wildcard | synthesized (**N06**) | upstream (**N3-06**) |

  For NSEC3, same-gap names were chosen by hash. All NSEC3 answers were validated (AD).
- **Interpretation:** the main baseline contrast for the variant study. For BIND, any NSEC3-based variant (minimally covering NSEC3 / white lies, compact NSEC3) can only show *non*-ANC differences: caching, rcodes, sizes.

### A4. BIND's synthesis covers every NSEC case RFC 8198 allows
- **Status:** diagnostic (matches RFC 8198 §5.1 and §5.3).
- **Evidence:** all synthesized with AD:
  - NXDOMAIN, same gap (**N01**);
  - NODATA for another type at an existing name (**N03**);
  - NODATA at an empty non-terminal, proved by a *covering* NSEC (**N04**);
  - NXDOMAIN below a cached NXDOMAIN (**N05**);
  - positive wildcard (**N06**);
  - wildcard NODATA (**N07**).

### A5. Synthesized answers carry the remaining TTL, and synthesis stays inside what the cache proves
- **Status:** diagnostic.
- **Evidence:**
  - **N01:** primed TTL 60; the synthesized answer 10 s later had TTL 50, not reset to 60.
  - **N12:** after the 60 s NSEC TTL, a same-gap name went upstream again.
  - **N02:** a name in an uncached gap went upstream although the wildcard-proof NSEC was cached.
- **Interpretation:** consistent with RFC 8198 §5.4 and RFC 9077.

### A6. The client's DO bit does not affect priming or synthesis
- **Status:** diagnostic.
- **Evidence:**
  - **N10:** priming by a DO=0 client still let a later DO=1 query be synthesized.
  - **N09:** a DO=0 client was served from synthesis too. Its authority section held only the SOA, with no NSEC or RRSIG.
- **Interpretation:** BIND validates and caches upstream data regardless of the client's DO. DO only shapes what the client is shown.

### A7. Synthesized names leave no trace of their own in the cache dump
- **Status:** diagnostic (one observation, from the cache dump of a pipeline check).
- **Evidence:** after `m…a` (fetched) and `m…b` (synthesized), `rndc dumpdb -cache` showed:
  - a negative entry for `m…a` (`\-ANY ;-$NXDOMAIN` with its proof attached);
  - the two NSEC records as standalone validated records;
  - **no entry for `m…b`**.
- **Interpretation:** synthesis reads the cached NSEC each time instead of creating per-name negative entries. This is relevant to the "storage" stage and to cache-pressure comparisons with minimally covering NSEC and NSEC3 white lies.
- **Follow-up:** repeat with several synthesized names and confirm with the dump; record cache sizes.

### A8. With the authoritative server down, BIND takes more than 5 s to return SERVFAIL
- **Status:** diagnostic (minor, methodology).
- **Evidence:** a manual negative control. dig's first try (5 s timeout) got no reply and it retried; `pipeline.sh check` uses `+time=30` and then gets SERVFAIL.
- **Measurement impact:** client timeouts in experiments must exceed BIND's own upstream retry time, or an "upstream failure" is misrecorded as a lost reply.


### A9. BIND does not keep minimally covering NSEC records for synthesis
- **Status:** diagnostic (repeated 3 times); the cause in BIND is not yet identified.
- **Evidence:**
  - **MN-03:** after `www.minnsec.test AAAA` (NODATA, online NSEC `www → \000.www` listing A TXT RRSIG NSEC), `www MX` went **upstream**, where the vanilla counterpart **N03** is synthesized.
  - **MN-02:** a name below a cached minimal NXDOMAIN went upstream, where vanilla **N05** is synthesized, although the cached cover `pred(m…a) → m…a\000` spans it.
  - `rndc dumpdb -cache` shows the cause:
    - for `nsec.test`, the NSEC is stored twice, attached to the negative entry **and** as a standalone `; secure` NSEC record;
    - for `minnsec.test`, NSECs (both covers and the NSEC at `www`) appear **only** as attached proof, with no standalone record, so there is nothing to synthesize from.
- **Expected:** synthesis (RFC 8198 §5.1 allows it; the records validate, AD is set).
- **Interpretation:** BIND appears to recognize online-signed or minimal NSEC records by their shape and keep them out of the synthesis cache. No ISC document found states this (search 2026-10-14). This bears on CLAUDE.md's open question of whether BIND identifies minimally covering NSEC.
- **Follow-up:**
  - Discriminating experiment with responder knobs: which property triggers it? Candidates: next name below the owner, owner that is not a real name, span width, `\000` labels.
  - Read BIND's cache and synth code (`lib/dns/qpcache.c`, `nsec.c`).
  - Compare with Unbound, Knot and PowerDNS.

### A10. BIND neither sends nor honors CO, so clients see NOERROR for compact-denied names
- **Status:** diagnostic (consistent with E1).
- **Evidence:**
  - **CN-01 / C3-01:** a nonexistent name in `cdoe-nsec.test` / `cdoe-nsec3.test` reaches the client as NOERROR with AD.
  - **CN-02:** with CO=1 from the client, BIND still returns NOERROR, does not echo CO, and sends no CO upstream; the responder log shows `"co": false` on all BIND queries.
- **Expected:** for clients without CO, NOERROR is what RFC 9824 §5.1 prescribes. A CO-aware resolver would answer a CO client with NXDOMAIN and CO.
- **Interpretation:** for BIND users, compact denial turns every nonexistent name into NOERROR/NODATA. That matters for applications that branch on NXDOMAIN (e.g. the DMARC "np" issue noted in CLAUDE.md §6).
- **Also observed:** compact answers are negative-cached per name (**CN-03**) and never synthesized for other names (**CN-04**, **CN-05**; RFC 9824 §6).
- **Follow-up:** test CO-aware resolvers, if any implement §5.1.

---

## B. Validator disagreements and validation subtleties

### B1. ldns drill rejects a correct NSEC NODATA proof for an empty non-terminal
- **Status:** diagnostic (drill 1.8.4 / ldns 1.8.4 from Alpine 3.22).
- **Evidence:** `tests/reference.py`, query `wild.nsec.test A`.
  - The response is NOERROR with one NSEC `secure.nsec.test → *.wild.nsec.test`. Its span contains `wild`, and its next name is below `wild`, so `wild` exists as an ENT.
  - drill: *"Error in denial of existence: wildcard not covered by the given NSEC RRs … Chase failed"*.
  - delv: `negative response, fully validated`.
  - BIND's authoritative server sends the **identical** response.
- **Why the answer is correct:** an existing name (ENTs included) is never matched by a wildcard (RFC 4592 §2.2.2), so no wildcard proof is required.
- **Why `ent.nsec.test A` passes:** its proof NSEC (`nsec.test → host.ent`) happens to also cover `*.nsec.test`.
- **Interpretation:** drill treats "no matching NSEC" as needing an NXDOMAIN-style wildcard proof. It is a validator disagreement on ENT NODATA proofs, the kind of edge case resolvers may also disagree on.
- **Follow-up:**
  - Test the same query through Unbound (shares NLnet Labs lineage), Knot and PowerDNS.
  - Check the NSEC3 counterpart: it passes in drill, because an NSEC3 ENT has a *matching* record.
  - Check whether ldns has a bug report.

### B2. A "broken" NSEC3 proof is still valid when one record covers two names
- **Status:** documented (correct behavior; a methodology note).
- **Evidence:** with the next-closer cover deliberately dropped from NSEC3 NXDOMAIN, delv returned `broken trust chain` only for names (`c`, `e`, `f`) whose next-closer and wildcard hashes fall in different NSEC3 gaps. For the other names, the wildcard's NSEC3 also covers the next closer, so the proof was in fact complete.
- **Measurement impact:** tests of broken proofs (planned **P03**) must pick names whose proof records are distinct; otherwise the "broken" response is valid.

### B3. The literal RFC 4470 §4 increment produces NXDOMAIN proofs BIND rejects, and drill accepts
- **Status:** documented (RFC 4470 erratum 6734, Reported 2021 by M. Andrews, ISC).
- **Evidence:**
  - With covers `pred(q) → \000.q`, delv returned `broken trust chain` for every minimal-NSEC NXDOMAIN, and `no valid NSEC` for wildcard answers.
  - delv's validation trace (`+vtrace`) logs: *"nsec proves name exist (empty)"*. A next name below the QNAME is the standard sign of an empty non-terminal, so the NSEC contradicts the NXDOMAIN.
  - drill 1.8.4 accepted the same responses ("Chase successful").
- **Context:** RFC 4470 is self-inconsistent here. §4 prescribes prepending a `\000` label, while §3's example uses a sibling (`exampld.com → example-.com`). Erratum 6734: `\000.domain` "can only be used to prove no data exists at 'domain'".
- **Resolution in our responder:** decision **D14** (covers use `q\000`). The literal form is kept as the knob `cover_next = "child"`, so resolvers can be tested against it.
- **Follow-up:** test the `child` form on Unbound, Knot and PowerDNS; which validators accept a proof that erratum 6734 calls wrong is itself a finding.
- **Related:** a second issue found while building it (**D15**): minimal covers must span the next closer name, or BIND rejects deep NXDOMAINs such as `foo.bar.ent`.

### B4. drill rejects every minimal-NSEC ENT proof
- **Status:** diagnostic (same limitation as B1).
- **Evidence:** `tests/reference.py` online section: `ent.minnsec.test A` and `wild.minnsec.test A` fail with "wildcard not covered by the given NSEC RRs". delv validates both.
- **Interpretation:** minimal NSEC always proves an ENT with a cover whose next name is below it (D4), so B1's limitation hits every ENT here, not just by coincidence as in `nsec.test`.

---

## C. Responder fidelity (against BIND as a reference signer and server)

### C1. The chains and all denial responses match BIND exactly
- **Status:** resolved (`tests/reference.py` passes).
- **Evidence:**
  - NSEC, NSEC3 and NSEC3 opt-out chains are identical to `dnssec-signzone` output.
  - All 81 query responses match BIND `named` structurally.

### C2. Three non-denial differences found and aligned to BIND
- **Status:** resolved.
- **Details:**
  - NS answers lacked the in-zone NS addresses in the additional section. Added.
  - The DNSKEY TTL was a constant 3600. Now the zone TTL, as `dnssec-signzone` does.
  - The NSEC3PARAM TTL was 300. Now 0, as BIND sets it; RFC 5155 specifies no value.
- **Note:** these could matter in the wild (e.g. resolvers caching DNSKEY), so any future server-side choice should be deliberate.

---

## D. Real-world reference data (golden fixtures, captured 2026-10-12)

### D1. The `.com` NSEC3 NXDOMAIN orders its proof as closest-encloser match, next-closer cover, wildcard cover
- **Status:** documented (decoded with our hash).
- **Evidence:** in `tests/golden/com-nsec3-nxdomain.txt`, hash(`com.`) = `CK0POJMG…` matches the first record. The second covers `nosuchdomain-12345.com.` (hash `IG5RMRTL…`), and the third covers `*.com.` (hash `3RL2R262…`). The flags field is 1 (opt-out), with 0 iterations and no salt (RFC 9276 compliant).

### D2. NSEC3 NXDOMAIN size depends on the qname, because records are reused
- **Status:** documented (RFC 5155 §7.2.2: "up to three").
- **Evidence:** in `nsec3.test` (9 hashes), one NSEC3 often covers both the next closer and the wildcard. So `nope.nsec3.test` gets 2 NSEC3 records and `c.nsec3.test` gets 3.
- **Measurement impact:** the future prevalence classifier and size comparisons must not assume a fixed record count per variant.

---

## E. Documentation and tooling notes

### E1. BIND's compact-denial support is in `dig` only
- **Status:** documented (release notes checked 2026-10-13; sources in CLAUDE.md §6).
- **Details:**
  - 9.18.38 and 9.20.11 add the CO flag and `+coflag` to dig [GL #5319].
  - MRs !11500 and !12750 only display type 128 as `NXNAME`.
  - No release note shows resolver or validator handling of compact answers.
  - An earlier claim in this project that BIND had "compact-denial support" was wrong and has been corrected.

### E2. Several BIND 9.20.x fixes touch exactly the paths under study
- **Status:** documented.
- **Details:**
  - 9.20.12: ANC failed when no parent NSEC was cached [GL #5422].
  - 9.20.21: NSEC3 iteration limit for referrals to unsigned delegations (CVE-2026-1519).
  - 9.20.26: invalid signed wildcards rejected (CVE-2026-11721); out-of-zone NSEC next names with synthesis (CVE-2026-13321); padded negative responses capped (CVE-2026-11605).
- **Implication:** resolver version is a first-class variable; record the exact version and digest per run.

### E3. dig sends ANY queries over TCP by default
- **Status:** documented (dig behavior).
- **Note:** seen while testing ANY (the server line read `(TCP)` without `+tcp`). It is irrelevant to resolvers, but explains transport fields in logs from manual tests.

### E4. "Minimally covering NSEC3" is not RFC 4470; it is RFC 7129's "white lies", deployed as PowerDNS narrow mode
- **Status:** documented (checked 2026-10-14). The variant was missing from the project's variant list until now.
- **Details:**
  - RFC 4470 (Standards Track) is NSEC-only.
  - The NSEC3 analogue is RFC 7129 Appendix B (Informational): owner = hash(QNAME) − 1, next = hash(QNAME) + 1, signed online, inside the normal closest-encloser proof.
  - PowerDNS Authoritative "narrow" mode implements it, and predates the RFC.
  - PowerDNS Recursor ≥ 4.9.0 keeps such tiny-span NSEC3 records out of its aggressive cache.
- **Implications:**
  - It is a sixth setup in the study (`minnsec3.test`).
  - Unlike minimal NSEC, it is identifiable from one response (span of 2 in hash space), which matters for the prevalence classifier.
  - BIND does no NSEC3 synthesis (A3), so the interesting comparison is PowerDNS Recursor vs the others.
- **Sources:** https://www.rfc-editor.org/rfc/rfc4470.txt, https://www.rfc-editor.org/rfc/rfc7129.txt, https://doc.powerdns.com/authoritative/_sources/dnssec/modes-of-operation.rst.txt, https://blog.powerdns.com/2023/06/30/powerdns-recursor-4-9-0-released
