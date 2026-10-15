# Findings log

Every observation worth revisiting, organized for comparison across resolvers. One-line overview: [FINDINGS-INDEX.md](FINDINGS-INDEX.md).

**How this file is organized**
- **Sections:** one per denial variant (NSEC, NSEC3, MINNSEC, WL, CDOE). Behavior common to all variants is in ALL. Things that aren't resolver behavior (validators, our responder, environments) are in INFRA.
- **Findings:** each states one general question or claim, then gives a **per-resolver table** with that resolver's result, status and evidence.
- **Adding a resolver:** fill in its row in every table; findings are not duplicated per resolver.
- **Adding a finding:** append it at the end of its section with the next number. Never renumber; update Status instead of deleting.
- **Old IDs** (A1–F7, used before 2026-10-15) map to the new ones in the table at the end.

**Status values** (per resolver row)
- **lab artifact**: the lab setup prevented measuring this for that resolver (INFRA.7, before INFRA.8); not a property of the resolver.
- **diag**: seen in the local Docker pipeline only. Must be re-measured in the production setup before it counts as a result.
- **doc**: stated in vendor documentation or an RFC, and reproduced.
- **conf**: reproduced in the production setup (none yet).
- **—**: not tested yet.

## Resolvers and environment

| Resolver | Version | Image | Lab address | Config |
|---|---|---|---|---|
| BIND | 9.20.29 | `internetsystemsconsortium/bind9@sha256:071465f8…41ad0` | 172.30.0.20 | `docker/bind/named.conf` (defaults + `synth-from-dnssec yes`) |
| Knot Resolver | 6.5.0 (package `6.5.0.dev1+928fe2-cznic.1`, see INFRA.5) | `cznic/knot-resolver@sha256:b2422a58…49e0` | 172.30.0.21 | `docker/knot/config.yaml` (defaults, 2 workers) |
| Unbound | not deployed | | | |
| PowerDNS Recursor | 5.4.7 | `powerdns/pdns-recursor-54@sha256:ec0ad7d6…eff8` | 172.30.0.22 | `docker/pdns/recursor.yml` (defaults + `dnssec.validation: validate`) |

- **Setup (since run 20261015T191407Z):** every resolver reaches the six zones by **ordinary delegation** from a signed local root (172.30.0.11), with that root's key as its only trust anchor (INFRA.8). Earlier runs used a static-stub/forward per zone with per-zone anchors (INFRA.7).
- **Zones:** six zones, same content, one per variant (docs/VARIANTS.md, docs/zones/).
- **Latest full run:** `results/20261015T191407Z` (BIND, Knot, PowerDNS via the local root; `--slow`). Last run with forwarding: `results/20261015T185519Z`.
- **Reproduce:** `docker/pipeline.sh up && docker/pipeline.sh experiments --slow`. Experiment IDs refer to `experiments/CATALOG.md`. Validator and reference checks: `venv/bin/python -m tests.reference`.

---

## ALL. Behavior across all variants

### ALL.1 Every resolver validates every variant
- **Question:** do resolvers accept all six denial variants as secure?
- **Experiments:** `pipeline.sh check` 5b; every experiment's AD flag.

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | Yes: AD on all six zones; NXDOMAIN for NSEC, NSEC3, minimal NSEC, white lies; NOERROR for both compact zones | diag | check 5b; CN-01, C3-01 |
| Knot | Yes: identical to BIND | diag | check 5b; CN-01, C3-01 |
| Unbound | — | — | |
| PowerDNS | Yes: identical to BIND and Knot (NXDOMAIN ×4, NOERROR ×2 compact, all AD) | diag | check 5b; CN-01, C3-01 |

### ALL.2 Synthesized answers carry the remaining TTL, and synthesis stops at expiry and at the edge of what the cache proves
- **Question:** RFC 8198 §5.4 and RFC 9077 TTL behavior.
- **Experiments:** N01 (TTL after a 10 s wait), N12 (after expiry), N02 (uncached gap).

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | Remaining TTL (60 → 50); upstream after expiry; no cross-gap synthesis | diag | N01, N12, N02 |
| Knot | Remaining TTL (60 → 49–50); upstream after expiry; no cross-gap synthesis | diag | N01, N12, N02 |
| Unbound | — | — | |
| PowerDNS | Remaining TTL (60 → 49); upstream after expiry; no cross-gap synthesis | diag | N01, N12, N02 (run 20261015T191407Z) |

- **Note:** Knot clamps every cached TTL to at least 5 s (`cache.ttl-min` default), which matters only for TTL experiments below 5 s.

### ALL.3 The client's DO bit does not affect priming or synthesis
- **Experiments:** N10 (priming by a DO=0 client), N09 (DO=0 client served by synthesis).

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | Irrelevant: validates and caches regardless; a DO=0 client gets SOA only | diag | N09, N10 |
| Knot | Same as BIND | diag | N09, N10 |
| Unbound | — | — | |
| PowerDNS | Same as BIND and Knot | diag | N09, N10 |

- **Interpretation:** DO only shapes what the client is shown.

### ALL.4 Resolvers synthesize even when the client sets CD=1, and differ on AD
- **Question:** RFC 8198 Appendix A ("Detailed Implementation Notes") says synthesis applies "unless the CD bit was set on the incoming query". The RFC body never mentions CD, so this is guidance, not a requirement.
- **Experiment:** N08 (primed cache, then a same-gap name with CD=1).

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | Synthesizes; answers with **AD=1** | diag (5+ runs) | N08 |
| Knot | Synthesizes; answers with **AD=0** | diag | N08 |
| Unbound | — | — | |
| PowerDNS | Synthesizes; answers with **AD=1** (like BIND) | diag | N08 |

- **Interpretation:** both depart from the RFC's implementation note. AD on CD=1 answers is a separate question (RFC 6840 §5.7–5.9) where they disagree.
- **Follow-up:** check BIND and Knot sources for intent; whether CD=1 also skips validation of upstream data.

### ALL.5 The upstream query pattern for a deep nonexistent name differs by resolver and by routing
- **Question:** for a deep nonexistent name, what does the resolver send upstream?
- **Experiment:** N11 (`d1.d2.m<tag>.nsec.test A` after a flush).

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | Forwarding (static-stub): NS for `m<tag>`, DNSKEY, full name (3 upstream). **Delegation:** NS for `m<tag>`, AAAA for its own nameserver name `ns1.nsec.test` (no AAAA glue), DNSKEY, full name (4) | doc (ARM: relaxed mode "falls back to normal (non-minimized) query mode when it receives either NXDOMAIN") | N11 (runs 20261015T185519Z, 20261015T191407Z) |
| Knot | Forwarding: DNSKEY, NS for `m<tag>`, full name (3). **Delegation:** DNSKEY, then the full name directly (2): no minimisation below the zone cut | diag | N11 (runs 20261015T185519Z, 20261015T191407Z) |
| Unbound | — | — | |
| PowerDNS | Forwarding: `m<tag>` **A**, DNSKEY, full name (3). **Delegation:** `m<tag>` A, DNSKEY, then **stops** (2): the validated NXDOMAIN ends resolution (`nothing_below_nxdomain: dnssec`, RFC 8020) | diag | N11 (runs 20261015T185519Z, 20261015T191407Z) |

- **Interpretation:** the fallback ignores the resolver's own validated denial (RFC 8020 cut, RFC 8198).
- **Measurement impact:** a deep first query costs 2 upstream queries plus DNSKEY. Don't misread that as missing ANC.
- **Follow-up:** planned P05 (strict minimisation).

### ALL.6 Upstream query-name casing (0x20)
- **Question:** does the resolver randomize letter case in upstream queries?
- **Evidence source:** responder log.

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | No: sends names as the client wrote them | diag | responder log |
| Knot | **Yes**: e.g. `kNoT1a.NSec.TeSt.` | diag | responder log |
| Unbound | — (has a `use-caps-for-id` option; default to be checked) | — | |
| PowerDNS | No: case preserved (`outgoing.lowercase: false`); 0 of 128 upstream queries mixed-case | doc (yamlsettings) | responder log |

- **Measurement impact:** match server-side logs case-insensitively (the harness does). An authority that doesn't echo case exactly would break 0x20 resolvers.

### ALL.7 Resolver-initiated upstream queries
- **Question:** which upstream queries does the resolver send on its own, not caused by a client query?
- **Evidence source:** responder log; Knot's startup log.

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | None seen toward our zones beyond DNSKEY fetches | diag | responder log |
| Knot | RFC 8145 trust-anchor signalling: `_ta-<keytag>.<zone>` type NULL per anchored zone, at startup, hourly with the anchor refresh, and after a cache purge | doc (RFC 8145) | responder log; startup log |
| Unbound | — | — | |
| PowerDNS | None: 0 `_ta-*` queries in 128 upstream queries | diag | responder log |

- **Measurement impact:** filter these from upstream counts. The harness ignores `_ta-*` names (`SELF_INITIATED`).

### ALL.8 Time to SERVFAIL when the authoritative server is down
- **Question:** how long until the client gets SERVFAIL?

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | More than 5 s: dig's first 5 s try got no reply | diag (one manual observation) | manual negative control |
| Knot | SERVFAIL within 30 s (time not measured) | diag | check 6 |
| Unbound | — | — | |
| PowerDNS | SERVFAIL within 30 s (time not measured); EDE expected (`extended_resolution_errors: true`) | diag | check 6 |

- **Measurement impact:** probe timeouts must exceed the resolver's own upstream retry time. `pipeline.sh check` uses `+time=30`.

### ALL.9 Resolvers may answer `.test` names themselves (RFC 6761 special-use handling)
- **Question:** RFC 6761 lets resolvers treat special-use names such as `.test` locally. Do they, and how does that interact with routing?
- **Evidence:** after switching to delegation, without an explicit per-zone rule.

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | No: resolves `.test` through the configured root | diag | root log |
| Knot | **Yes**: answers every `.test` name itself with a synthetic empty zone (`test. SOA localhost. nobody.invalid. …`), as **NXDOMAIN with AD set**, without asking the root. Hidden while a `forward` rule for each zone took precedence. Lab fix: `policy.add(policy.suffix(policy.PASS, policy.todnames({'test.'})))` in the Lua block (Knot policy docs: special-use rules "can be overridden by action policy.PASS") | diag | dig `foo.test`; root log (no queries until PASS) |
| Unbound | — (documented to serve `test.` locally by default; needs `local-zone: "test." nodefault`) | — | |
| PowerDNS | No: resolves `.test` through the configured root | diag | root log |

- **Interpretation:** Knot marks locally invented NXDOMAINs as authenticated, which a client cannot tell apart from a DNSSEC-proven NXDOMAIN.
- **Measurement impact:** in-the-wild zones must not live under special-use names; lab configs need an explicit exemption per resolver.

### ALL.10 Resolvers may refuse to query nameservers at private or special-purpose addresses
- **Question:** a delegation whose nameserver addresses are private (the lab uses 172.30.0.0/24) is unusual on the Internet but common inside networks. Do resolvers follow it by default?
- **Evidence:** default configuration values, and the lab after switching to delegation (INFRA.8).

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | Queries the lab addresses with no configuration change | diag | root and responder logs |
| Knot | Queries the lab addresses with no configuration change | diag | root and responder logs |
| Unbound | — (documented: `do-not-query-localhost: yes` blocks only loopback; `private-address` is empty by default) | — | |
| PowerDNS | **No by default**: `outgoing.dont_query` defaults to RFC 1918, loopback, link-local, CGNAT and the documentation ranges, including 172.16.0.0/12. Lab exemption: the same list without 172.16.0.0/12. Forwarders (`forward_zones`) are exempt, so this only appeared with delegation | doc (default list) | `rec_control get-parameter outgoing.dont_query`; PowerDNS settings docs |

- **Interpretation:** a hardening default (it stops a delegation from steering the resolver at internal hosts), and another way forwarding and delegation behave differently in PowerDNS (cf. INFRA.7). PowerDNS also refuses 192.0.2.0/24 even with the exemption, which only affects the deliberately unreachable glue of `secure.*` and `insecure.*` in our zones.
- **Measurement impact:** none in the wild (public addresses). In the lab, the exemption is a deviation from defaults; see the list in INFRA.8.

---

## NSEC. Vanilla NSEC (`nsec.test`)

### NSEC.1 Aggressive synthesis covers every NSEC case RFC 8198 allows
- **Question:** does the resolver synthesize NXDOMAIN, NODATA, ENT NODATA, sub-NXDOMAIN and wildcard answers from cached NSEC (RFC 8198 §5.1, §5.3)?
- **Experiments:** N01 (NXDOMAIN, same gap), N03 (NODATA, other type), N04 (ENT, covering NSEC), N05 (below a cached NXDOMAIN), N06 (positive wildcard), N07 (wildcard NODATA).

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | All six synthesized, with AD | doc (ARM `synth-from-dnssec`) | N01, N03–N07 |
| Knot | All six synthesized, with AD | doc (docs: "aggressive caching for DNSSEC-validated data") | N01, N03–N07 |
| Unbound | — | — | |
| PowerDNS | All six synthesized, with AD | doc (`dnssec.aggressive_nsec_cache_size`, RFC 8198) | N01, N03–N07 (run 20261015T191407Z) |

### NSEC.2 Synthesized names leave no per-name cache entry
- **Question:** what does synthesis store (the storage stage)?

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | `rndc dumpdb -cache` after `m…a` (fetched) and `m…b` (synthesized): a negative entry for `m…a` with its proof attached, the NSECs as standalone validated records, **no entry for `m…b`** | diag (one dump) | cache dump |
| Knot | — (no cache-dump method used yet) | — | |
| Unbound | — | — | |
| PowerDNS | — (`rec_control dump-cache - a` shows the NSECs stored in its aggressive cache) | — | |

- **Interpretation:** synthesis reads the cached NSEC each time. This is relevant to cache-pressure comparisons with the minimal variants.
- **Follow-up:** repeat with several names; record cache sizes; find Knot's equivalent (`kresctl` / cache API).

### NSEC.3 Validators disagree on an ENT NODATA proved by a covering NSEC
- **Case:** `wild.nsec.test A`. The answer is NOERROR with one NSEC `secure → *.wild`; its span contains `wild` and its next name is below `wild`, so `wild` exists as an ENT. BIND's authoritative server sends the identical response (INFRA.1).
- **Why it is correct:** an existing name is never matched by a wildcard (RFC 4592 §2.2.2), so no wildcard proof is needed.

| Validator / resolver | Result | Status | Evidence |
|---|---|---|---|
| delv (BIND) | Accepts (`negative response, fully validated`) | diag | gates |
| ldns drill 1.8.4 | **Rejects**: "wildcard not covered by the given NSEC RRs" | diag | tests/reference.py (`KNOWN_DRILL`) |
| BIND resolver | — for `wild`; accepts the analogous `ent` (N04, AD) | diag | N04 |
| Knot | — for `wild`; accepts `ent` (N04, AD) | diag | N04 |
| Unbound | — (shares NLnet Labs lineage with ldns) | — | |
| PowerDNS | — for `wild`; NODATA for `ent` validated (N04 prime, AD) | diag | N04 |

- **Why `ent` passes in drill:** its proof NSEC (`nsec.test → host.ent`) happens to also cover `*.nsec.test`.
- **Follow-up:** add `wild.nsec.test A` as an experiment on every resolver; check for an ldns bug report. The same limitation hits every ENT in the minimal-NSEC zone (MINNSEC.3).

---

## NSEC3. Vanilla NSEC3 (`nsec3.test`)

### NSEC3.1 Synthesis from NSEC3 splits the resolvers
- **Question:** does the resolver synthesize from cached NSEC3 (RFC 8198 §5.2 allows it)?
- **Experiments:** N3-01 (NXDOMAIN, second name in the same hash gap, chosen by hash), N3-03 (NODATA, other type), N3-06 (positive wildcard). NSEC counterparts: N01, N03, N06 (NSEC.1).

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | **Never**: all three upstream | doc (ARM: synthesis "only from NSEC"; NSEC3 "planned for the future") | N3-01/03/06 |
| Knot | **Yes** for NXDOMAIN and NODATA (N3-01, N3-03: every run). **Wildcard (N3-06) is variable**: synthesized in 3 of 9 runs; in failing runs the second probe first sends a minimisation query `wild.nsec3.test NS`, then the full name | diag | N3-01/03/06; runs 20261015T172911Z, 20261015T185519Z, 20261015T191407Z + 6 repeats |
| Unbound | — | — | |
| PowerDNS | **Yes** for NXDOMAIN and NODATA (N3-01, N3-03); **no** for the wildcard (N3-06, 1 run) | doc (aggressive NSEC3 with `aggressive_cache_min_nsec3_hit_ratio` 2000; our spans ≈ 1/9) | N3-01/03/06 (run 20261015T191407Z) |

- **Interpretation:** the clearest resolver difference so far: BIND never synthesizes from NSEC3, Knot and PowerDNS do (NXDOMAIN and NODATA). On Knot and PowerDNS the NSEC3 variants are distinguishable by synthesis (vanilla synthesized; white lies and compact not, WL.2 and CDOE.2). On BIND they cannot be. The NSEC3 wildcard case is unreliable (Knot variable, PowerDNS not in one run).
- **Follow-up:** an NSEC3 opt-out zone (RFC 8198 §5.2: opt-out spans must not be used for synthesis); NSEC3 TTL expiry; inspect Knot's cached NSEC3; explain Knot's N3-06 variability (hypothesis: whether the closest-encloser proof for the ENT `wild` is cached depends on the minimisation query's outcome; a wildcard answer carries only the next-closer cover, RFC 5155 §7.2.6).

### NSEC3.2 NSEC3 NXDOMAIN has 2 or 3 records, depending on the name
- **Status:** doc (RFC 5155 §7.2.2: "up to three"). A property of the zone, not of resolvers.
- **Evidence:** in `nsec3.test` (9 hashes), one NSEC3 often covers both the next closer and the wildcard. So `nope.nsec3.test` gets 2 records and `c.nsec3.test` gets 3.
- **Measurement impact:** the prevalence classifier and size comparisons must not assume a fixed count.

### NSEC3.3 A "broken" NSEC3 proof is still valid when one record covers two names
- **Status:** doc (correct behavior; a methodology note).
- **Evidence:** with the next-closer cover deliberately dropped, delv rejected only names (`c`, `e`, `f`) whose next-closer and wildcard hashes fall in different gaps. For the others, the remaining record still covered both.
- **Measurement impact:** broken-proof experiments (planned P03) must pick names whose proof records are distinct.

### NSEC3.4 Real-world reference: `.com` orders its proof as closest-encloser match, next-closer cover, wildcard cover
- **Status:** doc (decoded with our hash, golden fixture captured 2026-10-12).
- **Evidence:** in `tests/golden/com-nsec3-nxdomain.txt`, hash(`com.`) = `CK0POJMG…` matches record 1; record 2 covers `nosuchdomain-12345.com.` (`IG5RMRTL…`); record 3 covers `*.com.` (`3RL2R262…`). Flags 1 (opt-out), 0 iterations, no salt.

---

## MINNSEC. Minimally covering NSEC (`minnsec.test`, RFC 4470)

### MINNSEC.1 No resolver synthesizes from minimally covering NSEC
- **Question:** RFC 8198 §5.1 would allow synthesis wherever a cached record proves the answer. Minimal covers span only one name, but the NSEC at an existing name lists every type there, and a cover spans the denied name's whole subtree (D14).
- **Experiments:** MN-01 (adjacent name; never provable), MN-02 (name below a cached NXDOMAIN; provable), MN-03 (NODATA, other type; provable). Vanilla counterparts: N01, N05, N03.

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | **None synthesized**, even where provable (MN-02, MN-03). Cause: `rndc dumpdb -cache` shows minimal NSECs only attached to negative entries, never as standalone records, whereas vanilla NSECs are stored standalone too | diag (3+ runs); **undocumented** (no ISC source found, 2026-10-14) | MN-01/02/03; cache dump |
| Knot | None synthesized | doc (Knot 4.1.0 release notes: aggressive caching disabled for minimal ranges; not re-verified for 6.x) | MN-01/02/03 |
| Unbound | — | — | |
| PowerDNS | No synthesis from minimal NSEC NODATA (MN-03 upstream). MN-02 (name below a minimal NXDOMAIN) was answered without the responder, most likely by its RFC 8020 rule (`nothing_below_nxdomain: dnssec`), not NSEC synthesis | diag | MN-01/02/03 (run 20261015T191407Z) |

- **Interpretation:** both resolvers so far keep minimal NSEC out of aggressive negative caching, Knot by design and BIND silently. This bears on CLAUDE.md's open question of whether BIND recognizes minimally covering NSEC.
- **Follow-up:** a discriminating experiment with responder knobs (which property triggers BIND: next name below the owner, owner not a real name, span width, `\000` labels?); BIND source (`lib/dns/qpcache.c`, `nsec.c`).

### MINNSEC.2 The literal RFC 4470 §4 cover is rejected by some validators and accepted by others
- **Case:** covers `pred(q) → \000.q`, RFC 4470 §4's increment taken literally (knob `cover_next = "child"`). Our default (D14) uses `q\000` instead.
- **Standards context:** RFC 4470 is self-inconsistent here (§4 prepends a `\000` label; §3's example uses a sibling, `exampld.com → example-.com`). **Erratum 6734** (Reported 2021, M. Andrews, ISC): `\000.domain` "can only be used to prove no data exists at 'domain'".

| Validator / resolver | Result | Status | Evidence |
|---|---|---|---|
| delv (BIND) | **Rejects**: `broken trust chain`; trace: "nsec proves name exist (empty)". Wildcard answers: `no valid NSEC` | doc (erratum 6734) | delv `+vtrace` |
| ldns drill 1.8.4 | **Accepts** ("Chase successful") | diag | drill |
| BIND resolver | — (same validator code as delv; expect rejection) | — | |
| Knot | — | — | |
| Unbound | — | — | |
| PowerDNS | — | — | |

- **Related:** covers must also span the **next closer** name (D15), or BIND rejects deep NXDOMAINs such as `foo.bar.ent`.
- **Follow-up:** run a `cover_next = "child"` zone through every resolver.

### MINNSEC.3 drill rejects every minimal-NSEC ENT proof
- **Case:** minimal NSEC proves an ENT with a cover whose next name is below it (D4), the pattern NSEC.3 describes, here on every ENT.

| Validator / resolver | Result | Status | Evidence |
|---|---|---|---|
| delv (BIND) | Accepts `ent` and `wild` | diag | gates |
| ldns drill 1.8.4 | Rejects both ("wildcard not covered") | diag | tests/reference.py (`KNOWN_DRILL`) |
| BIND, Knot, PowerDNS, Unbound | — (ENT queries in `minnsec.test` not yet run through resolvers) | — | |

---

## WL. NSEC3 white lies (`minnsec3.test`, RFC 7129 App. B)

### WL.1 "Minimally covering NSEC3" is RFC 7129's white lies, not RFC 4470
- **Status:** doc (checked 2026-10-14). This variant was missing from the project's list until then.
- **Details:**
  - RFC 4470 (Standards Track) is NSEC-only.
  - The NSEC3 form is RFC 7129 Appendix B (Informational): owner = hash − 1, next = hash + 1, signed online, inside the normal closest-encloser proof.
  - PowerDNS Authoritative "narrow" mode implements it, and predates the RFC.
- **Implication:** identifiable from a single response (a span of 2 in hash space), unlike minimal NSEC; useful for the prevalence classifier.
- **Sources:** RFC 4470, RFC 7129, PowerDNS DNSSEC modes docs, PowerDNS Recursor 4.9.0 release notes (URLs in CLAUDE.md §6).

### WL.2 No resolver synthesizes from white lies
- **Experiment:** WL-01 (second nonexistent name after a white-lies NXDOMAIN).

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | Upstream (no NSEC3 synthesis at all, NSEC3.1) | doc | WL-01 |
| Knot | Upstream, **although Knot synthesizes from vanilla NSEC3** (NSEC3.1): each record covers only one hash | diag | WL-01 |
| Unbound | — | — | |
| PowerDNS | Upstream, consistent with its documented filter (Recursor ≥ 4.9.0 keeps "NSEC3 entries which cover only a small fraction of possible names" out of its aggressive cache), although with 1-hash spans no resolver could synthesize anyway | diag | WL-01 (run 20261015T191407Z) |

- **Follow-up:** PowerDNS is the resolver documented to detect this case explicitly.

---

## CDOE. Compact denial of existence (`cdoe-nsec.test`, `cdoe-nsec3.test`, RFC 9824)

### CDOE.1 Clients see NOERROR for nonexistent names, and no resolver sends or honors CO
- **Question:** RFC 9824 §5.1: resolvers return NOERROR to clients that don't set CO, and NXDOMAIN (with CO) to clients that do.
- **Experiments:** CN-01, C3-01 (client without CO), CN-02 (client with CO).

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | NOERROR with AD for both zones. With CO from the client: still NOERROR, CO not echoed, no CO upstream | diag (consistent with INFRA.4: compact support is dig-only) | CN-01/02, C3-01 |
| Knot | Same as BIND | diag (Knot docs don't mention CO or RFC 9824) | CN-01/02, C3-01 |
| Unbound | — | — | |
| PowerDNS | Same as BIND and Knot: NOERROR with AD; with CO, still NOERROR, no CO echoed or sent upstream | diag (no CO/RFC 9824 in its docs) | CN-01/02, C3-01 |

- **Interpretation:** for users of these resolvers, compact denial turns every nonexistent name into NOERROR/NODATA. That matters for software that branches on NXDOMAIN (e.g. the DMARC "np" issue, CLAUDE.md §6).
- **Follow-up:** find a CO-aware resolver.

### CDOE.2 Compact answers are cached per name and never synthesized for other names
- **Experiments:** CN-03 (same name again), CN-04 (second name), CN-05 (name below a compact-denied name), C3-02 (NSEC3 form, second name).

| Resolver | Result | Status | Evidence |
|---|---|---|---|
| BIND | Same name from cache; all others upstream | doc (RFC 9824 §6: RFC 8198 and RFC 8020 not supported) | CN-03/04/05, C3-02 |
| Knot | Same as BIND (including C3-02, although Knot synthesizes from vanilla NSEC3) | diag | CN-03/04/05, C3-02 |
| Unbound | — | — | |
| PowerDNS | Same as BIND and Knot | diag | CN-03/04/05, C3-02 |

---

## INFRA. Validators, our responder, and environments

### INFRA.1 Our chains and denial responses match BIND's signer and server exactly
- **Status:** resolved (`tests/reference.py` passes).
- **Evidence:**
  - NSEC, NSEC3 and NSEC3 opt-out chains are identical to `dnssec-signzone` output.
  - All 81 query responses match BIND `named` structurally.
  - drill accepts every non-referral answer, apart from the known cases NSEC.3 and MINNSEC.3.

### INFRA.2 Three non-denial differences from BIND were found and aligned
- **Status:** resolved.
- **Details:**
  - NS answers now carry in-zone NS addresses in the additional section.
  - The DNSKEY TTL is now the zone TTL (was a constant 3600).
  - The NSEC3PARAM TTL is now 0 (was 300; RFC 5155 specifies none).
- **Note:** these could matter in the wild (e.g. DNSKEY caching), so future server-side choices should be deliberate.

### INFRA.3 Several BIND 9.20.x fixes touch exactly the paths under study
- **Status:** doc (release notes, 2026-10-13).
- **Details:**
  - 9.20.12: ANC failed when no parent NSEC was cached [GL #5422].
  - 9.20.21: NSEC3 iteration limit for referrals to unsigned delegations (CVE-2026-1519).
  - 9.20.26: invalid signed wildcards rejected (CVE-2026-11721); out-of-zone NSEC next names with synthesis (CVE-2026-13321); padded negative responses capped (CVE-2026-11605).
- **Implication:** resolver version is a first-class variable; record version and digest per run (the harness's `env.json` does).

### INFRA.4 BIND's compact-denial support is in dig only
- **Status:** doc (release notes, 2026-10-13; sources in CLAUDE.md §6).
- **Details:**
  - 9.18.38 and 9.20.11 add the CO flag and `+coflag` to dig [GL #5319].
  - MRs !11500 and !12750 only display type 128 as `NXNAME`.
  - No release note shows resolver or validator handling.
  - An earlier claim in this project that BIND had "compact-denial support" was wrong and was corrected.

### INFRA.5 The official Knot Resolver "v6.5.0" image reports a development version
- **Status:** doc (observed in the image, 2026-10-15).
- **Evidence:** `cznic/knot-resolver:v6.5.0` and `:latest` share digest `sha256:b2422a58…49e0`, but `kresd --version` prints `6.5.0.dev1+928fe2`; the package is `knot-resolver6 6.5.0.dev1+928fe2-cznic.1`.
- **Implication:** record the package version string and digest, not just "6.5.0".

### INFRA.6 dig sends ANY queries over TCP by default
- **Status:** doc (dig behavior).
- **Note:** explains transport fields in logs from manual tests; irrelevant to resolvers.

### INFRA.7 The lab's zone routing (static-stub / forward) is not neutral: PowerDNS disables aggressive caching for forwarded zones
- **Status:** doc (source code), observed 2026-10-15. **Resolved in the lab by INFRA.8** (delegation instead of forwarding); kept as a finding because it describes PowerDNS behavior for any forwarded zone.
- **Evidence:**
  - PowerDNS reaches our zones through `recursor.forward_zones` (RD=0), the only per-zone routing it offers. It validates, caches and *stores* NSEC records in its aggressive cache (`rec_control dump-cache - a`), but never synthesized: the `aggressive-nsec-cache-nsec-hits` counter didn't move, and every same-gap name went upstream (bring-up, 3 paused retries, run 20261015T185519Z).
  - `rec_control trace-regex` shows resolution going "Step0 Not cached → qname is in a forwarded domain" straight to the forwarder, with no aggressive-cache step.
  - Source, PowerDNS 5.4.x `pdns/recursordist/syncres.cc`: `if (g_aggressiveNSECCache && !wasForwardedOrAuthZone) { ... getDenial(...) }`. Insertion (line ~4916) has no such condition, which explains why the records are stored but unused.
- **Interpretation:** a deliberate PowerDNS design choice for forwarded and auth zones, not a bug and not its behavior on delegated zones. BIND (static-stub) and Knot (`forward` with `authoritative: true`) do use their aggressive caches for the same setup, so the routing artifact only shows up per resolver.
- **Implication:** to measure PowerDNS (and to remove routing as a confounder for all resolvers), resolvers should reach the zones through **ordinary delegation**: a local signed root (or `test.` parent) with NS + DS for each variant zone, a custom root hint per resolver, and the local root key as trust anchor. That's the same resolution path as the planned in-the-wild setup (CLAUDE.md §8).
- **Sources:** https://raw.githubusercontent.com/PowerDNS/pdns/rel/rec-5.4.x/pdns/recursordist/syncres.cc; trace output; `docker/pipeline.sh check` observation lines.

### INFRA.8 Local delegation setup: resolvers reach the zones from a signed local root
- **Status:** resolved (built 2026-10-15; 55/55 pipeline checks, run 20261015T191407Z).
- **Setup:**
  - A second responder instance (`root`, 172.30.0.11) serves `zones/root/root.zone`: a signed root zone that delegates the six variant zones to the responder (NS, glue `172.30.0.10`, DS). The DS records are generated by `pipeline.sh up` from the zones' keys.
  - Every resolver gets `docker/root.hints` and the local root's key as its **only** trust anchor (BIND `dnssec-validation yes`; Knot's file replaces its default root anchor, "overriding previously set trust anchors for ."; PowerDNS `trustanchors` for `.`).
  - Static-stub and forward zones are gone.
- **Lab-only exemptions and deviations from defaults** (each also commented in its config file). Every one of them must be removed, or re-justified, when moving to the in-the-wild setup, where the zones live under a real domain at public addresses:

  | Resolver | Setting | Why | Needed in the wild? |
  |---|---|---|---|
  | all | Root hints `docker/root.hints` and the lab root key as the only trust anchor | the lab has its own root | no: the real root and its default anchor |
  | Knot | Lua `policy.add(policy.suffix(policy.PASS, policy.todnames({'test.'})))` in `docker/knot/config.yaml` | Knot answers `.test` itself (RFC 6761) with an AD-flagged NXDOMAIN (ALL.9) | no: real domains aren't special-use |
  | Knot | Lua `modules.load('hints > iterate'); hints.root{…}` | Knot 6's YAML has no root-hints option | no |
  | PowerDNS | `outgoing.dont_query` = default list without 172.16.0.0/12 in `docker/pdns/recursor.yml` | the default refuses to query private addresses, which include the lab network (ALL.10) | no: public addresses |
  | PowerDNS | `dnssec.validation: validate` instead of the default `process` | validate every answer, like BIND and Knot | a choice: keep it, and record it |
  | BIND | none beyond hints and anchor (`.test` and private addresses work by default) | | |
  | Unbound (planned) | `local-zone: "test." nodefault` | documented to answer `.test` locally (ALL.9) | no |

- **Zone files:** `ns1 A` changed from 127.0.0.1 to 172.30.0.10, because delegation-following resolvers use it.
- **Effect:** PowerDNS's aggressive caching became measurable (INFRA.7). The routing change also altered other behavior (ALL.5, ALL.9, ALL.10), confirming that routing was a confounder.

---

## Old IDs → new IDs

| Old | New | | Old | New | | Old | New |
|---|---|---|---|---|---|---|---|
| A1 | ALL.4 | | B1 | NSEC.3 | | E1 | INFRA.4 |
| A2 | ALL.5 | | B2 | NSEC3.3 | | E2 | INFRA.3 |
| A3 | NSEC3.1 | | B3 | MINNSEC.2 | | E3 | INFRA.6 |
| A4 | NSEC.1 | | B4 | MINNSEC.3 | | E4 | WL.1 |
| A5 | ALL.2 | | C1 | INFRA.1 | | E5 | INFRA.5 |
| A6 | ALL.3 | | C2 | INFRA.2 | | F1 | ALL.6 |
| A7 | NSEC.2 | | D1 | NSEC3.4 | | F2 | ALL.7 |
| A8 | ALL.8 | | D2 | NSEC3.2 | | F3 | ALL.1, NSEC.1 |
| A9 | MINNSEC.1 | | | | | F4 | NSEC3.1 |
| A10 | CDOE.1, CDOE.2 | | | | | F5 | ALL.4 |
| | | | | | | F6 | MINNSEC.1, WL.2, CDOE.2 |
| | | | | | | F7 | ALL.2, ALL.3, ALL.5, CDOE.1 |
