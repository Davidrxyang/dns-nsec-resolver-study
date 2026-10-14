# Denial-of-existence variants: specification and implementation decisions

What each variant zone serves, which standard each rule comes from, and every implementation decision taken where the standards are silent or ambiguous. Code comments cite the decision IDs (Dn) used here. RFC text was checked on 2026-10-14.

## Overview

All six zones have identical content (`zones/nsec.test.zone` under another origin), so results compare directly.

| Zone | `denial =` | Class | Reference | Status of reference | Signing | Nonexistent name → | NSEC/NSEC3 per NXDOMAIN |
|---|---|---|---|---|---|---|---|
| `nsec.test` | `nsec` | `NsecDenial` | RFC 4034, 4035 | Standards Track | pre-signed | NXDOMAIN | 1–2 |
| `nsec3.test` | `nsec3` | `Nsec3Denial` | RFC 5155, 9276 | Standards Track | pre-signed | NXDOMAIN | 2–3 |
| `minnsec.test` | `minimal-nsec` | `MinimalNsecDenial` | RFC 4470 (+ erratum 6734) | Standards Track | online | NXDOMAIN | 2 |
| `minnsec3.test` | `nsec3-white-lies` | `Nsec3WhiteLiesDenial` | RFC 7129 App. B | Informational | online | NXDOMAIN | 3 |
| `cdoe-nsec.test` | `compact-nsec` | `CompactNsecDenial` | RFC 9824 §3 | Standards Track | online | NOERROR (NXDOMAIN with CO) | 1 |
| `cdoe-nsec3.test` | `compact-nsec3` | `CompactNsec3Denial` | RFC 9824 §4 | Standards Track | online | NOERROR (NXDOMAIN with CO) | 1 |

Per-zone diagrams (name tree, chain, proofs, example responses generated from the responder): [docs/zones/](zones/README.md).

Code: `responder/denial.py` (variants), `responder/answer.py` (lookup flow), `responder/zone.py` (signing, incl. `sign_online`).

**Verification:**
- Unit tests: `tests/test_step2.py` (NSEC), `test_step3.py` (NSEC3), `test_step4.py` (the four online variants).
- delv gates: `tests/gates.sh`.
- Reference signer and drill: `tests/reference.py`.
- BIND resolution: `docker/pipeline.sh check`.

As of 2026-10-14, delv validates every applicable case in all six zones. The DS query at a zone's own apex can't be validated with an island trust anchor and is excluded.

---

## Responses by variant

Notation:
- `pred(x)` / `succ(x)`: RFC 4470 §4 predecessor and successor (`succ(x)` = `\000.x`).
- `x\000`: `x` with `\000` appended to its first label (the subtree successor; see D5 and D14).
- `h(x)`: NSEC3 hash of `x`.
- `ce`: closest encloser.
- `nc`: next closer name.

### Minimally covering NSEC (RFC 4470)

| Case | Authority (besides SOA) | Source |
|---|---|---|
| NXDOMAIN | NSEC `pred(nc) → nc\000` [RRSIG NSEC]; NSEC `pred(*.ce) → *.ce\000` [RRSIG NSEC] | RFC 4470 §3 (bitmap "MUST include RRSIG and NSEC … SHOULD NOT include any other"); D14, D15 |
| NODATA | NSEC `name → succ(name)` [real types + RRSIG NSEC] | §3 (relaxes RFC 4034 §4.1.1) |
| Empty non-terminal | NSEC `pred(ent) → succ(ent)` [RRSIG NSEC] (a cover whose next name is below the ENT) | D4 |
| Wildcard answer | expanded RRset with the wildcard's pre-signed RRSIG; NSEC `pred(nc) → nc\000` | RFC 4035 §3.1.3.3; D15 |
| Wildcard NODATA | NSEC `pred(nc) → nc\000`; NSEC `*.ce → succ(*.ce)` [wildcard types] | RFC 4035 §3.1.3.4 |
| Unsigned referral / DS NODATA at cut | NSEC `cut → cut\000` [NS RRSIG NSEC] | D5 |

### NSEC3 white lies (RFC 7129 Appendix B)

Every record is a white lie, as in the RFC's example:
- **match:** `h(x) → h(x)+1` with `x`'s real types;
- **cover:** `h(x)−1 → h(x)+1` with an empty bitmap.

Flags 0, iterations 0, no salt by default.

| Case | NSEC3 records | Source |
|---|---|---|
| NXDOMAIN | match(ce), cover(nc), cover(*.ce) | RFC 7129 App. B example; RFC 5155 §7.2.2 |
| NODATA / ENT | match(name) (an ENT has an empty bitmap) | RFC 5155 §7.2.3; D22 |
| Wildcard answer | cover(nc) | RFC 5155 §7.2.6; D22 |
| Wildcard NODATA | match(ce), cover(nc), match(*.ce) | RFC 5155 §7.2.5; D22 |
| Unsigned referral / DS NODATA | match(cut) [NS] | RFC 5155 §7.2.7, §7.2.4; D22 |

### Compact denial, NSEC (RFC 9824 §3)

| Case | Rcode | Authority (besides SOA) | Source |
|---|---|---|---|
| Nonexistent name | NOERROR; NXDOMAIN if DO=0 or CO=1 | NSEC `qname → succ(qname)` [RRSIG NSEC NXNAME] | §3.1 (bitmap MUST be exactly these); §5.1; D11 |
| NODATA | NOERROR | NSEC `name → succ(name)` [real types + RRSIG NSEC] | §3.2 |
| Empty non-terminal | NOERROR | NSEC `ent → succ(ent)` [RRSIG NSEC], no NXNAME | §3.2 |
| Wildcard answer | NOERROR | none; RRset signed online as an exact match (RRSIG labels = QNAME labels) | §3.3 (MUST) |
| Wildcard NODATA | NOERROR | NSEC `qname → succ(qname)` [the wildcard's types + RRSIG NSEC] | §3.3; D18 |
| Unsigned referral / DS NODATA | NOERROR | NSEC `cut → cut\000` [NS RRSIG NSEC] | §3.4; D19 |
| Query for type NXNAME | FORMERR + EDE 30 | none | §3.5 (MUST); D13 |

### Compact denial, NSEC3 (RFC 9824 §4)

Parameters `1 0 0 -` (§4 SHOULD). Every record is `h(x) → h(x)+1`.

| Case | Rcode | NSEC3 record | Source |
|---|---|---|---|
| Nonexistent name | as compact NSEC | `h(qname)` [NXNAME] | §4 |
| NODATA / ENT | NOERROR | `h(name)` [real types; empty for an ENT] | §4 + §3.2 |
| Wildcard answer | NOERROR | none; RRset signed as an exact match | §4 + §3.3 |
| Wildcard NODATA | NOERROR | `h(qname)` [the wildcard's types] | §4 + §3.3; D18 |
| Unsigned referral / DS NODATA | NOERROR | `h(cut)` [NS] | §4 + §3.4; D19 |

---

## Implementation decisions

Each entry gives what was decided, why, and what the standards say.

| ID | Decision | Rationale and standards basis |
|---|---|---|
| **D1** | The variant is chosen per zone in `zones/<zone>.toml` (`denial = …` plus parameters). | Project convention (CLAUDE.md §9): one switch per zone; signing, framing and logging are shared. |
| **D2** | All variant zones have identical content. | Differences in resolver behavior can then only come from the denial variant. |
| **D3** | Online records are signed with the zone's fixed validity window (inception = start − 1 h, expiration = start + 30 d), deterministically (RFC 6979), and the signatures are cached. | No RFC prescribes online-signing windows. Cloudflare uses rolling windows of about ±25 h around each query (fixture). The fixed window keeps responses reproducible. A rolling-window knob belongs with planned experiment P04. |
| **D4** | Minimal NSEC: an empty non-terminal is proved by a cover `pred(ent) → \000.ent`, not by an NSEC owned by the ENT. | RFC 4035 §2.3 forbids an NSEC as the only RRset at a name. RFC 9824 §7.2 relaxes that only for compact denial. A next name below the ENT is the standard proof that the ENT exists (as in a pre-signed chain). |
| **D5** | Online NSEC owned by a delegation point (minimal and compact): next name = `cut\000`, not `\000.cut`. | RFC 9824 §3.4 specifies this for referrals, because `\000.cut` would lie inside the child zone. RFC 4470 is silent; we apply the same rule. |
| **D6** | Length limits: `succ` falls back to the subtree successor if `\000.x` would exceed 255 octets. The subtree successor raises (giving SERVFAIL) if the first label already has 63 octets. `pred` shortens its `\377` padding to stay within 255 octets. | RFC 4470 §4 says its functions are "imperfect" and ignore the 63- and 255-octet limits. RFC 9824 is silent. |
| **D7** | `pred`: names are lowercased first. A decremented octet that lands in `A`–`Z` is lowered to `@` (0x40). | Canonical order compares `A`–`Z` as `a`–`z` (RFC 4034 §6.1), so `Z` would sort *above* `[`. `@` is the largest octet that sorts below them. RFC 4470 says nothing about case. |
| **D8** | Minimal NSEC: if an existing name lies between `pred(x)` and `x`, it becomes the cover's owner with its real bitmap. | RFC 4470 §3: "use the covered existing name closest to the QNAME as the owner". If that name were an ENT, the NSEC would be owned by an ENT (see D4). With the RFC's epsilon functions this needs an existing name like `nopd\377…`, so it is practically unreachable. |
| **D9** | Online NSEC3 variants publish NSEC3PARAM `1 0 0 -` at the apex, with TTL 0. | RFC 9824 doesn't say whether to publish it. RFC 7129's example apex bitmap includes NSEC3PARAM. TTL 0 matches BIND's signer (FINDINGS C2). It also lets the prevalence classifier see NSEC3 at the apex. |
| **D10** | Online NSEC3 variants never use opt-out (flags 0). | RFC 9824 §4 gives flags 0 and notes opt-out brings no benefit. All RFC 7129 examples use 0. Without an existing chain there is nothing to opt out of. |
| **D11** | Compact denial: NXDOMAIN when the query has CO=1 (with CO echoed) or has DO=0; NOERROR otherwise. CO is echoed only by compact zones. | §5.1: with CO, the server "will set the Compact Answers OK … flag and … set the response code field to NXDOMAIN". §5: servers "should try to preserve" NXDOMAIN where possible, and for non-DO queries "could" return a normal NXDOMAIN; with no proof to keep consistent, we do. Non-compact zones don't implement §5.1, so they don't echo CO. |
| **D12** | Online NSEC variants answer a query for type NSEC at an existing name with the online record (and include its RRSIG in a qtype-RRSIG answer). | Their bitmaps advertise NSEC at the name, so answering NODATA would contradict the zone's own proofs. No RFC covers direct NSEC queries to online signers. |
| **D13** | A query for type NXNAME (128) gets FORMERR with EDE 30 (Invalid Query Type) in every zone. | RFC 9824 §3.5: the server "MUST return a Format Error"; EDE 30 is a MAY. NXNAME is a meta type in the IANA registry, not just in compact zones. |
| **D14** | Minimal NSEC covers for nonexistent names use next name `x\000` (the subtree successor), not `\000.x`. A knob, `cover_next = "child"`, gives the literal RFC 4470 §4 form for experiments. | RFC 4470 §4 says to increment by prepending a `\000` label, but its §3 example uses a sibling (`exampld.com → example-.com`). **Erratum 6734** (Reported, M. Andrews, ISC, 2021): `\000.domain` "can only be used to prove no data exists at 'domain'". BIND's validator rejects the literal form ("nsec proves name exist (empty)", then `broken trust chain`), while drill accepts it (FINDINGS B3). `x\000` is the smallest name after `x`'s whole subtree, the same construction as RFC 9824 §3.4. |
| **D15** | Minimal NSEC covers span the **next closer name**, not the QNAME. | A minimal span around a QNAME two or more labels below the closest encloser lies inside the next closer's subtree, so it never proves the next closer absent. BIND then rejects the proof (seen with `foo.bar.ent`). Pre-signed chains get this implicitly from their wide gaps; RFC 5155 makes the next closer explicit for NSEC3. RFC 4470 says "QNAME" without addressing this. |
| **D16** | Online records use lowercased (canonical) owner names. | Validators compare names case-insensitively, and the signed data is canonical anyway (RFC 4034 §6.2). Cloudflare echoes the query's case instead; we don't, which also keeps the signature cache effective. |
| **D17** | Every online NSEC/NSEC3 uses the negative TTL, min(SOA TTL, SOA MINIMUM) = 60. | RFC 9077 applies to all NSEC/NSEC3. RFC 4470 and RFC 9824 only show example TTLs (3600, 300). |
| **D18** | Compact wildcard NODATA: the next name is `succ(qname)` (NSEC), or `h(qname)+1` (NSEC3). | §3.3 calls it "akin to a non-wildcard NODATA" without giving a next name; we take §3.2's rule. |
| **D19** | Compact DS query at an unsigned delegation: the parent-side NSEC in §3.4's referral form (`cut → cut\000`, NS RRSIG NSEC). | §3.4 covers referrals only; the RFC doesn't treat a direct DS query separately. RFC 4035 §3.1.4.1 requires the parent side to answer. |
| **D20** | Negative answers in every variant carry the SOA and its RRSIG. | RFC 2308 negative caching. RFC 9824 doesn't mention the SOA, but Cloudflare's compact answers include it (fixture). |
| **D21** | White lies: the closest-encloser match is also a white lie (`h(ce) → h(ce)+1`). Cover bitmaps are empty, unless `h−1` happens to be an existing name's hash, in which case they carry that name's types. | RFC 7129 App. B example and text, verbatim. |
| **D22** | White lies for NODATA, ENT, wildcard and referral answers: RFC 5155 §7.2 proof structure built from white-lie records. | RFC 7129 App. B only shows NXDOMAIN. |
| **D23** | NSEC3 variants: if a nonexistent name's hash equals an existing name's hash, the answer is SERVFAIL. | RFC 5155 §7.2.9. |
| **D24** | One combined signing key (CSK), one algorithm (13), for every record. | RFC 4470 §3 needs an RRSIG for every algorithm in the DNSKEY RRset, and here there is one. RFC 9824 §8 recommends elliptic-curve algorithms for online signing. |
| **D25** | Minimal NSEC and white-lies wildcard answers use the wildcard's pre-signed RRSIG (labels < owner) plus an online cover; only compact denial signs them as exact matches. | RFC 4470 and RFC 7129 change only the denial records; RFC 4035 §3.1.3.3 still governs wildcard answers. RFC 9824 §3.3 explicitly differs. |

---

## Behavior observed so far

See FINDINGS.md for details:
- **BIND 9.20.29** validates all six variants. It never synthesizes from NSEC3 (A3), and it does not store minimal-NSEC records for synthesis (A9). It does not send or honor CO, so clients see NOERROR for compact-denied names (A10).
- **drill 1.8.4** rejects minimal-NSEC ENT proofs, a known limitation (B1, B4).
- **The literal RFC 4470 §4 cover form** is rejected by BIND (B3; D14).
