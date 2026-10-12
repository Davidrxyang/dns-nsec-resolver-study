# CLAUDE.md: NSEC/NSEC3 variant measurement project

This file is the project context for Claude Code. It was written at the end of a planning conversation in claude.ai and carries over everything decided so far. Read it fully before writing code. Anything marked **[VERIFY]** came from memory or inference and has not been checked against an RFC or real data.

Date of handoff: 2026-10-12.

---

## 1. Project summary

Internet-measurement research project. Question: **how do recursive resolvers handle different authenticated-denial-of-existence variants?**

Variants under study:

| Variant | Reference | Notes |
|---|---|---|
| NSEC (vanilla) | RFC 4034/4035 | Pre-signed chain, real gaps |
| NSEC3 (vanilla) | RFC 5155 | Hashed names, closest-encloser proof |
| Minimally covering NSEC | RFC 4470 | Signer behavior, wire format is a normal NSEC whose next name is the immediate successor of the owner |
| Compact Denial of Existence (CDOE) with NSEC | RFC 9824 | NOERROR/NODATA for nonexistent names, NXNAME (type 128) in bitmap |
| CDOE with NSEC3 | RFC 9824 §4 | One NSEC3 matching the QNAME hash; NXNAME is the sole bitmap entry |

Resolvers to study: BIND, Unbound, Knot Resolver, PowerDNS Recursor.

Working hypothesis (from documentation review, to be confirmed experimentally): apart from NSEC vs NSEC3, resolvers do not explicitly differentiate the variants. Known implicit handling: Knot disables aggressive negative caching (ANC) for minimal ranges; PowerDNS disables ANC for minimally covering NSEC3; BIND lists RFC 4470 and has recent compact-denial support.

Three processing points to examine per resolver: **intake** (from authoritative), **storage** (cache), **output** (to client).

Plan: (1) docs review, (2) local experiments, (3) distributed in-the-wild measurement. Also open: how common are RFC 4470 / RFC 9824 variants in the wild?

---

## 2. Current phase and scope

**We are at the start of local experiments.** The immediate job is a **custom authoritative responder in Python** that behaves like a real nameserver and can emit each variant under fine-grained control. No resolvers are involved yet: the client (`dig`, `delv`, scripts) queries the responder directly.

**Language: Python** (dnspython + cryptography). We briefly considered Go (miekg/dns) and decided to stay with Python.

Later (not now): deploy the same responder on cloud VMs, delegate real signed child zones for in-the-wild measurement, and deploy resolvers on AWS.

### Design decision already made

Two options were weighed: (A) modify a production authoritative server, or (B) write a small custom responder. **Decision: B.**

Reasons: production servers produce correct standard denial and would be fought; each server only produces the variants it implements in its own way (confounds comparison); we need per-response control, including deliberately odd or malformed output, and server-side logging as ground truth for the wild measurements.

**Signing cannot be skipped.** Validating resolvers only process NSEC/NSEC3 interestingly (accept, cache, ANC, synthesize) if the records validate. So the responder needs real RRSIGs, a DNSKEY, and a trust anchor (locally) or a DS in a signed parent (in the wild).

Mitigation for fidelity risk: validate our vanilla NSEC/NSEC3 output against a reference signer (Knot, BIND, or PowerDNS signing the same zone) and against independent validators. If vanilla matches, variants built on the same code are trustworthy.

---

## 3. Step plan for the responder

**Step 0. Decisions.** Python, dnspython + cryptography, ECDSA P-256 (algorithm 13, small signatures), listen on `127.0.0.1:5300` UDP and TCP (5353 was the original plan, but it is mDNS and avahi holds it; `--port` overrides), `.test` names so nothing collides with real DNS. One zone per variant eventually (`nsec.test.`, `nsec3.test.`, `minnsec.test.`, `cdoe-nsec.test.`, `cdoe-nsec3.test.`), each with its own key and local trust anchor.

**Step 1. Minimal real nameserver (DONE 2026-10-12).** See section 4. Run `venv/bin/python -m responder`; gates in `tests/gates.sh`, unit tests via `venv/bin/python -m unittest discover -s tests -t .`.

**Step 2. Vanilla NSEC.** NXDOMAIN needs SOA + cover for qname + cover for the wildcard at the closest encloser (each with RRSIG). NODATA needs the matching NSEC with a correct bitmap. Also: wildcard expansion, empty non-terminals, DS at delegations. Gate: structure matches the root response fixture; validates in `delv` and `dns.dnssec.validate`.

  **DONE 2026-10-12.** Chain built in `responder/denial.py` (`NsecDenial`), lookup flow in `responder/answer.py`, variant chosen by `zones/<zone>.toml` (`denial = "nsec"`). Checked against RFC 4035 §2.2/§2.3/§3.1.3/§3.1.4 and RFC 9077 (NSEC TTL and negative SOA TTL = min(SOA TTL, SOA MINIMUM)). Delegation NS and glue are not signed and get no NSEC. `tests/test_step2.py` diffs NXDOMAIN shape against `tests/golden/root-nsec-nxdomain.txt`; `tests/gates.sh` has delv checks for every case, and a deliberately broken proof (wildcard NSEC dropped) makes delv fail with "broken trust chain". Simplifications: CNAME is returned but not chased; qtype ANY gets NOTIMP; AXFR/IXFR get REFUSED. Still open: no reference signer installed (`dnssec-signzone`, `ldns-signzone`, Knot) to diff the NSEC chain against.

**Step 3. Vanilla NSEC3.** Configurable algorithm, iterations, salt, opt-out flag; NSEC3PARAM at apex. Closest-encloser proof: match for closest encloser, cover for next-closer name, cover for wildcard. Gate: matches `.com` fixture shape; our hash function reproduces real `.com` hashes.

**Step 4. Variants (one switch per zone).** Minimally covering NSEC and NSEC3 (RFC 4470, RFC 7129 App. B); CDOE NSEC; CDOE NSEC3. Gate: CDOE NSEC output matches the Cloudflare fixture shape; for NSEC3 variants there is no real public reference, so rely on RFC text and validators.

**Step 5. Logging and control.** Log timestamp, source, transport, qname, qtype, DO, EDNS size, RD, and a hash of the response sent. Per-zone config; later per-query overrides for deliberate edge cases.

---

## 4. Step 1 specification (do this first)

Goal: prove signing and basic serving work end to end before touching denial.

Environment: `pip install dnspython cryptography`.

1. Generate an ECDSA P-256 key; build its DNSKEY. Single key as both KSK and ZSK is fine for now (check which flags value, 256 or 257, the validators accept; 257 is the usual choice for a key that anchors trust).
2. In-memory zone: SOA, NS, DNSKEY, one `A`, one `TXT` (e.g. `www.nsec.test.`).
3. Sign every RRset (`dns.dnssec.sign` or equivalent). Validity window: **inception a few minutes in the past, expiration well in the future** so clock skew cannot interfere.
4. Handle only: positive answers (RRSIGs included only if DO is set); everything else returns `REFUSED` or `NOTIMP` (denial is step 2).
5. Header/EDNS behavior: copy query ID and question; set `qr` and `aa`; copy `rd`; **never set `ra`**; echo EDNS and the DO bit if the query had them.
6. Serve UDP and TCP; set `tc` if a UDP response exceeds the client's advertised size.
7. Log every query (see step 5 fields).

### Gates (run in order; each isolates a different failure)

```bash
# 1. Answers at all, flags right?
dig -p 5300 @127.0.0.1 +dnssec +norec www.nsec.test A

# 2. TCP works?
dig -p 5300 @127.0.0.1 +tcp +dnssec www.nsec.test A

# 3. DNSKEY and its signature come back?
dig -p 5300 @127.0.0.1 +dnssec nsec.test DNSKEY

# 4. Independent validation with a local trust anchor
delv -p 5300 @127.0.0.1 -a zones/nsec.test.anchor +root=nsec.test www.nsec.test A
```

Expected for gate 4: `; fully validated`. Verified on delv 9.20.24: `-a`, `-p`, `+root=NAME` exist; the anchor file is named.conf syntax, `trust-anchors { nsec.test. static-key 257 3 13 "<b64>"; };` (delv treats static-key and initial-key the same). The responder writes it to `zones/<zone>.anchor` at startup. `delv` sets RD=1, so the responder must answer normally when RD is set (without claiming `ra`).

Also cross-check in Python: `dns.dnssec.validate(rrset, rrsigset, {zone_name: dnskey_rrset})`. Note: signing and validating with the same library can hide shared bugs, so `delv` passing is the real independent check.

### Common failure causes

- Signature window (see above).
- Canonical form: names lowercased in signed data, RRset records in canonical order. Use dnspython's helpers; do not hand-assemble.
- Key tag, algorithm, and trust anchor must agree (algorithm 13, same key tag).
- DNSKEY RRset must be signed by the key the trust anchor names.
- RRSIGs belong only in responses to queries with DO set.
- ECDSA signatures are randomized, so compare structure, not raw signature bytes, when diffing.

---

## 5. Domain knowledge established so far

### 5.1 How the three real responses were obtained

All three were captured with `dig +dnssec +norec @<authoritative> <nonexistent-name> A` from the researcher's laptop (dig 9.20.24). `+dnssec` sets the DO bit; without DO an authority returns only the SOA. The denial variant returned is a **property of the zone as signed by its owner**, not something the querier chooses, and **not predictable from the operator** (Verisign signs the root with NSEC and `.com` with NSEC3). In the wild you classify a zone by probing it.

### 5.2 Classification table (for the future prevalence classifier)

Probe with DO set for a name that almost certainly does not exist:

| Observed | Variant |
|---|---|
| NXDOMAIN + NSEC records | NSEC (vanilla, or minimally covering: check gap) |
| NXDOMAIN + NSEC3 records | NSEC3 |
| NOERROR + NSEC/NSEC3 with NXNAME (type 128) in bitmap | Compact denial (RFC 9824) |
| NOERROR/NODATA + one NSEC, next name = `\000.` + owner, no NXNAME | Older "black lies" |
| No NSEC/NSEC3 | Unsigned zone or server ignored DO |

Minimally covering NSEC is **not** distinguishable by wire format alone: it is a normal NSEC whose gap happens to be one name. Probe several names; any wide gap rules it out. Also useful: query `NSEC3PARAM` at the apex (present means the zone uses NSEC3). A zone's behavior can depend on qtype and on whether the name exists (online signers), so use several probes (nonexistent name, existing name with missing type, DS query).

### 5.3 Golden fixtures

Save these three as files under `tests/golden/` and diff structure (record counts, ordering, flags, RCODE, bitmaps, TTL/RRSIG fields, EDNS echo) against the responder output. Signatures abbreviated here; re-capture the full output with dig for the fixtures. Capture dates are 2026-10-08.

**Root: vanilla NSEC, NXDOMAIN, RSA (alg 8)**

```
$ dig +dnssec +norec @a.root-servers.net nosuchtld-12345. A
status: NXDOMAIN   flags: qr aa   ANSWER: 0, AUTHORITY: 6, ADDITIONAL: 1
EDNS: version 0, flags: do; udp: 4096   MSG SIZE 1035

.        86400 IN SOA   a.root-servers.net. nstld.verisign-grs.com. 2026100801 1800 900 604800 86400
.        86400 IN RRSIG SOA 8 0 86400 20261021170000 20261008160000 8763 . <sig>
norton.  86400 IN NSEC  now. NS DS RRSIG NSEC
norton.  86400 IN RRSIG NSEC 8 1 86400 20261021170000 20261008160000 8763 . <sig>
.        86400 IN NSEC  aaa. NS SOA RRSIG NSEC DNSKEY ZONEMD
.        86400 IN RRSIG NSEC 8 0 86400 20261021170000 20261008160000 8763 . <sig>
```

Shape: SOA, name-cover NSEC (norton. to now. covers the qname), wildcard-cover NSEC (`.` to `aaa.` covers `*.`), each with RRSIG.

**.com: NSEC3 with opt-out, NXDOMAIN, ECDSA (alg 13)**

```
$ dig +dnssec +norec @a.gtld-servers.net nosuchdomain-12345.com A
status: NXDOMAIN   flags: qr aa   ANSWER: 0, AUTHORITY: 8, ADDITIONAL: 1
EDNS: version 0, flags: do; udp: 4096   MSG SIZE 758

com. 900 IN SOA a.gtld-servers.net. nstld.verisign-grs.com. 1791483514 1800 900 604800 900
com. 900 IN RRSIG SOA 13 1 900 20261015181834 20261008170834 41446 com. <sig>
CK0POJMG874LJREF7EFN8430QVIT8BSM.com. 900 IN NSEC3 1 1 0 - CK0Q35HRS4H76G6CHNB9414CJN6S5UPL NS SOA RRSIG DNSKEY NSEC3PARAM
CK0POJMG874LJREF7EFN8430QVIT8BSM.com. 900 IN RRSIG NSEC3 13 2 900 20261013002613 20261005231613 41446 com. <sig>
IG5R31M6T147OMOL6JQDLQQUBITNJPVT.com. 900 IN NSEC3 1 1 0 - IG5RPBVTAI2UVUC3FQ245KEI693A27CQ NS DS RRSIG
IG5R31M6T147OMOL6JQDLQQUBITNJPVT.com. 900 IN RRSIG NSEC3 13 2 900 20261012002418 20261004231418 41446 com. <sig>
3RL2Q58205687C8I9KC9MV46DGHCNS45.com. 900 IN NSEC3 1 1 0 - 3RL2VRNHRTNQP2ACB7JK3K0OGV4ST3U3 NS DS RRSIG
3RL2Q58205687C8I9KC9MV46DGHCNS45.com. 900 IN RRSIG NSEC3 13 2 900 20261012002603 20261004231603 41446 com. <sig>
```

NSEC3 fields: hash alg 1 (SHA-1), flags 1 (opt-out), iterations 0, salt none. The first record's bitmap (SOA, DNSKEY, NSEC3PARAM) identifies it as the hash of `com.` (closest-encloser match). The other two cover the next-closer name and the wildcard; which is which requires computing hashes (not done yet). **Test: our NSEC3 hash of `com.` must equal `CK0POJMG874LJREF7EFN8430QVIT8BSM`.**

**Cloudflare: compact denial with NXNAME, NOERROR, ECDSA (alg 13)**

```
$ dig +dnssec +norec @ns4.cloudflare.com nosuchname-12345.cloudflare.com A
status: NOERROR   flags: qr aa   ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 1
EDNS: version 0, flags: do; udp: 1232   MSG SIZE 390

cloudflare.com. 300 IN SOA ns3.cloudflare.com. dns.cloudflare.com. 2416724497 10000 2400 604800 300
nosuchname-12345.cloudflare.com. 300 IN NSEC \000.nosuchname-12345.cloudflare.com. RRSIG NSEC TYPE128
nosuchname-12345.cloudflare.com. 300 IN RRSIG NSEC 13 3 300 20261009191938 20261007171938 34505 cloudflare.com. <sig>
cloudflare.com. 300 IN RRSIG SOA 13 2 300 20261009191938 20261007171938 34505 cloudflare.com. <sig>
```

Shape: one NSEC owned by the QNAME itself, next name `\000.` + QNAME, bitmap `RRSIG NSEC TYPE128` (TYPE128 is NXNAME; this dig version prints the raw number), no A in the bitmap, online-signed with a short validity window, 4 records total.

### 5.4 Facts worth remembering

- **Header flags.** `qr` response; `aa` authoritative; `rd` recursion desired (client); `ra` recursion available (resolver); `tc` truncated; `ad` authenticated data (set by validating resolvers only, never by authorities); `cd` checking disabled. Authoritative responses here: `qr aa` only.
- **DO bit** (EDNS) is required for NSEC/NSEC3/RRSIG to be included. `udp:` in the OPT record is a max UDP payload size; Cloudflare uses 1232 to avoid fragmentation.
- **SOA** in a negative response identifies the zone and sets the plain negative-caching TTL (RFC 2308: min of SOA TTL and SOA minimum field). **When testing ANC, use short SOA TTLs so ordinary negative caching does not mask aggressive negative caching.**
- **NSEC canonical ordering** is label-wise from the right, lowercase, byte-wise (not plain string sort). `norton.` < `nosuchtld-12345.` < `now.`.
- **NSEC3:** SHA-1 over wire-format lowercase name + salt, repeated iterations+1 times, base32hex encoded. RFC 9276 best practice is iterations 0 and no salt. Opt-out flag means gaps may contain unsigned delegations.
- **NXNAME** is type 128 (RFC 9824). For NSEC3 CDOE it is the sole bitmap entry.
- **RRSIG fields:** type covered, algorithm (8 RSA/SHA-256, 13 ECDSA P-256), label count (excludes wildcard `*`; resolvers use it to detect wildcard expansion), original TTL, expiration, inception, key tag, signer. Online signers use short windows; Verisign pre-signs with staggered windows.
- **ECDSA P-256** signatures are about 64 bytes vs about 256 for RSA-2048, which keeps responses under UDP limits.
- **RFC 9824 caveat [VERIFY]:** the next-name for CDOE is *not always* `\000.` + owner. The RFC computes a slightly different "epsilon" in some cases (when the immediate successor would fall under a delegated subzone). RFC 9824 also covers wildcards ("claims the QNAME exists explicitly"), direct queries for NXNAME (section 3.5), DS handling, and NSEC3 changes (section 4). **Read the RFC text, not summaries.** RFC 9824 is dated August/September 2025; it updates RFC 4034 and RFC 4035.

---

## 6. Documentation-review findings (from the researcher's notes)

- **BIND 9:** lists RFC 4470, not RFC 9824, yet CDOE support appears in 9.18.x release notes (notes for 9.18.38) and GitLab issues (5319); NXNAME work in MRs 11500 and 12750. Open question: is 4470 support only online-signing, or is there a mechanism that identifies minimally covering NSEC?
- **Unbound:** RFC compliance page lists neither 4470 nor 9824; has aggressive-NSEC docs.
- **Knot Resolver:** RFC list lacks both; release notes mention ANC disabled for minimal ranges (4.1.0, 2019).
- **PowerDNS Recursor:** compliance page lacks both; ANC disabled for minimally covering NSEC3 (pdns-users, June 2023).

Related work to read for experiment design: OARC aggressive NSEC3 presentation; "DNS record dropping" (Lee et al.); "Negative Caching" (Deccio et al.); OARC "Authenticated Denial" presentation; dmarcwise.io DMARC NP / DNSSEC incompatibility; "Dissecting NSEC/3 deployment" (Zhang et al.).

---

## 7. Local verification toolkit

- `dig` for raw responses; `delv` (BIND tools) for validation against a local trust anchor.
- `dns.dnssec.validate` in dnspython as a second implementation. Use more than one validator: they can disagree on edge cases.
- DNSViz's command-line tool can probe a specific server with a local trust anchor **[VERIFY options]**.
- A reference signer (Knot, BIND, or PowerDNS) signing the same zone for vanilla NSEC/NSEC3 comparison.
- Public infrastructure cannot validate our zones directly (not delegated). Use it for golden fixtures and to test our code on real data: reproduce the real `.com` apex hash; verify a real NSEC RRSIG with a real DNSKEY using our canonicalization code; check our canonical ordering on real chains.

---

## 8. Later phases (for context, not for now)

**Wild measurement setup:** register one domain; run each variant as its own signed child zone; run the parent ourselves so we can publish DS records without a registrar per variant (only the parent domain needs a DS at the registrar). Use unique random labels per probe; probe pairs of names falling in the same gap to detect ANC (did the resolver come back to us or not, using server logs as ground truth).

**Targets:** public resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9, 208.67.222.222, 64.6.64.6; confirm each validates via the `ad` flag first), RIPE Atlas probes for ISP resolvers, open resolvers. Caveats: public resolvers are anycast fleets with many caches (breaks the simple "ask twice" ANC test; repeat probes); their software is mostly opaque.

**Prevalence study:** take signed domains from a top list or zone files, group by NS operator, probe one or two zones per operator with the classifier. Known leads **[VERIFY]**: Cloudflare (online-signed minimal NSEC since about 2016, now NXNAME), PowerDNS Authoritative narrow NSEC3 mode, CoreDNS dnssec plugin. CDOE NSEC3 may be rare or absent in the wild; if so it is a local-only test.

**Local resolver experiments (ANC probe):** enable aggressive NSEC on each resolver; query a nonexistent name in a vanilla-NSEC zone, then a second name in the same gap, and watch whether the second goes upstream (tcpdump, query logs, or server-side logs). Repeat against minimal-cover and CDOE zones. Matrix: variant x resolver x query type (nonexistent name, missing type, wildcard, empty non-terminal, DS) x configuration (ANC on/off, defaults). Observe cache contents and client-facing RCODEs for intake/storage/output.

**Good probing etiquette:** low rate, random labels, spread over time; authoritative servers belong to others.

---

## 9. Working conventions for Claude Code

- **Do not trust, verify.** Several statements in this file are marked [VERIFY]. When a claim affects code behavior (RFC details, tool flags), check the RFC text or tool help rather than relying on this document.
- Keep responder code small and structured so each variant is a switch on the zone config, and share signing, framing, and logging code across all variants.
- Prefer dnspython helpers for canonicalization and signing; do not hand-assemble signed data.
- Every milestone needs a gate: a script that runs `dig`/`delv` and the golden-fixture structure diff.
- Suggested repo layout:

```
nsec-responder/
  CLAUDE.md
  responder/        # server, zone config, signing, denial builders per variant
  tests/
    golden/         # the three real dig captures
    gates.sh        # dig/delv gate commands
    test_*.py
  zones/            # per-variant zone definitions and trust anchors
  logs/
```

## 10. Immediate next actions

1. Create the repo layout and `pip install dnspython cryptography`.
2. Save the three golden fixtures with full dig output.
3. Implement and pass step 1 gates (section 4).
4. Check the installed `delv` flags and trust-anchor format.
5. Read RFC 4470, RFC 7129 Appendix B, RFC 9824, and RFC 5155 section 7 before step 2 and step 3.
6. Then proceed to step 2 (vanilla NSEC denial).
