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
| Minimally covering NSEC3 ("NSEC3 white lies") | RFC 7129 App. B (Informational) | Online signing; each cover NSEC3 has owner = hash(name) − 1 and next = hash(name) + 1, inside the normal NXDOMAIN closest-encloser proof (up to 3 NSEC3). Deployed as PowerDNS Authoritative "narrow" mode |
| Compact Denial of Existence (CDOE) with NSEC | RFC 9824 | NOERROR/NODATA for nonexistent names, NXNAME (type 128) in bitmap |
| CDOE with NSEC3 | RFC 9824 §4 | One NSEC3 matching the QNAME hash; NXNAME is the sole bitmap entry |

Resolvers to study: BIND, Unbound, Knot Resolver, PowerDNS Recursor.

Working hypothesis (from documentation review, to be confirmed experimentally): apart from NSEC vs NSEC3, resolvers do not explicitly differentiate the variants. Known implicit handling: Knot disables aggressive negative caching (ANC) for minimal ranges; PowerDNS Recursor (≥ 4.9.0) does not store NSEC3 records covering only a tiny fraction of names in its aggressive cache, i.e. minimally covering NSEC3 / white lies; BIND lists RFC 4470, synthesizes (ANC) from NSEC only, never NSEC3, and its compact-denial support so far is in `dig` only (see section 6).

Three processing points to examine per resolver: **intake** (from authoritative), **storage** (cache), **output** (to client).

Plan: (1) docs review, (2) local experiments, (3) distributed in-the-wild measurement. Also open: how common are RFC 4470, RFC 7129 white-lies, and RFC 9824 variants in the wild?

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

**Step 0. Decisions.** Python, dnspython + cryptography, ECDSA P-256 (algorithm 13, small signatures), listen on `127.0.0.1:5300` UDP and TCP (5353 was the original plan, but it is mDNS and avahi holds it; `--port` overrides), `.test` names so nothing collides with real DNS. One zone per variant eventually (`nsec.test.`, `nsec3.test.`, `minnsec.test.`, `minnsec3.test.` (white lies), `cdoe-nsec.test.`, `cdoe-nsec3.test.`), each with its own key and local trust anchor.

**Step 1. Minimal real nameserver (DONE 2026-10-12).** See section 4. Run `venv/bin/python -m responder`; gates in `tests/gates.sh`, unit tests via `venv/bin/python -m unittest discover -s tests -t .`.

**Step 2. Vanilla NSEC.** NXDOMAIN needs SOA + cover for qname + cover for the wildcard at the closest encloser (each with RRSIG). NODATA needs the matching NSEC with a correct bitmap. Also: wildcard expansion, empty non-terminals, DS at delegations. Gate: structure matches the root response fixture; validates in `delv` and `dns.dnssec.validate`.

  **DONE 2026-10-12.** Chain built in `responder/denial.py` (`NsecDenial`), lookup flow in `responder/answer.py`, variant chosen by `zones/<zone>.toml` (`denial = "nsec"`). Checked against RFC 4035 §2.2/§2.3/§3.1.3/§3.1.4 and RFC 9077 (NSEC TTL and negative SOA TTL = min(SOA TTL, SOA MINIMUM)). Delegation NS and glue are not signed and get no NSEC. `tests/test_step2.py` diffs NXDOMAIN shape against `tests/golden/root-nsec-nxdomain.txt`; `tests/gates.sh` has delv checks for every case, and a deliberately broken proof (wildcard NSEC dropped) makes delv fail with "broken trust chain". Simplifications: CNAME is returned but not chased; qtype ANY gets NOTIMP; AXFR/IXFR get REFUSED. Reference-signer check done 2026-10-14 (see the fidelity note under Step 3).

**Step 3. Vanilla NSEC3.** Configurable algorithm, iterations, salt, opt-out flag; NSEC3PARAM at apex. Closest-encloser proof: match for closest encloser, cover for next-closer name, cover for wildcard. Gate: matches `.com` fixture shape; our hash function reproduces real `.com` hashes.

  **DONE 2026-10-14.**
  - `Nsec3Denial` is in `responder/denial.py`; zone `nsec3.test` has the same content as `nsec.test`; `zones/nsec3.test.toml` sets `iterations`, `salt` and `opt_out` (RFC 9276 defaults: 0, empty, false).
  - NSEC3 records are kept in `SignedZone.extra`, outside the name tree, so hashed owner names answer NXDOMAIN (RFC 5155 §7.2.8). ENTs get NSEC3 with empty bitmaps. An unsigned delegation's bitmap is `NS` only. NSEC3PARAM flags are always 0. A run-time hash collision raises, which the server turns into SERVFAIL (§7.2.9).
  - Opt-out drops unsigned delegations from the chain, and referrals and DS queries then carry the closest-provable-encloser proof.
  - **Verified:**
    - the hash reproduces `com.` both with dnspython and with an independent hashlib implementation (`tests/golden.nsec3_hash`);
    - the `.com` fixture decodes to CE match, next-closer cover, wildcard cover, and our NXDOMAIN for `c.nsec3.test` has the same shape;
    - delv fully validates every case, including opt-out;
    - delv rejects a proof missing its next-closer cover (`broken trust chain`).
  - Tests: `tests/test_step3.py` (17). Gates: the `s3` section of `tests/gates.sh`.
  - Pipeline: BIND has a static-stub for `nsec3.test`; `pipeline.sh up` runs `responder --anchors-only` before BIND starts.
  - Experiments N3-01, N3-03 and N3-06: BIND **never synthesizes from NSEC3**. Their NSEC counterparts N01, N03 and N06 are synthesized.

  **Fidelity mitigation (§2): done 2026-10-14.** `venv/bin/python -m tests.reference` needs Docker and uses the pinned BIND image and Alpine drill. It runs three checks:
  1. **Chains:** BIND 9.20.29 `dnssec-signzone` signs the same zone files (NSEC; NSEC3 `-3 - -H 0`; opt-out `-A`). Every NSEC, NSEC3 and NSEC3PARAM is identical to ours: owner, next name, bitmap, TTL and parameters.
  2. **Responses:** BIND `named` serves those zones authoritatively (`minimal-responses yes`). 81 queries go to both servers, covering positive, NXDOMAIN, NODATA, ENT, wildcard, referrals and DS. All match structurally; key and signature fields are excluded.
     - Three differences were found and aligned to BIND: DNSKEY TTL = the zone TTL; NSEC3PARAM TTL 0; NS answers now carry in-zone NS addresses in the additional section.
  3. **Non-BIND validator:** ldns `drill -S` (1.8.4) accepts every non-referral answer and rejects them under a wrong key.
     - One **known validator disagreement:** drill rejects the NSEC ENT NODATA `wild.nsec.test A` with "wildcard not covered". The answer is correct (an ENT exists, so no wildcard applies; RFC 4592 §2.2.2), BIND sends the identical answer, and delv validates it. The reasoning is in `KNOWN_DRILL`. It's a lead for later: validators differ on ENT NODATA proofs.

**Step 4. Variants (one switch per zone).** Minimally covering NSEC (RFC 4470); minimally covering NSEC3 / "white lies" (RFC 7129 App. B; PowerDNS narrow mode); CDOE NSEC; CDOE NSEC3. All four need per-response online signing. Suggested order: minimal NSEC, white lies, CDOE NSEC, CDOE NSEC3. Gate: CDOE NSEC output matches the Cloudflare fixture shape; for NSEC3 variants there is no real public reference, so rely on RFC text and validators.

  **DONE 2026-10-14.** All four variants are built: `minimal-nsec`, `nsec3-white-lies`, `compact-nsec`, `compact-nsec3`. Zones: `minnsec.test`, `minnsec3.test`, `cdoe-nsec.test`, `cdoe-nsec3.test`, all with the same content as `nsec.test`.
  - **Zone diagrams:** `docs/zones/<zone>.md`, generated by `venv/bin/python -m tools.zone_diagrams`; regenerate after changing zones or denial code.
  - **Spec and decisions:** `docs/VARIANTS.md` has a per-variant response table with RFC sections, and decisions D1–D25 wherever the RFCs are silent or ambiguous. Code comments cite the Dn IDs.
  - **Notable decisions:**
    - **D14:** minimal-NSEC covers use next `q\000`, not RFC 4470 §4's `\000.q`, per erratum 6734; BIND rejects the literal form. The literal form remains available as `cover_next = "child"`.
    - **D15:** covers span the next closer name.
    - **D11:** compact zones answer NXDOMAIN with CO or without DO.
    - **D13:** NXNAME queries get FORMERR + EDE 30.
  - **Online signing:** `SignedZone.sign_online` (deterministic and cached; D3).
  - **Verification:**
    - `tests/test_step4.py` (24 tests, including the Cloudflare fixture shape);
    - `tests/gates.sh` `s4` (65 checks, delv on every variant);
    - `tests/reference.py` (drill on the online variants);
    - `docker/pipeline.sh check` (BIND validates every zone).
  - **Experiments:** MN-xx, WL-xx, CN-xx, C3-xx.
  - **New findings:** A9 (BIND keeps no minimal NSEC for synthesis), A10 (BIND ignores CO), B3 (literal RFC 4470 rejected by BIND), B4.

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
| NXDOMAIN + NSEC3 records | NSEC3 (vanilla, or white lies: check spans) |
| NXDOMAIN + NSEC3 records whose spans are 2 (next hash = owner hash + 2, around hash(name)) | Minimally covering NSEC3 / white lies (RFC 7129 App. B; PowerDNS narrow) |
| NOERROR + NSEC/NSEC3 with NXNAME (type 128) in bitmap | Compact denial (RFC 9824) |
| NOERROR/NODATA + one NSEC, next name = `\000.` + owner, no NXNAME | Older "black lies" |
| No NSEC/NSEC3 | Unsigned zone or server ignored DO |

Minimally covering NSEC is **not** distinguishable by wire format alone: it is a normal NSEC whose gap happens to be one name. Probe several names; any wide gap rules it out. NSEC3 white lies, by contrast, are identifiable from a **single** response: a natural span of only 2 in a 2^160 hash space is practically impossible, so a cover whose next hash is the owner hash + 2 marks an online white-lies signer. Also useful: query `NSEC3PARAM` at the apex (present means the zone uses NSEC3). A zone's behavior can depend on qtype and on whether the name exists (online signers), so use several probes (nonexistent name, existing name with missing type, DS query).

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
- **RFC 9824 (verified 2026-10-14; details in docs/VARIANTS.md):**
  - The next name is `\000.qname`, except at a delegation, where it is `sub\000` (§3.4), since `\000.sub` would lie in the child zone.
  - Bitmaps: a nonexistent name gets exactly RRSIG NSEC NXNAME (§3.1); an ENT gets RRSIG NSEC (§3.2); NSEC3 gets NXNAME only, and nothing for an ENT (§4).
  - Wildcard answers are signed as exact matches (§3.3).
  - NXNAME queries MUST get FORMERR (§3.5).
  - CO is EDNS bit 1 (0x4000): the server echoes it and answers NXDOMAIN (§5.1).
  - RFC 8198 / RFC 8020 synthesis is not supported (§6).

---

## 6. Documentation-review findings (from the researcher's notes)

- **BIND 9** (release notes and ARM checked 2026-10-13):
  - Lists RFC 4470, not RFC 9824.
  - **Compact denial is `dig`-only.** 9.18.38 and 9.20.11 add CO-flag display and `+coflag` to dig [GL #5319]. MR !11500 (main) and its 9.20 backport !12750 only print type 128 as `NXNAME` instead of `TYPE128` [issue #5721]. No release note shows resolver or validator handling of NXNAME or compact answers.
  - **`synth-from-dnssec` (RFC 8198 ANC):** default `yes` again since 9.18.0 (disabled in 9.14.8) [GL #1265]. NSEC only: the current ARM says NSEC3 synthesis is "planned for the future". Expect no ANC from any NSEC3 variant.
  - **Version-sensitive fixes in 9.20.x:**
    - 9.20.12 fixed ANC not working when no parent NSEC was cached [GL #5422].
    - 9.20.21 limits NSEC3 iterations when validating referrals to unsigned delegations (CVE-2026-1519) [GL #5708].
    - 9.20.26 (one source says .27) changed denial-proof handling:
      - invalid signed wildcards rejected, a bug that broke synth (CVE-2026-11721) [GL #5871];
      - out-of-zone NSEC next names with synth (CVE-2026-13321) [GL #5873];
      - padded negative responses capped (CVE-2026-11605) [GL #4463].
    - So pin an exact 9.20.x, at or above 9.20.26, and record `named -V`.
  - **Sources:** https://bind9.readthedocs.io/en/stable/notes.html, https://downloads.isc.org/isc/bind9/9.18.41/doc/arm/html/notes.html, https://bind9.readthedocs.io/en/v9_18_1/notes.html, https://bind9.readthedocs.io/en/stable/_sources/reference.rst.txt (synth-from-dnssec), https://gitlab.isc.org/isc-projects/bind9/-/merge_requests/11500.
  - **Open:** is 4470 support only online signing, or is there a mechanism that identifies minimally covering NSEC? Does `static-stub` `server-addresses` accept a port? The ARM text mentions IP addresses only.
- **Unbound:** RFC compliance page lists neither 4470 nor 9824; has aggressive-NSEC docs.
- **Knot Resolver:** RFC list lacks both; release notes mention ANC disabled for minimal ranges (4.1.0, 2019).
- **PowerDNS Recursor:** compliance page lacks RFC 4470 and RFC 9824. Recursor 4.9.0 (2023-06-30): the aggressive cache does "not store NSEC3 entries which cover only a small fraction of possible names", and NSEC3 aggressive caching can be switched off separately (https://blog.powerdns.com/2023/06/30/powerdns-recursor-4-9-0-released). Context: OARC 40 aggressive-NSEC3 talk (https://indico.dns-oarc.net/event/46/contributions/977/).
- **Minimally covering NSEC3 / "NSEC3 white lies"** (checked 2026-10-14):
  - **Not in RFC 4470**, which is NSEC-only and mentions NSEC3 only as future work. Defined informally in **RFC 7129 Appendix B** (Informational): "the NSEC3 owner name is the hash of the QNAME minus one, and the next owner name is the hash of the QNAME plus one". The name comes from Kaminsky's Phreebird proxy (2011).
  - It does not formally relax RFC 5155 §3.1.7 ("next hashed owner name in hash order"), hence "lies"; validators only check coverage.
  - **PowerDNS Authoritative "narrow" mode** implements it, and predates RFC 7129 (pdns-dev 2016, Peter van Dijk). PowerDNS has no NSEC "black lies".
  - **Sources:** https://www.rfc-editor.org/rfc/rfc7129.txt, https://doc.powerdns.com/authoritative/_sources/dnssec/modes-of-operation.rst.txt, https://mailman.powerdns.com/pipermail/pdns-dev/2016-July/001604.html

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

**Prevalence study:** take signed domains from a top list or zone files, group by NS operator, probe one or two zones per operator with the classifier. Known leads **[VERIFY]**: Cloudflare (online-signed minimal NSEC since about 2016, now NXNAME), PowerDNS Authoritative narrow NSEC3 mode (= white lies, identifiable from one response), CoreDNS dnssec plugin. CDOE NSEC3 may be rare or absent in the wild; if so it is a local-only test.

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

**Findings log:** every interesting observation goes into `FINDINGS.md` (sections A–E). New entries go at the end of their section; entries are never renumbered; Status is updated instead of deleting.

Steps 1 and 2 are done, the golden fixtures are saved, and the delv flags are verified. Next:

0. **Pipeline status (2026-10-14): working.** `docker/pipeline.sh up|check|experiments|down`. All 6 checks pass, including responder-down → SERVFAIL. Diagnostic experiments are catalogued in `experiments/catalog.py` (rendered to `experiments/CATALOG.md`), and results go to `results/` (gitignored). Notable diagnostic observations on BIND 9.20.29:
   - **N08:** synthesizes even when the client sets CD=1, against RFC 8198 App. A (implementation notes; the RFC body never mentions CD).
   - **N11:** relaxed QNAME minimisation re-sends the full query after a validated NXDOMAIN for the minimised name. This is documented ARM behaviour, but it means a deep first query costs 2 upstream queries plus DNSKEY, which must not be misread as missing ANC.
   - N01–N07, N09, N10 and N12 behave as RFC 8198 describes: NXDOMAIN, NODATA, ENT and wildcard synthesis all happen; DO doesn't matter; synthesis stops after the 60 s TTL.
   - Planned probes P01–P05 need responder knobs or a BIND config variant.
1. **Local resolver pipeline (built; details below).** Docker Compose on the laptop: responder `172.30.0.10:53`, BIND (ISC image `internetsystemsconsortium/bind9`, 9.20.x ≥ 9.20.26 pinned by digest) `172.30.0.20:53`, client `172.30.0.30`.
   - Image checked 2026-10-13:
     - `internetsystemsconsortium/bind9:9.20` is **BIND 9.20.29** on Alpine 3.24. ISC publishes only branch tags (no `9.20.29` tag exists), so pin by **digest** (`docker inspect --format '{{index .RepoDigests 0}}' …`) and record it with the version. **Pinned:** `internetsystemsconsortium/bind9@sha256:071465f88068854d0ceadd9b985fb1acae4071e80754e545cd811fde57541ad0` = BIND 9.20.29 (pulled 2026-10-13).
     - Built with `--enable-dnstap`; supports ECDSAP256SHA256; includes `dig 9.20.29`, so the client can use the same image.
     - No bash (busybox `sh`) and no tcpdump; capture on the host's Docker bridge.
     - Entrypoint `/usr/sbin/named -u bind`; default cmd `-f -c /etc/bind/named.conf -L /var/log/bind/default.log`.
     - Mount config into `/etc/bind/` and logs at `/var/log/bind`. Mounted dirs must be writable by the container's `bind` user (**uid 53, gid 53**), e.g. `sudo chown 53:$(id -g) logs/bind && chmod 775 logs/bind`.
     - `rndc` needs a key in `/etc/bind/rndc.conf`.
   - BIND config: a `static-stub` zone for `nsec.test` pointing at the responder, the generated `zones/nsec.test.anchor` included as `trust-anchors`, `allow-recursion` limited to the client, `synth-from-dnssec yes`.
   - Logs: responder `queries.jsonl`; BIND dnstap if `named -V` shows `--enable-dnstap` (else query log + tcpdump); `rndc dumpdb -cache` for cache contents.
   - Bring-up order: dig from BIND's container straight to the responder; dig at BIND locally (expect `ad`); client → BIND for NXDOMAIN (expect `ad`, responder sees RD=0 DO=1); repeat (cached); a second name in the same gap (ANC); a wrong anchor (SERVFAIL).
   - Later on AWS: same images and configs; then replace the static-stub with a real delegated domain (section 8).
2. Step 2 leftovers:
   - make the broken-proof delv checks permanent tests;
   - add a NODATA golden fixture (root `. AAAA`);
3. Next options:
   - the A9 discriminating experiment (what makes BIND skip minimal NSEC);
   - the planned knobs P01–P05;
   - more resolvers in the pipeline (Unbound, Knot Resolver, PowerDNS Recursor), most interesting for A1, A9, B1/B3/B4, and PowerDNS's white-lies handling;
   - Step 5 (per-query overrides).
