"""Generate one diagram document per zone in docs/zones/.

Everything shown is produced by the responder's own code: zones are loaded
with SignedZone and example queries are answered by Responder.build_response
in-process (no network). Regenerate after changing zones or denial code:

    venv/bin/python -m tools.zone_diagrams
"""

import re
import tempfile
import tomllib
from pathlib import Path

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype

from responder.denial import VARIANTS
from responder.server import Responder
from responder.zone import SignedZone

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "zones"

ABOUT = {
    "nsec": ("Vanilla NSEC", "RFC 4034, RFC 4035", "pre-signed chain in canonical name order"),
    "nsec3": ("Vanilla NSEC3", "RFC 5155, RFC 9276", "pre-signed chain in hash order"),
    "minimal-nsec": ("Minimally covering NSEC", "RFC 4470 (+ erratum 6734)",
                     "online: one-name covers built and signed per response"),
    "nsec3-white-lies": ("NSEC3 white lies", "RFC 7129 Appendix B",
                         "online: hash−1 → hash+1 covers built and signed per response"),
    "compact-nsec": ("Compact denial of existence, NSEC", "RFC 9824 §3",
                     "online: one NSEC owned by the QNAME, built and signed per response"),
    "compact-nsec3": ("Compact denial of existence, NSEC3", "RFC 9824 §4",
                      "online: one NSEC3 matching hash(QNAME), built and signed per response"),
}

# How an NXDOMAIN-style proof works, per variant (principle, not generated).
PROOF = {
    "nsec": """\
canonical name order (one signed chain, built once):
  @ ── host.ent ── insecure ══════════════ ns1 ── secure ── *.wild ── www ──┐
                            ▲ NSEC insecure → ns1 covers "nope"           │
  ◀──────────────────────────────────────────────────────────── wraps ────┘
NXDOMAIN = NSEC covering the qname (here insecure → ns1)
         + NSEC covering *.<closest encloser> (here the apex NSEC @ → host.ent)
The same records answer every name in their gap, so resolvers can reuse them (RFC 8198).""",
    "nsec3": """\
hash order (one signed chain of hashed names, built once):
  h(@) ── h(secure) ── h(www) ── … ── h(insecure) ──▶ back to h(@)
NXDOMAIN = NSEC3 matching h(closest encloser)      "this name exists"
         + NSEC3 covering h(next closer name)       "the name below it does not"
         + NSEC3 covering h(*.closest encloser)      "no wildcard applies"
One record may cover two of these, so 2 or 3 NSEC3 per NXDOMAIN.""",
    "minimal-nsec": """\
built per query; each cover spans only the name it denies (and its subtree):
  … existing ─────── pred(nc) ═[ nc and everything below it ]═ nc\\000 ─────── existing …
                      ▲ owner                                   ▲ next
NXDOMAIN = cover of the next closer name + cover of *.<closest encloser>
The span contains no other name, so a resolver cannot reuse it for a different name.
Next name nc\\000 (not \\000.nc) because \\000.nc would imply nc exists (D14, erratum 6734).""",
    "nsec3-white-lies": """\
built per query; each record spans a single hash step:
  match:  h(x) ──▶ h(x)+1                   "x exists" (real bitmap)
  cover:  h(x)−1 ──▶ h(x)+1                 "nothing between", h(x) is the only hash inside
NXDOMAIN = match(closest encloser) + cover(next closer) + cover(*.closest encloser)
Identifiable from one answer: natural NSEC3 spans are never 2 in a 2^160 space.""",
    "compact-nsec": """\
built per query; the QNAME is answered as if it existed with no data:
  nope ──▶ \\000.nope    [RRSIG NSEC NXNAME]
  NXNAME (type 128) marks "this name does not really exist"
Rcode NOERROR (NODATA); NXDOMAIN only if the query sets CO (RFC 9824 §5.1) or lacks DO (D11).
One record, no wildcard proof; nothing is reusable for other names (RFC 9824 §6).""",
    "compact-nsec3": """\
built per query; one NSEC3 matching the QNAME's hash:
  h(nope) ──▶ h(nope)+1    [NXNAME]
Rcode NOERROR (NODATA); NXDOMAIN only with CO or without DO (D11).
One record, no closest-encloser or wildcard proof (RFC 9824 §4).""",
}

# (label, qtype, what it shows); "@" is the apex
EXAMPLES = [
    ("nope", "A", "nonexistent name"),
    ("c", "A", "nonexistent name in another gap"),
    ("foo.bar.ent", "A", "nonexistent name two labels below an ENT"),
    ("www", "AAAA", "NODATA: name exists, type does not"),
    ("ent", "A", "empty non-terminal"),
    ("x.wild", "A", "wildcard answer"),
    ("a.b.wild", "TXT", "wildcard NODATA"),
    ("foo.insecure", "A", "referral to an unsigned child"),
    ("foo.secure", "A", "referral to a signed child"),
    ("insecure", "DS", "DS query at an unsigned delegation"),
]


def short(text):
    """Abbreviate long runs of \\255 octets for readability."""
    return re.sub(r"(\\255){4,}", lambda m: f"\\255×{len(m.group(0)) // 4}", text)


def types_of(rd):
    out = []
    for window, bitmap in rd.windows:
        for i, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    out.append(dns.rdatatype.to_text(window * 256 + i * 8 + bit))
    return " ".join(out)


def rel(name, origin):
    return "@" if name == origin else short(name.relativize(origin).to_text())


def name_tree(z):
    """ASCII tree of the zone's names with their (non-DNSSEC) record types."""
    origin = z.origin
    names = set(z.zone.nodes)
    for n in list(names):
        while n != origin:
            n = n.parent()
            names.add(n)
    hidden = {dns.rdatatype.DNSKEY, dns.rdatatype.NSEC, dns.rdatatype.NSEC3PARAM,
              dns.rdatatype.RRSIG}

    def describe(n):
        node = z.zone.get_node(n)
        types = sorted(dns.rdatatype.to_text(r.rdtype) for r in node.rdatasets
                       if r.rdtype not in hidden) if node else []
        marks = []
        if node is None or not node.rdatasets:
            marks.append("◇ empty non-terminal")
        if n.labels[0] == b"*":
            marks.append("★ wildcard")
        if n in z.cuts:
            ds = z.zone.get_rdataset(n, dns.rdatatype.DS)
            marks.append("✂ delegation, " + ("signed (DS)" if ds else "unsigned (no DS)"))
        if z.is_occluded(n):
            marks.append("▣ glue (not authoritative)")
        return " ".join(types), "; ".join(marks)

    children = {}
    for n in names:
        if n != origin:
            children.setdefault(n.parent(), []).append(n)
    lines = []

    def walk(n, prefix, last):
        label = origin.to_text() + "  (apex)" if n == origin else n.labels[0].decode()
        types, marks = describe(n)
        branch = "" if n == origin else ("└── " if last else "├── ")
        lines.append(f"{prefix}{branch}{label:<{max(1, 24 - len(prefix) - len(branch))}} "
                     f"{types:<14} {marks}".rstrip())
        kids = sorted(children.get(n, []))
        ext = "" if n == origin else ("    " if last else "│   ")
        for i, k in enumerate(kids):
            walk(k, prefix + ext, i == len(kids) - 1)

    walk(origin, "", True)
    return "\n".join(lines)


def static_chain(z, kind):
    """The pre-signed chain, in chain order, with the original name per record."""
    origin = z.origin
    rows = []
    if kind == "nsec":
        for owner in z.denial.owners:
            rd = z.zone.get_rdataset(owner, dns.rdatatype.NSEC)[0]
            rows.append((rel(owner, origin), rel(rd.next, origin), types_of(rd), ""))
    else:
        by_hash = {}
        names = set(z.zone.nodes)
        for n in list(names):
            while n != origin:
                n = n.parent()
                names.add(n)
        for n in names:
            by_hash[z.denial._hash(n)] = n
        for (owner, t), rds in sorted(z.extra.items()):
            if t != dns.rdatatype.NSEC3:
                continue
            h = owner.labels[0].decode().upper()
            rd = rds[0]
            rows.append((h, rd.to_text().split()[4].upper(), types_of(rd),
                         rel(by_hash.get(h, owner), origin)))
    return rows


def ring(rows, kind):
    width = max(len(r[0]) for r in rows)
    lines = []
    for i, (owner, nxt, types, name) in enumerate(rows):
        lead = "┌─▶ " if i == 0 else "│   "
        who = f"  ← {name}" if name else ""
        empty = "(empty)" if not types else types
        lines.append(f"{lead}{owner:<{width}}{who:<22} [{empty}]")
        lines.append("│       ▼" if i < len(rows) - 1 else "└───────┘  next of the last record wraps to the first")
    return "\n".join(lines)


def roles(z, qname, rrset):
    """Which relevant names a denial record matches (=) or covers (∋)."""
    origin, out = z.origin, []
    if not z.name_exists(qname):
        ce = z.closest_encloser(qname)
        nc = dns.name.Name(qname.labels[-(len(ce.labels) + 1):])
        targets = [("qname", qname), ("next closer", nc), ("closest encloser", ce),
                   ("wildcard " + rel(dns.name.Name((b"*",) + ce.labels), origin),
                    dns.name.Name((b"*",) + ce.labels))]
    else:
        targets = [("qname", qname)]
    rd = rrset[0]
    if rrset.rdtype == dns.rdatatype.NSEC:
        o, n = rrset.name, rd.next

        def cov(x):
            return o < x < n if o < n else (x > o or x < n)
        for label, x in targets:
            if x == o:
                out.append(f"= {label}")
            elif cov(x):
                out.append(f"∋ {label}")
    else:
        o = rrset.name.labels[0].decode().upper()
        n = rd.to_text().split()[4].upper()
        for label, x in targets:
            h = dns.dnssec.nsec3_hash(x, z.denial.salt or None, z.denial.iterations, 1)
            if h == o:
                out.append(f"= {label}")
            elif (o < h < n) if o < n else (h > o or h < n):
                out.append(f"∋ {label}")
    seen, uniq = set(), []
    for r in out:
        if r.split(" ", 1)[1] not in seen:
            seen.add(r.split(" ", 1)[1])
            uniq.append(r)
    return ", ".join(uniq) or "-"


def example(responder, z, label, qtype):
    origin = z.origin
    qname = origin if label == "@" else dns.name.from_text(label, origin)
    q = dns.message.make_query(qname, qtype, want_dnssec=True, use_edns=0)
    q.flags &= ~dns.flags.RD
    r = responder.build_response(q)
    head = f"{dns.rcode.to_text(r.rcode())}  flags: {dns.flags.to_text(r.flags).lower()}"
    lines = []
    for section, rrsets in (("ans", r.answer), ("auth", r.authority)):
        for rr in rrsets:
            if rr.rdtype == dns.rdatatype.RRSIG:
                if section == "ans":
                    lines.append(f"  {section}  RRSIG {dns.rdatatype.to_text(rr.covers)} (labels {rr[0].labels})")
                continue
            t = dns.rdatatype.to_text(rr.rdtype)
            if rr.rdtype == dns.rdatatype.NSEC:
                rd = rr[0]
                lines.append(f"  {section}  NSEC  {rel(rr.name, origin)} → {rel(rd.next, origin)}  "
                             f"[{types_of(rd) or '(empty)'}]   {roles(z, qname, rr)}")
            elif rr.rdtype == dns.rdatatype.NSEC3:
                rd = rr[0]
                lines.append(f"  {section}  NSEC3 {rr.name.labels[0].decode().upper()} → "
                             f"{rd.to_text().split()[4].upper()}  flags {rd.flags}  "
                             f"[{types_of(rd) or '(empty)'}]   {roles(z, qname, rr)}")
            else:
                lines.append(f"  {section}  {t} {rel(rr.name, origin)}")
    for rr in r.additional:
        lines.append(f"  add   {dns.rdatatype.to_text(rr.rdtype)} {rel(rr.name, origin)}")
    return head, lines


def write(zone_file, key_dir):
    conf_file = zone_file.with_suffix(".toml")
    conf = tomllib.loads(conf_file.read_text()) if conf_file.exists() else {}
    kind = conf.get("denial", "nsec")
    params = {k: v for k, v in conf.items() if k != "denial"}
    z = SignedZone(zone_file, key_dir, VARIANTS[kind](**params))
    responder = Responder([z])
    title, ref, how = ABOUT[kind]
    origin = z.origin.to_text()
    md = [f"# Zone `{origin}`: {title}", "",
          f"- **Variant:** `denial = \"{kind}\"`" + ("".join(f", `{k} = {v!r}`" for k, v in params.items())),
          f"- **Standard:** {ref}",
          f"- **Denial records:** {how}",
          "- **Rules and implementation decisions:** [docs/VARIANTS.md](../VARIANTS.md)",
          "- Generated by `venv/bin/python -m tools.zone_diagrams` from the responder's own output; do not edit by hand.",
          "",
          "## 1. Name tree", "",
          "Same content in every variant zone. DNSSEC records (DNSKEY, NSEC, NSEC3PARAM, RRSIG) are added at load time and are not shown.",
          "", "```", name_tree(z), "```", "",
          "Legend: ◇ empty non-terminal (exists, no records) · ★ wildcard · ✂ delegation point · ▣ glue below a cut", ""]
    if kind in ("nsec", "nsec3"):
        rows = static_chain(z, kind)
        order = "canonical name order" if kind == "nsec" else "hash order, unrelated to name order"
        md += [f"## 2. Denial chain ({len(rows)} records, {order})", "",
               "Each arrow is one signed record: owner → next, with the type bitmap of the owner name.",
               "", "```", ring(rows, kind), "```", ""]
        if kind == "nsec3":
            md += ["NSEC3 records live outside the name tree (hashed owner names do not exist for queries, RFC 5155 §7.2.8). Empty non-terminals get records with empty bitmaps; glue gets none.", ""]
        else:
            md += ["Empty non-terminals and glue get no NSEC (RFC 4035 §2.3).", ""]
    else:
        md += ["## 2. Denial records", "",
               "There is **no stored chain**. Each negative answer carries records built for that query and signed on the spot; see the examples below and the variant's rules in [VARIANTS.md](../VARIANTS.md).", ""]
    md += ["## 3. How the proof works", "", "```", PROOF[kind], "```", ""]
    md += ["## 4. Example responses", "",
           "Authority-section denial records: `owner → next [bitmap]`, followed by what each record **matches** (=) or **covers** (∋). RRSIGs on denial records are omitted; every record shown is signed.",
           ""]
    for label, qtype, what in EXAMPLES:
        head, lines = example(responder, z, label, qtype)
        q = origin if label == "@" else f"{label}.{origin}"
        md += [f"### `{q} {qtype}`: {what}", "", "```", head] + lines + ["```", ""]
    out = OUT / f"{origin.rstrip('.')}.md"
    out.write_text("\n".join(md))
    return out, title, ref, kind


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    index = ["# Zone diagrams", "",
             "One document per zone, generated from the responder's own output by `venv/bin/python -m tools.zone_diagrams`. All zones have the same names and records; they differ only in how nonexistence is proved.", "",
             "| Zone | Variant | Standard |", "|---|---|---|"]
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for zone_file in sorted((REPO / "zones").glob("*.zone")):
            out, title, ref, kind = write(zone_file, Path(tmp))
            rows.append((list(ABOUT).index(kind), f"| [`{out.stem}`]({out.name}) | {title} (`{kind}`) | {ref} |"))
            print(f"wrote {out.relative_to(REPO)}")
    index += [row for _, row in sorted(rows)]
    (OUT / "README.md").write_text("\n".join(index) + "\n")
    print(f"wrote {(OUT / 'README.md').relative_to(REPO)}")


if __name__ == "__main__":
    main()
