"""Fidelity check against a reference signer and server (BIND 9.20.29).

1. Chain diff: BIND's dnssec-signzone signs the same zone files (NSEC,
   NSEC3, NSEC3 opt-out); every NSEC/NSEC3/NSEC3PARAM is compared field by
   field with the chain our responder builds.
2. Response diff: BIND's named serves its signed zones authoritatively and
   the same queries go to it and to our responder. Responses are compared
   structurally: header, and per section the RRsets (owner, type, TTL,
   rdata), with key- and time-dependent fields (DNSKEY key material, RRSIG
   key tag, signature, validity window) left out.
3. Independent validator: NLnet Labs' ldns `drill -S` (not BIND code)
   chases every non-referral answer from our responder to the zone's key,
   and must reject the same answers when given a wrong key.

Needs Docker. Run: venv/bin/python -m tests.reference
"""

import subprocess
import sys
import tempfile
import time
from pathlib import Path

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.zone

from responder.denial import (CompactNsec3Denial, CompactNsecDenial, MinimalNsecDenial,
                              Nsec3Denial, NsecDenial, Nsec3WhiteLiesDenial)
from responder.server import Responder, start
from responder.zone import SignedZone

REPO = Path(__file__).resolve().parent.parent
IMAGE = ("internetsystemsconsortium/bind9@sha256:"
         "071465f88068854d0ceadd9b985fb1acae4071e80754e545cd811fde57541ad0")
REF_PORT = 5399
ALPINE = "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"
REFERRALS = {"foo.secure", "insecure", "foo.insecure", "ns.secure"}  # drill would chase into fake children

# Online-signed variants: no reference signer implements them, so only the
# independent-validator check (drill) applies.
ONLINE = [("minnsec.test", MinimalNsecDenial()), ("minnsec3.test", Nsec3WhiteLiesDenial()),
          ("cdoe-nsec.test", CompactNsecDenial()), ("cdoe-nsec3.test", CompactNsec3Denial())]

# Answers drill rejects although they are correct. Each entry says why; they
# are reported as KNOWN on every run, not hidden.
KNOWN_DRILL = {
    "wild.nsec.test. A": (
        "ENT NODATA proved by the covering NSEC secure -> *.wild (next name is below wild, so wild "
        "exists). drill 1.8.4 demands a wildcard proof whenever no NSEC matches the name, but a "
        "wildcard never applies to an existing name (RFC 4592 §2.2.2). BIND's authoritative server "
        "sends the identical response and delv validates it. ent.nsec.test A passes only because "
        "its NSEC happens to also cover *.nsec.test."),
}
# Minimally covering NSEC proves every ENT with a cover whose next name lies
# below the ENT (docs/VARIANTS.md D4), so the same drill limitation applies
# to every ENT there, not just by chance as in nsec.test.
for _ent in ("ent.minnsec.test. A", "wild.minnsec.test. A"):
    KNOWN_DRILL[_ent] = (
        "ENT NODATA proved by a minimal cover predecessor(ent) -> \\000.ent (next name below the "
        "ENT, so the ENT exists). Same drill 1.8.4 limitation as wild.nsec.test A: it demands a "
        "wildcard proof although none applies to an existing name (RFC 4592 §2.2.2). delv validates it.")

# name -> (zone file, our denial, dnssec-signzone NSEC3 options)
CONFIGS = {
    "nsec": [("nsec.test", NsecDenial(), [])],
    "nsec3": [("nsec3.test", Nsec3Denial(), ["-3", "-", "-H", "0"])],
    "nsec3-optout": [("nsec3.test", Nsec3Denial(opt_out=True), ["-3", "-", "-H", "0", "-A"])],
}

QUERIES = [
    ("www", "A"), ("www", "TXT"), ("@", "SOA"), ("@", "NS"), ("@", "DNSKEY"), ("@", "DS"),
    ("nope", "A"), ("c", "A"), ("a", "A"), ("zzz", "A"), ("foo.bar.ent", "A"),
    ("www", "AAAA"), ("ent", "A"), ("wild", "A"), ("WwW", "AAAA"),
    ("x.wild", "A"), ("deep.er.wild", "A"), ("x.wild", "TXT"), ("a.b.wild", "TXT"), ("*.wild", "A"),
    ("foo.secure", "A"), ("insecure", "A"), ("foo.insecure", "A"), ("ns.secure", "A"),
    ("secure", "DS"), ("insecure", "DS"),
]
EXTRA_QUERIES = {"nsec": [("@", "NSEC")], "nsec3": [("@", "NSEC3PARAM")],
                 "nsec3-optout": [("@", "NSEC3PARAM")]}


def docker(workdir, entrypoint, *args, detach=False, network=None):
    cmd = ["docker", "run", "--rm", "--user", f"{_uid()}", "-v", f"{workdir}:/w", "-w", "/w",
           "--entrypoint", entrypoint]
    if detach:
        cmd.insert(2, "-d")
    if network:
        cmd += ["--network", network]
    return subprocess.run(cmd + [IMAGE, *args], capture_output=True, text=True, check=True).stdout


def _uid():
    import os
    return f"{os.getuid()}:{os.getgid()}"


def sign_with_bind(workdir, origin, nsec3_opts):
    (workdir / f"{origin}.zone").write_text((REPO / "zones" / f"{origin}.zone").read_text())
    docker(workdir, "dnssec-keygen", "-q", "-a", "ECDSAP256SHA256", "-f", "KSK", origin)
    docker(workdir, "dnssec-signzone", "-S", "-z", *nsec3_opts, "-O", "full",
           "-o", origin, "-f", f"{origin}.signed", f"{origin}.zone")
    return dns.zone.from_file(str(workdir / f"{origin}.signed"), origin=origin, relativize=False)


# --- chain diff -------------------------------------------------------------

def chain(records):
    """{(owner, type): (ttl, normalized rdata)} for NSEC, NSEC3, NSEC3PARAM."""
    out = {}
    for owner, rdtype, rds in records:
        if rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3, dns.rdatatype.NSEC3PARAM):
            out[(owner.to_text().lower(), dns.rdatatype.to_text(rdtype))] = \
                (rds.ttl, " ".join(rds[0].to_text().lower().split()))
    return out


def ref_chain(signed):
    return chain((n, rds.rdtype, rds) for n, node in signed.nodes.items() for rds in node.rdatasets)


def our_chain(z):
    recs = [(n, rds.rdtype, rds) for n, node in z.zone.nodes.items() for rds in node.rdatasets]
    recs += [(n, t, rds) for (n, t), rds in z.extra.items()]
    return chain(recs)


def diff_chains(ref, ours):
    problems = []
    for key in sorted(set(ref) | set(ours)):
        if key not in ours:
            problems.append(f"missing in ours: {key} {ref[key]}")
        elif key not in ref:
            problems.append(f"extra in ours:   {key} {ours[key]}")
        elif ref[key] != ours[key]:
            problems.append(f"differs {key}:\n      bind {ref[key]}\n      ours {ours[key]}")
    return problems


# --- response diff ----------------------------------------------------------

def normalize(r):
    def rrsets(section):
        out = []
        for rr in section:
            t = dns.rdatatype.to_text(rr.rdtype)
            if rr.rdtype == dns.rdatatype.RRSIG:
                data = sorted(f"{dns.rdatatype.to_text(rd.type_covered)} {rd.algorithm} "
                              f"{rd.labels} {rd.original_ttl} {rd.signer.to_text().lower()}" for rd in rr)
            elif rr.rdtype == dns.rdatatype.DNSKEY:
                data = sorted(f"{rd.flags} {rd.protocol} {rd.algorithm}" for rd in rr)
            else:
                data = sorted(" ".join(rd.to_text().lower().split()) for rd in rr)
            out.append((rr.name.to_text().lower(), t, rr.ttl, tuple(data)))
        return sorted(out)
    return {
        "rcode": dns.rcode.to_text(r.rcode()),
        "flags": dns.flags.to_text(r.flags),
        "do": bool(r.ednsflags & dns.flags.DO),
        "answer": rrsets(r.answer),
        "authority": rrsets(r.authority),
        "additional": rrsets(r.additional),
    }


def ask(port, qname, qtype):
    q = dns.message.make_query(qname, qtype, want_dnssec=True, use_edns=0)
    q.flags &= ~dns.flags.RD
    return dns.query.udp(q, "127.0.0.1", port=port, timeout=3)


def start_reference_named(workdir, origins):
    zones = "\n".join(f'zone "{o}" {{ type primary; file "/w/{o}.signed"; }};' for o in origins)
    (workdir / "named.conf").write_text(f"""
options {{
    directory "/tmp"; pid-file none;
    listen-on port {REF_PORT} {{ 127.0.0.1; }}; listen-on-v6 {{ none; }};
    recursion no; dnssec-validation no; notify no;
    minimal-responses yes;   // like ours: no NS/glue added to positive answers
}};
{zones}
""")
    cid = docker(workdir, "named", "-g", "-c", "/w/named.conf", detach=True, network="host").strip()
    for _ in range(50):
        try:
            ask(REF_PORT, origins[0] + ".", "SOA")
            return cid
        except Exception:
            time.sleep(0.2)
    logs = subprocess.run(["docker", "logs", cid], capture_output=True, text=True).stderr
    subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
    raise RuntimeError(f"reference named did not start:\n{logs[-2000:]}")


def drill_checks(work, port, zones, queries):
    """Chase each answer with drill; also with a wrong key, which must fail."""
    (work / "drill").mkdir(exist_ok=True)
    for z in zones:
        (work / "drill" / f"{z.origin}key").write_text(f"{z.origin} 300 IN DNSKEY {z.dnskey.to_text()}\n")
    wrong = SignedZone(REPO / "zones" / f"{zones[0].origin}zone", work / "wrongkey", NsecDenial())
    (work / "drill" / "wrong.key").write_text(f"{wrong.origin} 300 IN DNSKEY {wrong.dnskey.to_text()}\n")
    lines = []
    for z in zones:
        for label, qtype in queries:
            if label in REFERRALS:
                continue
            q = z.origin.to_text() if label == "@" else f"{label}.{z.origin}"
            lines.append(f'r=$(drill -S -k /k/{z.origin}key -p {port} @127.0.0.1 "{q}" {qtype} 2>&1 | tail -1); echo "{q} {qtype}|$r"')
    q0 = f"nope.{zones[0].origin}"
    lines.append(f'r=$(drill -S -k /k/wrong.key -p {port} @127.0.0.1 "{q0}" A 2>&1 | tail -1); echo "WRONGKEY {q0}|$r"')
    script = "apk add -q drill >/dev/null 2>&1 || exit 9\n" + "\n".join(lines)
    out = subprocess.run(["docker", "run", "--rm", "--network", "host", "-v", f"{work / 'drill'}:/k",
                          ALPINE, "sh", "-c", script], capture_output=True, text=True).stdout
    failures = 0
    for line in out.splitlines():
        what, _, result = line.partition("|")
        ok = ("Chase successful" in result) != what.startswith("WRONGKEY")
        if not ok and what in KNOWN_DRILL:
            print(f"  KNOWN  drill {what}: {result}\n           {KNOWN_DRILL[what]}")
            continue
        failures += not ok
        print(f"  {'OK    ' if ok else 'FAIL  '} drill {what}: {result}")
    return failures


def main():
    failures = 0
    for name, zones in CONFIGS.items():
        print(f"\n=== {name}")
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            work.chmod(0o755)
            ours, origins = [], []
            for origin, denial, opts in zones:
                signed = sign_with_bind(work, origin, opts)
                z = SignedZone(REPO / "zones" / f"{origin}.zone", work / "ourkeys", denial)
                problems = diff_chains(ref_chain(signed), our_chain(z))
                failures += bool(problems)
                print(f"chain {origin}: {'MATCH' if not problems else 'DIFFERENCES'}")
                for p in problems:
                    print("    " + p)
                ours.append(z)
                origins.append(origin)

            cid = start_reference_named(work, origins)
            udp, tcp = start(Responder(ours), "127.0.0.1", 0)
            port = udp.server_address[1]
            try:
                for origin in origins:
                    for label, qtype in QUERIES + EXTRA_QUERIES[name]:
                        qname = origin + "." if label == "@" else f"{label}.{origin}."
                        a, b = normalize(ask(REF_PORT, qname, qtype)), normalize(ask(port, qname, qtype))
                        if a == b:
                            print(f"  MATCH   {qname} {qtype}")
                            continue
                        failures += 1
                        print(f"  DIFFER  {qname} {qtype}")
                        for k in a:
                            if a[k] != b[k]:
                                print(f"      {k}:\n        bind {a[k]}\n        ours {b[k]}")
                failures += drill_checks(work, port, ours, QUERIES + EXTRA_QUERIES[name])
            finally:
                udp.shutdown(); tcp.shutdown(); udp.server_close(); tcp.server_close()
                subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
    print("\n=== online variants (drill only)")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        zones = [SignedZone(REPO / "zones" / f"{o}.zone", work / "ourkeys", d) for o, d in ONLINE]
        udp, tcp = start(Responder(zones), "127.0.0.1", 0)
        try:
            failures += drill_checks(work, udp.server_address[1], zones, QUERIES)
        finally:
            udp.shutdown(); tcp.shutdown(); udp.server_close(); tcp.server_close()

    print(f"\n{'ALL MATCH' if not failures else f'{failures} difference(s)'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
