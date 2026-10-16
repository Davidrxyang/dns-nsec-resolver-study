"""Probe plumbing for experiments against the local pipeline.

A probe sends one query to the resolver and records both what came back
(the "output" view) and which queries the resolver sent to the responder
meanwhile (the "intake" view, from logs/queries.jsonl). Results are
diagnostics: the pipeline is local and the cache is flushed per experiment.
"""

import json
import random
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

REPO = Path(__file__).resolve().parent.parent
RESPONDER_LOG = REPO / "logs" / "queries.jsonl"
LOG_SETTLE = 0.3                # seconds for the responder to write its log line


@dataclass(frozen=True)
class Resolver:
    """A resolver in the Docker lab (compose.yml): address, cache flush, version."""
    name: str
    ip: str
    flush: tuple                # docker compose args that empty the whole cache
    version: tuple              # docker compose args that print the version
    # False if the lab's routing (forward/stub zones) keeps this resolver from
    # using aggressive negative caching at all, so ANC experiments are artifacts.
    anc_in_lab: bool = True
    lab_note: str = ""


RESOLVERS = {
    "bind": Resolver("bind", "172.30.0.20",
                     ("exec", "-T", "bind", "rndc", "flush"),
                     ("exec", "-T", "bind", "named", "-v")),
    # A full purge (no name) is effective when kresctl returns; checked 2026-10-15.
    "knot": Resolver("knot", "172.30.0.21",
                     ("exec", "-T", "knot", "kresctl", "cache", "clear"),
                     ("exec", "-T", "knot", "kresd", "--version")),
    # wipe-cache '.$' clears record, negative and packet caches; checked 2026-10-15.
    "pdns": Resolver("pdns", "172.30.0.22",
                     ("exec", "-T", "pdns", "rec_control", "wipe-cache", ".$"),
                     ("exec", "-T", "pdns", "pdns_recursor", "--version")),
    # reload "flushes the cache and reads the config file fresh" (unbound-control(8)),
    # but keeps the infra cache (server RTT and reachability): flush that too (INFRA.9).
    "unbound": Resolver("unbound", "172.30.0.23",
                        ("exec", "-T", "unbound", "sh", "-c",
                         "unbound-control reload && unbound-control flush_infra all"),
                        ("exec", "-T", "unbound", "unbound", "-V")),
    # Before the lab root (INFRA.8), PowerDNS reached the zones via forward_zones and
    # could not synthesize at all (INFRA.7): set anc_in_lab=False for any resolver
    # that must use forwarding, so its ANC results are reported as lab artifacts.
}

# Queries a resolver sends on its own, not caused by the probe: Knot's RFC 8145
# trust-anchor signalling (_ta-<keytag>.<zone> NULL), sent at startup, hourly,
# and after a cache purge (FINDINGS ALL.7).
SELF_INITIATED = ("_ta-",)


def compose(*args, check=True) -> str:
    out = subprocess.run(["docker", "compose", *args], cwd=REPO,
                         capture_output=True, text=True, check=check)
    return out.stdout.strip()


def flush_cache(resolver: Resolver) -> None:
    compose(*resolver.flush)


def environment(resolvers) -> dict:
    def git(*a):
        return subprocess.run(["git", *a], cwd=REPO, capture_output=True, text=True).stdout.strip()
    return {
        "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_commit": git("rev-parse", "HEAD"),
        "git_dirty": bool(git("status", "--porcelain")),
        "resolvers": {r.name: {"ip": r.ip, "version": compose(*r.version, check=False)}
                      for r in resolvers},
        "images": compose("ps", "--format", "{{.Service}} {{.Image}}", check=False).splitlines(),
    }


def _rrsets(section):
    out = []
    for rrset in section:
        t = dns.rdatatype.to_text(rrset.rdtype)
        if rrset.rdtype == dns.rdatatype.RRSIG:
            t += " " + dns.rdatatype.to_text(rrset.covers)
        out.append({"name": rrset.name.to_text().lower(), "type": t, "ttl": rrset.ttl,
                    "rdata": [rd.to_text() for rd in rrset][:3]})
    return out


@dataclass
class Probe:
    qname: str
    qtype: str
    do: bool
    cd: bool
    co: bool = False
    rcode: str = ""
    flags: list = field(default_factory=list)
    answer: list = field(default_factory=list)
    authority: list = field(default_factory=list)
    upstream: list = field(default_factory=list)   # "qname qtype[ CO]" the resolver sent to the responder
    error: str = ""

    @property
    def ad(self):
        return "AD" in self.flags

    @property
    def went_upstream(self):
        return bool(self.upstream)


class Context:
    """Per-experiment helper: the resolver under test, fresh labels, probes."""

    def __init__(self, resolver: Resolver):
        self.resolver = resolver
        self.tag = f"{random.randrange(10**8):08d}"
        self.probes: list[Probe] = []

    def expect(self, bind, **others):
        """This resolver's expected value: BIND's unless overridden by name
        (e.g. knot=None, pdns=False); None means no expectation (observation)."""
        return others.get(self.resolver.name, bind)

    def label(self, prefix: str) -> str:
        """Unique label; the first letter picks the NSEC gap (see zones/nsec.test.zone)."""
        return f"{prefix}{self.tag}"

    def probe(self, qname, qtype="A", do=True, cd=False, co=False, timeout=5.0) -> Probe:
        p = Probe(qname, qtype, do, cd, co)
        start = RESPONDER_LOG.stat().st_size if RESPONDER_LOG.exists() else 0
        q = dns.message.make_query(qname, qtype, want_dnssec=do, use_edns=0)
        if cd:
            q.flags |= dns.flags.CD
        if co:
            q.ednsflags |= dns.flags.CO
        try:
            r = dns.query.udp(q, self.resolver.ip, timeout=timeout)
            if r.flags & dns.flags.TC:
                r = dns.query.tcp(q, self.resolver.ip, timeout=timeout)
            p.rcode = dns.rcode.to_text(r.rcode())
            p.flags = dns.flags.to_text(r.flags).split()
            if r.ednsflags & dns.flags.CO:
                p.flags.append("CO")
            p.answer = _rrsets(r.answer)
            p.authority = _rrsets(r.authority)
        except Exception as e:  # timeouts are results too
            p.error = f"{type(e).__name__}: {e}"
        time.sleep(LOG_SETTLE)
        p.upstream = self._upstream_since(start)
        self.probes.append(p)
        return p

    def _upstream_since(self, offset):
        if not RESPONDER_LOG.exists():
            return []
        with RESPONDER_LOG.open() as f:
            f.seek(offset)
            lines = [json.loads(line) for line in f if line.strip()]
        return [f"{e.get('qname', '?').lower()} {e.get('qtype', '?')}" + (" CO" if e.get("co") else "")
                for e in lines if e.get("src") == self.resolver.ip
                and not e.get("qname", "").lower().startswith(SELF_INITIATED)]
