# dns-nsec-resolver-study
tools for dns authenticated doe nsec variant resolver behavior study

Six signed zones with **identical content** that differ only in how they prove a name does not exist:

| Zone | Variant | Standard |
|---|---|---|
| `nsec.test` | vanilla NSEC | RFC 4034/4035 |
| `nsec3.test` | vanilla NSEC3 | RFC 5155 |
| `minnsec.test` | minimally covering NSEC | RFC 4470 |
| `minnsec3.test` | NSEC3 white lies | RFC 7129 App. B |
| `cdoe-nsec.test` | compact denial, NSEC | RFC 9824 §3 |
| `cdoe-nsec3.test` | compact denial, NSEC3 | RFC 9824 §4 |

## Compare the variants side by side

Ask one question in all six zones and see each variant's answer (rcode, flags, denial records):

```bash
venv/bin/python -m responder &           # once: serve all zones on 127.0.0.1:5300
tools/compare.sh nope                    # a nonexistent name
```

Useful questions (labels exist in every zone):

```bash
tools/compare.sh nope                    # nonexistent name: NXDOMAIN vs NOERROR, 1-3 records
tools/compare.sh foo.bar.ent             # nonexistent, two labels below an empty non-terminal
tools/compare.sh www AAAA                # NODATA: the name exists, the type does not
tools/compare.sh ent                     # empty non-terminal
tools/compare.sh x.wild                  # wildcard answer
tools/compare.sh a.b.wild TXT            # wildcard NODATA
tools/compare.sh foo.insecure            # referral to an unsigned child
tools/compare.sh insecure DS             # DS query at an unsigned delegation
tools/compare.sh nope A +coflag          # compact denial with CO set: NXDOMAIN restored
tools/compare.sh --bind nope             # the same through BIND (Docker pipeline): the resolver's view
```

Any extra arguments go to dig. Without the script, the same comparison is:

```bash
for z in nsec nsec3 minnsec minnsec3 cdoe-nsec cdoe-nsec3; do echo "== $z.test"; dig -p 5300 @127.0.0.1 +dnssec +norec +nocmd +nostats +noquestion nope.$z.test A | grep -E 'status|IN[[:space:]]+NSEC3?[[:space:]]'; done
```

Which record proves what, for every zone: [docs/zones/](docs/zones/README.md). Rules and implementation decisions: [docs/VARIANTS.md](docs/VARIANTS.md).

## Usage

Run from the repo root (paths like `zones/nsec.test.anchor` are relative).

```bash
python3 -m venv venv && venv/bin/pip install dnspython cryptography

venv/bin/python -m responder              # serve zones/*.zone on 127.0.0.1:5300 (UDP+TCP)
tests/gates.sh                            # dig/delv gates (server must be running)
venv/bin/python -m unittest discover -s tests -t .
venv/bin/python -m tests.reference        # fidelity: diff vs BIND signer/server, validate with ldns drill (Docker)
```

Options: `--addr`, `--port`, `--zone-dir`, `--log` (default `logs/queries.jsonl`).
Each `zones/X.zone` may have an `X.toml` choosing its denial variant (`denial = "nsec"`).
The anchor file for `delv` is written at startup.

## Validating a single answer

```bash
dig -p 5300 @127.0.0.1 +dnssec +norec nope.nsec.test A                                   # one zone, full output
delv -p 5300 @127.0.0.1 -a zones/nsec.test.anchor +root=nsec.test nope.nsec.test A       # independent validation
```

Replace `nsec.test` with any zone (and its `zones/<zone>.anchor`).
`delv` should print `; fully validated` (or `; negative response, fully validated`).
Refused queries such as AXFR show up only in `logs/queries.jsonl`.

## Local resolver pipeline (Docker: client -> BIND 9.20.29 / Knot Resolver 6.5.0 / PowerDNS Recursor 5.4.7 -> responder)

```bash
docker/pipeline.sh up            # build and start; BIND .20, Knot .21, PowerDNS .22 (172.30.0.x)
docker/pipeline.sh check         # bring-up checks for every resolver, incl. responder-down SERVFAIL
docker/pipeline.sh experiments   # catalogued probes on every resolver; --resolver bind|knot|pdns, --only N01,N08, --slow
docker/pipeline.sh down
```

Resolvers find the zones by iterating from a signed local root (a second responder at .11, `zones/root/`), with root hints and the root key as their only trust anchor: the same delegation path as in the wild.
Responder logs: `logs/queries.jsonl` (zones) and `logs/root-queries.jsonl` (root).
Lab-only exemptions from resolver defaults (Knot answers `.test` itself unless told not to; PowerDNS won't query private addresses) are listed in [FINDINGS.md](FINDINGS.md) INFRA.8.

Experiments are defined in `experiments/catalog.py` and listed in [experiments/CATALOG.md](experiments/CATALOG.md)
(regenerate with `venv/bin/python -m experiments catalog`). Each run writes `results/<UTC time>/`.
Interesting observations are logged in [FINDINGS.md](FINDINGS.md).
Regenerate the per-zone diagrams after changing zones or denial code: `venv/bin/python -m tools.zone_diagrams`.
