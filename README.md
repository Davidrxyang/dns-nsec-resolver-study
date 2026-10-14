# dns-nsec-resolver-study
tools for dns authenticated doe nsec variant resolver behavior study

## Usage

Run from the repo root (paths like `zones/nsec.test.anchor` are relative).

```bash
python3 -m venv venv && venv/bin/pip install dnspython cryptography

venv/bin/python -m responder              # serve zones/*.zone on 127.0.0.1:5300 (UDP+TCP)
tests/gates.sh                            # dig/delv gates (server must be running)
venv/bin/python -m unittest discover -s tests -t .
```

Options: `--addr`, `--port`, `--zone-dir`, `--log` (default `logs/queries.jsonl`).
Each `zones/X.zone` may have an `X.toml` choosing its denial variant (`denial = "nsec"`).
The anchor file for `delv` is written at startup.

## Example queries (`nsec.test`, vanilla NSEC)

```bash
dig -p 5300 @127.0.0.1 +dnssec +norec www.nsec.test A          # answer
dig -p 5300 @127.0.0.1 +dnssec +norec nope.nsec.test A         # NXDOMAIN
dig -p 5300 @127.0.0.1 +dnssec +norec www.nsec.test AAAA       # NODATA
dig -p 5300 @127.0.0.1 +dnssec +norec ent.nsec.test A          # empty non-terminal
dig -p 5300 @127.0.0.1 +dnssec +norec x.wild.nsec.test A       # wildcard
dig -p 5300 @127.0.0.1 +dnssec +norec foo.secure.nsec.test A   # referral (DS)
dig -p 5300 @127.0.0.1 +dnssec +norec insecure.nsec.test DS    # no-DS proof

delv -p 5300 @127.0.0.1 -a zones/nsec.test.anchor +root=nsec.test nope.nsec.test A

# nsec3.test: same zone content, vanilla NSEC3 (hashed names, closest-encloser proofs)
dig -p 5300 @127.0.0.1 +dnssec +norec nsec3.test NSEC3PARAM
dig -p 5300 @127.0.0.1 +dnssec +norec c.nsec3.test A           # NXDOMAIN, 3 NSEC3
delv -p 5300 @127.0.0.1 -a zones/nsec3.test.anchor +root=nsec3.test c.nsec3.test A
```

`delv` should print `; fully validated` (or `; negative response, fully validated`).
Refused queries such as AXFR show up only in `logs/queries.jsonl`.

## Local resolver pipeline (Docker: client -> BIND 9.20.29 -> responder)

```bash
docker/pipeline.sh up            # build and start; BIND at 172.30.0.20
docker/pipeline.sh check         # bring-up checks, incl. responder-down SERVFAIL
docker/pipeline.sh experiments   # catalogued behavior probes; add --only N01,N08 or --slow
docker/pipeline.sh down
```

Experiments are defined in `experiments/catalog.py` and listed in [experiments/CATALOG.md](experiments/CATALOG.md)
(regenerate with `venv/bin/python -m experiments catalog`). Each run writes `results/<UTC time>/`.
