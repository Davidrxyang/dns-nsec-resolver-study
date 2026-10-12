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
```

`delv` should print `; fully validated` (or `; negative response, fully validated`).
Refused queries such as AXFR show up only in `logs/queries.jsonl`.
