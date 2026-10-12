# dns-nsec-resolver-study
tools for dns authenticated doe nsec variant resolver behavior study

## Usage

```bash
python3 -m venv venv && venv/bin/pip install dnspython cryptography

venv/bin/python -m responder              # serve zones/*.zone on 127.0.0.1:5300 (UDP+TCP)
dig -p 5300 @127.0.0.1 +dnssec www.nsec.test A
delv -p 5300 @127.0.0.1 -a zones/nsec.test.anchor +root=nsec.test www.nsec.test A

tests/gates.sh                            # dig/delv gates (server must be running)
venv/bin/python -m unittest discover -s tests -t .
```

Options: `--addr`, `--port`, `--zone-dir`, `--log` (default `logs/queries.jsonl`).
