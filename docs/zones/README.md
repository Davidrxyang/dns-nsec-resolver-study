# Zone diagrams

One document per zone, generated from the responder's own output by `venv/bin/python -m tools.zone_diagrams`. All zones have the same names and records; they differ only in how nonexistence is proved.

| Zone | Variant | Standard |
|---|---|---|
| [`nsec.test`](nsec.test.md) | Vanilla NSEC (`nsec`) | RFC 4034, RFC 4035 |
| [`nsec3.test`](nsec3.test.md) | Vanilla NSEC3 (`nsec3`) | RFC 5155, RFC 9276 |
| [`minnsec.test`](minnsec.test.md) | Minimally covering NSEC (`minimal-nsec`) | RFC 4470 (+ erratum 6734) |
| [`minnsec3.test`](minnsec3.test.md) | NSEC3 white lies (`nsec3-white-lies`) | RFC 7129 Appendix B |
| [`cdoe-nsec.test`](cdoe-nsec.test.md) | Compact denial of existence, NSEC (`compact-nsec`) | RFC 9824 §3 |
| [`cdoe-nsec3.test`](cdoe-nsec3.test.md) | Compact denial of existence, NSEC3 (`compact-nsec3`) | RFC 9824 §4 |
