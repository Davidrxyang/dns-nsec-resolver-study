"""Run the responder: python -m responder [--port 5300]."""

import argparse
import threading
from pathlib import Path

from .server import Responder, start
from .zone import SignedZone

REPO = Path(__file__).resolve().parent.parent


def main():
    p = argparse.ArgumentParser(description="NSEC-variant authoritative responder")
    p.add_argument("--addr", default="127.0.0.1")
    # 5353 is mDNS and usually taken by avahi; use 5300.
    p.add_argument("--port", type=int, default=5300)
    p.add_argument("--zone-dir", type=Path, default=REPO / "zones")
    p.add_argument("--log", type=Path, default=REPO / "logs" / "queries.jsonl")
    args = p.parse_args()

    zones = []
    for zf in sorted(args.zone_dir.glob("*.zone")):
        z = SignedZone(zf, args.zone_dir / "keys")
        anchor = args.zone_dir / f"{z.origin.to_text(omit_final_dot=True)}.anchor"
        anchor.write_text(z.anchor_text())
        print(f"loaded {z.origin} key_tag={z.key_tag} anchor={anchor}")
        print(f"  {z.ds_text()}")
        zones.append(z)

    args.log.parent.mkdir(parents=True, exist_ok=True)
    responder = Responder(zones, args.log)
    start(responder, args.addr, args.port)
    print(f"listening on {args.addr}:{args.port} udp+tcp", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
