"""Query handling and UDP/TCP framing.

The lookup itself lives in answer.py; this module handles the header, EDNS,
error RCODEs, size limits, transport, and logging.
"""

import hashlib
import json
import socketserver
import struct
import threading
import time

import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from .answer import answer
from .zone import SignedZone

OUR_UDP_PAYLOAD = 1232  # advertised in our OPT record; avoids fragmentation
MIN_UDP_PAYLOAD = 512


class Responder:
    def __init__(self, zones: list[SignedZone], log_path=None):
        self.zones = zones
        self.log_file = open(log_path, "a", buffering=1) if log_path else None
        self.log_lock = threading.Lock()

    def find_zone(self, qname):
        best = None
        for z in self.zones:
            if qname.is_subdomain(z.origin):
                if best is None or len(z.origin) > len(best.origin):
                    best = z
        return best

    def build_response(self, query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query, our_payload=OUR_UDP_PAYLOAD)
        response.flags |= dns.flags.AA
        do = bool(query.ednsflags & dns.flags.DO)
        if query.edns >= 0:
            # make_response adds OPT but does not echo DO.
            response.use_edns(0, dns.flags.DO if do else 0, OUR_UDP_PAYLOAD)
            if query.edns > 0:
                response.flags &= ~dns.flags.AA
                response.set_rcode(dns.rcode.BADVERS)
                return response

        if query.opcode() != dns.opcode.QUERY:
            response.flags &= ~dns.flags.AA
            response.set_rcode(dns.rcode.NOTIMP)
            return response
        if len(query.question) != 1:
            response.flags &= ~dns.flags.AA
            response.set_rcode(dns.rcode.FORMERR)
            return response

        q = query.question[0]
        zone = self.find_zone(q.name) if q.rdclass == dns.rdataclass.IN else None
        if zone is None:
            response.flags &= ~dns.flags.AA
            response.set_rcode(dns.rcode.REFUSED)
            return response

        if q.rdtype in (dns.rdatatype.AXFR, dns.rdatatype.IXFR):
            response.flags &= ~dns.flags.AA
            response.set_rcode(dns.rcode.REFUSED)
            return response
        if q.rdtype == dns.rdatatype.ANY:
            # Not needed for the study; RFC 8482 minimal ANY could go here.
            response.flags &= ~dns.flags.AA
            response.set_rcode(dns.rcode.NOTIMP)
            return response

        answer(response, zone, q.name, q.rdtype, do)
        return response

    def handle(self, wire: bytes, transport: str, src) -> bytes | None:
        try:
            query = dns.message.from_wire(wire)
        except dns.exception.DNSException as e:
            self.log({"src": src[0], "sport": src[1], "transport": transport,
                      "error": f"parse: {type(e).__name__}"})
            return None

        try:
            response = self.build_response(query)
        except Exception as e:
            # A bug must not turn into silence (looks like packet loss to a
            # resolver); answer SERVFAIL and record what happened.
            self.log({"src": src[0], "sport": src[1], "transport": transport,
                      "error": f"internal: {type(e).__name__}: {e}"})
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.SERVFAIL)

        if transport == "udp":
            limit = max(MIN_UDP_PAYLOAD, query.payload) if query.edns >= 0 else MIN_UDP_PAYLOAD
        else:
            limit = 65535
        try:
            out = response.to_wire(max_size=limit)
        except dns.exception.TooBig:
            response.answer, response.authority, response.additional = [], [], []
            response.flags |= dns.flags.TC
            out = response.to_wire(max_size=limit)

        # Question entries are empty RRsets (falsy), so compare with None.
        q = query.question[0] if query.question else None
        self.log({
            "src": src[0],
            "sport": src[1],
            "transport": transport,
            "id": query.id,
            "qname": q.name.to_text() if q is not None else None,
            "qtype": dns.rdatatype.to_text(q.rdtype) if q is not None else None,
            "rd": bool(query.flags & dns.flags.RD),
            "edns": query.edns,
            "edns_payload": query.payload if query.edns >= 0 else None,
            "do": bool(query.ednsflags & dns.flags.DO),
            "rcode": dns.rcode.to_text(response.rcode()),
            "tc": bool(response.flags & dns.flags.TC),
            "resp_size": len(out),
            "resp_sha256": hashlib.sha256(out).hexdigest(),
        })
        return out

    def log(self, record: dict) -> None:
        record = {"ts": round(time.time(), 6), **record}
        line = json.dumps(record)
        with self.log_lock:
            print(line, flush=True)
            if self.log_file:
                self.log_file.write(line + "\n")


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        out = self.server.responder.handle(data, "udp", self.client_address)
        if out is not None:
            sock.sendto(out, self.client_address)


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        conn.settimeout(10)
        try:
            while True:
                hdr = _recv_exact(conn, 2)
                if hdr is None:
                    return
                (length,) = struct.unpack("!H", hdr)
                data = _recv_exact(conn, length)
                if data is None:
                    return
                out = self.server.responder.handle(data, "tcp", self.client_address)
                if out is None:
                    return
                conn.sendall(struct.pack("!H", len(out)) + out)
        except (TimeoutError, ConnectionError):
            return


def _recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


class _UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start(responder: Responder, addr: str, port: int):
    """Start UDP and TCP servers in background threads; return both servers."""
    udp = _UDPServer((addr, port), _UDPHandler)
    tcp = _TCPServer((addr, udp.server_address[1]), _TCPHandler)
    for srv in (udp, tcp):
        srv.responder = responder
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    return udp, tcp
