#!/usr/bin/env python3
"""Local encrypted DNS servers for the e2e test of vigil's upstream DoT/DoH.

Usage: edns_server.py CERT KEY DOT_PORT DOH_PORT PLAIN_PORT HITS_FILE

- DoT (RFC 7858) on 127.0.0.1:DOT_PORT, pipelined frames.
- DoH (RFC 8484, HTTP/1.1 keep-alive POST) on 127.0.0.1:DOH_PORT at /dns-query.
- Plain DNS over UDP on 127.0.0.1:PLAIN_PORT; every query it receives is
  appended to HITS_FILE, so the test can prove nothing leaked in cleartext.

Encrypted answers: A 192.0.2.53 (any name but one.one.one.one: 1.1.1.1); TXT for big.vigil.test is
~1.5 KB (exceeds 512 bytes, so UDP clients must get TC). Plain answers:
A 192.0.2.99. The certificate is the committed test CA's
(core/vigil-core/testdata/edns), valid for dns.vigil.test and 127.0.0.1.
"""
import http.server, socket, socketserver, ssl, struct, sys, threading

cert, key = sys.argv[1], sys.argv[2]
dot_port, doh_port, plain_port = map(int, sys.argv[3:6])
hits_file = sys.argv[6]


def question(q):
    """Returns (end offset of the first question, qname, qtype)."""
    i, labels = 12, []
    while q[i]:
        labels.append(q[i + 1:i + 1 + q[i]].decode("ascii", "replace"))
        i += 1 + q[i]
    i += 1
    return i + 4, ".".join(labels).lower(), struct.unpack(">H", q[i:i + 2])[0]


def answer(q, a_ip):
    end, name, qtype = question(q)
    records = []
    if qtype == 1:
        # The real address, so the SOCKS5 send_domain check can connect by
        # name to a host vigil resolved.
        records.append((1, bytes([1, 1, 1, 1] if name == "one.one.one.one" else a_ip)))
    elif qtype == 16 and name == "big.vigil.test":
        txt = b"".join(bytes([200]) + b"x" * 200 for _ in range(7))
        records.append((16, txt))
    flags = 0x8180 | (struct.unpack(">H", q[2:4])[0] & 0x0100)
    out = q[:2] + struct.pack(">HHHHH", flags, 1, len(records), 0, 0) + q[12:end]
    for rtype, rdata in records:
        out += struct.pack(">HHHIH", 0xC00C, rtype, 1, 60, len(rdata)) + rdata
    return out


def tls_context(alpn):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    if alpn:
        ctx.set_alpn_protocols(alpn)
    return ctx


class DotHandler(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        buf = b""
        while True:
            try:
                chunk = s.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            while len(buf) >= 2 and len(buf) >= 2 + struct.unpack(">H", buf[:2])[0]:
                n = struct.unpack(">H", buf[:2])[0]
                q, buf = buf[2:2 + n], buf[2 + n:]
                a = answer(q, [192, 0, 2, 53])
                s.sendall(struct.pack(">H", len(a)) + a)


class TlsTcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, ctx):
        self.ctx = ctx
        super().__init__(addr, handler)

    def get_request(self):
        sock, addr = self.socket.accept()
        return self.ctx.wrap_socket(sock, server_side=True), addr


class DohHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        ok = (self.path == "/dns-query"
              and self.headers.get("Content-Type") == "application/dns-message"
              and body[:2] == b"\0\0")
        if not ok:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        a = answer(body, [192, 0, 2, 53])
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(a)))
        self.end_headers()
        self.wfile.write(a)

    def log_message(self, *args):
        pass


def plain():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", plain_port))
    while True:
        q, peer = s.recvfrom(4096)
        with open(hits_file, "a") as f:
            f.write(question(q)[1] + "\n")
        s.sendto(answer(q, [192, 0, 2, 99]), peer)


dot = TlsTcpServer(("127.0.0.1", dot_port), DotHandler, tls_context(None))
doh = TlsTcpServer(("127.0.0.1", doh_port), DohHandler, tls_context(["http/1.1"]))
open(hits_file, "w").close()
threading.Thread(target=dot.serve_forever, daemon=True).start()
threading.Thread(target=doh.serve_forever, daemon=True).start()
plain()
