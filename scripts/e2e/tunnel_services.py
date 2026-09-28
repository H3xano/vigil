#!/usr/bin/env python3
"""Services on the far side of the WireGuard e2e tunnel, logging what they
see (with the client address, which tells tunnelled from leaked traffic):

  HTTP  on [::]:8080   GET  -> "HTTP <client ip> <path>"
  DNS   on ADDR:53     A    -> ADDR, logged as "DNS <qname>"
  UDP   echo on [::]:7777    -> "ECHO <client ip>"

usage: tunnel_services.py ADDR LOGFILE
"""
import http.server, socket, socketserver, struct, sys, threading

addr, logpath = sys.argv[1], sys.argv[2]
lock = threading.Lock()


def log(line):
    with lock, open(logpath, "a") as f:
        f.write(line + "\n")


class Http(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        log(f"HTTP {self.client_address[0].removeprefix('::ffff:')} {self.path}")
        body = b"through the tunnel\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class Http6(socketserver.ThreadingMixIn, http.server.HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, 53))
    while True:
        q, src = s.recvfrom(4096)
        if len(q) < 12:
            continue
        i, labels = 12, []
        while i < len(q) and q[i]:
            labels.append(q[i + 1:i + 1 + q[i]].decode(errors="replace"))
            i += 1 + q[i]
        qtype = struct.unpack("!H", q[i + 1:i + 3])[0]
        question = q[12:i + 5]
        log(f"DNS {'.'.join(labels)}")
        if qtype == 1:
            ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(addr)
            head = q[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 1, 0, 0)
        else:
            ans = b""
            head = q[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 0, 0, 0)
        s.sendto(head + question + ans, src)


def echo():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.bind(("::", 7777))
    while True:
        d, src = s.recvfrom(65535)
        log(f"ECHO {src[0].removeprefix('::ffff:')}")
        s.sendto(d, src)


threading.Thread(target=dns, daemon=True).start()
threading.Thread(target=echo, daemon=True).start()
log("READY")
Http6(("::", 8080), Http).serve_forever()
