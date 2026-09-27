#!/usr/bin/env python3
"""Minimal RFC 6587 (octet-counting) syslog TCP collector for tests."""
import socket, sys, threading

port, out = int(sys.argv[1]), sys.argv[2]
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", port)); srv.listen()

def handle(conn):
    buf = b""
    with conn, open(out, "ab") as f:
        while True:
            data = conn.recv(65536)
            if not data:
                return
            buf += data
            while b" " in buf:
                length, rest = buf.split(b" ", 1)
                if not length.isdigit():
                    f.write(b"BAD-FRAMING\n"); f.flush(); return
                n = int(length)
                if len(rest) < n:
                    break
                f.write(rest[:n] + b"\n"); f.flush()
                buf = rest[n:]

while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
