#!/usr/bin/env python3
"""Captures the first bytes a TLS client sends (its ClientHello records).

usage: capture_hello.py PORT OUTFILE -- CLIENT COMMAND...

Listens on 127.0.0.1:PORT, runs the client command (which must connect to
that port), stores what the client sent before going quiet, and closes the
connection (the client then fails, which is expected). `vigil-cli ja4
OUTFILE` turns the capture into the client's JA4 fingerprint, so the e2e
test can list the exact fingerprint of the local curl build in a JA4 feed.
"""
import socket, subprocess, sys

port, out = int(sys.argv[1]), sys.argv[2]
cmd = sys.argv[sys.argv.index("--") + 1:]
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(1)
client = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
srv.settimeout(10)
conn, _ = srv.accept()
conn.settimeout(1.0)
data = b""
try:
    while len(data) < 65536:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data += chunk
except socket.timeout:
    pass
conn.close()
client.wait(timeout=10)
open(out, "wb").write(data)
