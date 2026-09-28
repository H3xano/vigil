#!/usr/bin/env python3
"""PCAP-over-IP client for the capture stage: connects (retrying until the
engine listens), writes a ready file once the PCAP header has arrived, then
saves everything it receives until the engine closes the connection.

Usage: pcap_stream_client.py HOST PORT OUT READY_FILE
"""
import socket, sys, time

host, port, out, ready = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
deadline = time.time() + 30
while True:
    try:
        s = socket.create_connection((host, port), timeout=2)
        break
    except OSError:
        if time.time() > deadline:
            sys.exit("PCAP-over-IP server never listened")
        time.sleep(0.1)
s.settimeout(120)
data = b""
while len(data) < 24:
    chunk = s.recv(65536)
    if not chunk:
        break
    data += chunk
open(ready, "w").write("ready")
with open(out, "wb") as f:
    f.write(data)
    while True:
        try:
            chunk = s.recv(65536)
        except OSError:
            break
        if not chunk:
            break
        f.write(chunk)
