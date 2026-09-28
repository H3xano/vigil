#!/usr/bin/env python3
"""Client side of the in-flow beaconing e2e stage (runs in the namespace).

Usage: beacon_client.py HOST BASE_PORT SECONDS

Holds one connection to each server of beacon_server.py for SECONDS: reads
the heartbeat and chatter messages and uploads 64 KiB every 100 ms to the
sink. Prints "heartbeat=N chatter=N uploaded=N" and fails if the
connections did not carry what they should.
"""
import socket, sys, threading, time

host, base, secs = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
counts = {"heartbeat": 0, "chatter": 0, "uploaded": 0}
deadline = time.monotonic() + secs


def reader(name, port):
    c = socket.create_connection((host, port), timeout=10)
    c.settimeout(1.0)
    while time.monotonic() < deadline:
        try:
            data = c.recv(65536)
        except socket.timeout:
            continue
        if not data:
            break
        counts[name] += len(data)
    c.close()


def uploader(port):
    c = socket.create_connection((host, port), timeout=10)
    chunk = b"U" * 65536
    while time.monotonic() < deadline:
        c.sendall(chunk)
        counts["uploaded"] += len(chunk)
        time.sleep(0.1)
    c.close()


threads = [
    threading.Thread(target=reader, args=("heartbeat", base)),
    threading.Thread(target=uploader, args=(base + 1,)),
    threading.Thread(target=reader, args=("chatter", base + 2)),
]
for t in threads:
    t.start()
for t in threads:
    t.join()
print(" ".join(f"{k}={v}" for k, v in counts.items()))
ok = counts["heartbeat"] >= 300 * int(secs / 2 - 1) and counts["chatter"] >= 300 * 4 and counts["uploaded"] >= 5 * 65536 * secs
sys.exit(0 if ok else 1)
