#!/usr/bin/env python3
"""TCP servers for the in-flow beaconing e2e stage.

Usage: beacon_server.py HOST BASE_PORT

  BASE_PORT      heartbeat: sends a 300-byte message every 2 s on each
                 connection (an implant's check-in inside one open connection)
  BASE_PORT + 1  sink: reads and discards (a bulk upload)
  BASE_PORT + 2  chatter: sends 300-byte messages at irregular gaps (a person
                 using a chat app over one connection)
"""
import socket, sys, threading, time

host, base = sys.argv[1], int(sys.argv[2])
CHATTER_GAPS = [1.3, 4.7, 1.9, 5.5, 2.6, 1.2, 3.8, 6.0, 1.5, 4.2, 2.2, 5.1]


def heartbeat(c):
    while True:
        c.sendall(b"H" * 300)
        time.sleep(2.0)


def sink(c):
    while c.recv(65536):
        pass


def chatter(c):
    i = 0
    while True:
        time.sleep(CHATTER_GAPS[i % len(CHATTER_GAPS)])
        c.sendall(b"C" * 300)
        i += 1


def serve(port, handler):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(8)
    while True:
        c, _ = s.accept()

        def run(c=c):
            try:
                handler(c)
            except OSError:
                pass
            finally:
                c.close()

        threading.Thread(target=run, daemon=True).start()


for off, h in enumerate([heartbeat, sink, chatter]):
    threading.Thread(target=serve, args=(base + off, h), daemon=True).start()
while True:
    time.sleep(3600)
