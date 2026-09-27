#!/usr/bin/env python3
"""TCP server that resets every connection right after accepting it.

Used by the e2e test to check that an upstream reset reaches the app as a
reset (not as an orderly close). Usage: rst_server.py HOST PORT
"""
import socket, struct, sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(16)
while True:
    c, _ = s.accept()
    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    c.close()
