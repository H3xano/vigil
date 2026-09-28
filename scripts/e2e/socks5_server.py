#!/usr/bin/env python3
"""Minimal SOCKS5 server for the e2e test (RFC 1928 CONNECT and UDP
ASSOCIATE, RFC 1929 username/password). Logs one line per request:

    AUTH user          CONNECT host:port          UDP host:port

usage: socks5_server.py HOST PORT LOGFILE [USER PASS]
"""
import select, socket, struct, sys, threading

host, port, logpath = sys.argv[1], int(sys.argv[2]), sys.argv[3]
creds = (sys.argv[4], sys.argv[5]) if len(sys.argv) > 5 else None
log_lock = threading.Lock()


def log(line):
    with log_lock, open(logpath, "a") as f:
        f.write(line + "\n")


def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise ConnectionError("eof")
        b += c
    return b


def read_addr(s):
    atyp = recv_exact(s, 1)[0]
    if atyp == 1:
        h = socket.inet_ntop(socket.AF_INET, recv_exact(s, 4))
    elif atyp == 4:
        h = socket.inet_ntop(socket.AF_INET6, recv_exact(s, 16))
    elif atyp == 3:
        h = recv_exact(s, recv_exact(s, 1)[0]).decode()
    else:
        raise ValueError("atyp")
    return h, struct.unpack("!H", recv_exact(s, 2))[0]


def encode_addr(h, p):
    try:
        return b"\x01" + socket.inet_pton(socket.AF_INET, h) + struct.pack("!H", p)
    except OSError:
        return b"\x04" + socket.inet_pton(socket.AF_INET6, h) + struct.pack("!H", p)


def reply(c, rep, addr=("0.0.0.0", 0)):
    c.sendall(b"\x05" + bytes([rep]) + b"\x00" + encode_addr(*addr))


def pipe(a, b):
    socks = [a, b]
    try:
        while True:
            r, _, _ = select.select(socks, [], [], 300)
            if not r:
                return
            for s in r:
                d = s.recv(65536)
                if not d:
                    return
                (b if s is a else a).sendall(d)
    except OSError:
        pass


def udp_associate(c):
    fam = c.getsockname()
    v6 = ":" in fam[0]
    u = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_DGRAM)
    # Bound to the wildcard so it can reach the internet; advertised on the
    # address the client used for the control connection.
    u.bind(("::" if v6 else "0.0.0.0", 0))
    reply(c, 0, (fam[0], u.getsockname()[1]))
    client = None
    seen = set()
    while True:
        r, _, _ = select.select([c, u], [], [], 300)
        if not r or c in r and not c.recv(1024):
            break
        if u not in r:
            continue
        d, src = u.recvfrom(65535)
        if src[0] == fam[0] or client is None or src[:2] == client:
            # From the client: header + payload.
            if d[:3] != b"\x00\x00\x00":
                continue
            client = src[:2]
            atyp = d[3]
            if atyp == 1:
                h, off = socket.inet_ntop(socket.AF_INET, d[4:8]), 8
            elif atyp == 4:
                h, off = socket.inet_ntop(socket.AF_INET6, d[4:20]), 20
            else:
                continue
            p = struct.unpack("!H", d[off:off + 2])[0]
            if (h, p) not in seen:
                seen.add((h, p))
                log(f"UDP {h}:{p}")
            u.sendto(d[off + 2:], (h, p))
        else:
            u.sendto(b"\x00\x00\x00" + encode_addr(src[0], src[1]) + d, client)
    u.close()


def handle(c):
    try:
        n = recv_exact(c, 2)[1]
        methods = recv_exact(c, n)
        if creds:
            if 2 not in methods:
                c.sendall(b"\x05\xff")
                return
            c.sendall(b"\x05\x02")
            recv_exact(c, 1)
            user = recv_exact(c, recv_exact(c, 1)[0]).decode()
            pw = recv_exact(c, recv_exact(c, 1)[0]).decode()
            ok = (user, pw) == creds
            c.sendall(b"\x01" + (b"\x00" if ok else b"\x01"))
            log(f"AUTH {user} {'ok' if ok else 'failed'}")
            if not ok:
                return
        else:
            c.sendall(b"\x05\x00")
        _, cmd, _ = recv_exact(c, 3)
        h, p = read_addr(c)
        if cmd == 1:
            log(f"CONNECT {h}:{p}")
            try:
                up = socket.create_connection((h, p), timeout=10)
                up.settimeout(None)
            except ConnectionRefusedError:
                return reply(c, 5)
            except OSError:
                return reply(c, 4)
            reply(c, 0, up.getsockname()[:2])
            pipe(c, up)
            up.close()
        elif cmd == 3:
            log("ASSOCIATE")
            udp_associate(c)
        else:
            reply(c, 7)
    except (OSError, ValueError, ConnectionError):
        pass
    finally:
        c.close()


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((host, port))
srv.listen(64)
log("LISTENING")
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
