#!/usr/bin/env python3
"""Small-packet load for scripts/bench-throughput.sh (MODE=tcp|udp|dns).

Servers (run on the host):
  serve-tcp HOST PORT SIZE   answer every connection with one HTTP response
                             of SIZE bytes, then close
  serve-udp HOST PORT        echo datagrams
  serve-dns HOST PORT        answer every DNS query with A 192.0.2.1

Clients (run inside the namespace, through vigil); print "<ops> <seconds>":
  tcp HOST PORT N CONC       N short HTTP/1.0 requests, one connection each
  udp HOST PORT N CONC SIZE  N request/reply datagrams over CONC flows
  dns SERVER N CONC          N A queries for unique names over CONC sockets
  idle HOST PORT SECS        20 requests, then 4 open connections for SECS
"""
import asyncio, os, socket, struct, sys, threading, time


def serve_tcp(host, port, size):
    body = b"x" * size
    resp = b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % size + body

    async def handle(r, w):
        try:
            await r.readuntil(b"\r\n\r\n")
            w.write(resp)
            await w.drain()
        except Exception:
            pass
        w.close()

    async def main():
        srv = await asyncio.start_server(handle, host, port, backlog=1024)
        await srv.serve_forever()

    asyncio.run(main())


def serve_udp(host, port, dns=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
    s.bind((host, port))
    while True:
        d, a = s.recvfrom(65535)
        if dns:
            if len(d) < 12:
                continue
            # Question ends at the first zero label after the header, + 4.
            q_end = d.index(b"\0", 12) + 5
            d = (d[:2] + b"\x81\x80" + d[4:6] + b"\0\x01\0\0\0\0" + d[12:q_end]
                 + b"\xc0\x0c\0\x01\0\x01\0\0\0\x3c\0\x04\xc0\x00\x02\x01")
        s.sendto(d, a)


def run_threads(conc, fn):
    t0 = time.monotonic()
    ts = [threading.Thread(target=fn, args=(i,)) for i in range(conc)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return time.monotonic() - t0


def client_tcp(host, port, n, conc):
    req = b"GET /small HTTP/1.0\r\nHost: bench\r\n\r\n"
    done = [0]

    async def one():
        r, w = await asyncio.open_connection(host, port)
        w.write(req)
        await r.read()  # until the server closes
        w.close()
        done[0] += 1

    async def main():
        sem = asyncio.Semaphore(conc)

        async def guarded():
            async with sem:
                try:
                    await one()
                except OSError:
                    pass

        await asyncio.gather(*(guarded() for _ in range(n)))

    t0 = time.monotonic()
    asyncio.run(main())
    return done[0], time.monotonic() - t0


def client_dgram(server, n, conc, make, check):
    per = n // conc
    done = [0] * conc

    def worker(i):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(server)
        for k in range(per):
            msg = make(i, k)
            for _ in range(3):
                s.send(msg)
                try:
                    if check(msg, s.recv(65535)):
                        done[i] += 1
                        break
                except socket.timeout:
                    pass
        s.close()

    secs = run_threads(conc, worker)
    return sum(done), secs


def client_idle(host, port, secs):
    ops, _ = client_tcp(host, port, 20, 4)
    # The server waits for a request that never comes: idle relays.
    held = [socket.create_connection((host, port)) for _ in range(4)]
    time.sleep(secs)
    for s in held:
        s.close()
    return ops, secs


def dns_query(i, k):
    qid = (i * 7919 + k) & 0xFFFF
    name = b"".join(bytes([len(l)]) + l for l in (b"q%d-%d" % (i, k), b"bench", b"test"))
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + name + b"\0\0\x01\0\x01"


def main():
    cmd, a = sys.argv[1], sys.argv[2:]
    if cmd == "serve-tcp":
        serve_tcp(a[0], int(a[1]), int(a[2]))
    elif cmd == "serve-udp":
        serve_udp(a[0], int(a[1]))
    elif cmd == "serve-dns":
        serve_udp(a[0], int(a[1]), dns=True)
    else:
        if cmd == "tcp":
            ops, secs = client_tcp(a[0], int(a[1]), int(a[2]), int(a[3]))
        elif cmd == "udp":
            size = int(a[4])
            ops, secs = client_dgram(
                (a[0], int(a[1])), int(a[2]), int(a[3]),
                lambda i, k: struct.pack(">II", i, k) + b"u" * max(0, size - 8),
                lambda m, r: r == m)
        elif cmd == "dns":
            ops, secs = client_dgram(
                (a[0], 53), int(a[1]), int(a[2]), dns_query,
                lambda m, r: r[:2] == m[:2])
        elif cmd == "idle":
            ops, secs = client_idle(a[0], int(a[1]), float(a[2]))
        else:
            sys.exit(__doc__)
        print(ops, "%.3f" % secs)


if __name__ == "__main__":
    main()
