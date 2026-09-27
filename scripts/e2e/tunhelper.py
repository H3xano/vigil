#!/usr/bin/env python3
"""Creates a TUN device in the current network namespace and hands its
descriptor to vigil-cli over a Unix socket (SCM_RIGHTS)."""
import fcntl, os, socket, struct, sys, time

TUNSETIFF = 0x400454CA
IFF_TUN, IFF_NO_PI = 0x0001, 0x1000

name, sock_path = sys.argv[1], sys.argv[2]
fd = os.open("/dev/net/tun", os.O_RDWR)
fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI))
for _ in range(100):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path)
        break
    except OSError:
        time.sleep(0.1)
else:
    sys.exit("vigil-cli socket never appeared")
socket.send_fds(s, [b"tun"], [fd])
s.close()
os.close(fd)
