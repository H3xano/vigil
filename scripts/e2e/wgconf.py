#!/usr/bin/env python3
"""Configures a kernel WireGuard interface over generic netlink, for hosts
without wireguard-tools (the e2e test runs unprivileged, in namespaces).

usage: wgconf.py IFNAME PRIVATE_KEY_B64 LISTEN_PORT PEER_PUBLIC_B64 ALLOWED_IP[,ALLOWED_IP...]
       wgconf.py --show IFNAME     print "handshake=<unix s> rx=<bytes> tx=<bytes>" of the first peer
"""
import base64, ipaddress, os, socket, struct, sys

NETLINK_GENERIC = 16
GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY, CTRL_ATTR_FAMILY_ID, CTRL_ATTR_FAMILY_NAME = 3, 1, 2
NLM_F_REQUEST, NLM_F_ACK, NLM_F_DUMP = 1, 4, 0x300
NLMSG_ERROR, NLA_F_NESTED = 2, 0x8000
WG_CMD_GET_DEVICE, WG_CMD_SET_DEVICE = 0, 1
WGDEVICE_A_IFNAME, WGDEVICE_A_PRIVATE_KEY, WGDEVICE_A_LISTEN_PORT, WGDEVICE_A_PEERS = 2, 3, 6, 8
WGPEER_A_PUBLIC_KEY, WGPEER_A_FLAGS, WGPEER_A_LAST_HANDSHAKE_TIME = 1, 3, 6
WGPEER_A_RX_BYTES, WGPEER_A_TX_BYTES, WGPEER_A_ALLOWEDIPS = 7, 8, 9
WGPEER_F_REPLACE_ALLOWEDIPS = 2
WGALLOWEDIP_A_FAMILY, WGALLOWEDIP_A_IPADDR, WGALLOWEDIP_A_CIDR_MASK = 1, 2, 3


def attr(t, payload):
    n = 4 + len(payload)
    return struct.pack("=HH", n, t) + payload + b"\0" * ((4 - n % 4) % 4)


def nested(t, parts):
    return attr(t | NLA_F_NESTED, b"".join(parts))


def parse_attrs(b):
    out = {}
    while len(b) >= 4:
        n, t = struct.unpack("=HH", b[:4])
        if n < 4:
            break
        out.setdefault(t & 0x3FFF, []).append(b[4:n])
        b = b[(n + 3) & ~3:]
    return out


class Genl:
    def __init__(self):
        self.s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        self.s.bind((0, 0))
        self.seq = 0

    def request(self, family, cmd, attrs, flags=NLM_F_REQUEST | NLM_F_ACK):
        self.seq += 1
        body = struct.pack("=BBH", cmd, 1, 0) + attrs
        self.s.send(struct.pack("=IHHII", 16 + len(body), family, flags, self.seq, os.getpid()) + body)
        msgs = []
        while True:
            data = self.s.recv(65536)
            while data:
                n, typ, _, _, _ = struct.unpack("=IHHII", data[:16])
                payload = data[16:n]
                data = data[(n + 3) & ~3:]
                if typ == NLMSG_ERROR:
                    err = struct.unpack("=i", payload[:4])[0]
                    if err:
                        raise OSError(-err, os.strerror(-err))
                    return msgs
                if typ == 3:  # NLMSG_DONE
                    return msgs
                msgs.append(parse_attrs(payload[4:]))
            if not flags & NLM_F_ACK and msgs:
                return msgs

    def family(self, name):
        m = self.request(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, attr(CTRL_ATTR_FAMILY_NAME, name.encode() + b"\0"),
                         NLM_F_REQUEST)
        return struct.unpack("=H", m[0][CTRL_ATTR_FAMILY_ID][0][:2])[0]


def main():
    g = Genl()
    wg = g.family("wireguard")
    if sys.argv[1] == "--show":
        ifname = sys.argv[2].encode() + b"\0"
        msgs = g.request(wg, WG_CMD_GET_DEVICE, attr(WGDEVICE_A_IFNAME, ifname), NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP)
        for m in msgs:
            for peers in m.get(WGDEVICE_A_PEERS, []):
                for peer in parse_attrs(peers).values():
                    p = parse_attrs(peer[0])
                    hs = struct.unpack("=qq", p[WGPEER_A_LAST_HANDSHAKE_TIME][0])[0]
                    rx = struct.unpack("=Q", p[WGPEER_A_RX_BYTES][0])[0]
                    tx = struct.unpack("=Q", p[WGPEER_A_TX_BYTES][0])[0]
                    print(f"handshake={hs} rx={rx} tx={tx}")
                    return
        print("handshake=0 rx=0 tx=0")
        return
    ifname, priv, port, peer, allowed = sys.argv[1:6]
    ips = []
    for i, cidr in enumerate(allowed.split(",")):
        net = ipaddress.ip_network(cidr, strict=False)
        fam = socket.AF_INET if net.version == 4 else socket.AF_INET6
        ips.append(nested(i, [attr(WGALLOWEDIP_A_FAMILY, struct.pack("=H", fam)),
                              attr(WGALLOWEDIP_A_IPADDR, net.network_address.packed),
                              attr(WGALLOWEDIP_A_CIDR_MASK, struct.pack("=B", net.prefixlen))]))
    peer_attrs = nested(0, [attr(WGPEER_A_PUBLIC_KEY, base64.b64decode(peer)),
                            attr(WGPEER_A_FLAGS, struct.pack("=I", WGPEER_F_REPLACE_ALLOWEDIPS)),
                            nested(WGPEER_A_ALLOWEDIPS, ips)])
    g.request(wg, WG_CMD_SET_DEVICE, attr(WGDEVICE_A_IFNAME, ifname.encode() + b"\0")
              + attr(WGDEVICE_A_PRIVATE_KEY, base64.b64decode(priv))
              + attr(WGDEVICE_A_LISTEN_PORT, struct.pack("=H", int(port)))
              + nested(WGDEVICE_A_PEERS, [peer_attrs]))


main()
