#!/usr/bin/env python3
"""Asserts on the packet capture stage: the PCAPng export written by
`vigil-cli run --pcap-on-exit`, the PCAP-over-IP stream and the events.

Usage: check_pcap.py EXPORT.pcapng STREAM.pcap EVENTS.jsonl CLI.log STREAM_PORT
"""
import json, shutil, struct, subprocess, sys

export_path, stream_path, events_path, log_path, port = sys.argv[1:6]


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + "capture:" + name + ("" if ok else f" :: {str(detail)[:300]}"))


def key(pkt):
    """(proto, src, sport, dst, dport, tcp flags, payload) of an IPv4 packet."""
    if len(pkt) < 20 or pkt[0] >> 4 != 4:
        return None
    ihl = (pkt[0] & 15) * 4
    proto = pkt[9]
    src = ".".join(map(str, pkt[12:16]))
    dst = ".".join(map(str, pkt[16:20]))
    l4 = pkt[ihl:]
    if proto == 17 and len(l4) >= 8:
        sp, dp = struct.unpack(">HH", l4[:4])
        return ("udp", src, sp, dst, dp, 0, l4[8:])
    if proto == 6 and len(l4) >= 20:
        sp, dp = struct.unpack(">HH", l4[:4])
        off = (l4[12] >> 4) * 4
        return ("tcp", src, sp, dst, dp, l4[13], l4[off:])
    return None


def read_pcapng(path):
    data = open(path, "rb").read()
    blocks, pos = [], 0
    while pos + 12 <= len(data):
        btype, blen = struct.unpack_from("<II", data, pos)
        if blen < 12 or blen % 4 or pos + blen > len(data) or struct.unpack_from("<I", data, pos + blen - 4)[0] != blen:
            raise ValueError(f"bad block at {pos}")
        blocks.append((btype, data[pos + 8:pos + blen - 4]))
        pos += blen
    if pos != len(data):
        raise ValueError("trailing bytes")
    return blocks


def epb(body):
    _, hi, lo, cap, orig = struct.unpack_from("<IIIII", body, 0)
    pkt = body[20:20 + cap]
    pos = 20 + cap + (-cap % 4)
    opts = {}
    while pos + 4 <= len(body):
        code, olen = struct.unpack_from("<HH", body, pos)
        if code == 0:
            break
        opts[code] = body[pos + 4:pos + 4 + olen]
        pos += 4 + olen + (-olen % 4)
    return (hi << 32 | lo), pkt, orig, opts


events = [json.loads(l) for l in open(events_path) if l.strip()]
flows = [e for e in events if e["type"] == "flow"]
stats = [e for e in events if e["type"] == "stats"]

# --- PCAPng export
try:
    blocks = read_pcapng(export_path)
except Exception as e:  # noqa: BLE001
    blocks = []
    check("export-structure", False, e)
else:
    types = [t for t, _ in blocks]
    shb_ok = types[:2] == [0x0A0D0D0A, 1] and struct.unpack_from("<I", blocks[0][1], 0)[0] == 0x1A2B3C4D
    check("export-structure", shb_ok and all(t == 6 for t in types[2:]), types[:4])
    check("export-linktype-raw", struct.unpack_from("<H", blocks[1][1], 0)[0] == 101)
pkts = [epb(b) for t, b in blocks if t == 6]
check("export-has-packets", len(pkts) >= 10, len(pkts))
log = open(log_path).read()
summary = next((json.loads(l.split("pcap ", 1)[1]) for l in log.splitlines() if "vigil-cli: pcap {" in l), None)
check("export-summary", summary is not None and summary["packets"] == len(pkts) and summary["bytes"] > 0
      and summary["first_ts"] <= summary["last_ts"] and summary["truncated_by_ring"] is False, summary)
check("export-timestamps-ordered", all(a[0] <= b[0] for a, b in zip(pkts, pkts[1:])))

keys = [(key(p), p, opts) for _, p, _, opts in pkts]
dns_q = [k for k in keys if k[0] and k[0][0] == "udp" and k[0][3] == "10.111.222.2" and k[0][4] == 53]
dns_a = [k for k in keys if k[0] and k[0][0] == "udp" and k[0][1] == "10.111.222.2" and k[0][2] == 53]
flag = lambda k: struct.unpack("<I", k[2].get(2, b"\0\0\0\0"))[0] & 3
check("export-dns-query-outbound", any(b"capture-probe" in k[0][6] and flag(k) == 2 for k in dns_q), len(dns_q))
check("export-dns-answer-inbound", dns_a and all(flag(k) == 1 for k in dns_a), len(dns_a))
http = [f for f in flows if f.get("http_method") == "GET"]
check("http-flow-event", len(http) == 1, http)
if http:
    fid = http[0]["id"]
    tagged = [k for k in keys if k[2].get(1, b"").decode().endswith(f"flow={fid}")]
    syn = [k for k in tagged if k[0][0] == "tcp" and k[0][5] & 0x12 == 0x02]
    get = [k for k in tagged if b"GET / HTTP/1.1" in k[0][6] and b"vigil-capture-e2e" in k[0][6]]
    resp = [k for k in tagged if k[0][6].startswith(b"HTTP/1.")]
    check("export-flow-comment-syn", len(syn) >= 1, len(tagged))
    check("export-flow-comment-request", len(get) == 1 and flag(get[0]) == 2, len(get))
    check("export-flow-comment-response", len(resp) >= 1 and flag(resp[0]) == 1, len(resp))

# --- PCAP-over-IP stream
data = open(stream_path, "rb").read()
ok_hdr = len(data) >= 24 and struct.unpack_from("<IHHiIII", data, 0)[0] == 0xA1B2C3D4 \
    and struct.unpack_from("<I", data, 20)[0] == 101
check("stream-header", ok_hdr, data[:24].hex())
recs, pos = [], 24
while pos + 16 <= len(data):
    sec, usec, incl, orig = struct.unpack_from("<IIII", data, pos)
    if pos + 16 + incl > len(data):
        break
    recs.append(data[pos + 16:pos + 16 + incl])
    pos += 16 + incl
check("stream-records-complete", pos == len(data) and len(recs) >= 10, (pos, len(data), len(recs)))
stream_keys = [key(p) for p in recs]
check("stream-dns-query", any(k and k[0] == "udp" and k[4] == 53 and b"capture-probe" in k[6] for k in stream_keys))
check("stream-http-request", any(k and k[0] == "tcp" and b"vigil-capture-e2e" in k[6] for k in stream_keys))

# --- stats
cap = [s["capture"] for s in stats if "capture" in s]
check("stats-capture-enabled", cap and all(c["enabled"] for c in cap) and cap[-1]["packets"] > 0, cap[-1:] if cap else None)
st = [c["stream"] for c in cap if c.get("stream")]
check("stats-stream-listening", any(s["listening"] == f"127.0.0.1:{port}" and s["clients"] == 1 and s["sent"] > 0 for s in st), st[-1:])

# --- optional: Wireshark's tools read both files
if shutil.which("capinfos") and shutil.which("tshark"):
    r = subprocess.run(["capinfos", "-c", "-T", "-r", export_path], capture_output=True, text=True)
    check("capinfos-reads-export", r.returncode == 0 and f"\t{len(pkts)}" in r.stdout, r.stdout + r.stderr)
    r = subprocess.run(["tshark", "-r", stream_path, "-Y", "dns.qry.name contains \"capture-probe\""], capture_output=True, text=True)
    check("tshark-decodes-stream", r.returncode == 0 and "capture-probe" in r.stdout, r.stdout + r.stderr)
    r = subprocess.run(["tshark", "-r", export_path, "-Y", "frame.comment contains \"flow=\"", "-T", "fields", "-e", "frame.comment"],
                       capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        # Newer tshark versions name the field pkt_comment / frame.comment differently.
        r = subprocess.run(["tshark", "-r", export_path, "-Y", "pkt_comment contains \"flow=\""], capture_output=True, text=True)
    check("tshark-reads-comments", r.returncode == 0 and r.stdout.strip() != "", r.stderr)
else:
    print("SKIP capture:wireshark-tools :: capinfos/tshark not installed")
