#!/usr/bin/env python3
"""Asserts on the events of the in-flow beaconing stage.

Usage: check_beacon.py EVENTS.jsonl BASE_PORT
"""
import json, sys

events = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
base = int(sys.argv[2])
flows = {e["id"]: e for e in events if e["type"] == "flow"}
ends = {e["id"]: e for e in events if e["type"] == "flow_end"}
beacons = [e for e in events if e["type"] == "alert" and e["kind"] == "beacon"]


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + "beacon:" + name + ("" if ok else f" :: {detail}"))


def port_of(a):
    return int(str(a["detail"].get("dst", ":0")).rsplit(":", 1)[1])


intra = [a for a in beacons if a["detail"].get("kind") == "intra_flow"]
hb = [a for a in intra if port_of(a) == base]
check("heartbeat-alert", len(hb) == 1, beacons)
if hb:
    d = hb[0]["detail"]
    print(f"beacon: alert after {d['age_s']} s: every {d['interval_s']:.2f} s, jitter {d['jitter']:.3f}, "
          f"{d['samples']} bursts of {d['burst_bytes']} B")
    check("heartbeat-interval", 1.6 <= d["interval_s"] <= 2.4 and d["jitter"] <= 0.25, d)
    check("heartbeat-burst-size", 250 <= d["burst_bytes"] <= 400, d)
    check("heartbeat-detail", d["flow_id"] in flows and flows[d["flow_id"]]["dst_port"] == base and d["samples"] >= 6, d)
    check("heartbeat-severity", hb[0]["severity"] == "medium" and "inside one open connection" in hb[0]["message"], hb[0])
sink = [f for f in flows.values() if f["dst_port"] == base + 1]
check("bulk-upload-relayed", any(ends.get(f["id"], {}).get("tx", 0) >= 5_000_000 for f in sink), [ends.get(f["id"]) for f in sink])
check("bulk-upload-no-alert", not [a for a in beacons if port_of(a) == base + 1], beacons)
check("irregular-chatter-no-alert", not [a for a in beacons if port_of(a) == base + 2], beacons)
check("no-connection-beacon", not [a for a in beacons if a["detail"].get("kind") != "intra_flow"], beacons)
