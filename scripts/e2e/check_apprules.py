#!/usr/bin/env python3
"""Asserts on the events of the per-app rules stage (inside-apprules.sh).

Usage: check_apprules.py EVENTS.jsonl SINK_PORT
"""
import json, sys

events = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
port = int(sys.argv[2])
flows = {e["id"]: e for e in events if e["type"] == "flow"}
ends = {e["id"]: e for e in events if e["type"] == "flow_end"}
dns = [e for e in events if e["type"] == "dns"]
CUT = "blocked: app rule: wifi"


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + "apprules:" + name + ("" if ok else f" :: {detail}"))


sink = [f for f in flows.values() if f["dst_port"] == port]
check("uid-attributed", sink and all(f["uid"] == 10123 for f in sink), sink)
cut_tcp = [f for f in sink if f["verdict"] == "allow" and ends.get(f["id"], {}).get("error") == CUT]
check("tcp-cut-reported", len(cut_tcp) == 1, [(f, ends.get(f["id"])) for f in sink])
udp = [f for f in flows.values() if f["proto"] == "udp" and f["dst_port"] == 18799]
check("udp-cut-reported", any(ends.get(f["id"], {}).get("error") == CUT for f in udp), [(f, ends.get(f["id"])) for f in udp])
refused = [f for f in sink if f["verdict"] == "block"]
check("tcp-refused-with-reason", refused and all(f["reason"] == "app rule: wifi" for f in refused), refused)
check("dns-app-domain-rule", any(d["qname"] == "perapp.vigil-test.example" and d["verdict"] == "block"
                                 and d["reason"] == "app domain rule (perapp.vigil-test.example)" for d in dns), dns)
check("dns-app-rule", any(d["qname"] == "example.com" and d["reason"] == "app rule: wifi" for d in dns), dns)
check("every-flow-ended", set(flows) == set(ends), set(flows) ^ set(ends))
