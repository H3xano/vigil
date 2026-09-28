#!/usr/bin/env python3
"""Asserts on the events of one encrypted upstream DNS phase of the e2e test.

Usage: check_edns.py EVENTS PHASE HITS_FILE
"""
import json, sys

events = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
phase = sys.argv[2]
hits = [l.strip() for l in open(sys.argv[3]) if l.strip()]
dns = [e for e in events if e["type"] == "dns"]
stats = [e for e in events if e["type"] == "stats"]
last = stats[-1] if stats else {}


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + f"{phase}:events:" + name + ("" if ok else f" :: {detail}"))


allowed = [d for d in dns if d["verdict"] == "allow"]
blocked = [d for d in dns if d["verdict"] == "block"]
via = sorted({d.get("upstream") for d in allowed if d.get("upstream")})
if phase in ("local-dot", "local-doh", "live-dot", "live-doh"):
    want = phase.split("-")[1]
    check("upstream-field", via == [want], via)
    check("answers-logged", any(d["rcode"] == "NOERROR" and d["answers"] for d in allowed))
    check("stats-ok", last.get("encrypted_dns_ok", 0) > 0 and last.get("encrypted_dns_last_ok_ts", 0) > 0, last)
if phase.startswith("local-"):
    check("no-cleartext", hits == [], hits[:5])
    check("sinkhole-no-upstream", any(d["qname"] == "ads.vigil-test.example" and d.get("upstream") is None for d in blocked), blocked)
if phase == "fail-closed":
    fails = [d for d in dns if d["rcode"] == "SERVFAIL"]
    check("servfail-logged", any(d.get("upstream") == "dot" and "dot" in (d.get("reason") or "") for d in fails), fails)
    check("no-cleartext", hits == [], hits[:5])
    check("stats-failed", last.get("encrypted_dns_failed", 0) > 0 and last.get("encrypted_dns_last_error"), last)
if phase == "fallback":
    check("fell-back", any(d.get("upstream") == "udp" and d["qname"] == "d.vigil.test" for d in allowed), dns)
    check("plain-hit", "d.vigil.test" in hits, hits)
    check("stats-fallback", last.get("encrypted_dns_fallback", 0) > 0, last)
