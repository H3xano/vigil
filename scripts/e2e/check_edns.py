#!/usr/bin/env python3
"""Asserts on the events of one encrypted upstream DNS phase of the e2e test.

Usage: check_edns.py EVENTS PHASE HITS_FILE [SOCKS_LOG]
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
if phase in ("local-dot", "local-doh", "live-dot", "live-doh", "socks5-dot"):
    want = phase.split("-")[1]
    if phase == "socks5-dot":
        # The hard-coded resolver query is plain DNS over TCP (via the proxy).
        via = sorted({d.get("upstream") for d in allowed if d.get("server") == "virtual" and d.get("upstream")})
    check("upstream-field", via == [want], via)
    check("answers-logged", any(d["rcode"] == "NOERROR" and d["answers"] for d in allowed))
    check("stats-ok", last.get("encrypted_dns_ok", 0) > 0 and last.get("encrypted_dns_last_ok_ts", 0) > 0, last)
if phase.startswith("local-") or phase == "socks5-dot":
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
if phase == "socks5-dot":
    proxy = [l.strip() for l in open(sys.argv[4]) if l.strip()]
    flows = [e for e in events if e["type"] == "flow"]
    check("dot-via-proxy", "CONNECT 127.0.0.1:18853" in proxy, proxy)
    hard = [d for d in allowed if d.get("server") != "virtual"]
    check("hardcoded-dns-tcp-via-proxy", any(d.get("upstream") == "tcp" for d in hard) and any(l.startswith("CONNECT 9.9.9.9:53") for l in proxy), (hard[:2], proxy))
    ja4 = [f for f in flows if f.get("domain") == "ja4-blocked.vigil-test.example"]
    check("ja4-block-event", any(f["verdict"] == "block" and f.get("ja4_match") and (f.get("reason") or "").startswith("ja4:") for f in ja4), ja4)
    check("ja4-block-no-proxy-contact", not any("ja4-blocked" in l or l == "CONNECT 1.1.1.1:443" for l in proxy), proxy)
    check("allowed-by-name-via-proxy", "CONNECT one.one.one.one:443" in proxy and any(f.get("domain") == "one.one.one.one" and f.get("via") == "socks5" and f["verdict"] == "allow" for f in flows), proxy)
    ups = [e.get("upstream") or {} for e in stats]
    check("stats-upstream-socks5", any(u.get("mode") == "socks5" and u.get("state") == "up" for u in ups), ups[-1:])
