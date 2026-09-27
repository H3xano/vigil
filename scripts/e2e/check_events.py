#!/usr/bin/env python3
"""Asserts on the JSON events emitted by vigil-cli during the e2e run."""
import json, sys

events = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
flows = {e["id"]: e for e in events if e["type"] == "flow"}
ends = {e["id"]: e for e in events if e["type"] == "flow_end"}
dns = [e for e in events if e["type"] == "dns"]
alerts = [e for e in events if e["type"] == "alert"]
stats = [e for e in events if e["type"] == "stats"]

def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + "events:" + name + ("" if ok else f" :: {detail}"))

check("engine-started", any(e["type"] == "engine" and e["state"] == "started" for e in events))
check("every-flow-ends", set(flows) <= set(ends), sorted(set(flows) - set(ends))[:10])
check("dns-logged", any(d["qname"] == "example.com" and d["verdict"] == "allow" and d["answers"] for d in dns))
check("dns-sinkhole-logged", any(d["qname"] == "ads.vigil-test.example" and d["verdict"] == "block" for d in dns))
check("dns-tcp-logged", any(d["transport"] == "tcp" for d in dns))
check("hardcoded-dns-seen", any(d["server"].startswith("9.9.9.9") for d in dns))
check("hardcoded-dns-alert", any(a["kind"] == "hardcoded_dns" for a in alerts))
quic = [f for f in flows.values() if f.get("domain_source") == "quic"]
sni = [f for f in flows.values() if f.get("domain_source") == "sni" and f["domain"] == "example.com"]
check("sni-extracted", bool(sni), "no example.com sni flow")
check("ja4-present", all(f.get("ja4", "").startswith("t1") for f in sni), [f.get("ja4") for f in sni])
check("https-bytes-counted", any(ends[f["id"]]["rx"] > 200 for f in sni if f["id"] in ends))
check("sni-block", any(f["domain"] == "blocked-sni.vigil-test.example" and f["verdict"] == "block" and f["domain_source"] == "sni" for f in flows.values()))
check("http-host-block", any(f["domain"] == "blocked-sni.vigil-test.example" and f["verdict"] == "block" and f["domain_source"] == "http" for f in flows.values()))
check("ip-block", any(f["dst_ip"] == "192.0.2.10" and f["verdict"] == "block" for f in flows.values()))
check("http-plaintext-tag", any("plaintext_http" in f["tags"] and f["domain"] == "example.com" for f in flows.values()))
check("dns-attribution", any(f["domain_source"] == "dns" and f["domain"] == "example.com" and f["dst_port"] == 443 for f in flows.values()))
check("quic-allowed-relayed", any(f["domain"] == "www.cloudflare.com" and f["verdict"] == "allow" and ends.get(f["id"], {}).get("rx", 0) > 0 for f in quic), quic)
check("refused-reported", any("refused" in (ends.get(i, {}).get("error") or "").lower() for i in flows))
check("beacon-alert", any(a["kind"] == "beacon" and a["target"] == "example.net" for a in alerts), alerts)
dl = [ends[f["id"]] for f in flows.values() if f["domain"] == "speed.cloudflare.com" and f["id"] in ends]
check("download-bytes", any(e["rx"] >= 1048576 for e in dl), [(e["tx"], e["rx"]) for e in dl])
check("upload-bytes", any(e["tx"] >= 524288 for e in dl), [(e["tx"], e["rx"]) for e in dl])
check("quic-sni-extracted", any(f["domain"] == "quic-probe.vigil-test.example" for f in quic), quic)
check("quic-threat-blocked", any(f["verdict"] == "block" for f in quic))
check("threat-alert", any(a["kind"] == "threat_domain" and a["severity"] == "high" for a in alerts), alerts)
check("stats-emitted", len(stats) >= 1 and stats[-1]["packets_out"] > 0)
check("dns-tcp-hardcoded-inspected", any(d["server"].startswith("9.9.9.9") and d["transport"] == "tcp" for d in dns), [d["server"] for d in dns])
rst = [f for f in flows.values() if f["dst_port"] == 18765]
check("upstream-reset-flow-reported", any("reset" in (ends.get(f["id"], {}).get("error") or "").lower() for f in rst), [(f["id"], ends.get(f["id"])) for f in rst])
check("engine-stopped", any(e["type"] == "engine" and e["state"] == "stopped" for e in events))
check("connect-error-reported",any(ends.get(i, {}).get("error", "") and "connect" in ends[i]["error"] for i in flows))
