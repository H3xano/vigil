#!/usr/bin/env python3
"""Prints the engine config of an encrypted upstream DNS e2e phase.

Usage: edns_config.py PHASE CA_PEM_FILE DOT_PORT DOH_PORT PLAIN_PORT
"""
import json, sys

phase, ca_file = sys.argv[1], sys.argv[2]
dot_port, doh_port, plain_port = map(int, sys.argv[3:6])
ca = open(ca_file).read()

local_dot = {"host": "dns.vigil.test", "addrs": ["127.0.0.1"], "port": dot_port}
# A reachable server whose certificate does not cover the name: must fail.
wrong_name = {"host": "wrong.vigil.test", "addrs": ["127.0.0.1"], "port": dot_port}
edns = {
    "local-dot": {"mode": "dot", "servers": [local_dot]},
    "local-doh": {"mode": "doh", "servers": [
        {"url": f"https://dns.vigil.test:{doh_port}/dns-query", "addrs": ["127.0.0.1"]}]},
    "fail-closed": {"mode": "dot", "servers": [wrong_name]},
    "fallback": {"mode": "dot", "servers": [wrong_name], "fallback_plain": True},
    # Presets shipped by the app. Quad9 DoH only speaks HTTP/2.
    "live-dot": {"mode": "dot", "servers": [
        {"host": "dns.quad9.net", "addrs": ["9.9.9.9", "149.112.112.112"]}]},
    "live-doh": {"mode": "doh", "servers": [
        {"url": "https://dns.quad9.net/dns-query", "addrs": ["9.9.9.9", "149.112.112.112"]}]},
}[phase]
config = {"stats_interval_ms": 500, "encrypted_dns": edns}
if not phase.startswith("live-"):
    edns["extra_root_ca_pem"] = ca
    # The plain resolver records every query it gets (cleartext leak check).
    config["upstream_dns"] = [f"127.0.0.1:{plain_port}"]
print(json.dumps(config))
