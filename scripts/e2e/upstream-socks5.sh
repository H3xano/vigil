#!/usr/bin/env bash
# SOCKS5 upstream e2e stage (host side). A local SOCKS5 server on loopback
# (with username/password) is vigil's only way out; a namespace behind the
# TUN runs checks in three phases, synchronised through files:
#   1. proxy up: HTTP(S), DNS (over TCP through the proxy), QUIC over UDP
#      ASSOCIATE all go through it;
#   2. send_domain on (config reloaded with SIGHUP): CONNECT by TLS SNI name;
#   3. proxy killed: fail closed (connections and DNS fail, nothing leaks).
# usage: upstream-socks5.sh ROOT WORK RESULTS
set -u
root="$1"; work="$2"; results="$3"
here="$root/scripts/e2e"
cli="$root/core/target/debug/vigil-cli"
port=18766
log="$work/socks.log"; : > "$log"
check() { # name, command...
  local name="s5-$1"; shift
  if out="$("$@" 2>&1)"; then echo "PASS $name" | tee -a "$results"
  else echo "FAIL $name :: $(echo "$out" | tail -n 3 | tr '\n' ' ')" | tee -a "$results"; fi
}
wait_for() { for _ in $(seq 1200); do [ -e "$1" ] && return 0; sleep 0.1; done; echo "timeout waiting for $1"; return 1; }

python3 "$here/socks5_server.py" 127.0.0.1 $port "$log" vigil e2e-secret &
proxy=$!
write_config() { # send_domain
  cat > "$work/s5.json" <<JSON
{"stats_interval_ms": 1000, "tcp_connect_timeout_ms": 10000,
 "upstream": {"mode": "socks5", "fail_closed": true,
   "socks5": {"server": "127.0.0.1:$port", "username": "vigil", "password": "e2e-secret", "send_domain": $1}}}
JSON
}
write_config false
"$cli" run --fd-socket "$work/s5.sock" --config "$work/s5.json" > "$work/s5-events.jsonl" 2> "$work/s5-cli.log" &
cli_pid=$!
unshare -rnm bash "$here/inside-socks5.sh" "$work/s5.sock" "$results" "$work" &
inside=$!

wait_for "$work/phase1.done"
check "proxy-authenticated"   grep -q '^AUTH vigil ok' "$log"
check "dns-over-tcp-via-proxy" grep -Eq '^CONNECT (1\.1\.1\.1|9\.9\.9\.9):53$' "$log"
check "https-via-proxy-by-ip" grep -Eq '^CONNECT [0-9.]+:443$' "$log"
check "udp-associate-used"    grep -q '^UDP 1.1.1.1:443' "$log"
sleep 1.5 # let a stats event capture phase 1 before the reload replaces the dialer
write_config true; kill -HUP $cli_pid; sleep 1; touch "$work/phase2.go"

wait_for "$work/phase2.done"
check "send-domain-connects-by-name" grep -q '^CONNECT example.com:443$' "$log"
kill $proxy; wait $proxy 2>/dev/null; touch "$work/phase3.go"

wait_for "$work/phase3.done"
wait $inside
kill -INT $cli_pid; wait $cli_pid 2>/dev/null
python3 - "$work/s5-events.jsonl" <<'PY' | tee -a "$results"
import json, sys
ev = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
flows = {e["id"]: e for e in ev if e["type"] == "flow"}
ends = {e["id"]: e for e in ev if e["type"] == "flow_end"}
stats = [e["upstream"] for e in ev if e["type"] == "stats"]
def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + "s5-events:" + name + ("" if ok else f" :: {detail}"))
relayed = [f for f in flows.values() if f["verdict"] == "allow"]
check("flows-via-socks5", relayed and all(f.get("via") == "socks5" for f in relayed), [(f["dst_ip"], f.get("via")) for f in relayed][:10])
check("stats-mode-and-udp", any(s["mode"] == "socks5" and s["state"] == "up" and s["udp"] == "supported" for s in stats), stats[:2])
check("stats-down-after-proxy-loss", any(s["state"] == "down" and "socks5 proxy" in (s["last_error"] or "") for s in stats), stats[-2:])
errs = [ends[i]["error"] or "" for i in flows if i in ends]
check("fail-closed-errors-name-proxy", any("socks5 proxy" in e for e in errs), errs[-5:])
check("every-flow-ends", set(flows) <= set(ends), sorted(set(flows) - set(ends))[:10])
PY
cp "$work/s5-events.jsonl" "$here/last-s5-events.jsonl" 2>/dev/null || true
