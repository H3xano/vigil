#!/usr/bin/env bash
# WireGuard upstream e2e stage. Runs as "root" of a fresh user+net+mount
# namespace (unshare -rnm), which plays the device's underlying network:
#
#   netns "app": tun0 ──fd──► vigil-cli (this namespace) ──UDP──► netns "srv"
#                                                        veth 10.99.0.1 ↔ 10.99.0.2
#   netns "srv": kernel wg0 10.200.0.1/24 + fd00:200::1/64, and services that
#                log the client address (tunnel: 10.200.0.2, leak: 10.99.0.1).
#
# A direct route to the far side exists on purpose, so a leak would succeed
# and show up in the services' log.
# usage: upstream-wireguard.sh ROOT WORK RESULTS
set -u
root="$1"; work="$2"; results="$3"
here="$root/scripts/e2e"
cli="$root/core/target/debug/vigil-cli"
A="ip netns exec app"
check() { # name, command...
  local name="wg-$1"; shift
  if out="$("$@" 2>&1)"; then echo "PASS $name" | tee -a "$results"
  else echo "FAIL $name :: $(echo "$out" | tail -n 3 | tr '\n' ' ')" | tee -a "$results"; fi
}
neg() { ! "$@"; }
svclog="$work/wg-services.log"; : > "$svclog"

mount -t tmpfs tmpfs /run && mkdir -p /run/netns || { echo "FAIL wg-setup :: no /run/netns" | tee -a "$results"; exit 0; }
ip link set lo up
ip netns add srv && ip netns add app
ip link add veth0 type veth peer name veth1 netns srv
ip addr add 10.99.0.1/24 dev veth0 && ip link set veth0 up
ip -n srv addr add 10.99.0.2/24 dev veth1 && ip -n srv link set veth1 up && ip -n srv link set lo up
ip route add 10.200.0.0/24 via 10.99.0.2
if ! ip -n srv link add wg0 type wireguard 2>/dev/null; then
  echo "SKIP wg-* :: kernel WireGuard links unavailable in an unprivileged namespace" | tee -a "$results"
  exit 0
fi
read -r vpriv vpub < <("$cli" wg-keypair)
read -r spriv spub < <("$cli" wg-keypair)
ip netns exec srv python3 "$here/wgconf.py" wg0 "$spriv" 51820 "$vpub" 10.200.0.2/32,fd00:200::2/128 \
  || { echo "FAIL wg-setup :: wgconf" | tee -a "$results"; exit 0; }
ip -n srv addr add 10.200.0.1/24 dev wg0
ip -n srv addr add fd00:200::1/64 dev wg0 nodad
ip -n srv link set wg0 up
ip netns exec srv python3 "$here/tunnel_services.py" 10.200.0.1 "$svclog" &
svc=$!

write_config() { # fail_closed network_id
  cat > "$work/wg.json" <<JSON
{"stats_interval_ms": 1000, "tcp_connect_timeout_ms": 4000, "upstream_dns": ["10.200.0.1:53"],
 "upstream": {"mode": "wireguard", "fail_closed": $1, "network_id": "$2",
   "wireguard": {"private_key": "$vpriv", "peer_public_key": "$spub", "endpoint": "10.99.0.2:51820",
     "addresses": ["10.200.0.2/32", "fd00:200::2/128"], "mtu": 1420}}}
JSON
}
write_config true net-1
"$cli" run --fd-socket "$work/wg.sock" --config "$work/wg.json" > "$work/wg-events.jsonl" 2> "$work/wg-cli.log" &
cli_pid=$!
$A python3 "$here/tunhelper.py" tun0 "$work/wg.sock" || { echo "FAIL wg-setup :: tun" | tee -a "$results"; kill $cli_pid $svc; exit 0; }
$A ip link set lo up
$A ip addr add 10.111.222.1/24 dev tun0
$A ip -6 addr add fd76:6967:696c::1/64 dev tun0 nodad
$A ip link set tun0 up mtu 1500
$A ip route add default dev tun0
$A ip -6 route add default dev tun0
for _ in $(seq 50); do grep -q READY "$svclog" && break; sleep 0.1; done

udp_echo='import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b"ping",("10.200.0.1",7777)); d=s.recv(100); sys.exit(d!=b"ping")'
check "http-v4-through-tunnel"  bash -c "$A curl -sS --max-time 10 http://10.200.0.1:8080/v4 | grep -q tunnel"
check "http-v6-through-tunnel"  bash -c "$A curl -g -sS --max-time 10 'http://[fd00:200::1]:8080/v6' | grep -q tunnel"
check "dns-through-tunnel"      bash -c "[ \"\$($A dig +short +time=3 +tries=1 wg.test A @10.111.222.2)\" = 10.200.0.1 ]"
check "udp-through-tunnel"      $A python3 -c "$udp_echo"
check "tunnel-source-address"   grep -q '^HTTP 10.200.0.2 /v4' "$svclog"
check "v6-tunnel-source-address" grep -q '^HTTP fd00:200::2 /v6' "$svclog"
check "dns-query-seen-by-peer"  grep -q '^DNS wg.test' "$svclog"
check "udp-seen-by-peer"        grep -q '^ECHO 10.200.0.2' "$svclog"
# A destination the host could also reach directly: must still use the tunnel.
check "no-leak-while-up"        bash -c "$A curl -sS --max-time 10 -o /dev/null http://10.99.0.2:8080/leak-up && grep -q '^HTTP 10.200.0.2 /leak-up' '$svclog'"
check "kernel-peer-handshake"   bash -c "ip netns exec srv python3 '$here/wgconf.py' --show wg0 | grep -qv 'handshake=0 '"
# Network change: the socket is re-created, the session survives.
write_config true net-2; kill -HUP $cli_pid; sleep 1
check "roaming-keeps-working"   bash -c "$A curl -sS --max-time 10 http://10.200.0.1:8080/roamed | grep -q tunnel"

# The peer disappears.
ip -n srv link del wg0
check "fail-closed-tcp"         neg $A curl -sS --max-time 8 -o /dev/null http://10.99.0.2:8080/leak-down
check "fail-closed-no-leak"     neg grep -q 'leak-down' "$svclog"
check "fail-closed-dns"         bash -c "$A dig +time=8 +tries=1 other.test A @10.111.222.2 | grep -q 'status: SERVFAIL'"
# Fail-open: once the tunnel is judged down (handshakes failing ~25 s after
# traffic stopped being answered), connections go direct.
write_config false net-2; kill -HUP $cli_pid
opened=""
for i in $(seq 20); do
  if $A curl -sS --max-time 4 -o /dev/null "http://10.99.0.2:8080/open-$i" 2>/dev/null; then opened=$i; break; fi
  sleep 1
done
check "fail-open-goes-direct"   bash -c "[ -n '$opened' ] && grep -q '^HTTP 10.99.0.1 /open-$opened' '$svclog'"

kill -INT $cli_pid; wait $cli_pid 2>/dev/null
kill $svc 2>/dev/null
python3 - "$work/wg-events.jsonl" <<'PY' | tee -a "$results"
import json, sys
ev = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
flows = [e for e in ev if e["type"] == "flow"]
stats = [e["upstream"] for e in ev if e["type"] == "stats"]
def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + "wg-events:" + name + ("" if ok else f" :: {detail}"))
tun = [f for f in flows if f["dst_ip"] == "10.200.0.1"]
check("flows-via-wireguard", tun and all(f.get("via") == "wireguard" for f in tun), [(f["dst_ip"], f.get("via")) for f in flows][:10])
check("stats-up-with-handshake", any(s["mode"] == "wireguard" and s["state"] == "up" and s["handshake_age_s"] is not None and s["rx_bytes"] > 0 for s in stats), stats[:3])
check("stats-down-after-peer-loss", any(s["state"] == "down" for s in stats), [s["state"] for s in stats])
check("fail-open-flow-via-direct", any(f["dst_ip"] == "10.99.0.2" and f.get("via") == "direct" for f in flows), [(f["dst_ip"], f.get("via")) for f in flows if f["dst_ip"] == "10.99.0.2"])
PY
cp "$work/wg-events.jsonl" "$here/last-wg-events.jsonl" 2>/dev/null || true
