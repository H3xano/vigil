#!/usr/bin/env bash
# Runs inside the unprivileged network namespace for the in-flow beaconing
# stage (see e2e-netns.sh): long-lived connections to beacon_server.py on
# the host, through the engine.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
sock="$1"; results="$2"; port="$3"
python3 "$here/tunhelper.py" tun0 "$sock" || exit 1
ip link set lo up
ip addr add 10.111.222.1/24 dev tun0
ip link set tun0 up mtu 1500
ip route add default dev tun0

if out="$(python3 "$here/beacon_client.py" "$VIGIL_HOST_IP" "$port" 24 2>&1)"; then
  echo "PASS beacon-connections :: $out" | tee -a "$results"
else
  echo "FAIL beacon-connections :: $(echo "$out" | tail -n 3 | tr '\n' ' ')" | tee -a "$results"
fi
