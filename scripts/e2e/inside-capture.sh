#!/usr/bin/env bash
# Runs inside the unprivileged network namespace for the packet capture
# stage (see e2e-netns.sh): a few DNS lookups and an HTTP request whose
# packets must appear in the PCAPng export and the PCAP-over-IP stream.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
sock="$1"; results="$2"; ready="$3"
python3 "$here/tunhelper.py" tun0 "$sock" || exit 1
ip link set lo up
ip addr add 10.111.222.1/24 dev tun0
ip link set tun0 up mtu 1500
ip route add default dev tun0

# Wait until the PCAP-over-IP client on the host is connected, so the
# stream sees every packet below.
for _ in $(seq 100); do [ -f "$ready" ] && break; sleep 0.1; done
[ -f "$ready" ] || echo "FAIL capture-stream-connected :: no client after 10 s" | tee -a "$results"

check() { # name, command...
  local name="$1"; shift
  if out="$("$@" 2>&1)"; then echo "PASS $name" | tee -a "$results"
  else echo "FAIL $name :: $(echo "$out" | tail -n 3 | tr '\n' ' ')" | tee -a "$results"; fi
}
# Only local servers: the DNS query needs an answer of any kind (the
# virtual resolver answers even when the upstream fails), the HTTP request
# goes to a server on the host.
check "capture-dns-lookup" bash -c 'dig +time=3 +tries=1 capture-probe.example.com A @10.111.222.2 | grep -q "status:"'
check "capture-http-request" curl -sS -o /dev/null --max-time 15 -A vigil-capture-e2e "http://$VIGIL_HOST_IP:$VIGIL_CAPTURE_HTTP_PORT/"
sleep 1
