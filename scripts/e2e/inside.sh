#!/usr/bin/env bash
# Runs inside the unprivileged network namespace (see e2e-netns.sh).
set -u
here="$(cd "$(dirname "$0")" && pwd)"
sock="$1"; results="$2"
python3 "$here/tunhelper.py" tun0 "$sock" || exit 1
ip link set lo up
ip addr add 10.111.222.1/24 dev tun0
ip -6 addr add fd76:6967:696c::1/64 dev tun0 nodad
ip link set tun0 up mtu 1500
ip route add default dev tun0
ip -6 route add default dev tun0
echo "nameserver 10.111.222.2" > "$here/.resolv.conf"
mount --bind "$here/.resolv.conf" /etc/resolv.conf

pass=0; fail=0
check() { # name, command...
  local name="$1"; shift
  if out="$("$@" 2>&1)"; then echo "PASS $name" | tee -a "$results"; pass=$((pass+1));
  else echo "FAIL $name :: $(echo "$out" | tail -n 3 | tr '\n' ' ')" | tee -a "$results"; fail=$((fail+1)); fi
}
neg() { ! "$@"; }

check "dns-udp-resolves"       bash -c 'dig +short +time=3 +tries=1 example.com A @10.111.222.2 | grep -Eq "^[0-9.]+$"'
check "dns-tcp-resolves"       bash -c 'dig +tcp +short +time=3 +tries=1 example.com A @10.111.222.2 | grep -Eq "^[0-9.]+$"'
check "dns-hardcoded-server"   bash -c 'dig +short +time=3 +tries=1 example.org A @9.9.9.9 | grep -Eq "^[0-9.]+$"'
check "dns-sinkhole-null"      bash -c '[ "$(dig +short +time=3 +tries=1 ads.vigil-test.example A @10.111.222.2)" = "0.0.0.0" ]'
check "dns-sinkhole-aaaa"      bash -c '[ "$(dig +short +time=3 +tries=1 ads.vigil-test.example AAAA @10.111.222.2)" = "::" ]'
check "https-via-tunnel"       curl -sS -o /dev/null --max-time 15 -w '%{http_code}' https://example.com/
check "http-via-tunnel"        curl -sS -o /dev/null --max-time 15 http://example.com/
ip=$(dig +short example.com A @10.111.222.2 | head -n1)
check "sni-block-resets"       neg curl -sS -o /dev/null --max-time 10 --resolve "blocked-sni.vigil-test.example:443:$ip" https://blocked-sni.vigil-test.example/
check "http-host-block"        neg curl -sS -o /dev/null --max-time 10 -H 'Host: blocked-sni.vigil-test.example' "http://$ip/"
check "ip-feed-block"          neg curl -sS -o /dev/null --max-time 10 http://192.0.2.10/
check "sni-block-is-reset"     bash -c 'curl -sS -o /dev/null --max-time 10 --resolve "blocked-sni.vigil-test.example:443:$0" https://blocked-sni.vigil-test.example/ 2>&1 | grep -qi "reset"' "$ip"
check "tcp-refused-faithful"   bash -c 'curl -sS --max-time 10 -o /dev/null "http://$VIGIL_HOST_IP:1/" 2>&1 | grep -Eqi "refused|couldn.t connect to server"'
# The server resets right after accepting: the app must see a reset (a
# refused connect or a failed read), never an orderly EOF.
check "upstream-reset-faithful" bash -c 'exec 3<>/dev/tcp/$VIGIL_HOST_IP/$VIGIL_RST_PORT || exit 0; sleep 1; ! cat <&3 >/dev/null 2>&1'
check "dns-tcp-hardcoded"      bash -c 'dig +tcp +short +time=3 +tries=1 example.org A @9.9.9.9 | grep -Eq "^[0-9.]+$"'
check "download-1mb-integrity" bash -c 'curl -sS --max-time 60 https://speed.cloudflare.com/__down?bytes=1048576 | wc -c | grep -qx 1048576'
check "upload-512kb"           bash -c 'head -c 524288 /dev/urandom | curl -sS --max-time 60 -o /dev/null -w "%{http_code}" --data-binary @- https://speed.cloudflare.com/__up | grep -q 200'
check "quic-blocked-no-reply"  bash -c '"$0" quic-probe 1.1.1.1:443 quic-probe.vigil-test.example | grep -q "no reply"' "$here/../../core/target/debug/vigil-cli"
check "quic-allowed-reply"     bash -c '"$0" quic-probe 1.1.1.1:443 www.cloudflare.com | grep -q "^reply"' "$here/../../core/target/debug/vigil-cli"
check "dns-attributed-raw-tcp" bash -c 'exec 3<>/dev/tcp/example.com/443; sleep 4; exec 3>&-'
check "beacon-series"          bash -c 'for i in 1 2 3 4 5 6; do curl -s -o /dev/null --max-time 5 http://example.net/; sleep 2; done'
check "ipv6-dns-answer"        bash -c 'dig +short +time=3 +tries=1 example.com AAAA @10.111.222.2 | grep -q ":"'
echo "inside: $pass passed, $fail failed"
