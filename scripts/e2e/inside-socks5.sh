#!/usr/bin/env bash
# Runs inside the unprivileged network namespace for the SOCKS5 stage (see
# upstream-socks5.sh), in phases synchronised with the host side.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
sock="$1"; results="$2"; work="$3"
cli="$here/../../core/target/debug/vigil-cli"
python3 "$here/tunhelper.py" tun0 "$sock" || exit 1
ip link set lo up
ip addr add 10.111.222.1/24 dev tun0
ip -6 addr add fd76:6967:696c::1/64 dev tun0 nodad
ip link set tun0 up mtu 1500
ip route add default dev tun0
ip -6 route add default dev tun0
echo "nameserver 10.111.222.2" > "$work/resolv.conf"
mount --bind "$work/resolv.conf" /etc/resolv.conf
check() { # name, command...
  local name="s5-$1"; shift
  if out="$("$@" 2>&1)"; then echo "PASS $name" | tee -a "$results"
  else echo "FAIL $name :: $(echo "$out" | tail -n 3 | tr '\n' ' ')" | tee -a "$results"; fi
}
neg() { ! "$@"; }
wait_for() { for _ in $(seq 1200); do [ -e "$1" ] && return 0; sleep 0.1; done; return 1; }

# Phase 1: everything through the proxy.
ip=$(dig +short +time=5 +tries=2 example.com A @10.111.222.2 | grep -E "^[0-9.]+$" | head -n1)
check "dns-resolves"       bash -c 'dig +short +time=5 +tries=2 example.com A @10.111.222.2 | grep -Eq "^[0-9.]+$"'
check "https"              curl -sS -o /dev/null --max-time 20 https://example.com/
check "http"               curl -sS -o /dev/null --max-time 20 http://example.com/
check "hardcoded-dns"      bash -c 'dig +short +time=5 +tries=2 example.org A @9.9.9.9 | grep -Eq "^[0-9.]+$"'
check "quic-over-udp-associate" bash -c '"$0" quic-probe 1.1.1.1:443 www.cloudflare.com | grep -q "^reply"' "$cli"
touch "$work/phase1.done"

# Phase 2: send_domain.
wait_for "$work/phase2.go"
check "https-send-domain"  curl -sS -o /dev/null --max-time 20 https://example.com/
touch "$work/phase2.done"

# Phase 3: the proxy is gone; nothing may leak around it.
wait_for "$work/phase3.go"

check "fail-closed-https"  neg curl -sS -o /dev/null --max-time 8 --resolve "example.com:443:${ip:-192.0.2.1}" https://example.com/
check "fail-closed-dns"    bash -c 'dig +time=8 +tries=1 example.net A @10.111.222.2 | grep -q "status: SERVFAIL"'
check "fail-closed-udp"    bash -c '"$0" quic-probe 1.1.1.1:443 www.cloudflare.com | grep -q "no reply"' "$cli"
touch "$work/phase3.done"
