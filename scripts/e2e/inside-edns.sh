#!/usr/bin/env bash
# Runs inside the unprivileged network namespace for the encrypted upstream
# DNS phases of e2e-netns.sh. Usage: inside-edns.sh SOCK RESULTS PHASE
set -u
here="$(cd "$(dirname "$0")" && pwd)"
sock="$1"; results="$2"; phase="$3"
python3 "$here/tunhelper.py" tun0 "$sock" || exit 1
ip link set lo up
ip addr add 10.111.222.1/24 dev tun0
ip -6 addr add fd76:6967:696c::1/64 dev tun0 nodad
ip link set tun0 up mtu 1500
ip route add default dev tun0
ip -6 route add default dev tun0

check() { # name, command...
  local name="$1"; shift
  if out="$("$@" 2>&1)"; then echo "PASS $phase:$name" | tee -a "$results";
  else echo "FAIL $phase:$name :: $(echo "$out" | tail -n 3 | tr '\n' ' ')" | tee -a "$results"; fi
}
dig1() { dig +time=4 +tries=1 "$@" @10.111.222.2; }

case "$phase" in
  local-dot|local-doh)
    check "udp-answer"      bash -c '[ "$(dig +short +time=4 +tries=1 a.vigil.test A @10.111.222.2)" = 192.0.2.53 ]'
    check "tcp-answer"      bash -c '[ "$(dig +tcp +short +time=4 +tries=1 b.vigil.test A @10.111.222.2)" = 192.0.2.53 ]'
    check "burst"           bash -c 'for i in $(seq 1 20); do dig +short +time=4 +tries=1 n$i.vigil.test A @10.111.222.2 & done | grep -c 192.0.2.53 | grep -qx 20'
    # 1.5 KB answer: a UDP client without EDNS must see TC ...
    check "udp-truncated"   bash -c 'dig +noedns +ignore +time=4 +tries=1 big.vigil.test TXT @10.111.222.2 | grep -q "flags:.* tc"'
    # ... and dig's automatic TCP retry gets the whole answer.
    check "tc-tcp-retry"    bash -c 'dig +noedns +time=4 +tries=1 big.vigil.test TXT @10.111.222.2 | grep -q "ANSWER: 1,"'
    check "sinkhole-intact" bash -c '[ "$(dig +short +time=4 +tries=1 ads.vigil-test.example A @10.111.222.2)" = 0.0.0.0 ]'
    ;;
  fail-closed)
    check "servfail"        bash -c 'dig +time=4 +tries=1 c.vigil.test A @10.111.222.2 | grep -q "status: SERVFAIL"'
    check "sinkhole-intact" bash -c '[ "$(dig +short +time=4 +tries=1 ads.vigil-test.example A @10.111.222.2)" = 0.0.0.0 ]'
    ;;
  fallback)
    check "plain-answer"    bash -c '[ "$(dig +short +time=9 +tries=1 d.vigil.test A @10.111.222.2)" = 192.0.2.99 ]'
    ;;
  live-dot|live-doh)
    check "resolves"        bash -c 'dig +short +time=5 +tries=1 example.com A @10.111.222.2 | grep -Eq "^[0-9.]+$"'
    check "resolves-aaaa"   bash -c 'dig +short +time=5 +tries=1 example.com AAAA @10.111.222.2 | grep -q ":"'
    ;;
esac
