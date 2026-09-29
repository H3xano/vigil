#!/usr/bin/env bash
# Runs inside the unprivileged network namespace for the per-app rules stage
# (see e2e-netns.sh). vigil-cli attributes every connection to UID 10123,
# which is blocked on Wi-Fi and has a domain rule of its own. The device
# state is switched by rewriting the state file and sending SIGUSR1 to the
# CLI ($VIGIL_CLI_PID), as the app does with nativeSetDeviceState.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
sock="$1"; results="$2"; state="$3"; port="$4"
python3 "$here/tunhelper.py" tun0 "$sock" || exit 1
ip link set lo up
ip addr add 10.111.222.1/24 dev tun0
ip link set tun0 up mtu 1500
ip route add default dev tun0

check() { # name, command...
  local name="$1"; shift
  if out="$("$@" 2>&1)"; then echo "PASS $name" | tee -a "$results";
  else echo "FAIL $name :: $(echo "$out" | tail -n 3 | tr '\n' ' ')" | tee -a "$results"; fi
}
retry() { # command...: up to 3 attempts, for checks that need a real internet host
  local i; for i in 1 2 3; do "$@" && return 0; [ $i -lt 3 ] && sleep 2; done; return 1
}
neg() { ! "$@"; }
set_state() {
  echo "$1" > "$state"
  kill -USR1 "$VIGIL_CLI_PID"
  sleep 0.5
}
# Connects to the host's sink server (it reads and never answers), sends a
# line, then waits: prints "reset" if the connection is reset, "eof" on an
# orderly close, "open" if it is still open after $1 seconds.
hold() {
  python3 - "$VIGIL_HOST_IP" "$port" "$1" <<'PY'
import socket, sys
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5)
s.sendall(b"hello\n")
s.settimeout(float(sys.argv[3]))
try:
    print("eof" if s.recv(100) == b"" else "data")
except ConnectionResetError:
    print("reset")
except socket.timeout:
    print("open")
PY
}
export -f hold
export port

# On mobile data: nothing is blocked but the app's own domain rule.
check "apprules-dns-app-domain-rule" bash -c '[ "$(dig +short +time=3 +tries=1 perapp.vigil-test.example A @10.111.222.2)" = "0.0.0.0" ]'
check "apprules-dns-ttl-zero"        bash -c 'dig +noall +answer +time=3 +tries=1 perapp.vigil-test.example A @10.111.222.2 | awk "{print \$2}" | grep -qx 0'
check "apprules-dns-resolves"        retry bash -c 'dig +short +time=3 +tries=2 example.com A @10.111.222.2 | grep -Eq "^[0-9.]+$"'
check "apprules-connect-allowed"     bash -c "[ \"\$(hold 1)\" = open ]"

# An open TCP connection and a UDP flow, then the device joins Wi-Fi.
hold 6 > "$state.hold" &
holder=$!
python3 -c 'import socket, sys; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", (sys.argv[1], 18799))' "$VIGIL_HOST_IP"
sleep 1
set_state '{"network":"wifi","screen_on":true,"foreground_uids":null}'
wait $holder
check "apprules-open-connection-reset" bash -c "grep -qx reset '$state.hold'"
check "apprules-new-connection-refused" bash -c "curl -sS --max-time 5 -o /dev/null http://\$VIGIL_HOST_IP:$port/ 2>&1 | grep -Eqi 'reset|refused|connect to server'"
check "apprules-dns-sinkholed-on-wifi"  bash -c '[ "$(dig +short +time=3 +tries=1 example.com A @10.111.222.2)" = "0.0.0.0" ]'

# Back on mobile data: allowed again, at once.
set_state '{"network":"cellular","screen_on":true,"foreground_uids":null}'
check "apprules-allowed-again"       bash -c "[ \"\$(hold 1)\" = open ]"
check "apprules-dns-resolves-again"  retry bash -c 'dig +short +time=3 +tries=2 example.com A @10.111.222.2 | grep -Eq "^[0-9.]+$"'
