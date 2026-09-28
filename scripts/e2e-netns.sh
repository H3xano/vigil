#!/usr/bin/env bash
# End-to-end test of the vigil engine on Linux without root.
#
# An unprivileged user+network namespace gets a TUN device whose descriptor is
# passed to vigil-cli running in the *host* namespace. Every packet generated
# by dig/curl inside the namespace therefore traverses the real engine (TCP
# stack, UDP NAT, DNS, policy) and is relayed to the internet over ordinary
# host sockets. The emitted events are then checked.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'kill ${cli_pid:-0} ${rst_pid:-0} ${edns_pid:-0} 2>/dev/null || true; rm -rf "$work"' EXIT
export PATH="$HOME/.cargo/bin:$PATH"
(cd "$root/core" && cargo build -q -p vigil-cli)
cli="$root/core/target/debug/vigil-cli"

cat > "$work/feed.txt" <<'FEED'
# vigil e2e test feed
ads.vigil-test.example
blocked-sni.vigil-test.example
192.0.2.0/24
FEED
cat > "$work/threat.txt" <<'FEED'
quic-probe.vigil-test.example
FEED
echo '{"stats_interval_ms": 1000, "beacon": {"min_interval_s": 1.0, "min_events": 5, "max_jitter": 0.25}}' > "$work/config.json"
export VIGIL_HOST_IP="$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
# A server on the host that resets every connection (upstream-reset checks).
export VIGIL_RST_PORT=18765
python3 "$root/scripts/e2e/rst_server.py" "$VIGIL_HOST_IP" "$VIGIL_RST_PORT" &
rst_pid=$!

sock="$work/tun.sock"
"$cli" run --fd-socket "$sock" --config "$work/config.json" \
  --feed test:tracking:"$work/feed.txt" --feed threats:c2:"$work/threat.txt" \
  > "$work/events.jsonl" 2> "$work/cli.log" &
cli_pid=$!

results="$work/results.txt"; : > "$results"
unshare -rnm bash "$root/scripts/e2e/inside.sh" "$sock" "$results" || true
sleep 2
kill -INT $cli_pid; wait $cli_pid || true

python3 "$root/scripts/e2e/check_events.py" "$work/events.jsonl" | tee -a "$results"
cp "$work/events.jsonl" "$root/scripts/e2e/last-events.jsonl"

# Encrypted upstream DNS: one engine run per phase, forwarding the virtual
# resolver's queries over DoT/DoH to local servers (test CA from
# core/vigil-core/testdata/edns) and to two public presets.
testdata="$root/core/vigil-core/testdata/edns"
hits="$work/plain-hits.txt"
python3 "$root/scripts/e2e/edns_server.py" "$testdata/server.pem" "$testdata/server.key" \
  18853 18443 18053 "$hits" &
edns_pid=$!
sleep 0.5
for phase in local-dot local-doh fail-closed fallback live-dot live-doh; do
  python3 "$root/scripts/e2e/edns_config.py" "$phase" "$testdata/ca.pem" 18853 18443 18053 > "$work/edns.json"
  : > "$hits"
  rm -f "$sock"
  "$cli" run --fd-socket "$sock" --config "$work/edns.json" --feed test:tracking:"$work/feed.txt" \
    > "$work/edns-events.jsonl" 2> "$work/edns-cli.log" &
  cli_pid=$!
  unshare -rnm bash "$root/scripts/e2e/inside-edns.sh" "$sock" "$results" "$phase" || true
  sleep 1
  kill -INT $cli_pid; wait $cli_pid || true
  python3 "$root/scripts/e2e/check_edns.py" "$work/edns-events.jsonl" "$phase" "$hits" | tee -a "$results"
done
kill $edns_pid 2>/dev/null || true
echo "---"
fails=$(grep -c '^FAIL' "$results" || true)
passes=$(grep -c '^PASS' "$results" || true)
echo "e2e: $passes passed, $fails failed"
[ "$fails" -eq 0 ]
