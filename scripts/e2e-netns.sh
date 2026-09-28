#!/usr/bin/env bash
# End-to-end test of the vigil engine on Linux without root.
#
# An unprivileged user+network namespace gets a TUN device whose descriptor is
# passed to vigil-cli running in the *host* namespace. Every packet generated
# by dig/curl inside the namespace therefore traverses the real engine (TCP
# stack, UDP NAT, DNS, policy) and is relayed to the internet over ordinary
# host sockets. The emitted events are then checked.
#
# Further stages exercise the upstream paths: a local SOCKS5 proxy
# (scripts/e2e/upstream-socks5.sh) and a kernel WireGuard peer in a nested
# namespace (scripts/e2e/upstream-wireguard.sh). E2E_STAGES selects stages
# (default "direct socks5 wireguard").
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'kill ${cli_pid:-} ${rst_pid:-} 2>/dev/null || true; rm -rf "$work"' EXIT
export PATH="$HOME/.cargo/bin:$PATH"
(cd "$root/core" && cargo build -q -p vigil-cli)
cli="$root/core/target/debug/vigil-cli"
stages="${E2E_STAGES:-direct socks5 wireguard}"
results="$work/results.txt"; : > "$results"

if [[ " $stages " == *" direct "* ]]; then
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

unshare -rnm bash "$root/scripts/e2e/inside.sh" "$sock" "$results" || true
sleep 2
kill -INT $cli_pid; wait $cli_pid || true
unset cli_pid

python3 "$root/scripts/e2e/check_events.py" "$work/events.jsonl" | tee -a "$results"
cp "$work/events.jsonl" "$root/scripts/e2e/last-events.jsonl"
fi

if [[ " $stages " == *" socks5 "* ]]; then
  echo "--- upstream: socks5"
  mkdir -p "$work/s5"
  bash "$root/scripts/e2e/upstream-socks5.sh" "$root" "$work/s5" "$results" || echo "FAIL s5-stage :: exited $?" | tee -a "$results"
fi

if [[ " $stages " == *" wireguard "* ]]; then
  echo "--- upstream: wireguard"
  mkdir -p "$work/wg"
  unshare -rnm bash "$root/scripts/e2e/upstream-wireguard.sh" "$root" "$work/wg" "$results" || echo "FAIL wg-stage :: exited $?" | tee -a "$results"
fi

echo "---"
fails=$(grep -c '^FAIL' "$results" || true)
passes=$(grep -c '^PASS' "$results" || true)
skips=$(grep -c '^SKIP' "$results" || true)
echo "e2e: $passes passed, $fails failed, $skips skipped"
[ "$fails" -eq 0 ]
