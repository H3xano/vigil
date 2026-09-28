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
trap 'kill ${cli_pid:-0} ${rst_pid:-0} 2>/dev/null || true; rm -rf "$work"' EXIT
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
# JA4 feed: the exact fingerprint of this machine's curl with --tls-max 1.2
# (captured locally, so it differs from plain curl's) and of the ClientHello
# that `vigil-cli quic-probe` sends. Block mode is on; allowlisted names are
# exempt, which exercises the alert-only path in the same run.
python3 "$root/scripts/e2e/capture_hello.py" 18766 "$work/hello12.bin" -- \
  curl -s --max-time 5 --tls-max 1.2 --resolve ja4-capture.vigil-test.example:18766:127.0.0.1 \
  https://ja4-capture.vigil-test.example:18766/
ja4_curl12="$("$cli" ja4 "$work/hello12.bin")"
ja4_quic="$("$cli" ja4 --quic-probe)"
cat > "$work/ja4.txt" <<FEED
# vigil e2e JA4 feed
$ja4_curl12  curl TLS1.2 (e2e)
$ja4_quic # vigil quic-probe (e2e)
FEED
echo "e2e: JA4 feed: $ja4_curl12 $ja4_quic"
echo '{"stats_interval_ms": 1000, "beacon": {"min_interval_s": 1.0, "min_events": 5, "max_jitter": 0.25},
  "block_ja4_matches": true, "allow_domains": ["example.org", "www.cloudflare.com"]}' > "$work/config.json"
export VIGIL_HOST_IP="$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
# A server on the host that resets every connection (upstream-reset checks).
export VIGIL_RST_PORT=18765
python3 "$root/scripts/e2e/rst_server.py" "$VIGIL_HOST_IP" "$VIGIL_RST_PORT" &
rst_pid=$!

sock="$work/tun.sock"
"$cli" run --fd-socket "$sock" --config "$work/config.json" \
  --feed test:tracking:"$work/feed.txt" --feed threats:c2:"$work/threat.txt" \
  --feed ja4-e2e:ja4:"$work/ja4.txt" \
  > "$work/events.jsonl" 2> "$work/cli.log" &
cli_pid=$!

results="$work/results.txt"; : > "$results"
unshare -rnm bash "$root/scripts/e2e/inside.sh" "$sock" "$results" || true
sleep 2
kill -INT $cli_pid; wait $cli_pid || true

python3 "$root/scripts/e2e/check_events.py" "$work/events.jsonl" | tee -a "$results"
cp "$work/events.jsonl" "$root/scripts/e2e/last-events.jsonl"
echo "---"
fails=$(grep -c '^FAIL' "$results" || true)
passes=$(grep -c '^PASS' "$results" || true)
echo "e2e: $passes passed, $fails failed"
[ "$fails" -eq 0 ]
