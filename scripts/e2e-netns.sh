#!/usr/bin/env bash
# End-to-end test of the vigil engine on Linux without root.
#
# An unprivileged user+network namespace gets a TUN device whose descriptor is
# passed to vigil-cli running in the *host* namespace. Every packet generated
# by dig/curl inside the namespace therefore traverses the real engine (TCP
# stack, UDP NAT, DNS, policy) and is relayed to the internet over ordinary
# host sockets. The emitted events are then checked.
#
# Further stages exercise encrypted upstream DNS (DoT/DoH to local test
# servers and public presets) and the upstream paths: a local SOCKS5 proxy
# (scripts/e2e/upstream-socks5.sh) and a kernel WireGuard peer in a nested
# namespace (scripts/e2e/upstream-wireguard.sh), and packet capture (PCAPng
# export and PCAP-over-IP). E2E_STAGES selects stages
# (default "direct beacon capture edns socks5 wireguard").
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'kill ${cli_pid:-} ${beacon_pid:-} ${rst_pid:-} ${edns_pid:-} ${socks_pid:-} ${stream_pid:-} 2>/dev/null || true; rm -rf "$work"' EXIT
export PATH="$HOME/.cargo/bin:$PATH"
(cd "$root/core" && cargo build -q -p vigil-cli)
cli="$root/core/target/debug/vigil-cli"
stages="${E2E_STAGES:-direct beacon capture edns socks5 wireguard}"
results="$work/results.txt"; : > "$results"

cat > "$work/feed.txt" <<'FEED'
# vigil e2e test feed
ads.vigil-test.example
blocked-sni.vigil-test.example
192.0.2.0/24
FEED
# JA4 feed: the exact fingerprint of this machine's curl with --tls-max 1.2
# (captured locally, so it differs from plain curl's) and of the ClientHello
# that `vigil-cli quic-probe` sends. Block mode is on; allowlisted names are
# exempt, which exercises the alert-only path in the same run. The edns stage
# blocks the TLS 1.2 fingerprint with SOCKS5 send_domain (lazy connect).
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
sock="$work/tun.sock"

if [[ " $stages " == *" direct "* ]]; then
cat > "$work/threat.txt" <<'FEED'
quic-probe.vigil-test.example
FEED
# Tiny IP-to-ASN table (iptoasn.com TSV): the QUIC probes' 1.1.1.1, the
# blocked 192.0.2.0/24 (also reached through NAT64 by inside.sh) and an
# unrouted row.
printf '%s\t%s\t%s\t%s\t%s\n' \
  1.1.1.0 1.1.1.255 13335 US CLOUDFLARENET \
  192.0.2.0 192.0.2.255 64496 ZZ 'VIGIL-E2E Documentation AS' \
  198.18.0.0 198.19.255.255 0 None 'Not routed' > "$work/asn.tsv"
echo '{"stats_interval_ms": 1000, "beacon": {"min_interval_s": 1.0, "min_events": 5, "max_jitter": 0.25},
  "block_ja4_matches": true, "allow_domains": ["example.org", "www.cloudflare.com"]}' > "$work/config.json"
export VIGIL_HOST_IP="$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
# A server on the host that resets every connection (upstream-reset checks).
export VIGIL_RST_PORT=18765
python3 "$root/scripts/e2e/rst_server.py" "$VIGIL_HOST_IP" "$VIGIL_RST_PORT" &
rst_pid=$!

"$cli" run --fd-socket "$sock" --config "$work/config.json" \
  --feed test:tracking:"$work/feed.txt" --feed threats:c2:"$work/threat.txt" \
  --feed ja4-e2e:ja4:"$work/ja4.txt" --feed iptoasn:asn:"$work/asn.tsv" \
  > "$work/events.jsonl" 2> "$work/cli.log" &
cli_pid=$!

unshare -rnm bash "$root/scripts/e2e/inside.sh" "$sock" "$results" || true
sleep 2
kill -INT $cli_pid; wait $cli_pid || true
unset cli_pid

python3 "$root/scripts/e2e/check_events.py" "$work/events.jsonl" | tee -a "$results"
cp "$work/events.jsonl" "$root/scripts/e2e/last-events.jsonl"
fi

if [[ " $stages " == *" beacon "* ]]; then
echo "--- beaconing inside long-lived connections"
# Local servers on the host: a 2 s heartbeat inside one connection must raise
# an intra_flow beacon alert; a bulk upload and irregular chatter must not.
# Short test thresholds: 250 ms sampling, flows watched after 2 s, 1 s idle
# gap, no rate cap (so the burst logic itself rejects the bulk upload).
export VIGIL_HOST_IP="$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
beacon_port=18770
python3 "$root/scripts/e2e/beacon_server.py" "$VIGIL_HOST_IP" "$beacon_port" &
beacon_pid=$!
echo '{"stats_interval_ms": 250, "beacon": {"min_interval_s": 1.0, "min_events": 6, "max_jitter": 0.25,
  "flow_min_age_s": 2, "flow_idle_gap_s": 1.0, "flow_min_burst_bytes": 64, "flow_max_avg_bps": 1e12}}' > "$work/beacon.json"
rm -f "$sock"
"$cli" run --fd-socket "$sock" --config "$work/beacon.json" > "$work/beacon-events.jsonl" 2> "$work/beacon-cli.log" &
cli_pid=$!
unshare -rnm bash "$root/scripts/e2e/inside-beacon.sh" "$sock" "$results" "$beacon_port" || true
sleep 1
kill -INT $cli_pid; wait $cli_pid || true
kill $beacon_pid 2>/dev/null || true
unset cli_pid beacon_pid
python3 "$root/scripts/e2e/check_beacon.py" "$work/beacon-events.jsonl" "$beacon_port" | tee -a "$results"
fi

if [[ " $stages " == *" capture "* ]]; then
echo "--- packet capture (PCAPng export, PCAP-over-IP)"
# Capture on, with the PCAP-over-IP server on loopback (allowlisted). A
# client on the host records the stream; the CLI exports the ring as
# PCAPng when it stops. Both must hold the namespace's DNS and HTTP
# packets, the export with flow and direction annotations.
stream_port=18790
echo "{\"stats_interval_ms\": 500, \"capture\": {\"enabled\": true, \"buffer_bytes\": 4194304,
  \"stream\": {\"enabled\": true, \"port\": $stream_port, \"bind\": \"127.0.0.1\", \"allow\": [\"127.0.0.1\"]}}}" > "$work/capture.json"
rm -f "$sock" "$work/stream.ready"
"$cli" run --fd-socket "$sock" --config "$work/capture.json" --pcap-on-exit "$work/capture.pcapng" \
  > "$work/capture-events.jsonl" 2> "$work/capture-cli.log" &
cli_pid=$!
python3 "$root/scripts/e2e/pcap_stream_client.py" 127.0.0.1 "$stream_port" "$work/stream.pcap" "$work/stream.ready" &
stream_pid=$!
unshare -rnm bash "$root/scripts/e2e/inside-capture.sh" "$sock" "$results" "$work/stream.ready" || true
sleep 1
kill -INT $cli_pid; wait $cli_pid || true
wait $stream_pid || true
unset cli_pid stream_pid
python3 "$root/scripts/e2e/check_pcap.py" "$work/capture.pcapng" "$work/stream.pcap" "$work/capture-events.jsonl" \
  "$work/capture-cli.log" "$stream_port" | tee -a "$results"
fi

if [[ " $stages " == *" edns "* ]]; then
echo "--- encrypted upstream DNS"
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
# Combined: encrypted DNS and JA4 blocking with a SOCKS5 upstream (send_domain,
# so relayed connections are made lazily). DoT must reach the local server
# through the proxy; a JA4-blocked connection must never reach the proxy.
phase=socks5-dot
socks_log="$work/edns-socks.log"; : > "$socks_log"
python3 "$root/scripts/e2e/socks5_server.py" 127.0.0.1 18767 "$socks_log" &
socks_pid=$!
python3 "$root/scripts/e2e/edns_config.py" "$phase" "$testdata/ca.pem" 18853 18443 18053 18767 > "$work/edns.json"
: > "$hits"
rm -f "$sock"
"$cli" run --fd-socket "$sock" --config "$work/edns.json" --feed test:tracking:"$work/feed.txt" \
  --feed ja4-e2e:ja4:"$work/ja4.txt" > "$work/edns-events.jsonl" 2> "$work/edns-cli.log" &
cli_pid=$!
unshare -rnm bash "$root/scripts/e2e/inside-edns.sh" "$sock" "$results" "$phase" || true
sleep 1
kill -INT $cli_pid; wait $cli_pid || true
kill $socks_pid 2>/dev/null || true
python3 "$root/scripts/e2e/check_edns.py" "$work/edns-events.jsonl" "$phase" "$hits" "$socks_log" | tee -a "$results"
kill $edns_pid 2>/dev/null || true
unset cli_pid edns_pid socks_pid
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
