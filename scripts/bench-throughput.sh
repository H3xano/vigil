#!/usr/bin/env bash
# Measures download throughput through the release engine (netns + TUN)
# against a direct download from the host, and reports engine CPU time.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
(cd "$root/core" && cargo build -q --release -p vigil-cli)
cli="$root/core/target/release/vigil-cli"
bytes="${BYTES:-50000000}"
# Unset pids expand to nothing: `kill 0` would signal the whole process group.
work="$(mktemp -d)"; trap 'kill ${pid:-} ${srv:-} 2>/dev/null || true; rm -rf "$work"' EXIT
if [ "${LOCAL:-0}" = 1 ]; then
  # Serve a file from this host to measure the engine's own ceiling.
  host_ip="$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
  truncate -s "$bytes" "$work/blob"
  (cd "$work" && exec python3 -m http.server 8765 --bind "$host_ip" >/dev/null 2>&1) & srv=$!
  sleep 1
  url="http://$host_ip:8765/blob"
else
  url="https://speed.cloudflare.com/__down?bytes=$bytes"
fi

direct=$(LC_ALL=C curl -s -o /dev/null -w '%{speed_download}' "$url")
"$cli" run --fd-socket "$work/s" --no-stats > "$work/events.jsonl" 2>/dev/null &
pid=$!
tunneled=$(unshare -rnm bash -c '
  python3 "$1/scripts/e2e/tunhelper.py" tun0 "$2" && ip link set lo up &&
  ip addr add 10.111.222.1/24 dev tun0 && ip link set tun0 up mtu 1500 && ip route add default dev tun0 &&
  echo "nameserver 10.111.222.2" > "$3/resolv" && mount --bind "$3/resolv" /etc/resolv.conf &&
  LC_ALL=C curl -s -o /dev/null -w "%{speed_download}" "$4"' _ "$root" "$work/s" "$work" "$url")
cpu=$(ps -o times= -p $pid | tr -d ' ')
rss=$(ps -o rss= -p $pid | tr -d ' ')
kill -INT $pid; wait $pid || true
unset pid
LC_ALL=C awk -v d="$direct" -v t="$tunneled" -v c="$cpu" -v r="$rss" -v b="$bytes" 'BEGIN {
  printf "direct:    %7.1f Mbit/s\n", d*8/1e6
  printf "via vigil: %7.1f Mbit/s (%.0f%% of direct)\n", t*8/1e6, 100*t/d
  printf "engine CPU: %ss for %d MB, RSS %d MB\n", c, b/1e6, r/1024 }'
