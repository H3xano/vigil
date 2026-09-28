#!/usr/bin/env bash
# Measures throughput through the release engine (netns + TUN) and the
# engine's CPU time for it.
#
#   MODE=bulk (default)  one download of BYTES, compared with a direct one
#                        (LOCAL=1: from a server on this host; else Cloudflare)
#   MODE=tcp             N short HTTP requests, one connection each (CONC at once)
#   MODE=udp             N request/reply datagrams of SIZE bytes over CONC flows
#   MODE=dns             N DNS queries (unique names) to the virtual resolver
#   MODE=idle            a few connections, 4 of them left open, then SECS idle
#
# The small-packet modes always use servers on this host. Engine CPU is
# utime + stime of the engine process during the transfer only.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH" LC_ALL=C
(cd "$root/core" && cargo build -q --release -p vigil-cli)
cli="${VIGIL_CLI:-$root/core/target/release/vigil-cli}"
mode="${MODE:-bulk}"
bytes="${BYTES:-50000000}"
n="${N:-20000}"
conc="${CONC:-16}"
load="$root/scripts/e2e/benchload.py"
# Unset pids expand to nothing: `kill 0` would signal the whole process group.
work="$(mktemp -d)"; trap 'kill ${pid:-} ${srv:-} 2>/dev/null || true; [ -n "${KEEP:-}" ] && cp -r "$work" "$KEEP"; rm -rf "$work"' EXIT
host_ip="$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
engine_args=()
case "$mode" in
  bulk)
    if [ "${LOCAL:-0}" = 1 ]; then
      # Serve a file from this host to measure the engine's own ceiling.
      truncate -s "$bytes" "$work/blob"
      (cd "$work" && exec python3 -m http.server 8765 --bind "$host_ip" >/dev/null 2>&1) & srv=$!
      sleep 1
      url="http://$host_ip:8765/blob"
    else
      url="https://speed.cloudflare.com/__down?bytes=$bytes"
    fi
    direct=$(LC_ALL=C curl -s -o /dev/null -w '%{speed_download}' "$url")
    client=(env LC_ALL=C curl -s -o /dev/null -w "%{speed_download}" "$url") ;;
  tcp)
    python3 "$load" serve-tcp "$host_ip" 8766 "${SIZE:-1000}" & srv=$!
    client=(python3 "$load" tcp "$host_ip" 8766 "$n" "$conc") ;;
  udp)
    python3 "$load" serve-udp "$host_ip" 8767 & srv=$!
    client=(python3 "$load" udp "$host_ip" 8767 "$n" "$conc" "${SIZE:-100}") ;;
  dns)
    python3 "$load" serve-dns "$host_ip" 8768 & srv=$!
    engine_args=(--upstream "$host_ip:8768")
    client=(python3 "$load" dns 10.111.222.2 "$n" "$conc") ;;
  idle)
    python3 "$load" serve-tcp "$host_ip" 8766 1000 & srv=$!
    client=(python3 "$load" idle "$host_ip" 8766 "${SECS:-10}") ;;
  *) echo "unknown MODE $mode" >&2; exit 2 ;;
esac

[ -n "${STATS:-}" ] || engine_args+=(--no-stats)
"$cli" run --fd-socket "$work/s" "${engine_args[@]}" > "$work/events.jsonl" 2>/dev/null &
pid=$!
# utime + stime (clock ticks) and context switches of all engine threads.
cpu_ticks() { awk '{ print $14 + $15 }' "/proc/$pid/stat"; }
ctx() { cat /proc/"$pid"/task/*/status 2>/dev/null | awk '/ctxt_switches/ { s += $2 } END { print s + 0 }'; }
unshare -rnm bash -c '
  python3 "$1/scripts/e2e/tunhelper.py" tun0 "$2" && ip link set lo up &&
  ip addr add 10.111.222.1/24 dev tun0 && ip link set tun0 up mtu 1500 && ip route add default dev tun0 &&
  echo "nameserver 10.111.222.2" > "$3/resolv" && mount --bind "$3/resolv" /etc/resolv.conf &&
  touch "$3/ready" && while [ ! -e "$3/go" ]; do sleep 0.05; done && shift 3 && "$@" > "$0/out"' \
  "$work" "$root" "$work/s" "$work" "${client[@]}" &
inner=$!
while [ ! -e "$work/ready" ]; do sleep 0.05; done
sleep 0.3
cpu0=$(cpu_ticks); ctx0=$(ctx)
touch "$work/go"
wait $inner
cpu1=$(cpu_ticks); ctx1=$(ctx)
rss=$(ps -o rss= -p $pid | tr -d ' ')
kill -INT $pid; wait $pid || true
unset pid
hz=$(getconf CLK_TCK)
cpu=$(awk -v a="$cpu0" -v b="$cpu1" -v hz="$hz" 'BEGIN { printf "%.2f", (b - a) / hz }')
cs=$((ctx1 - ctx0))
if [ "$mode" = idle ]; then
  echo "idle: engine CPU ${cpu}s in ${SECS:-10}s after a burst, $cs context switches, RSS $((rss / 1024)) MB"
elif [ "$mode" = bulk ]; then
  LC_ALL=C awk -v d="$direct" -v t="$(cat "$work/out")" -v c="$cpu" -v r="$rss" -v b="$bytes" -v cs="$cs" 'BEGIN {
    printf "direct:    %7.1f Mbit/s\n", d*8/1e6
    printf "via vigil: %7.1f Mbit/s (%.0f%% of direct)\n", t*8/1e6, 100*t/d
    printf "engine CPU: %ss for %d MB (%.2f s/GB), %d context switches, RSS %d MB\n", c, b/1e6, c*1e9/b, cs, r/1024 }'
else
  read -r ops secs < "$work/out"
  LC_ALL=C awk -v m="$mode" -v o="$ops" -v n="$n" -v s="$secs" -v c="$cpu" -v r="$rss" -v cs="$cs" 'BEGIN {
    printf "%s: %d/%d ops in %.2fs (%.0f ops/s)\n", m, o, n, s, o/s
    printf "engine CPU: %ss (%.1f us/op), %d context switches, RSS %d MB\n", c, c*1e6/o, cs, r/1024 }'
fi
