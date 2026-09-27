#!/usr/bin/env bash
# Loads the host build of libvigil.so into a JVM and drives the engine
# through the same JNI entry points the Android app uses. Runs inside an
# unprivileged network namespace with a real TUN device.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
(cd "$root/core" && cargo build -q -p vigil-jni)
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
javac -d "$work/classes" "$root"/scripts/jni-smoke/dev/vigil/inspector/engine/*.java
lib="$root/core/target/debug/libvigil.so"
unshare -rn bash -c '
  set -e
  work="$1"; lib="$2"
  exec 3<>/dev/net/tun
  python3 - <<PY
import fcntl, struct
fcntl.ioctl(3, 0x400454CA, struct.pack("16sH", b"tun0", 0x0001 | 0x1000))
PY
  ip link set lo up; ip addr add 10.111.222.1/24 dev tun0; ip link set tun0 up; ip route add default dev tun0
  java -cp "$work/classes" dev.vigil.inspector.engine.Smoke "$lib" 3 "$work/ready" &
  jpid=$!
  for i in $(seq 50); do [ -f "$work/ready" ] && break; sleep 0.1; done
  dig +short +time=2 +tries=1 blocked.vigil-test.example A @10.111.222.2 || true
  curl -s --max-time 2 http://198.51.100.7/ || true
  curl -s --max-time 2 http://203.0.113.9/ || true
  wait $jpid
' _ "$work" "$lib"
