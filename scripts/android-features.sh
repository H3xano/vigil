#!/usr/bin/env bash
# On-device checks for encrypted upstream DNS (DoH via Quad9), SOCKS5
# chaining (a proxy on the host, reached from the emulator at 10.0.2.2) and
# the Maximum throughput toggle (restarts the session).
#
# Requires: adb in PATH, an emulator with `adb root`, the debug APK built.
# WireGuard needs a real peer and is covered by scripts/e2e-netns.sh.
set -uo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
pkg=dev.vigil.inspector.debug
svc=$pkg/dev.vigil.inspector.vpn.VigilVpnService
apk="${APK:-$root/android/app/build/outputs/apk/debug/app-debug.apk}"
pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1 :: ${2:-}"; fail=$((fail+1)); }
sh_() { adb shell "su 2000 sh -c '$1'" 2>&1 | tr -d '\r'; }
tun_up() { adb shell ip -br addr 2>/dev/null | grep -q " 10.111.222.1/"; }
wait_tun() { for _ in $(seq 60); do tun_up && return 0; sleep 1; done; return 1; }
wait_no_tun() { for _ in $(seq 15); do tun_up || return 0; sleep 1; done; return 1; }
http_ok() { sh_ "(cat /data/local/tmp/ft-req.txt; sleep 3) | nc -w 8 ${1:-example.com} 80 | head -n 1" | grep -q "HTTP/1.1"; }
grant() {
  adb shell appops set $pkg ACTIVATE_VPN allow; adb shell appops set $pkg GET_USAGE_STATS allow
  adb shell appops get $pkg ACTIVATE_VPN | grep -q "ACTIVATE_VPN: allow" || { echo "could not grant VPN consent"; exit 1; }
}
settings() { # JSON patch applied to the app's settings; restarts the app process
  adb shell am force-stop $pkg
  adb pull /data/data/$pkg/shared_prefs/vigil.xml /tmp/vigil-ft-prefs.xml >/dev/null
  python3 "$root/scripts/e2e/edit_settings.py" /tmp/vigil-ft-prefs.xml "$1"
  adb exec-in run-as $pkg sh -c 'cat > shared_prefs/vigil.xml' < /tmp/vigil-ft-prefs.xml
}
start() { grant; adb shell am start-foreground-service -n $svc -a dev.vigil.inspector.START >/dev/null; wait_tun; }
stop() { adb shell am startservice -n $svc -a dev.vigil.inspector.STOP >/dev/null; wait_no_tun; }
screen_text() { # visible text of a vigil screen
  adb shell am start -n $pkg/dev.vigil.inspector.ui.MainActivity --es destination "$1" -f 0x14000000 >/dev/null; sleep 4
  adb shell uiautomator dump /data/local/tmp/ft-ui.xml >/dev/null 2>&1
  adb shell cat /data/local/tmp/ft-ui.xml | grep -o 'text="[^"]*"' | sed 's/text="//; s/"$//'
}

adb root >/dev/null; sleep 2
adb uninstall $pkg >/dev/null 2>&1
adb install -r -g "$apk" >/dev/null || { echo "install failed"; exit 1; }
adb shell "printf 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' > /data/local/tmp/ft-req.txt; chmod 644 /data/local/tmp/ft-req.txt"
adb shell am start -n $pkg/dev.vigil.inspector.ui.MainActivity >/dev/null; sleep 6

# --- Encrypted DNS: DoH through Quad9 ------------------------------------------
settings '{"onboarded": true, "encryptedDns": {"mode": "doh", "provider": "quad9", "fallbackPlain": false}}'
start && ok "tunnel up with DoH" || bad "tunnel up with DoH"
r=$(sh_ "ping -c 1 -W 3 wikipedia.org"); echo "$r" | grep -q "PING wikipedia.org (" && ok "names resolve over DoH" || bad "names resolve over DoH" "$r"
http_ok && ok "HTTP with DoH" || bad "HTTP with DoH"
sleep 12  # the status line comes from the periodic stats event
txt=$(screen_text dns)
echo "$txt" | grep -qi "working" && ok "Encrypted DNS screen reports working" || bad "Encrypted DNS screen reports working" "$(echo "$txt" | grep -iE 'work|fail|last' | head -3)"
adb exec-out screencap -p > /tmp/vigil-ft-dns.png
stop

# --- SOCKS5 chaining through a proxy on the host --------------------------------
sport=18080; slog="$(mktemp)"
python3 "$root/scripts/e2e/socks5_server.py" 0.0.0.0 $sport "$slog" vigil ft-secret & spid=$!
trap 'kill $spid 2>/dev/null' EXIT
sleep 1
settings '{"encryptedDns": {"mode": "off"}, "upstream": {"mode": "socks5", "failClosed": true, "socks5": {"host": "10.0.2.2", "port": '$sport', "username": "vigil", "password": "ft-secret", "udp": "auto"}}}'
start && ok "tunnel up with SOCKS5" || bad "tunnel up with SOCKS5"
http_ok && ok "HTTP through SOCKS5" || bad "HTTP through SOCKS5"
r=$(sh_ "ping -c 1 -W 3 example.org"); echo "$r" | grep -q "PING example.org (" && ok "DNS through SOCKS5" || bad "DNS through SOCKS5" "$r"
grep -q ":80" "$slog" && ok "proxy saw the HTTP connection" || bad "proxy saw the HTTP connection" "$(tail -3 "$slog")"
grep -q ":53" "$slog" && ok "proxy saw DNS (TCP/53)" || bad "proxy saw DNS (TCP/53)" "$(tail -3 "$slog")"
sleep 12
txt=$(screen_text upstream); adb exec-out screencap -p > /tmp/vigil-ft-upstream.png
echo "$txt" | grep -qiE "socks|connected|working|up" && ok "Upstream screen shows SOCKS5 status" || bad "Upstream screen shows SOCKS5 status" "$(echo "$txt" | head -5)"
kill $spid 2>/dev/null; wait $spid 2>/dev/null; sleep 2
if http_ok example.net; then bad "fail-closed blocks traffic when the proxy is down" "HTTP still worked"; else ok "fail-closed blocks traffic when the proxy is down"; fi
stop

# --- Maximum throughput toggle restarts the session with 2 workers ---------------
settings '{"upstream": {"mode": "direct"}, "maxThroughput": false}'
start >/dev/null
adb logcat -c
adb shell am start -n $pkg/dev.vigil.inspector.ui.MainActivity --es destination settings -f 0x14000000 >/dev/null; sleep 3
tap_text() { # scrolls down in small steps until a node with this text is visible, then taps its centre
  for _ in $(seq 14); do
    adb shell rm -f /data/local/tmp/ft-ui.xml
    for _ in 1 2 3; do adb shell uiautomator dump /data/local/tmp/ft-ui.xml >/dev/null 2>&1 && adb shell test -s /data/local/tmp/ft-ui.xml && break; sleep 1; done
    b=$(adb shell cat /data/local/tmp/ft-ui.xml 2>/dev/null | grep -o "text=\"$1\"[^>]*bounds=\"[^\"]*\"" | grep -o 'bounds="[^"]*"' | head -1 | tr -dc '0-9,[]' | tr '][' ' ,')
    if [ -n "$b" ]; then set -- $(echo "$b" | tr ',' ' '); adb shell input tap $(( ($1+$3)/2 )) $(( ($2+$4)/2 )); return 0; fi
    adb shell input swipe 540 1600 540 1100 400; sleep 1
  done; return 1
}
if tap_text "Maximum throughput"; then
  for _ in $(seq 20); do adb logcat -d | grep -q "engine worker threads changed" && break; sleep 1; done
  adb logcat -d | grep -q "engine worker threads changed" && ok "Maximum throughput toggle restarts inspection" || bad "Maximum throughput toggle restarts inspection" "no restart logged"
  wait_tun && http_ok && ok "HTTP after the throughput restart" || bad "HTTP after the throughput restart"
else
  bad "Maximum throughput toggle restarts inspection" "setting not found on screen"
fi
stop

crashes=$(adb logcat -d -b crash | grep -c "$pkg")
[ "$crashes" = 0 ] && ok "no crashes in logcat" || bad "no crashes in logcat" "$crashes lines"
echo "---"
echo "android-features: $pass passed, $fail failed"
[ "$fail" = 0 ]
