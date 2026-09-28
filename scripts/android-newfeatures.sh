#!/usr/bin/env bash
# On-device checks for the features added after 0.4.0: tracker labels and
# spyware packs (downloaded from their publishers, so this needs internet),
# spyware blocking, the health check screen, PCAP-over-IP streaming and
# per-app network conditions.
#
# Requires: adb in PATH, an emulator with `adb root`, the debug APK built.
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
http_ok() { sh_ "(cat /data/local/tmp/nf-req.txt; sleep 3) | nc -w 8 example.com 80 | head -n 1" | grep -q "HTTP/1.1"; }
grant() {
  adb shell appops set $pkg ACTIVATE_VPN allow; adb shell appops set $pkg GET_USAGE_STATS allow
  adb shell appops get $pkg ACTIVATE_VPN | grep -q "ACTIVATE_VPN: allow" || { echo "could not grant VPN consent"; exit 1; }
}
settings() { # JSON patch applied to the app's settings; restarts the app process
  adb shell am force-stop $pkg
  adb pull /data/data/$pkg/shared_prefs/vigil.xml /tmp/vigil-nf-prefs.xml >/dev/null
  python3 "$root/scripts/e2e/edit_settings.py" /tmp/vigil-nf-prefs.xml "$1"
  adb exec-in run-as $pkg sh -c 'cat > shared_prefs/vigil.xml' < /tmp/vigil-nf-prefs.xml
}
start() { grant; adb shell am start-foreground-service -n $svc -a dev.vigil.inspector.START >/dev/null; wait_tun; }
stop() { adb shell am startservice -n $svc -a dev.vigil.inspector.STOP >/dev/null; wait_no_tun; }
screen_text() { # visible text of a vigil screen
  adb shell am start -n $pkg/dev.vigil.inspector.ui.MainActivity --es destination "$1" -f 0x14000000 >/dev/null; sleep 5
  adb shell uiautomator dump /data/local/tmp/nf-ui.xml >/dev/null 2>&1
  adb shell cat /data/local/tmp/nf-ui.xml | grep -o 'text="[^"]*"' | sed 's/text="//; s/"$//'
}
wait_log() { # wait_log <seconds> <regex>
  for _ in $(seq "$1"); do adb logcat -d 2>/dev/null | grep -qE "$2" && return 0; sleep 1; done; return 1
}

adb root >/dev/null; sleep 2
adb uninstall $pkg >/dev/null 2>&1
adb install -r -g "$apk" >/dev/null || { echo "install failed"; exit 1; }
adb shell "printf 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' > /data/local/tmp/nf-req.txt; chmod 644 /data/local/tmp/nf-req.txt"
adb logcat -c
adb shell am start -n $pkg/dev.vigil.inspector.ui.MainActivity >/dev/null; sleep 6

# --- Downloads: tracker labels and spyware packs ---------------------------------
echo "--- tracker labels and spyware packs"
wait_log 240 "trackers adguard-companiesdb: [0-9]{4,} domains" && ok "tracker database downloaded" \
  || bad "tracker database downloaded" "no 'trackers adguard-companiesdb' log line"
wait_log 240 "spyware index mvt-index: [0-9]+ packs" && ok "MVT index downloaded" \
  || bad "MVT index downloaded" "no 'spyware index' log line"
wait_log 240 "spyware echap-stalkerware-network: [0-9]+ domains" && ok "Echap network pack converted" \
  || bad "Echap network pack converted" "no 'spyware echap-stalkerware-network' log line"
wait_log 300 "spyware mvt-[a-z0-9-]+: [0-9]+ domains" && ok "an MVT pack converted" \
  || bad "an MVT pack converted" "no 'spyware mvt-…' log line"
adb shell run-as $pkg ls files/feeds 2>/dev/null | grep -q '\.spy\.json' && ok "pack files stored" \
  || bad "pack files stored" "no *.spy.json in files/feeds"

# --- Spyware domain blocked while inspecting -------------------------------------
echo "--- spyware blocking"
settings '{"onboarded": true}'
start || bad "vpn up" "tun not up"
sleep 8 # feed preload
spy=$(adb shell run-as $pkg cat files/feeds/echap-stalkerware-network.txt 2>/dev/null | tr -d '\r' \
  | grep -v '^#' | grep -E '^[a-z0-9.-]+\.[a-z]{2,}$' | head -n 1)
if [ -n "$spy" ]; then
  out=$(sh_ "ping -c 1 -W 2 $spy")
  # The 0.0.0.0 sinkhole shows as 127.0.0.1 in ping; NXDOMAIN as "unknown host".
  if echo "$out" | grep -qE "127\.0\.0\.1|0\.0\.0\.0|unknown host"; then ok "stalkerware domain $spy sinkholed"
  else bad "stalkerware domain $spy sinkholed" "$(echo "$out" | head -n 2)"; fi
else bad "stalkerware domain sinkholed" "no domain in the converted Echap feed"; fi
http_ok && ok "normal traffic still works" || bad "normal traffic still works"

# --- Health check screen ---------------------------------------------------------
echo "--- health check"
txt=$(screen_text health)
echo "$txt" | grep -qi "health check" && ok "health check screen opens" || bad "health check screen opens" "$(echo "$txt" | head -n 5 | tr '\n' '|')"
adb shell input keyevent KEYCODE_HOME; sleep 1

# --- PCAP-over-IP ------------------------------------------------------------------
echo "--- packet capture stream"
stop
settings '{"capture":{"enabled":true,"streamEnabled":true,"streamBind":"loopback","streamPort":57012}}'
start || bad "vpn up with capture" "tun not up"
sleep 3
adb forward tcp:57012 tcp:57012 >/dev/null
python3 - <<'EOF' > /tmp/vigil-nf-pcap.txt 2>&1 &
import socket, struct, time
s = socket.create_connection(("127.0.0.1", 57012), timeout=20)
buf = b""; end = time.time() + 20
while time.time() < end and len(buf) < 24 + 16 + 20:
    try:
        d = s.recv(65536)
    except socket.timeout:
        break
    if not d: break
    buf += d
if len(buf) >= 24:
    magic, _, _, _, _, _, link = struct.unpack("<IHHiIII", buf[:24])
    print("magic=%08x link=%d bytes=%d" % (magic, link, len(buf)))
else:
    print("short=%d" % len(buf))
EOF
reader=$!
sleep 2
http_ok >/dev/null
wait $reader
res=$(cat /tmp/vigil-nf-pcap.txt)
echo "$res" | grep -q "magic=a1b2c3d4 link=101" && ok "PCAP-over-IP header (raw IP)" || bad "PCAP-over-IP header (raw IP)" "$res"
n=$(echo "$res" | sed -n 's/.*bytes=\([0-9]*\).*/\1/p')
[ "${n:-0}" -gt 60 ] && ok "PCAP-over-IP streams packets" || bad "PCAP-over-IP streams packets" "$res"
adb forward --remove tcp:57012 >/dev/null 2>&1

# --- Per-app network conditions (shell, UID 2000) ----------------------------------
echo "--- per-app network conditions"
stop
# edit_settings.py merges objects, so every flag is set explicitly.
settings '{"capture":{"enabled":false,"streamEnabled":false},"appRules":{"uid:2000":{"blockWifi":true,"blockCellular":false}}}'
start; sleep 3
http_ok && wifi_blocks=no || wifi_blocks=yes
stop
settings '{"appRules":{"uid:2000":{"blockWifi":false,"blockCellular":true}}}'
start; sleep 3
http_ok && cell_blocks=no || cell_blocks=yes
# Exactly one of the two conditions matches the emulator's default network.
if [ "$wifi_blocks" != "$cell_blocks" ]; then ok "network condition applies to one network type only (wifi=$wifi_blocks cellular=$cell_blocks)"
else bad "network condition applies to one network type only" "wifi=$wifi_blocks cellular=$cell_blocks"; fi
stop
settings '{"appRules":{"uid:2000":{"blockWifi":false,"blockCellular":false}}}'
start; sleep 3
http_ok && ok "no rule: traffic works again" || bad "no rule: traffic works again"
stop

echo "android-newfeatures: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
