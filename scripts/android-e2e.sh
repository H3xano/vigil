#!/usr/bin/env bash
# On-device end-to-end test on an emulator or rooted (userdebug) device.
#
# Installs the debug APK, grants VPN consent through appops, starts the
# inspector, generates real traffic (shell user via nc/ping, and Chrome), then
# asserts on the app's own Room database and saves screenshots.
#
# Requires: adb in PATH, one device with `adb root` (e.g. a google_apis image).
set -uo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
pkg=dev.vigil.inspector.debug
apk="${APK:-$root/android/app/build/outputs/apk/debug/app-debug.apk}"
out="${OUT:-$root/docs/screenshots}"
mkdir -p "$out"
db=/data/data/$pkg/databases/vigil.db
pass=0; fail=0
ok()   { echo "PASS $1"; pass=$((pass+1)); }
bad()  { echo "FAIL $1 :: ${2:-}"; fail=$((fail+1)); }
sql()  { adb shell "sqlite3 $db \"$1\"" | tr -d '\r'; }
check_sql() { # name, query returning a count
  local n; n=$(sql "$2"); if [ "${n:-0}" -gt 0 ] 2>/dev/null; then ok "$1 ($n)"; else bad "$1" "count=${n:-?}"; fi
}

adb root >/dev/null; sleep 2
adb uninstall $pkg >/dev/null 2>&1
adb install -r -g "$apk" >/dev/null || { echo "install failed"; exit 1; }
adb shell appops set $pkg ACTIVATE_VPN allow
adb shell appops set $pkg GET_USAGE_STATS allow
adb logcat -c

# First launch seeds the database (built-in feeds) and settings.
adb shell am start -n $pkg/dev.vigil.inspector.ui.MainActivity >/dev/null
sleep 6
adb shell am force-stop $pkg
uid=$(adb shell stat -c %u /data/data/$pkg | tr -d '\r')

# A local test feed plus a pre-accepted onboarding dialog.
adb shell "mkdir -p /data/data/$pkg/files/feeds && printf 'ads.vigil-e2e.example\nblocked-http.vigil-e2e.example\nblocked-sni.vigil-e2e.example\n' > /data/data/$pkg/files/feeds/e2e.txt"
adb shell "chown -R $uid:$uid /data/data/$pkg/files"
now=$(($(date +%s)*1000))
sql "INSERT OR REPLACE INTO feeds(id,name,url,category,enabled,builtin,description,authHeader,lastUpdated,domains,ipRanges,lastError) VALUES('e2e','E2E test feed','https://example.invalid/e2e.txt','malware',1,0,'test',NULL,$now,3,0,NULL)" >/dev/null
prefs=$(adb shell "cat /data/data/$pkg/shared_prefs/vigil.xml" | tr -d '\r')
if echo "$prefs" | grep -q '&quot;onboarded&quot;:false'; then
  adb shell "sed -i 's/&quot;onboarded&quot;:false/\&quot;onboarded\&quot;:true/' /data/data/$pkg/shared_prefs/vigil.xml"
else
  adb shell "sed -i 's/}<\/string>/,\&quot;onboarded\&quot;:true}<\/string>/' /data/data/$pkg/shared_prefs/vigil.xml"
fi

# Start the inspector exactly as the UI does (consent already granted).
adb shell am start-foreground-service -n $pkg/dev.vigil.inspector.vpn.VigilVpnService -a dev.vigil.inspector.START >/dev/null
for i in $(seq 30); do adb shell ip addr show tun0 2>/dev/null | grep -q 10.111.222.1 && break; sleep 1; done
if adb shell ip addr show tun0 | grep -q 10.111.222.1; then ok "tun0 established"; else bad "tun0 established"; fi
sleep 3

# --- Traffic ---------------------------------------------------------------
sh_() { adb shell "su 2000 sh -c '$1'" 2>&1 | tr -d '\r'; }
r=$(sh_ "ping -c 1 -W 3 example.com"); echo "$r" | grep -q "PING example.com (" && ok "shell resolves example.com" || bad "shell resolves example.com" "$r"
# Android renders the 0.0.0.0 sinkhole answer as the local host when pinging.
r=$(sh_ "ping -c 1 -W 2 ads.vigil-e2e.example"); echo "$r" | grep -qE "\((0\.0\.0\.0|::|127\.0\.0\.1)\)" && ok "sinkholed (no real address)" || bad "sinkholed (no real address)" "$r"
# toybox nc exits as soon as stdin hits EOF, so keep stdin open while the reply arrives.
adb shell "printf 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' > /data/local/tmp/req-ok.txt; printf 'GET / HTTP/1.1\r\nHost: blocked-http.vigil-e2e.example\r\n\r\n' > /data/local/tmp/req-blocked.txt; chmod 644 /data/local/tmp/req-*.txt"
r=$(sh_ "(cat /data/local/tmp/req-ok.txt; sleep 3) | nc -w 8 example.com 80 | head -n 1")
echo "$r" | grep -q "HTTP/1.1" && ok "HTTP through tunnel ($r)" || bad "HTTP through tunnel" "$r"
ip=$(sh_ "ping -c 1 -W 2 example.com" | sed -n 's/^PING [^ ]* (\([0-9.]*\)).*/\1/p' | head -n1)
r=$(sh_ "(cat /data/local/tmp/req-blocked.txt; sleep 3) | nc -w 5 $ip 80 | head -c 200")
[ -z "$r" ] && ok "HTTP Host block closes connection" || bad "HTTP Host block closes connection" "$r"

# Chrome: TLS (and possibly QUIC) with real SNI, attributed to Chrome's UID.
adb shell 'echo "chrome --disable-fre --no-default-browser-check --no-first-run" > /data/local/tmp/chrome-command-line'
adb shell am set-debug-app --persistent com.android.chrome >/dev/null
adb shell am start -a android.intent.action.VIEW -d https://example.com -p com.android.chrome >/dev/null
sleep 12
adb shell am start -a android.intent.action.VIEW -d https://www.wikipedia.org -p com.android.chrome >/dev/null
sleep 10
adb shell am force-stop com.android.chrome
sleep 4

# --- Assertions on the app's database -------------------------------------
check_sql "dns lookups recorded"                "SELECT COUNT(*) FROM dns_queries"
check_sql "dns attributed to an app"            "SELECT COUNT(*) FROM dns_queries WHERE pkg != 'unknown'"
check_sql "sinkhole recorded with feed reason"  "SELECT COUNT(*) FROM dns_queries WHERE qname='ads.vigil-e2e.example' AND verdict='block' AND reason LIKE 'feed:e2e%'"
check_sql "shell HTTP flow attributed + sniffed" "SELECT COUNT(*) FROM flows WHERE pkg='com.android.shell' AND domain='example.com' AND domainSource='http' AND rx > 0"
check_sql "HTTP Host block recorded"            "SELECT COUNT(*) FROM flows WHERE domain='blocked-http.vigil-e2e.example' AND verdict='block' AND domainSource='http'"
check_sql "Chrome TLS flows with SNI"           "SELECT COUNT(*) FROM flows WHERE pkg='com.android.chrome' AND domainSource IN ('sni','quic') AND domain LIKE '%example.com'"
check_sql "Chrome JA4 fingerprints"             "SELECT COUNT(*) FROM flows WHERE pkg='com.android.chrome' AND ja4 LIKE 't13d%'"
check_sql "flows finished with byte counts"     "SELECT COUNT(*) FROM flows WHERE endTs IS NOT NULL AND rx > 1000"
check_sql "threat alert raised"                 "SELECT COUNT(*) FROM alerts WHERE kind='threat_domain' AND severity='high'"
check_sql "foreground/background tagging"       "SELECT COUNT(*) FROM flows WHERE background IS NOT NULL"
check_sql "built-in feeds downloaded on device" "SELECT COUNT(*) FROM feeds WHERE builtin=1 AND lastUpdated IS NOT NULL AND domains + ipRanges > 0"
echo "--- sample of recorded flows:"
sql "SELECT pkg, proto, COALESCE(domain, dstIp), dstPort, domainSource, verdict, tx, rx FROM flows ORDER BY id DESC LIMIT 12"
echo "--- sample of recorded lookups:"
sql "SELECT pkg, qname, qtype, rcode, verdict FROM dns_queries ORDER BY id DESC LIMIT 8"
echo "--- feeds:"
sql "SELECT id, enabled, domains, ipRanges, lastError FROM feeds WHERE enabled=1"

# --- Screenshots -----------------------------------------------------------
shot() { adb shell am start -n $pkg/dev.vigil.inspector.ui.MainActivity ${2:+--es destination $2} -f 0x14000000 >/dev/null; sleep 3; adb exec-out screencap -p > "$out/$1.png"; }
shot dashboard
shot activity activity
shot alerts alerts
shot apps apps
shot feeds feeds
[ -s "$out/dashboard.png" ] && ok "screenshots saved to $out" || bad "screenshots"

# --- Stability -------------------------------------------------------------
crashes=$(adb logcat -d -b crash | grep -c "$pkg" || true)
[ "$crashes" -eq 0 ] && ok "no crashes in logcat" || { bad "no crashes in logcat" "$crashes"; adb logcat -d -b crash | tail -40; }
adb shell am start-foreground-service -n $pkg/dev.vigil.inspector.vpn.VigilVpnService -a dev.vigil.inspector.STOP >/dev/null
sleep 4
adb shell ip addr show tun0 >/dev/null 2>&1 && bad "tun0 removed after stop" || ok "tun0 removed after stop"
echo "android-e2e: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
