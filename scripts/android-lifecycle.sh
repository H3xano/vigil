#!/usr/bin/env bash
# Service lifecycle test on an emulator or rooted (userdebug) device:
# network switches, airplane mode under load, Doze, injected engine errors
# (restart budget), process death, always-on VPN at boot and Private DNS.
#
# Requires: adb in PATH, one device with `adb root`, the debug APK built
# (`./gradlew assembleDebug`). Reboots the device once (SKIP_BOOT=1 to skip).
set -uo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
pkg=dev.vigil.inspector.debug
svc=$pkg/dev.vigil.inspector.vpn.VigilVpnService
apk="${APK:-$root/android/app/build/outputs/apk/debug/app-debug.apk}"
pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1 :: ${2:-}"; fail=$((fail+1)); }
sh_() { adb shell "su 2000 sh -c '$1'" 2>&1 | tr -d '\r'; }
tun_up() { adb shell ip -br addr 2>/dev/null | grep -q " 10.111.222.1/"; }  # any tunN: restarts may create tun1
wait_tun() { for _ in $(seq "${1:-30}"); do tun_up && return 0; sleep 1; done; return 1; }
wait_no_tun() { for _ in $(seq "${1:-15}"); do tun_up || return 0; sleep 1; done; return 1; }
# One HTTP request as the shell user; toybox nc needs stdin kept open.
http_ok() {
  local r
  for _ in $(seq "${1:-3}"); do
    r=$(sh_ "(cat /data/local/tmp/lc-req.txt; sleep 3) | nc -w 8 example.com 80 | head -n 1")
    echo "$r" | grep -q "HTTP/1.1" && return 0
    sleep 3
  done
  return 1
}
check_net() { if http_ok "${2:-3}"; then ok "$1"; else bad "$1" "no HTTP reply"; fi; }
start_vpn() { grant_vpn; adb shell am start-foreground-service -n $svc -a dev.vigil.inspector.START >/dev/null; }
grant_vpn() {
  for _ in $(seq 10); do
    adb shell appops set $pkg ACTIVATE_VPN allow; adb shell appops set $pkg GET_USAGE_STATS allow
    adb shell appops get $pkg ACTIVATE_VPN | grep -q "ACTIVATE_VPN: allow" && return 0
    sleep 1
  done
  echo "could not grant VPN consent"; exit 1
}
alive() { [ -n "$(adb shell pidof $pkg | tr -d '\r')" ]; }

adb root >/dev/null; sleep 2
adb uninstall $pkg >/dev/null 2>&1
adb install -r -g "$apk" >/dev/null || { echo "install failed"; exit 1; }
adb shell "printf 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' > /data/local/tmp/lc-req.txt; chmod 644 /data/local/tmp/lc-req.txt"
# Seed settings, then pre-accept onboarding.
adb shell am start -n $pkg/dev.vigil.inspector.ui.MainActivity >/dev/null; sleep 6
adb shell am force-stop $pkg
adb pull /data/data/$pkg/shared_prefs/vigil.xml /tmp/vigil-lc-prefs.xml >/dev/null
python3 "$root/scripts/e2e/edit_settings.py" /tmp/vigil-lc-prefs.xml '{"onboarded": true}'
adb exec-in run-as $pkg sh -c 'cat > shared_prefs/vigil.xml' < /tmp/vigil-lc-prefs.xml
adb shell am force-stop $pkg
# Grant VPN consent last: an appop set right after install can be reset while
# the package is still being set up.
grant_vpn
adb shell svc wifi enable; adb shell svc data enable
adb shell cmd connectivity airplane-mode disable >/dev/null 2>&1
adb logcat -c

# --- Baseline -----------------------------------------------------------------
start_vpn
if wait_tun 60; then ok "tun0 established"; else bad "tun0 established"; echo "VPN did not start; aborting (every later check would be meaningless)"; exit 1; fi
check_net "HTTP through tunnel"

# --- Network switches ---------------------------------------------------------
adb shell svc wifi disable; sleep 8
check_net "Wi-Fi off (cellular only)" 5
adb shell svc wifi enable; sleep 10
check_net "Wi-Fi back on" 5
adb shell svc data disable; sleep 8
check_net "cellular off (Wi-Fi only)" 5
adb shell svc data enable; sleep 5
tun_up && ok "tun0 survived network switches" || bad "tun0 survived network switches"

# --- Airplane mode toggles while traffic flows --------------------------------
( for _ in $(seq 20); do sh_ "(cat /data/local/tmp/lc-req.txt; sleep 1) | nc -w 3 example.com 80 >/dev/null" >/dev/null; done ) & load=$!
for _ in 1 2 3; do
  adb shell cmd connectivity airplane-mode enable >/dev/null; sleep 4
  adb shell cmd connectivity airplane-mode disable >/dev/null; sleep 6
done
wait $load 2>/dev/null
sleep 8
alive && ok "service alive after airplane toggles" || bad "service alive after airplane toggles"
check_net "HTTP after airplane toggles" 6

# --- Doze ---------------------------------------------------------------------
adb shell dumpsys deviceidle force-idle >/dev/null; sleep 10
tun_up && alive && ok "tunnel kept in Doze" || bad "tunnel kept in Doze"
adb shell dumpsys deviceidle unforce >/dev/null; sleep 3
check_net "HTTP after leaving Doze"

# --- Injected engine errors: restart, then give up after the budget ------------
inject() { adb shell am startservice -n $svc -a dev.vigil.inspector.INJECT_ENGINE_ERROR >/dev/null; }
inject; sleep 6
if adb logcat -d | grep -q "restarting in"; then ok "engine error triggers restart"; else bad "engine error triggers restart" "no restart log"; fi
wait_tun 20 && ok "tun0 back after restart" || bad "tun0 back after restart"
check_net "HTTP after engine-error restart"
inject; sleep 5; inject; sleep 8; inject; sleep 5
if wait_no_tun 15; then ok "gives up after restart budget (tun0 removed)"; else bad "gives up after restart budget" "tun0 still up"; fi
check_net "connectivity restored after giving up (no black hole)"

# --- Process death (START_STICKY) ---------------------------------------------
start_vpn; wait_tun 30
pid=$(adb shell pidof $pkg | tr -d '\r')
adb shell kill -9 "$pid"
if wait_tun 90 && alive && [ "$(adb shell pidof $pkg | tr -d '\r')" != "$pid" ]; then ok "service restarted after process death"; else bad "service restarted after process death"; fi
check_net "HTTP after process death" 6

# --- Private DNS --------------------------------------------------------------
# Strict mode left behind sends every lookup to dns.google over TLS, past
# vigil's resolver, and breaks the sinkhole checks of the other suites.
restore_private_dns() {
  adb shell settings put global private_dns_mode opportunistic
  adb shell settings delete global private_dns_specifier >/dev/null
}
trap restore_private_dns EXIT
adb shell settings put global private_dns_mode opportunistic; sleep 5
check_net "Private DNS automatic"
adb shell settings put global private_dns_specifier dns.google
adb shell settings put global private_dns_mode hostname; sleep 8
check_net "Private DNS strict (dns.google)" 5
restore_private_dns
[ "$(adb shell settings get global private_dns_mode | tr -d '\r')" = opportunistic ] || { sleep 2; restore_private_dns; }

# --- Always-on VPN at boot ----------------------------------------------------
if [ "${SKIP_BOOT:-0}" != 1 ]; then
  adb shell settings put secure always_on_vpn_app $pkg
  adb shell settings put secure always_on_vpn_lockdown 0
  adb reboot
  adb wait-for-device
  until [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do sleep 3; done
  adb root >/dev/null; sleep 3
  wait_tun 90 && ok "always-on VPN starts at boot" || bad "always-on VPN starts at boot"
  check_net "HTTP after boot" 6
  adb shell settings delete secure always_on_vpn_app >/dev/null
  adb shell settings delete secure always_on_vpn_lockdown >/dev/null
fi

# --- Wrap-up ------------------------------------------------------------------
adb shell am startservice -n $svc -a dev.vigil.inspector.STOP >/dev/null
wait_no_tun 15 && ok "tun0 removed after stop" || bad "tun0 removed after stop"
crashes=$(adb logcat -d -b crash | grep -c "$pkg")
[ "$crashes" = 0 ] && ok "no crashes in logcat" || bad "no crashes in logcat" "$crashes lines"
echo "---"
echo "android-lifecycle: $pass passed, $fail failed"
[ "$fail" = 0 ]
