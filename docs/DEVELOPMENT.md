# Development guide

How to set up a machine, build, run every test suite, and avoid the traps
already hit once. The project state and backlog are in [STATUS.md](STATUS.md).

## Toolchain

| Tool | Version used | Install |
|---|---|---|
| JDK | 17+ (21 works) | distro package |
| Android SDK | platform 35, build-tools 35 | Android Studio or `cmdline-tools` |
| Android NDK | **27.2.12479018** (pinned in `android/app/build.gradle.kts`) | `sdkmanager "ndk;27.2.12479018"` |
| Rust | stable (1.80+) | `rustup` |
| Rust targets | `aarch64-linux-android armv7-linux-androideabi x86_64-linux-android` | `rustup target add …` |
| cargo-ndk | 4.x | `cargo install cargo-ndk` |
| Gradle | 8.11.1 via the wrapper | automatic |

Linux-only test extras: `python3`, `dig` (dnsutils), `curl`, `unshare`
(util-linux), and unprivileged user namespaces enabled.

`android/local.properties` (not committed) must contain `sdk.dir=/path/to/Android/Sdk`.

## Build

```sh
# Engine only (host)
cd core && cargo build --workspace

# App (cross-compiles libvigil.so through the Gradle cargoBuild task)
cd android
./gradlew assembleDebug                    # all three ABIs
./gradlew assembleDebug -Pvigil.abis=x86_64,arm64-v8a
./gradlew assembleRelease                  # R8-minified; debug-signed without keystore.properties
./gradlew assembleRelease -Pvigil.skipCargo=true   # reuse the .so files in src/main/jniLibs
```

`src/main/jniLibs/` is generated and git-ignored.

## Test suites

Run all of these before committing anything that touches the engine or the
app. Every one was green at the 0.1.0 commit.

```sh
cd core && cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
scripts/e2e-netns.sh          # 43 checks, needs internet, no root
scripts/jni-smoke.sh          # 15 checks, no root
cd android && ./gradlew lintDebug testDebugUnitTest
scripts/android-e2e.sh        # 28 checks, needs an emulator/userdebug device (see below)
LOCAL=1 BYTES=1000000000 scripts/bench-throughput.sh   # engine ceiling
scripts/bench-throughput.sh                            # vs. real internet link
```

How the no-root tests work: `unshare -rnm` creates a user and network
namespace in which we are "root". A TUN device is created there, and its file
descriptor is passed over a Unix socket (SCM_RIGHTS) to `vigil-cli` running in
the host namespace. So traffic from `dig`/`curl` inside the namespace goes
through the real engine and out through the host's network.
`scripts/e2e/last-events.jsonl` keeps the events of the last run for
inspection.

## Emulator for on-device tests

```sh
sdkmanager "emulator" "system-images;android-35;google_apis;x86_64"
echo no | avdmanager create avd -n vigil35 -k "system-images;android-35;google_apis;x86_64" -d pixel_6
emulator -avd vigil35 -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect -no-snapshot -memory 3072 -cores 4 &
adb wait-for-device; until [ "$(adb shell getprop sys.boot_completed | tr -d '\r')" = 1 ]; do sleep 3; done
cd android && ./gradlew assembleDebug -Pvigil.abis=x86_64,arm64-v8a && cd .. && scripts/android-e2e.sh
```

Use a `google_apis` image, not `google_apis_playstore`: the test needs
`adb root`. KVM must be accessible. The script grants VPN consent with
`appops set <pkg> ACTIVATE_VPN allow`, drives Chrome, runs a syslog
collector on the host (the emulator reaches the host at `10.0.2.2`), taps
UI elements found with `uiautomator dump`, and writes screenshots to
`docs/screenshots/`.

## Gotchas already paid for

- **toybox `nc` quits on stdin EOF,** even without vigil. Feed it
  `(cat req; sleep 3) | nc …` or the reply is lost.
- **Files pushed as root into the app's data dir get the wrong SELinux MLS
  categories.** The app then cannot read or rename them, and
  `SharedPreferences` silently falls back. Write test files with
  `adb exec-in run-as <pkg> sh -c 'cat > path'` (debug builds only).
  `restorecon` does not fix the categories.
- **WorkManager restarts the process after `am force-stop`** (the feed job
  runs). Force-stop again after editing app files, before starting the
  service.
- **Android shows the `0.0.0.0` sinkhole as `127.0.0.1` in `ping`.**
- **Chrome sends a GREASE ECH extension on every handshake.** Don't treat
  the extension's presence as ECH (`ClientHello::ech_active`).
- **Chrome preconnects sockets it never uses.** They appear as 0-byte flows
  named from DNS once the 3 s sniff window expires.
- **AAPT2 needs `<adaptive-icon>` under `mipmap-anydpi-v26`,** despite lint's
  ObsoleteSdkInt hint (suppressed in `app/lint.xml`).
- **ClientHellos exceed one segment** (post-quantum key shares): always parse
  the reassembled stream (`tls::parse_records` handles it).
- **netstack-smoltcp creates a stream for every SYN,** retransmits included.
  The gate deduplicates pending SYNs, and streams without parked metadata are
  dropped.
- Stopping the engine must not race a blocking poll. All native calls go
  through `EngineHandle` (read lock), and `close()` takes the write lock.

## Code map

```
core/vigil-core/src/
  engine/mod.rs     runtime, TUN loop, dispatch, stats, flow tracker, Engine API
  engine/tcp.rs     SYN gate, relay, sniffing, policy decisions, alerts
  engine/udp.rs     UDP NAT, QUIC sniff window
  engine/dns.rs     DNS answer path, sinkhole, CNAME cloaking, upstream forwarding
  proto/{dns,tls,quic,http}.rs   parsers (pure)
  intel.rs          DomainSet / IpSet / feed parsing
  policy.rs         Policy, feed categories, DoH host list
  detect.rs         beacon detector, alert limiter
  event.rs          event types + bounded queue
  config.rs         Config (JSON contract with the app)
core/vigil-jni/src/lib.rs     JNI surface (mirrors engine/VigilNative.kt)
android/app/src/main/java/dev/vigil/inspector/
  vpn/              VigilVpnService, routes, config factory, tile, ServiceState
  engine/           VigilNative, PlatformBridge, EngineHandle, event/config models
  processing/       EventProcessor, ForegroundTracker, AlertNotifier
  data/             Room DB, settings, app resolver, feed catalog/repository
  export/           ECS records, syslog/HTTP formats, SiemExporter
  ui/               MainActivity, ViewModel, theme, components, screens/
```

**Contracts to keep in sync when changing them:**

- `core/vigil-core/src/config.rs` ↔ `engine/EngineConfig.kt`
- `core/vigil-core/src/event.rs` ↔ `engine/EngineEvent.kt` ↔ `docs/EVENTS.md`
- JNI signatures in `vigil-jni/src/lib.rs` ↔ `engine/VigilNative.kt` ↔
  `scripts/jni-smoke/…/VigilNative.java`
- The method names `ownerUid` and `protect` (looked up from native code) ↔
  `PlatformBridge.kt` and the ProGuard keep rules.
