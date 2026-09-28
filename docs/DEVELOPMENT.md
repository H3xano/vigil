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
scripts/e2e-netns.sh          # 49 checks, needs internet, no root
scripts/jni-smoke.sh          # 26 checks, no root
cd android && ./gradlew lintDebug testDebugUnitTest
scripts/android-e2e.sh        # 28 checks, needs an emulator/userdebug device (see below)
scripts/android-lifecycle.sh  # 21 checks + always-on at boot (reboots; SKIP_BOOT=1 to skip)
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

## Distribution

**Versioning.** `versionName` and `versionCode` are literals in
`android/app/build.gradle.kts` (F-Droid's update checker reads them from
there, so don't compute them). `versionCode = major * 10000 + minor * 100 +
patch`, e.g. 0.2.0 → 200, 1.4.2 → 10402. The APK is universal (all three ABIs,
no splits), so there are no per-ABI offsets. Keep the Rust workspace version
in `core/Cargo.toml` in step (the Settings screen shows it as the engine
version). Release tags are `vX.Y.Z`.

**F-Droid metadata** lives in `fastlane/metadata/android/en-US/`, which
F-Droid reads from the tagged commit: `title.txt`, `short_description.txt`
(≤ 80 characters), `full_description.txt`, `changelogs/<versionCode>.txt`,
`images/icon.png` (512×512, regenerate with
`python3 packaging/fdroid/render_icon.py` after changing the launcher icon)
and `images/phoneScreenshots/` (copies of `docs/screenshots/`, numbered for
ordering). Add a changelog file for every release. The draft fdroiddata
recipe is `packaging/fdroid/dev.vigil.inspector.yml`; it pins Rust, rustup,
cargo-ndk and the NDK, and must be bumped with them.

**Reproducible builds.** The release APK is bit-for-bit reproducible across
checkout directories: the `cargoBuild` task passes `--remap-path-prefix` for
the checkout and `CARGO_HOME` plus `-Wl,--build-id=none`, cargo builds with
`--locked`, and `vcsInfo` is off for release. F-Droid can therefore publish
the upstream-signed APK (`Binaries` + `AllowedAPKSigningKeys` in the recipe),
provided the release is built from a clean checkout of the tag with the same
toolchain as the recipe (Rust, cargo-ndk, NDK; JDK 17 or 21). Pass
`-Pvigil.unsignedRelease=true` to get `app-release-unsigned.apk`, which is
what F-Droid builds. To check:

```sh
git clone --branch vX.Y.Z <repo> /tmp/a && git clone --branch vX.Y.Z <repo> /tmp/b/elsewhere
# copy android/local.properties into both, then in each android/ directory:
./gradlew --no-build-cache assembleRelease -Pvigil.unsignedRelease=true
sha256sum /tmp/a/android/app/build/outputs/apk/release/app-release-unsigned.apk \
          /tmp/b/elsewhere/android/app/build/outputs/apk/release/app-release-unsigned.apk
# against a signed release APK (pip install apksigcopier):
apksigcopier compare --unsigned vigil-X.Y.Z.apk app-release-unsigned.apk
```

`--no-build-cache` matters: `org.gradle.caching` is on, and a cache hit
would make the second build trivially identical.

## Gotchas already paid for

- **The emulator gets OOM-killed** (about 4 GB RSS) if Gradle/cargo builds run
  alongside it on a 14 GB host. Build first, or stop the emulator
  (`adb emu kill`) before parallel builds.
- **Grant VPN consent after the first app launch.** An `appops set …
  ACTIVATE_VPN allow` issued right after `adb install` can be reset while the
  package is still being set up; the scripts re-grant and verify it.
- **Restarts may bring the tunnel up as `tun1`** (the new TUN is established
  before the old one closes). Look for 10.111.222.1 on any interface.
- **Rust is pinned** in `core/rust-toolchain.toml` (keep it in sync with the
  F-Droid recipe); rustup installs it on first use.

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
  The gate deduplicates pending SYNs and SYNs for already-admitted 4-tuples,
  and streams without parked metadata are dropped.
- **netstack-smoltcp is vendored** in `core/vendor/netstack-smoltcp` (via
  `[patch.crates-io]`) to add `TcpStream::abort` and report peer resets as
  `ConnectionReset`. Changes are marked `vigil patch`; re-apply them when
  upgrading the crate.
- **Stopping the engine is two steps:** `nativeShutdown` (stops the runtime and
  queues `flow_end` for every open flow), drain with `nativePollEvents(…, 0)`,
  then `nativeStop` frees the handle. Skipping the drain loses final byte counts.
- **Room schema changes need a migration** (`data/Database.kt`: `MIGRATION_1_2`
  and `MIGRATION_2_3` are hand-written; AutoMigration would copy whole tables)
  and the new schema JSON under `app/schemas/` must be committed, with a
  `MigrationTest` case. The schema is at version 3.
- **TAXII servers may reuse the `next` token** for every page of one paging
  session (OASIS medallion does). Only a run of empty pages counts as a loop.
  To test the TAXII client against a real server, run medallion and
  `VIGIL_TAXII_URL=http://127.0.0.1:5057/taxii2/ VIGIL_TAXII_USER=… VIGIL_TAXII_PASSWORD=… ./gradlew testDebugUnitTest --tests '*TaxiiLiveTest*' -Pvigil.skipCargo=true`
  (skipped without the variable).
- **Debug builds are `dev.vigil.inspector.debug`.** An older release install on
  the emulator is a different package; target the right one with `am start`.
- Stopping the engine must not race a blocking poll. All native calls go
  through `EngineHandle` (read lock), and `close()` takes the write lock.

## Code map

```
core/vigil-core/src/
  engine/mod.rs     runtime, TUN loop, dispatch, stats, flow tracker, Engine API
  engine/tcp.rs     SYN gate, relay, sniffing, policy decisions, alerts
  engine/udp.rs     UDP NAT, QUIC sniff window
  engine/dns.rs     DNS answer path, sinkhole, CNAME cloaking, upstream forwarding
  engine/sock.rs    protected sockets on the blocking pool, pooled upstream DNS sockets
  proto/{dns,tls,quic,http}.rs   parsers (pure)
  intel.rs          DomainSet / IpSet / Ja4Set / feed parsing
  policy.rs         Policy, feed categories, DoH host list
  detect.rs         beacon detector, alert limiter
  event.rs          event types + bounded queue
  config.rs         Config (JSON contract with the app)
core/vigil-jni/src/lib.rs     JNI surface (mirrors engine/VigilNative.kt)
core/vendor/netstack-smoltcp  patched netstack (TCP abort / reset reporting)
android/app/src/main/java/dev/vigil/inspector/
  vpn/              VigilVpnService, routes, config factory, tile, ServiceState
  engine/           VigilNative, PlatformBridge, EngineHandle, event/config models
  processing/       EventProcessor, ForegroundTracker, AlertNotifier
  data/             Room DB, settings, app resolver, feed catalog/repository,
                    JA4 validation and converters (Ja4.kt), STIX pattern reader (Stix.kt),
                    TAXII 2.1 client and indicator state (Taxii.kt)
  export/           ECS records, syslog/HTTP formats, ExportPipeline (retry), ElasticBulk, SiemExporter
  ui/               MainActivity, ViewModel, theme, components, screens/
```

**Contracts to keep in sync when changing them:**

- `core/vigil-core/src/config.rs` ↔ `engine/EngineConfig.kt`
- `core/vigil-core/src/event.rs` ↔ `engine/EngineEvent.kt` ↔ `docs/EVENTS.md`
- JNI signatures in `vigil-jni/src/lib.rs` ↔ `engine/VigilNative.kt` ↔
  `scripts/jni-smoke/…/VigilNative.java`
- The method names `ownerUid` and `protect` (looked up from native code) ↔
  `PlatformBridge.kt` and the ProGuard keep rules.
