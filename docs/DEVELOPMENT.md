# Development guide

How to set up a machine, build, run every test suite, and avoid the traps
already hit once. The project state and backlog are in [STATUS.md](STATUS.md).

## Toolchain

| Tool | Version used | Install |
|---|---|---|
| JDK | 17+ (21 works) | distro package |
| Android SDK | platform 36, build-tools 36.0.0 | `sdkmanager "platforms;android-36" "build-tools;36.0.0"` |
| Android NDK | **27.2.12479018** (pinned in `android/app/build.gradle.kts`) | `sdkmanager "ndk;27.2.12479018"` |
| Rust | **1.98.1** (pinned in `core/rust-toolchain.toml`) | `rustup` |
| Rust targets | `aarch64-linux-android armv7-linux-androideabi x86_64-linux-android` | `rustup target add …` |
| cargo-ndk | 4.x (4.1.2 for release builds) | `cargo install cargo-ndk --version 4.1.2 --locked` |
| Gradle | 9.8.0 via the wrapper | automatic |
| AGP, Kotlin, KSP | 9.4.1, 2.4.20, 2.3.12 (`android/build.gradle.kts`) | automatic |

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
app. Every one was green after the post-0.4.0 work; the counts are from
those runs.

```sh
cd core && cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace   # 190 unit tests
scripts/e2e-netns.sh          # 209 checks: direct, beacon (in-flow beaconing), apprules (per-app conditions and device state), capture (PCAPng export, PCAP-over-IP), edns (encrypted DNS, also via SOCKS5), socks5, wireguard stages (E2E_STAGES=...), needs internet, no root
scripts/jni-smoke.sh          # 38 checks, no root
cd android && ./gradlew lintDebug testDebugUnitTest   # 212 JVM tests (1 skipped: TaxiiLiveTest)
scripts/android-e2e.sh        # 28 checks, needs an emulator/userdebug device (see below)
scripts/android-lifecycle.sh  # 21 checks + always-on at boot (reboots; SKIP_BOOT=1 to skip)
scripts/android-features.sh   # 14 checks: DoH via Quad9, SOCKS5 via a proxy on the host, fail-closed, Maximum throughput restart
scripts/android-newfeatures.sh # 12 checks: tracker and spyware downloads (internet), spyware sinkhole, health check screen, PCAP-over-IP, per-app network conditions
LOCAL=1 BYTES=1000000000 scripts/bench-throughput.sh   # engine ceiling
scripts/bench-throughput.sh                            # vs. real internet link
```

`bench-throughput.sh` reports the engine's CPU time (utime + stime from
`/proc`, during the transfer only) per GB or per operation, context switches
and RSS. `MODE=` selects the workload; the small-packet ones use local
servers (`scripts/e2e/benchload.py`):

```sh
MODE=tcp N=5000 CONC=16 scripts/bench-throughput.sh   # short HTTP requests, one connection each
MODE=udp N=50000 CONC=16 scripts/bench-throughput.sh  # 100-byte request/reply datagrams
MODE=dns N=50000 CONC=16 scripts/bench-throughput.sh  # queries to the virtual resolver
MODE=idle SECS=10 scripts/bench-throughput.sh         # CPU while connections sit idle
VIGIL_CLI=/path/to/other/vigil-cli ...                 # compare builds; STATS=1 keeps stats events
```

The WireGuard client has an in-process benchmark against the unit tests'
user-space peer (3 bulk echo streams of 64 MiB, small round trips timed on
a fourth stream meanwhile; the single-threaded peer caps the bulk rate):

```sh
cd core && cargo test --release -p vigil-core -- --ignored wg_bench --nocapture
```

Moving encryption out of the smoltcp lock took the probe round trip under
load from p50 540 us / p99 1.3 ms to p50 120 us / p99 0.2 ms, and the bulk
echo from 105-135 to 144 MB/s (3 runs each, same host).

Numbers on the development host (x86_64, 2 engine workers, 3 runs each):

| Workload | 0.3.0 | now |
|---|---|---|
| bulk 1 GB (`LOCAL=1`) | 12.1 s CPU/GB, 1.30 Gbit/s | 5.6 s CPU/GB, 2.86 Gbit/s |
| tcp 5000 connections | 452 us/op, 410 req/s, RSS 551 MB | 374 us/op, 5,250 req/s, RSS 246 MB |
| udp 50 k datagrams | 39.0 us/op | 39.2 us/op |
| dns 50 k queries | 74.0 us/op | 65.0 us/op |
| idle 10 s, 4 open connections | 0.02 s | 0.02 s |

That host's clock source is HPET, so every clock read is a slow device
access (about a third of the engine's CPU time in these runs, mostly tokio's
scheduler bookkeeping). Phones read the clock cheaply; compare builds on the
same machine rather than taking the absolute numbers as a phone's. `perf` is
usually not permitted there (`perf_event_paranoid` 4); an `LD_PRELOAD`
sampler with frame pointers (`RUSTFLAGS="-C force-frame-pointers=yes"`,
`CARGO_PROFILE_RELEASE_STRIP=none`) works instead.

How the no-root tests work: `unshare -rnm` creates a user and network
namespace in which we are "root". A TUN device is created there, and its file
descriptor is passed over a Unix socket (SCM_RIGHTS) to `vigil-cli` running in
the host namespace. So traffic from `dig`/`curl` inside the namespace goes
through the real engine and out through the host's network.
`scripts/e2e/last-events.jsonl` keeps the events of the last run for
inspection. The CLI attributes nothing to apps, except with `--uid N`
(every connection is UID N); `--state FILE` sets the device state for
per-app conditions and re-reads it on `SIGUSR1`, which the apprules stage
sends from inside the namespace.

## Emulator for on-device tests

```sh
sdkmanager "emulator" "system-images;android-35;google_apis;x86_64" "system-images;android-36;google_apis;x86_64"
echo no | avdmanager create avd -n vigil35 -k "system-images;android-35;google_apis;x86_64" -d pixel_6
echo no | avdmanager create avd -n vigil36 -k "system-images;android-36;google_apis;x86_64" -d pixel_6   # targetSdk 36 behaviour
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

## Release checklist

Used for v0.2.0 to v0.4.0 (GitHub pre-releases, release-signed). Do the steps
in order; run heavy builds and the emulator one at a time (memory, see
Gotchas).

1. Bump versions: `android/app/build.gradle.kts` (`versionCode` =
   major×10000 + minor×100 + patch, `versionName`), `core/Cargo.toml`
   workspace version, then `cargo metadata --offline` to refresh the three
   vigil entries in `Cargo.lock` (check the lock diff touches only those),
   and `packaging/fdroid/dev.vigil.inspector.yml` (versionName/Code, commit
   tag, CurrentVersion/Code, APK name).
2. Store changelog `fastlane/metadata/android/en-US/changelogs/<versionCode>.txt`
   (≤ 500 characters); rename `## Unreleased` in CHANGELOG.md to
   `## X.Y.Z (date): GitHub pre-release`; update STATUS.md (header, release
   row, "New in" section).
3. Gates: fmt, clippy, `cargo test --locked`, Gradle lint + unit tests.
   Commit "Version X.Y.Z", push `main`, wait for CI to pass on that commit.
4. Build from clean clones of that exact commit:
   signed — clone to `/tmp/vigil-rel`, copy `android/local.properties` and
   `~/.vigil-release/keystore.properties`, `./gradlew assembleRelease
   --no-build-cache --no-daemon`; unsigned — clone to a different, deeper
   path, `assembleRelease -Pvigil.unsignedRelease=true --no-build-cache`.
   Compare every APK entry except the signature files (must be identical),
   check `strings libvigil.so | grep -E '/tmp/|/home/'` is empty,
   `apksigner verify --print-certs` shows `dc7a34da…8db3bc`, and
   `aapt2 dump badging` shows the new version.
5. On an emulator (vigil36): install the *previous published* release, start
   inspection, make traffic, then `adb install -r` the new APK; check the
   Room `user_version` migrated, row counts survived, traffic flows, every
   screen opens, and no `UnsatisfiedLink`/`NoSuchMethod`/
   `SerializationException`/crash in logcat (R8 build).
6. Tag `git tag -a vX.Y.Z <commit> -m "vigil X.Y.Z"`, push the tag,
   `gh release create vX.Y.Z --prerelease --title "vigil X.Y.Z" --notes-file …
   vigil-X.Y.Z.apk vigil-X.Y.Z.apk.sha256` (asset names are what the F-Droid
   recipe's `Binaries:` expects). Release notes: install/upgrade notes,
   checksum command, certificate SHA-256, what's new, caveats.
7. Download the assets anonymously and `sha256sum -c`. Delete the `/tmp`
   build trees (they contain a copy of `keystore.properties`).

## Gotchas already paid for

- **Don't `pkill -f <pattern>` from a Bash tool call** whose own command line
  contains the pattern: it kills the calling shell (exit 144). Use
  `./gradlew --stop`, or `pgrep -f '^exact command'`.
- **Sub-agents in worktrees start from the *pushed* `main`**, not local
  unpushed commits. Push (or tell them) before spawning, or expect to adapt
  their branch to newer local work when merging.
- **One emulator at a time.** It gets OOM-killed (about 4 GB RSS) if
  Gradle/cargo builds run alongside it on a 14 GB host. Build first, or stop
  the emulator (`adb emu kill`) before parallel builds, and `adb emu kill`
  when done.
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
  `ConnectionReset`, plus performance fixes: `shutdown()` completes when the
  FIN is queued (it waited out TIME-WAIT, holding every relay 10 s), TIME-WAIT
  lasts 1 s, a new SYN replaces an old socket with the same 4-tuple (a
  SYN|RST does not), `Stack::tcp_sender` lets the TUN reader feed the stack
  directly, and the poll loop yields without a tokio driver turn. Later
  fixes: sockets that smoltcp resets back to LISTEN (a RST in SYN-RECEIVED)
  or that never took their SYN (after 10 s) are reaped as resets instead
  of lingering as listeners, and `TcpAbortHandle::closed()` lets the relay
  notice that a half-closed app side was reset. Changes are marked `vigil patch`;
  re-apply them when upgrading the crate.
- **boringtun is vendored too** (`core/vendor/boringtun`, unmodified source)
  because its manifest also builds a `staticlib` and a `cdylib`, which
  cargo-ndk copied into `jniLibs` as a stray `libboringtun-*.so`. Keep
  `crate-type = ["rlib"]` when upgrading.
- **tokio's `try_send` on a fresh UDP socket returns WouldBlock** until the
  reactor has seen it writable. The WireGuard driver sends with a direct
  `send(2)` (socket2) so the first handshake is not silently dropped.
- **The e2e WireGuard stage needs kernel WireGuard links in an unprivileged
  namespace** (`ip link add … type wireguard`); `scripts/e2e/wgconf.py`
  configures them over generic netlink, so wireguard-tools are not needed.
  Without the module the stage prints SKIP. `E2E_STAGES="wireguard"` (or
  `direct`, `beacon`, `apprules`, `capture`, `edns`, `socks5`) runs single
  stages; `E2E_KEEP=1` keeps the work directory (configs, events, captured
  files) for inspection.
- **Stopping the engine is two steps:** `nativeShutdown` (stops the runtime and
  queues `flow_end` for every open flow), drain with `nativePollEvents(…, 0)`,
  then `nativeStop` frees the handle. Skipping the drain loses final byte counts.
- **Room schema changes need a migration** (`data/Database.kt`: `MIGRATION_1_2`,
  `MIGRATION_2_3` and `MIGRATION_3_4` are hand-written; AutoMigration would copy
  whole tables) and the new schema JSON under `app/schemas/` must be committed,
  with a `MigrationTest` case. The schema is at version 4.
- **The ASN table is not parsed by `nativeInspectFeedFile`** (that parses
  blocklists). `AsnDatabase.convert` gunzips and validates the download in
  Kotlin; the engine then loads the TSV with category `asn`. To measure the
  engine side on the full file: `curl -O https://iptoasn.com/data/ip2asn-combined.tsv.gz &&
  gunzip ip2asn-combined.tsv.gz && core/target/release/vigil-cli asn ip2asn-combined.tsv 1.1.1.1`.
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
  engine/mod.rs     runtime, TUN loop, dispatch, stats, flow tracker, feed preload, task supervision, Engine API
  engine/tcp.rs     SYN gate, relay, sniffing, policy decisions, alerts
  engine/udp.rs     UDP NAT, QUIC sniff window, flow cap and eviction
  engine/dns.rs     DNS answer path, sinkhole, CNAME cloaking, upstream forwarding
  engine/dns_upstream.rs  encrypted upstream DNS (DoT, DoH over HTTP/2 or 1.1), TLS config
  engine/sock.rs    protected sockets on the blocking pool, pooled upstream DNS sockets
  engine/capture/   packet capture: ring.rs (byte ring), pcap.rs (PCAPng/PCAP writers), stream.rs
                    (PCAP-over-IP server), mod.rs (hooks, flow/UID bindings, export)
  engine/upstream/  the dialer for every upstream socket (relays, UDP flows, plain DNS, DoT/DoH):
                    mod.rs direct + dispatch, wireguard.rs (boringtun + client smoltcp), socks5.rs
  proto/{dns,tls,quic,http}.rs   parsers (pure); tls.rs also computes JA4
  proto/doh.rs      DoH HTTP/1.1 request encoding and response parsing (pure)
  ../testdata/edns/ test-only CA and server certificate (dns.vigil.test, 127.0.0.1)
  packet.rs         L3/L4 parsing for dispatch, builders for UDP replies and TCP resets
  tun.rs            non-blocking TUN descriptor I/O
  platform.rs       Platform trait (UID lookup, protect) the host implements
  dnscache.rs       IP → name cache learned from DNS answers
  intel.rs          DomainSet / IpSet / Ja4Set / feed parsing
  asn.rs            IP → ASN table (iptoasn TSV, feed category `asn`); Policy::asn_lookup, one lookup per flow
  policy.rs         Policy (precedence in its header), per-app conditions and domain rules, feed categories,
                    DoH host list, JA4 block reasons
  detect.rs         beacon detectors (new connections, bursts inside long-lived flows), alert limiter
  event.rs          event types + bounded queue
  config.rs         Config (JSON contract with the app), `feeds`; config/upstream.rs the upstream section,
                    config/app_rules.rs app_rules / app_domain_rules and DeviceState (nativeSetDeviceState),
                    config/capture.rs the capture section
core/vigil-jni/src/lib.rs     JNI surface (mirrors engine/VigilNative.kt)
core/vigil-cli/src/main.rs    Linux host: run (--tun/--fd-socket, --uid, --state, --pcap-on-exit), parse-feed, asn, ja4,
                              quic-probe, wg-keypair, default-config
core/vendor/netstack-smoltcp  patched netstack (TCP abort / reset reporting, TIME-WAIT, LISTEN reaping, polling fixes)
core/vendor/boringtun         boringtun 0.7.1 built as an rlib only
android/app/src/main/java/dev/vigil/inspector/
  vpn/              VigilVpnService (session, device-state push, feed preload list), VpnRoutes, ConfigFactory,
                    InspectorTileService, ServiceState, ServicePolicy (pure service decisions: foreground on
                    quick restart, lockdown warning), RestartBudget (restarts after engine errors), IpLiteral
  engine/           VigilNative, PlatformBridge, EngineHandle (incl. exportPcap), EngineConfig, EngineEvent
  processing/       EventProcessor, EntityMapping (events → rows), NewAsnDetector (new_asn alerts),
                    ExfilDetector (upload-volume alerts), ForegroundTracker, AlertNotifier
  data/             Database.kt (Room entities, DAOs, migrations); Settings.kt (SettingsStore, SettingsCodec),
                    UpstreamSettings, WgQuick (parser), EncryptedDnsSettings, CaptureSettings,
                    AppRules (per-app conditions and domain rules), AlertMutes; AppResolver;
                    FeedCatalog, FeedRepository (downloads, FeedUpdateWorker), FeedValidation,
                    FeedHttp (GET with redirects handled so credentials stay on the entered host),
                    BoundedLineReader (line and size limits for untrusted downloads);
                    Asn.kt (ASN table download/validation and labels); Ja4.kt (JA4 validation, converters);
                    Stix.kt (STIX patterns, streamed bundles, relationship labels, app certificates);
                    Taxii.kt (TAXII 2.1 client and indicator state);
                    Trackers.kt (companiesdb conversion, suffix index, lazy loader),
                    TrackerUsage.kt (per-app tracker summaries and their queries);
                    Spyware.kt (packs, converters, MvtIndex, SpywareLabels for alerts), MiniYaml.kt
                    (block-YAML reader for the indicator sources), HealthCheck.kt (the pure health check),
                    InstalledApps.kt (packages and signing certificates)
  export/           ExportRecords.kt (ECS records incl. vigil.tracker; WireFormats: syslog/HTTP bodies),
                    ExportPipeline (retry, batch splitting), ElasticBulk, SiemExporter
  ui/               MainActivity (navigation), MainViewModel, Routes, Format, Glossary, theme/, components/,
                    Blocking.kt (registrable domains, block reason texts), CaptureExport.kt (PCAPng export
                    requests), HealthCheckViewModel, Retained.kt (rotation-safe, in-memory form drafts)
  ui/screens/       Dashboard (Overview), Activity, Dns, FlowDetail, Apps (incl. app detail), Alerts, Rules,
                    Feeds, Export, Settings, Upstream, Onboarding, CaptureSettings (Settings → Packet capture,
                    export buttons), HealthCheckScreen, DomainActions (block/allow buttons, per-app rules),
                    Trackers (tracker tags, app trackers section), Common
android/app/src/test/resources/  spyware/ and trackers/ excerpts of the real sources (licences in spyware/NOTICE)
```

**Contracts to keep in sync when changing them:**

- `core/vigil-core/src/config.rs` (+ `config/upstream.rs`,
  `config/app_rules.rs`, `config/capture.rs`) ↔ `engine/EngineConfig.kt` ↔
  `vpn/ConfigFactory.kt`. Rust tests parse the JSON asserted in
  `ConfigFactoryTest` verbatim: `feeds_json_contract` (start-config
  `feeds`), `upstream_json_contract`, `app_rules_json_contract` (per-app
  rules and the `nativeSetDeviceState` payload) and `capture_json_contract`.
  Change both sides together.
- `core/vigil-core/src/event.rs` ↔ `engine/EngineEvent.kt` ↔ `docs/EVENTS.md`
- Block `reason` strings (`policy.rs`) ↔ `ui/Blocking.kt` (`BlockReasons`)
- JNI signatures in `vigil-jni/src/lib.rs` ↔ `engine/VigilNative.kt` ↔
  `scripts/jni-smoke/…/VigilNative.java` ↔ the JNI table in `docs/EVENTS.md`
  (+ `EngineHandle` wrappers such as `exportPcap`)
- The method names `ownerUid` and `protect` (looked up from native code) ↔
  `PlatformBridge.kt` and the ProGuard keep rules.
