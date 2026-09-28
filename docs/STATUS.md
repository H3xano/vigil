# Project status and handoff

Last updated: 2026-09-28, version 0.3.0 (encrypted DNS, JA4/TAXII,
WireGuard/SOCKS5 chaining), GitHub pre-release.

Read this first when resuming work. It records what exists, what has been
verified and how, what is still missing (in priority order), and why the
non-obvious decisions were made. [DEVELOPMENT.md](DEVELOPMENT.md) covers how
to rebuild the toolchain and run the tests.

## Where things stand

vigil is **feature-complete for a 0.1 release and verified on an Android 15
emulator**. The owner installed the v0.1.0 APK on their own phone
(2026-09-27) and reports that it works. That was an informal check; the
systematic device testing in backlog item 1 is still to do.

| Area | State | Verified by |
|---|---|---|
| Rust engine (`core/vigil-core`) | done | 113 unit tests, 156 end-to-end checks with real traffic (`scripts/e2e-netns.sh`, stages direct / edns / socks5 / wireguard) |
| JNI layer (`core/vigil-jni`) | done | 28 checks from a real JVM (`scripts/jni-smoke.sh`) |
| Android app (`android/`) | done | 86 Kotlin unit tests, lint clean; on-device: 28 (`android-e2e.sh`), 21 lifecycle (`android-lifecycle.sh`), 12 DoH/SOCKS5 (`android-features.sh`) |
| Release APK (R8-minified) | builds, runs | manual smoke test on the emulator (JNI survives R8) |
| Linux CLI (`core/vigil-cli`) | done | used by the e2e and benchmark scripts |
| CI (`.github/workflows/ci.yml`) | **green** on GitHub Actions | both jobs pass: engine (fmt, clippy, tests, netns e2e, JNI) and android (lint, unit tests, release APK artifact) |
| Docs | README, ARCHITECTURE, EVENTS, PRIVACY, DEVELOPMENT, this file | |
| Repository | **public** since 2026-09-28: https://github.com/H3xano/vigil (`main`) | |
| Release | [v0.3.0](https://github.com/H3xano/vigil/releases/tag/v0.3.0) pre-release, **release-signed** APK (3 ABIs); v0.1.0 was debug-signed | checksum verified after upload; R8 build smoke-tested on the emulator |

Measured numbers (see the README "Performance" section):

- 1.28 Gbit/s through the engine on an x86_64 host, and no measurable
  overhead on a 39 Mbit/s internet link.
- About 12 s of CPU per GB relayed on the host.
- Engine RSS is 3–4 MB without feeds. The 850 k-domain feed uses 21 MB and
  parses in 0.44 s on the emulator.
- `libvigil.so` is 1.4 MB (arm64) and the release APK is 6.8 MB (three ABIs).

## Review fixes (2026-09-27, after 0.1.0)

A full review (engine, service/data layer, UI/export, competitive landscape)
found no remotely triggerable crash but many resource-limit and failure-path
problems. All were fixed except the items listed below; every suite is green
(numbers in the table above), and an intent with an unknown `destination` no
longer crashes the app (checked by hand on the emulator).

- Engine: global caps on UDP flows (evict longest-idle), TCP relays, pending
  connects and in-flight DNS; shared receive buffers; threat alerts keyed by
  feed entry + UID, bounded limiter and a 120/min alert budget; IP feeds
  applied to UDP/53; DNS over TCP to any resolver inspected; NAT64 addresses
  matched against IPv4 feeds; duplicate-SYN suppression; real TCP resets both
  ways (vendored netstack patch); `protect()` off the async workers and pooled
  upstream DNS sockets; config validation; `nativeShutdown` drains final
  `flow_end`s; REFUSED for multi-question queries; TC passed to clients.
- Service/data: engine errors restart the session (3 per 5 min, then stop with
  a notification, so the device is never left black-holed); all non-local IPv6
  (incl. NAT64) routed; ordered lifecycle commands and `stopSelf(startId)`;
  exception handler; package-change receiver; strict resolver validation and
  surfaced config rejections; serialised, cancellable, validated feed
  downloads; schema v2 (indices, migration); chunked retention and VACUUM.
- UI/export: SIEM batches retried until delivered (network-aware), Elastic
  per-item results with deterministic `_id`/`event.id`; masked tokens and
  cleartext warnings; route whitelist; throttled queries; WCAG-contrast light
  theme; TalkBack labels; onboarding, glossary help, feed progress, empty
  states; accurate privacy wording about feed downloads.

**Lifecycle verified on the emulator (2026-09-28):**
`scripts/android-lifecycle.sh` passes 21/21. It covers Wi-Fi/cellular
switches, airplane mode toggled under load, Doze, an engine error (injected
through a debug-only intent) that restarts the session, giving up after the
restart budget without black-holing the device, process death (START_STICKY),
and Private DNS automatic and strict. Always-on VPN starts 2 s after a reboot
with the service left `exported="false"`. A real TUN read error has still
never been observed, so the injected error stands in for it.

## New in 0.3.0 (released 2026-09-28 as a pre-release)

Three features, built in parallel and integrated; every suite above passes
on the merged tree, and direct-mode throughput is unchanged (1,296 Mbit/s).

- **Encrypted upstream DNS:** DoT and DoH (HTTP/2, HTTP/1.1 fallback) with
  Quad9 / Cloudflare / Google / Mullvad presets or a custom server, fail-closed
  by default (`fallback_plain` off → SERVFAIL, never cleartext). rustls with
  ring and webpki-roots. Verified on the emulator with Quad9 DoH.
- **JA4 threat matching and TAXII 2.1:** `ja4` feeds (exact and `a_b_*`
  entries), `threat_ja4` alerts, optional `block_ja4_matches`; TAXII 2.1
  collections (domains, IPs, JA4) polled incrementally; Room schema v3.
  Tested against an OASIS medallion server. The only built-in JA4 source
  (FoxIO mapping, 4 malware fingerprints) is off by default; its licence
  (FoxIO License 1.1, non-commercial) is downloaded by the device, not
  redistributed; the owner decided to keep it in the catalogue (2026-09-28).
- **Upstream chaining:** all upstream sockets go through one dialer
  (`engine/upstream/`): direct, WireGuard (boringtun + a client smoltcp
  stack, wg-quick import) or SOCKS5 (CONNECT, UDP ASSOCIATE, auth,
  `send_domain` for Tor). Fail-closed by default. Encrypted DNS also goes
  through the dialer. SOCKS5 verified on the emulator; WireGuard verified
  against a kernel peer in the netns e2e only.

Costs and caveats: arm64 `libvigil.so` grew from 1.44 MB to 3.16 MB
(rustls/ring/h2 ≈ 1.4 MB, boringtun ≈ 0.3 MB). WireGuard: one peer, a
256 KiB tunnelled TCP window, IPv6 only with an IPv6 tunnel address. Tor
(SOCKS5) cannot carry UDP, so QUIC falls back to TCP. `via` and the DNS
`upstream` are in events and SIEM export but not stored in Room.
Still needs a device: a real WireGuard provider `.conf` (roaming, battery
with keepalive) and Orbot on 127.0.0.1:9050 with Orbot excluded from the VPN.

## New after 0.3.0 (2026-09-28, unreleased)

Built in parallel by three agents, then a toolchain upgrade on the merged
tree. Every suite passes (numbers in DEVELOPMENT.md).

- **Path and DNS transport per connection:** Room schema v4 stores `via`
  (direct / WireGuard / SOCKS5) and the DNS `upstream` (UDP / TCP / DoT /
  DoH); shown in flow detail and Activity (with a "via tunnel/proxy" filter).
- **Offline ASN enrichment:** iptoasn.com (public domain), downloaded weekly
  (9 MB gzipped), about 10 MB of engine memory; `asn` on flow events, AS
  labels in the UI, ECS `destination.as.*` in the SIEM export. Opt-in
  `new_asn` alerts ("an app contacted a network it never used") with a
  learning period (7 days by default).
- **Beaconing inside one connection** (`beacon` with `detail.kind =
  "intra_flow"`), sampled from flow counters once per housekeeping tick;
  push channels (FCM, Apple, Mozilla) are ignored by default.
- **Upload-volume alerts** (`exfil_volume`, app-side): background uploads
  above a floor (50 MB/h by default) and 3× the app's own baseline, one-way
  traffic only; backup/sync apps exempt.
- **Performance:** 5.6 s CPU per GB instead of 12.1, 2.9 Gbit/s instead of
  1.3 on the host; fixed relays being held 10 s after close (and SYNs on a
  reused port being swallowed): 5,000 short connections in 1 s instead of
  12–23 s. Events reach the app up to 20 ms later (batched).
- **One engine worker by default:** 17–34% less CPU than two; the "Maximum
  throughput" setting switches to two (session restart). Rust's own default
  stays 2 (CLI and benchmarks).
- **Toolchain:** Gradle 9.8.0, AGP 9.4.1, Kotlin 2.4.20, compileSdk and
  targetSdk 36, current AndroidX, Room 2.8.5 (KSP2), CI actions on Node 24;
  the lint `GradleDependency` check is enabled again. Reproducible builds
  still verified (two clean builds, identical APKs).

## Feature inventory

**Engine:** TUN dispatch; user-space TCP (smoltcp via `netstack-smoltcp`)
with a SYN gate that connects upstream first; own UDP NAT; DNS
inspection/sinkholing (`0.0.0.0`/`::` or NXDOMAIN) with CNAME-cloaking
detection; DNS over TCP to the virtual resolver; truncation retry over TCP;
IP→name cache; TLS ClientHello parsing across records and segments; JA4;
QUIC v1/v2 Initial decryption with CRYPTO reassembly; HTTP Host sniffing;
feeds (hosts, domains, AdGuard `||d^`, IP/CIDR) streamed from disk into
arena sets; policy (app block, allow/deny, feeds, encrypted-DNS blocking);
detectors (beaconing, threat hits, hard-coded DNS, encrypted DNS); bounded
event queue; `flow`/`flow_update`/`flow_end` contract.

**App:** VpnService (always-on capable, Quick Settings tile, LAN exclusion
routes, underlying-network DNS tracking); EngineHandle lock; batched Room
persistence; UID→app resolution including shared UIDs; foreground/background
tagging (usage access); novelty alerts (opt-in); alert notifications; feed
catalogue (19 built-in) with daily WorkManager refresh and atomic
validated downloads; custom feeds with an Authorization header (MISP);
SIEM export (syslog UDP/TCP/TLS with KeyChain mTLS, HTTP NDJSON / Splunk
HEC / Elastic bulk); Compose UI (Overview, Activity, Apps plus detail,
Alerts, Settings, Feeds, Export, Rules, Flow detail); retention and clear
history.

## Backlog (priority order)

1. **Test on physical phones systematically.** The owner's phone works
   informally (record its model and Android version here). The lifecycle
   behaviour passes on the emulator (see above); `scripts/android-lifecycle.sh`
   also runs on a rooted/userdebug phone. Still needed on real hardware: at
   least one Pixel and one Samsung (One UI is aggressive with background
   services), battery drain over a day, and an IPv6-only carrier (464XLAT /
   NAT64). Also: a speed test with vigil on, with "Maximum throughput" off
   (1 engine worker, the default) and on (2 workers), plus vigil's battery
   use in Android settings over a day in each mode, to confirm the default.
   And WireGuard with a real provider `.conf`, and Orbot on 127.0.0.1:9050.
2. **F-Droid submission.** Decided: F-Droid first, with reproducible builds so
   F-Droid publishes the developer-signed APK. Done: release keystore (kept
   outside the repo by the owner; certificate SHA-256
   `dc7a34da…8db3bc`, full value in the recipe), fastlane metadata, the recipe
   `packaging/fdroid/dev.vigil.inspector.yml`, pinned Rust
   (`core/rust-toolchain.toml`), and a two-build reproducibility check on one
   machine. The repository is public (2026-09-28), so the remaining step is
   to open a merge request adding the recipe to fdroiddata
   (gitlab.com/fdroid/fdroiddata, as `metadata/dev.vigil.inspector.yml`). Play remains an option later
   (needs VpnService and `QUERY_ALL_PACKAGES` declarations).
3. **ICMP relay.** `ping` through vigil currently fails. Android apps can
   open unprivileged ICMP datagram sockets (`SOCK_DGRAM`/`IPPROTO_ICMP`), so
   echo requests could be relayed in `engine/mod.rs` `dispatch()` (the
   `_ => drop_it()` arm).
4. **More per-packet CPU work** (5.6 s/GB now, from 12.1). Ranked ideas from
   the profiling pass: a 4-tuple lookup instead of smoltcp's per-packet
   linear socket scan (big refactor); lazy or pooled per-connection 64 KB
   buffers (cuts zeroing on short connections); a coarse clock for the
   smoltcp loop (little gain on phones). Profile without `perf` as described
   in DEVELOPMENT.md.
5. **WireGuard throughput benchmark** and a larger tunnelled TCP window
   (256 KiB today, about 40 Mbit/s at 50 ms RTT).
6. **Persist the upload baseline in Room** (it is in `exfil_baseline.json`
   today) and export `new_asn` / `new_destination` alerts to the SIEM.
7. **Geolocation** (country of the address, not of the AS registration) if a
   free offline dataset with a compatible licence exists.
8. **PCAP export** of selected flows, for Wireshark users.
9. **compileSdk and targetSdk 37.** The build is on compileSdk and
    targetSdk 36 with the newest AndroidX that supports them. Compose BOM
    2026.08.00+ (UI 1.12), core 1.19, lifecycle 2.11 and navigation-compose
    2.10 need compileSdk 37; lint's `GradleDependency` warnings for them
    (and `OldTargetApi`) are suppressed line by line in
    `app/build.gradle.kts`. targetSdk 37 needs a review of the Android 17
    behaviour changes first.
10. Smaller items:
    - Hide or collapse Chrome's unused preconnect flows (0 bytes, name from
      DNS).
    - Feed the DoH detection list from HaGeZi `wildcard/doh-onlydomains.txt`
      instead of the hard-coded list in `policy.rs`.
    - Extend `ECH_PUBLIC_NAMES` in `proto/tls.rs` as providers deploy ECH.
    - Handle IP fragments (currently dropped and counted).
    - UI tests (Compose) and a dark-mode screenshot set.
    - Room migrations: the schema is at version 2 (exported to
      `android/app/schemas`); every entity change needs a migration and a
      `MigrationTest` case.
    - Move UI strings to resources (localisation) and add a theme toggle /
      dynamic colour; both were left out of the review fixes.
    - Persist unsent SIEM alerts across process death (the retry queue is
      in memory).

## Known limitations (by design or platform)

- One VPN at a time (Android limitation).
- Private DNS in strict mode hides DNS. The app shows a warning; names still
  come from SNI.
- Real ECH hides the destination name. Only provider public names are seen.
- DNS-derived names (`domain_source = "dns"`) are hints and never used for
  blocking, because CDN IPs are shared.
- A blocked app's DNS answers are cached by Android for the sinkhole TTL
  (60 s), so unblocking takes effect for names only after that.
- QUIC sniffing only looks at the first datagram of flows to ports 443/80; an
  adversarial app can evade it (see ARCHITECTURE.md).
- Engine resource caps (`max_udp_flows` etc.) are read at start; changing them
  needs a restart.

## Decision log

| Decision | Reason |
|---|---|
| Rust engine + Kotlin app, JNI (not UniFFI) | Tiny surface (9 functions), and no generated bindings to maintain. |
| Poll events instead of JNI callbacks | Keeps JVM calls off the packet path; a slow consumer drops events, not packets. |
| `netstack-smoltcp` instead of `ipstack`/tun2proxy | smoltcp's TCP is mature, and vigil keeps control of raw packets. `ipstack` describes itself as unstable and uses unbounded channels. |
| One engine worker by default, two with "Maximum throughput" | Phones spend their time on small packets, where one worker uses 17–34% less CPU; it still relays about 1.75 Gbit/s on the host, beyond typical phone links. To be confirmed on a phone (backlog 1). |
| Netstack TIME-WAIT 1 s and a new SYN replaces an old socket | The app side is a local TUN with no delayed segments; the 10 s TIME-WAIT held relays and buffers and swallowed SYNs on reused ports. |
| iptoasn.com for ASN data | Public domain and anonymously downloadable; IPinfo Lite needs a token and is CC-BY-SA, DB-IP's URL changes monthly. |
| 64 KB TCP window | The netstack default (320 KB × 4 buffers per connection) is too much memory on a phone, and 256 KB measured no faster. |
| Upstream connect before SYN-ACK | Faithful failures for apps. |
| minSdk 29 | `getConnectionOwnerUid`; the pre-29 kernel paths are SELinux-blocked. |
| Hand-written parsers, not `nom` | Small, dependency-free and fuzz-tested. |
| Arena-backed sorted `DomainSet` | 2.3 M domains in 57 MB, with a streaming build. |
| Settings as one JSON document in SharedPreferences | Atomic, observable, trivially extensible. |
| App excluded from its own VPN | Covers feed download and export sockets too; `protect()` is still applied to relay sockets. |
| Cleartext and user CAs allowed | Enterprise SIEM collectors on private CAs or plain HTTP on the LAN. Documented in `network_security_config.xml`. |
| Apache-2.0 | Friendly to enterprise and SIEM users. |
| F-Droid first, reproducible builds | Matches the open-source analyst audience, avoids Play's VpnService/QUERY_ALL_PACKAGES review, and reproducibility lets users keep one signing key across GitHub and F-Droid. |
| Debug-only `INJECT_ENGINE_ERROR` intent | Lets the lifecycle script exercise the real restart path; guarded by `BuildConfig.DEBUG` and the service is not exported. |
| rustls with ring, not aws-lc-rs | aws-lc-rs is hard to cross-compile for Android and to build reproducibly. |
| DoH over HTTP/2 (h2 crate) | Quad9 and Mullvad reject HTTP/1.1 DoH; hyper would be heavier. |
| One upstream dialer for every socket | Guarantees WireGuard/SOCKS5 fail-closed covers relays, UDP and all DNS paths; direct mode stays a plain protected socket. |
| boringtun vendored as an rlib | Otherwise cargo-ndk copied a stray `libboringtun` .so into the APK. |
| JA4 matches alert only by default | Fingerprints collide with benign clients (Sliver = Go's default TLS client). |
| Vendor netstack-smoltcp with a small patch | Upstream has no way to send a RST, so resets became FINs and truncated responses looked complete. Patch marked `vigil patch`. |
| Global resource caps, evict longest-idle UDP flow | One noisy app (P2P, WebRTC) must not exhaust memory or fds and take down every app's connectivity. |
| Threat alerts keyed by feed entry + UID | DGA/tunnelling produced one alert per random subdomain. |
| Engine error → bounded auto-restart | A dead TUN reader with routes up black-holes the device; the user may not notice. |
| SIEM: retry until delivered, deterministic record ids | Alerts are low-volume and high-value; ids make retries and Elastic partial failures idempotent. |
| Version pins (AGP 9.4.1, Kotlin 2.4.20, Gradle 9.8.0, compileSdk/targetSdk 36) | Newest stable, mutually compatible releases as of 2026-09. AGP 9 compiles Kotlin itself (no kotlin-android plugin); KGP is pinned on the build classpath to match the compose and serialization plugins. AndroidX stops where minCompileSdk 37 starts (backlog item 9). |
