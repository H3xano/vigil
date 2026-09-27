# Project status and handoff

Last updated: 2026-09-28, version 0.2.0 (review fixes, lifecycle testing,
release signing, F-Droid preparation).

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
| Rust engine (`core/vigil-core`) | done | 69 unit tests, 49 end-to-end checks with real traffic (`scripts/e2e-netns.sh`) |
| JNI layer (`core/vigil-jni`) | done | 26 checks from a real JVM (`scripts/jni-smoke.sh`) |
| Android app (`android/`) | done | 45 Kotlin unit tests, lint clean, 28 on-device checks (`scripts/android-e2e.sh`) |
| Release APK (R8-minified) | builds, runs | manual smoke test on the emulator (JNI survives R8) |
| Linux CLI (`core/vigil-cli`) | done | used by the e2e and benchmark scripts |
| CI (`.github/workflows/ci.yml`) | **green** on GitHub Actions | both jobs pass: engine (fmt, clippy, tests, netns e2e, JNI) and android (lint, unit tests, release APK artifact) |
| Docs | README, ARCHITECTURE, EVENTS, PRIVACY, DEVELOPMENT, this file | |
| Repository | **public** since 2026-09-28: https://github.com/H3xano/vigil (`main`) | |
| Release | [v0.2.0](https://github.com/H3xano/vigil/releases/tag/v0.2.0) pre-release, **release-signed** APK (3 ABIs); v0.1.0 was debug-signed | checksum verified after upload; R8 build smoke-tested on the emulator |

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
   NAT64).
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
4. **Per-packet CPU.** Profile the relay (about 12 s/GB). Candidates: a
   `Vec` allocation per packet in `dispatch`, mpsc hops (TUN → stack sink →
   smoltcp → stack stream → TUN writer), and reads of 16 KB copy chunks.
   Batching TUN reads or reusing buffers is likely the biggest win. Measure
   with `LOCAL=1 BYTES=1000000000 scripts/bench-throughput.sh`. A larger TCP
   window made no difference.
5. **STIX/TAXII 2.1 ingestion.** This was in the original idea but is not
   built. Custom feeds already accept MISP text exports; TAXII needs a
   collection poller (Kotlin) that converts domain-name and ipv4-addr
   indicators into a feed file.
6. **ASN / geo enrichment.** An offline IP→ASN database (e.g. iptoasn.com)
   would enable "new ASN for this app" alerts and nicer UI labels.
7. **Beaconing on long-lived connections.** Today only connection starts
   are observed. Periodic `flow_update` byte deltas could detect heartbeats
   inside one connection.
8. **PCAP export** of selected flows, for Wireshark users.
9. **Upgrade AndroidX.** Versions are pinned to what AGP 8.7.3 and
    compileSdk 35 support. Newer lifecycle, core and Room need AGP 8.9+ and
    compileSdk 36. The lint `GradleDependency` check is disabled because of
    this.
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
| Vendor netstack-smoltcp with a small patch | Upstream has no way to send a RST, so resets became FINs and truncated responses looked complete. Patch marked `vigil patch`. |
| Global resource caps, evict longest-idle UDP flow | One noisy app (P2P, WebRTC) must not exhaust memory or fds and take down every app's connectivity. |
| Threat alerts keyed by feed entry + UID | DGA/tunnelling produced one alert per random subdomain. |
| Engine error → bounded auto-restart | A dead TUN reader with routes up black-holes the device; the user may not notice. |
| SIEM: retry until delivered, deterministic record ids | Alerts are low-volume and high-value; ids make retries and Elastic partial failures idempotent. |
| Version pins (AGP 8.7.3, Kotlin 2.1.0, Gradle 8.11.1) | These were cached and working on the development machine. Upgrading is backlog item 9. |
