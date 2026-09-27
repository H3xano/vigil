# Project status and handoff

Last updated: 2026-09-27, version 0.1.0 (first complete build).

Read this first when resuming work. It records what exists, what has been
verified and how, what is still missing (in priority order), and why the
non-obvious decisions were made. [DEVELOPMENT.md](DEVELOPMENT.md) covers how
to rebuild the toolchain and run the tests.

## Where things stand

vigil is **feature-complete for a 0.1 release and verified on an Android 15
emulator**. It has **not yet been run on a physical phone**.

| Area | State | Verified by |
|---|---|---|
| Rust engine (`core/vigil-core`) | done | 40 unit tests, 43 end-to-end checks with real traffic (`scripts/e2e-netns.sh`) |
| JNI layer (`core/vigil-jni`) | done | 15 checks from a real JVM (`scripts/jni-smoke.sh`) |
| Android app (`android/`) | done | 12 Kotlin unit tests, lint clean, 28 on-device checks (`scripts/android-e2e.sh`) |
| Release APK (R8-minified) | builds, runs | manual smoke test on the emulator (JNI survives R8) |
| Linux CLI (`core/vigil-cli`) | done | used by the e2e and benchmark scripts |
| CI (`.github/workflows/ci.yml`) | **green** on GitHub Actions | both jobs pass: engine (fmt, clippy, tests, netns e2e, JNI) and android (lint, unit tests, release APK artifact) |
| Docs | README, ARCHITECTURE, EVENTS, PRIVACY, DEVELOPMENT, this file | |
| Repository | private: https://github.com/H3xano/vigil (`main`) | |

Measured numbers (see the README "Performance" section):

- 1.28 Gbit/s through the engine on an x86_64 host, and no measurable
  overhead on a 39 Mbit/s internet link.
- About 12 s of CPU per GB relayed on the host.
- Engine RSS is 3–4 MB without feeds. The 850 k-domain feed uses 21 MB and
  parses in 0.44 s on the emulator.
- `libvigil.so` is 1.4 MB (arm64) and the release APK is 6.8 MB (three ABIs).

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

1. **Test on physical phones.** At least one Pixel and one Samsung
   (One UI is known to be aggressive with background services). Check
   always-on VPN at boot, Doze and battery drain over a day, Private DNS
   "automatic" behaviour, IPv6-only carriers (464XLAT), and network
   switches between Wi-Fi and cellular.
2. **Release signing and distribution.** Create a release keystore and
   `android/keystore.properties` (never commit either). Decide between
   F-Droid and Play. Play needs a VpnService declaration and justification
   for `QUERY_ALL_PACKAGES` (network monitoring qualifies, but it has to be
   declared).
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
    - Onboarding flow that walks through usage access and notifications.
    - UI tests (Compose) and a dark-mode screenshot set.
    - Room migrations: the schema is at version 1 (exported to
      `android/app/schemas`), and any entity change now needs a migration.

## Known limitations (by design or platform)

- One VPN at a time (Android limitation).
- Private DNS in strict mode hides DNS. The app shows a warning; names still
  come from SNI.
- Real ECH hides the destination name. Only provider public names are seen.
- DNS-derived names (`domain_source = "dns"`) are hints and never used for
  blocking, because CDN IPs are shared.
- A blocked app's DNS answers are cached by Android for the sinkhole TTL
  (60 s), so unblocking takes effect for names only after that.

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
| Version pins (AGP 8.7.3, Kotlin 2.1.0, Gradle 8.11.1) | These were cached and working on the development machine. Upgrading is backlog item 9. |
