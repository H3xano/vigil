# Project status and handoff

Last updated: 2026-09-29, version 0.5.1 (fixes from a third review and
translation support, no new features), GitHub pre-release.

Read this first when resuming work. It records what exists, what has been
verified and how, what is still missing (in priority order), and why the
non-obvious decisions were made. [DEVELOPMENT.md](DEVELOPMENT.md) covers how
to rebuild the toolchain, run the tests and cut a release.

## Resume here (handoff of 2026-09-29)

State: `main` = tag `v0.5.1` plus the release docs commit, pushed; CI
green; v0.5.1 published as a GitHub pre-release (release-signed,
reproducible). Every host suite and every emulator suite passes (see the
table). No worktrees or feature branches are left.

**Waiting on the owner** (ask about these first; none can be done without them):

1. **Back up the release signing key to Bitwarden.** The key exists only in
   `~/.vigil-release/` (`vigil-release.jks` + `keystore.properties`) on the
   owner's machine; losing it means users can never upgrade. The Bitwarden
   CLI is installed at `~/.local/bin/bw` (v2026.9.0, logged out). The owner
   runs, in their own terminal (never paste the master password in chat):
   `~/.local/bin/bw login` then
   `~/.local/bin/bw unlock --raw > ~/.vigil-release/.bw-session && chmod 600 ~/.vigil-release/.bw-session`
   (`bw config server https://vault.bitwarden.eu` first if on the EU server).
   Then the assistant creates a secure note "vigil — Android release signing
   key" (hidden fields: store and key password; alias `vigil`; certificate
   SHA-256; restore instructions), attaches the `.jks` (needs Premium/Families,
   else base64 in the note), verifies by downloading it back and comparing
   bytes and opening it with the password, then runs `bw lock` and deletes the
   session file.
2. **F-Droid:** merge request opened 2026-09-29:
   https://gitlab.com/fdroid/fdroiddata/-/merge_requests/50590 (branch `vigil`
   on the fork gitlab.com/h3xano/fdroiddata, recipe pinned to the full hash of
   v0.5.1). The fork's CI can't run (new GitLab account not verified for
   shared runners); a note asks the maintainers to trigger it. Follow up on
   reviewer comments; update the MR branch rather than opening a new one.
3. **GitHub Support purge** of the 62 pre-rewrite commits (old author email /
   attribution trailers), still reachable by SHA: the request text is in
   `~/projects/vigil-github-purge-request.md` (outside the repo). After
   GitHub confirms, check e.g. `https://github.com/H3xano/vigil/commit/547958f`
   returns 404.
4. **Physical-phone testing** (backlog 1), especially battery with
   "Maximum throughput" off vs on, a real WireGuard provider `.conf`, and
   Orbot. Record the phone model and Android version below.

**Next development candidates** (owner has not chosen yet): the backlog below
from item 3 on. From the competitor review of 2026-09-28, still open: ready-made
SIEM content (Sigma rules, Wazuh decoders, Kibana/Splunk dashboards), MDM
managed configuration plus a device id in events, an incident bundle export
(alerts + flows + PCAP, hashed), a local automation API (intents / localhost),
user-defined detection rules, several WireGuard peers with per-app routing,
offline geolocation, a Play Store listing. Deliberately not planned: TLS
interception (MITM) and cosmetic ad blocking.

How recent work was done: features were built in parallel by sub-agents in
git worktrees (one per area, with a pre-agreed JSON/JNI contract), merged by
the main session, then an integration pass and the full test matrix
(including both emulators). See CLAUDE.md for the practical rules.

## Where things stand

vigil 0.5.0 is **feature-complete for its scope and verified on Android 15
and Android 16 emulators** (all suites below). The
owner installed v0.1.0 on their own phone (2026-09-27) and reports that it
works; that was an informal check, and the systematic device testing in
backlog item 1 is still to do.

| Area | State | Verified by |
|---|---|---|
| Rust engine (`core/vigil-core`) | done | 190 unit tests (1 ignored: `wg_bench`), 209 end-to-end checks with real traffic (`scripts/e2e-netns.sh`, stages direct / beacon / apprules / capture / edns / socks5 / wireguard) |
| JNI layer (`core/vigil-jni`) | done | 38 checks from a real JVM (`scripts/jni-smoke.sh`) |
| Android app (`android/`) | done | 237 Kotlin unit tests (1 skipped: live TAXII), lint clean; on-device on Android 15 **and** 16: 28 (`android-e2e.sh`), 23 lifecycle (`android-lifecycle.sh`), 14 features (`android-features.sh`), 12 new-feature checks (`android-newfeatures.sh`: tracker and spyware downloads, spyware sinkhole, health check screen, PCAP-over-IP, per-app network conditions) |
| Release APK (R8-minified) | builds, runs | reproducible (signed and unsigned builds from two clean clones in different paths, identical apart from signatures; no build paths in `libvigil.so`); installed over the published v0.5.0 on Android 16: schema 4 and rows kept, traffic flows, every screen opens, no JNI/serialization errors or crashes in logcat |
| Linux CLI (`core/vigil-cli`) | done | used by the e2e and benchmark scripts |
| CI (`.github/workflows/ci.yml`) | **green** on GitHub Actions at v0.5.1 | both jobs: engine (fmt, clippy, tests, netns e2e, JNI) and android (lint, unit tests, release APK artifact) |
| Docs | README, ARCHITECTURE, EVENTS, PRIVACY, DEVELOPMENT, HEALTH_CHECK, this file; all brought up to date after the post-0.4.0 work | |
| Repository | **public** since 2026-09-28: https://github.com/H3xano/vigil (`main`) | |
| Release | [v0.5.1](https://github.com/H3xano/vigil/releases/tag/v0.5.1) pre-release, **release-signed** APK (3 ABIs, 14.0 MB), certificate `dc7a34da…8db3bc`; v0.1.0 was debug-signed | checksum verified after an anonymous download |

Measured numbers (see the README "Performance" section):

- 2.87 Gbit/s through the engine on an x86_64 host (2 workers), 5.6 s of
  CPU per GB (was 12.1 at 0.3.0). The host's HPET clock inflates absolute
  CPU; see DEVELOPMENT.md.
- 5,000 short TCP connections in about 1 s (5,250 req/s).
- Engine RSS is about 5 MB without feeds. The 850 k-domain feed uses 21 MB;
  the ASN table about 10 MB.
- `libvigil.so` is 3.16 MB (arm64; TLS/HTTP/2 for encrypted DNS ≈ 1.4 MB,
  boringtun ≈ 0.3 MB) and the release APK is 12.4 MB (three ABIs).

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

## New in 0.4.0 (released 2026-09-28 as a pre-release)

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

## New in 0.5.0 (released 2026-09-28 as a pre-release)

A second full review (engine, upstream chaining, service/data, UI/export,
competitive landscape) by parallel reviewers, with every verified finding
fixed, then four features. Fixes and features were built by agents in
worktrees and merged; the full matrix (host and both emulators) passes on
the merged tree. CHANGELOG.md (0.5.0) lists everything; the highlights:

- **Most important fixes:** netstack sockets reset by the app during the
  handshake went back to LISTEN and leaked their relay (and could capture a
  later connection); a panic or a dead engine task was silent and left the
  device black-holed (now an `engine` error, so the service restarts the
  session); the UDP flow cap did not stop evicted flows; DNS over TCP to a
  hard-coded resolver bypassed app blocks and IP feeds; WireGuard in
  fail-open went direct during every network change; SOCKS5 timeouts
  disabled UDP permanently; foreground status was lost on a quick
  Stop→Start; feeds were only loaded after traffic started (now preloaded
  from the start config); SIEM batches refused with 400/413 were dropped.
- **Packet capture:** an in-memory ring (off by default, 16 MB) exported as
  PCAPng per connection, alert or app, and an optional PCAP-over-IP server.
- **Per-app firewall conditions:** Wi-Fi, mobile data, background, screen
  off, and per-app domain allow/block rules; the app pushes the device state
  (`nativeSetDeviceState`) and the engine cuts connections that become
  blocked.
- **Spyware and stalkerware:** MVT packs and Echap lists as threat feeds with
  spyware names in alerts, and a local health check (installed packages and
  signing certificates, recorded history) with an exportable report.
- **Tracker labels:** AdGuard companiesdb (CC BY-SA 4.0), labels only.
- **Feed downloads are ordered by importance:** threat lists, then spyware
  packs, then other lists, then the tracker labels and the ASN table (with
  about 30 built-in downloads now, a run stopped early must have fetched the
  protective ones first; found by the Android 16 e2e run).

## New in 0.5.1: third review fixes (2026-09-29)

A third review (engine, upstream/DNS/capture, service/data, UI/export,
competitors) by five parallel reviewers; the nine most important findings
were fixed by three agents in worktrees and merged. CHANGELOG.md
(0.5.1) lists them. Verified: every host suite, and every emulator
suite on Android 15 and 16. On Android 16, by hand: a PCAP-over-IP client
running as the shell (UID 2000) receives the stream, one running as an app
UID (10123) is refused ("an app on this device").

## New in 0.5.1: translation support (2026-09-29)

Every user-visible string moved to resources by four agents (one area each,
one `strings_<area>.xml` each), then merged; see docs/TRANSLATING.md and the
CHANGELOG. `StringResourcesTest` guards against new hard-coded English.
Verified: lint clean, 252 unit tests; on the Android 16 emulator every
screen opened in the en-XA and ar-XB pseudolocales without a crash or a
format error (en-XA showed no untranslated English; ar-XB mirrors), and
every emulator suite passes on the final APK on Android 15 and 16.

Test-environment notes from this run: the emulator's own DNS/network can
flake for minutes (downloads, `example.com` checks fail across suites while
the logic checks pass; rerun). An interrupted lifecycle run could leave
Private DNS strict (`dns.google`), which sends lookups past vigil and fails
the sinkhole checks; the lifecycle script now restores it on any exit and
android-e2e.sh resets a leftover strict mode. Stop Gradle daemons
(`./gradlew --stop`) before booting an emulator: they held about 5.5 GB and
the emulator was OOM-killed once.

## Feature inventory

**Engine:** TUN dispatch; user-space TCP (smoltcp via `netstack-smoltcp`)
with a SYN gate that connects upstream first; own UDP NAT; DNS
inspection/sinkholing (`0.0.0.0`/`::` or NXDOMAIN) with CNAME-cloaking
detection; DNS over TCP to the virtual resolver; truncation retry over TCP;
IP→name cache; TLS ClientHello parsing across records and segments; JA4;
QUIC v1/v2 Initial decryption with CRYPTO reassembly; HTTP Host sniffing;
feeds (hosts, domains, AdGuard `||d^`, IP/CIDR) streamed from disk into
arena sets, preloaded from the start config before the first packet;
policy (app block, per-app conditions on network / background / screen,
per-app domain rules, allow/deny, feeds, encrypted-DNS blocking) with open
connections cut when the device state makes them blocked; detectors
(beaconing between and within connections, threat hits, JA4, hard-coded DNS,
encrypted DNS, new ASN); ASN enrichment; upstream dialer (direct, WireGuard,
SOCKS5) with DoT/DoH; packet capture ring with PCAPng export and
PCAP-over-IP; supervised engine tasks; bounded event queue;
`flow`/`flow_update`/`flow_end` contract.

**App:** VpnService (always-on capable, Quick Settings tile, LAN exclusion
routes, underlying-network DNS tracking); EngineHandle lock; batched Room
persistence; UID→app resolution including shared UIDs; foreground/background
tagging (usage access) and the device-state push for per-app conditions;
novelty, new-ASN and upload-volume alerts; alert notifications with mutes;
feed catalogue (19 built-in lists, the ASN table, tracker labels, and the
spyware packs: Echap plus one feed per MVT pack) with a WorkManager refresh
in priority order and atomic validated downloads; custom feeds with a
credential header (MISP) and TAXII 2.1 collections, credentials never sent
to other hosts; spyware alert labels and the health check; tracker-company
labels and per-app tracker summaries; SIEM export (syslog UDP/TCP/TLS with
KeyChain mTLS, HTTP NDJSON / Splunk HEC / Elastic bulk, batch splitting);
packet capture settings and PCAPng export; Compose UI (Overview, Activity,
Apps plus detail with network access and per-app rules, Alerts, Settings,
Feeds, Export, Rules, Flow detail, Encrypted DNS, Upstream, Packet capture,
Health check); retention and clear history.

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
   For the post-0.4.0 features: a background rule with real app switching
   (usage access; expect up to about 1 s of refused connections when an app
   returns to the foreground, the foreground poll interval), PCAPng export
   through the system file picker and opened in Wireshark, PCAP-over-IP from
   a PC on the same Wi-Fi, and the health check with a known stalkerware
   test APK (see docs/HEALTH_CHECK.md).
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
8. **Follow-ups from the post-0.4.0 work:**
    - The app assumes every feed in the start config was preloaded; the
      engine only logs load errors. A per-feed load result (event or stats
      field) would let the app retry a failed preload.
    - Packet capture: no throughput benchmark with capture on; the
      PCAP-over-IP listener binds IPv4 only; export goes through the file
      picker only (no share sheet).
    - Optional extra tracker sources (Exodus, DuckDuckGo app list; both
      non-commercial licences, so off by default).
    - Health check: `android-property` and file-hash indicators from the MVT
      packs are ignored today.
    - The TCP/TLS syslog "test event" still says "delivered" when the
      collector only accepted the connection.
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
    - Room migrations: the schema is still at version 4 (the post-0.4.0
      work added queries and settings, no schema change) (exported to
      `android/app/schemas`); every entity change needs a hand-written
      migration and a `MigrationTest` case.
    - Add a theme toggle / dynamic colour. (UI strings moved to resources
      on 2026-09-29; see docs/TRANSLATING.md.)
    - Translations: set up hosted Weblate (owner account), then translate
      the feed download error details and spyware pack descriptions, which
      are still stored as English text.
    - Persist unsent SIEM alerts across process death (the retry queue is
      in memory).
11. **Open findings of the 2026-09-29 review** (lower priority, not fixed):
    no size cap on the history database (age-based pruning only; the
    health-check queries load every group); `block_encrypted_dns` misses DoH
    to IP literals (1.1.1.1, 8.8.8.8); fire-and-forget UDP from a blocked
    app can pass unattributed when the UID lookup finds no socket (not
    verified on a device); the HTTP Host sniffer ignores absolute-form
    targets and stalls 3 s on bare-LF requests; answers from app-chosen
    resolvers poison the IP-to-name cache for every app; per-app cut races
    (`open_cuttable_flow` re-checks before inserting; the UDP watch
    subscribes after the decision); `udp_idle_timeout_s` has no upper bound
    (overflow panic); QUIC varint `as usize` truncation on 32-bit; unknown
    feed categories silently become `tracking`; health check misses
    non-canonical IPv6 and IPv6 CIDR indicators; capture ring resize/export
    doubles memory under the lock; SOCKS5 UDP relay address not validated;
    `send_domain` lets the proxy reach a name whose IPs were never checked
    against IP feeds; UI nits (unread badge counts muted alerts, Undo of a
    mute restores the whole list, export after the SAF picker can fail
    silently, stale PCAP temp files); CI (actions not pinned by SHA, no
    `permissions:`, no `cargo audit`); README performance numbers
    outdated.

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
- A SOCKS5 proxy app on the device (Orbot) does not work with Android's
  always-on "Block connections without VPN" (lockdown): the proxy app is
  excluded from vigil's VPN so its traffic does not loop, and lockdown gives
  apps outside the VPN no network at all, so every proxied connection fails
  (closed, never direct). vigil detects this and says so in its notification
  (`ServiceState.upstreamWarning`); turn lockdown off or use a proxy on
  another device.
- If the saved settings become unreadable and they configured a WireGuard or
  SOCKS5 upstream that cannot be recovered, inspection refuses to start until
  the upstream is set up again (the unreadable document is kept as a backup
  in the app's preferences).
- The weekly database VACUUM runs only while inspection is off, or while the
  device is idle and charging, because it blocks event writes while it runs.

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
| Download feeds in priority order (threat lists first, ASN and tracker labels last) | About 30 built-in downloads since the spyware packs; a refresh stopped early (network change, WorkManager stop) must have fetched the protective lists first. |
| Feed preload in the start config (`feeds`, up to 10 s) | Blocklists apply from the first packet after boot or a restart; loading all built-in feeds took under 1 s on the emulator. |
| Engine tasks supervised; any exit or panic is an `engine` error | A dead task with routes up black-holes the device; the app's restart budget only works if the failure is reported. |
| Per-app device state pushed with its own JNI call (`nativeSetDeviceState`) | It changes on every app switch; `nativeUpdateConfig` rebuilds every domain list. |
| Per-app allow beats feeds for that app; any app block beats everything | Consistent with the global allowlist; an app block applies before the name is known, so allows cannot punch holes in it. |
| TTL 0 for DNS answers that depend on the app | Android's resolver cache is shared by all apps on a network. |
| Packet capture in memory only, attributed at export time | No payloads on disk unless the user exports; no per-packet lookups on the hot path (one atomic load when off). |
| PCAP-over-IP in Rust, Wi-Fi address only by default | The packets are already in the engine; streaming through Kotlin would cost a JNI call per packet. Exposure is limited to the local Wi-Fi and to an allowlist of client addresses, required for any network bind; on the device only the shell (`adb forward`) or root may connect. |
| Spyware packs from MVT's index and Echap, downloaded by the device; labels kept app-side | Source allowlist (mvt-project, AmnestyTech, AssoEchap on GitHub); the engine carries no per-entry labels for domain feeds. A small hand-written YAML reader instead of a YAML library. |
| AdGuard companiesdb for tracker labels, not loaded by the engine | CC BY-SA 4.0 (commercial use allowed; DuckDuckGo, Ghostery and Disconnect data are non-commercial); labels are looked up at display and export time. |
| UI strings in one resource file per area; `UiText` for text built without a Context | Smaller files for translators (one Weblate component each) and no merge conflicts between areas; data-layer and view-model messages stay testable on the JVM by comparing resource ids. Alert messages stay English in Room and the SIEM export (machine data); screens render a translated sentence from kind + detail, falling back to the stored message. |
