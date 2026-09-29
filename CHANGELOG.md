# Changelog

## Unreleased

Translation support:

- Every user-visible string is an Android resource (about 900 strings and
  80 plurals in `res/values/strings_<area>.xml`), with plurals for counts
  and whole sentences with positional placeholders. Alerts are shown in the
  app language from their kind and details; the stored and exported message
  stays English. The per-app language setting (Android 13+) lists the
  translated locales, generated at build time. Debug builds enable the en-XA
  and ar-XB pseudolocales. `StringResourcesTest` fails on English passed
  straight to the UI and on translations whose placeholders differ from the
  English. Guide for translators: `docs/TRANSLATING.md`. No translations
  yet.
- Wording: the notification counts "1 connection" (was "1 connections");
  `new_asn` alerts are titled "New network".

Fixes from the third review (2026-09-29):

- **PCAP-over-IP:** only the shell (`adb forward`) or root may connect from
  the phone itself; other apps are refused, whether they use loopback or the
  phone's own Wi-Fi address. Streaming on a network (Wi-Fi or all networks)
  needs a non-empty client allowlist. Stalled clients time out after 10 s and
  turning the stream off disconnects clients at once. The notification shows
  connected Wireshark clients.
- **WireGuard:** with fail-closed on, an address family AllowedIPs does not
  cover at all (typically IPv6 with a `0.0.0.0/0`-only config) is refused
  instead of going out directly; the wg-quick import warns about it.
- **SOCKS5:** encrypted-DNS connections opened directly while the proxy was
  down (fail-open) are no longer reused after it recovers.
- **Alerts:** high-severity alerts have their own budget, and
  `hardcoded_dns` is limited per app (new `detail.suppressed`), so one app
  can no longer crowd out threat alerts.
- **TLS:** ClientHellos up to the parser's 64 KiB limit are inspected (was
  32 KiB); the sniff buffer is freed once forwarded.
- **TAXII:** URL indicators on shared platforms (GitHub, Google Drive,
  Discord, Dropbox, shorteners…) no longer block the whole platform; the
  shared-platform check is now suffix-aware for spyware packs too.
- **Feed downloads:** built-in feeds, spyware packs, the ASN table and
  tracker data trust system CAs only; a spyware pack that loses more than
  half its indicators is refused and the previous copy kept.
- **Service:** an `Error` (not only an `Exception`) during a session gives up
  cleanly instead of leaving the VPN up with no engine; the TUN is closed if
  session setup fails after `establish()`; out-of-memory while converting a
  feed fails that feed only.
- **SIEM export:** redirects are a configuration error instead of silent
  loss; a collector that refuses every request keeps the records queued
  (config error) instead of discarding them after ~400 requests; syslog over
  TCP/TLS reconnects after an idle close; alerts have their own queue that
  flows and DNS cannot evict; `new_destination` and `new_asn` alerts are
  exported; Elastic `_bulk` URLs must name the index.

## 0.5.0 (2026-09-28): GitHub pre-release

New features:

- **Packet capture:** an optional in-memory ring of the raw packets apps send
  and receive, exported as PCAPng (per connection, alert or app, with
  `uid=… flow=…` comments and directions) or streamed live to Wireshark
  (PCAP-over-IP, off by default, Wi-Fi address only by default, allowlist).
  New JNI call `nativeExportPcap`; new config section `capture`.
- **Per-app firewall conditions:** block an app on Wi-Fi, on mobile data, in
  the background or while the screen is off, and allow or block a domain for
  one app only. Open connections are cut when a condition starts to apply.
  New JNI call `nativeSetDeviceState`; new config fields `app_rules`,
  `app_domain_rules`, `device_state`. One-tap block on the Apps list.
- **Spyware and stalkerware indicator packs:** the packs listed by MVT
  (Pegasus, Predator, NoviSpy and others, from the MVT project and Amnesty
  International) and Echap's stalkerware lists, downloaded from their
  publishers; hits are blocked and alerts name the spyware. A local
  **health check** compares installed apps (packages, signing certificates)
  and the recorded history against them and produces an exportable report.
- **Tracker labels:** destinations labelled with the tracker company and
  category (AdGuard companiesdb, CC BY-SA 4.0); per-app tracker summaries,
  tracker counts on the Apps list, a "Top tracker companies" card, and
  `vigil.tracker.*` in SIEM records.

Fixes from the post-0.4.0 review:

- Feed downloads run in order of importance (threat lists, then spyware
  packs, then other lists, then tracker labels and the ASN table), so a
  refresh stopped early has fetched the protective lists first.

- Engine: connections reset by the app during the handshake were leaked
  (netstack sockets back in LISTEN); a panic or a dead engine task now reports
  an error and restarts the session instead of black-holing the device; the
  UDP flow cap now stops evicted flows; DNS over TCP to a hard-coded resolver
  now obeys app blocks and IP feeds, and unparseable messages are refused;
  half-closed relays end when the app resets; SYN+RST and IPv6 TCP with
  extension headers are dropped; DoH chunk overflow on 32-bit; DNS cache
  sweep; HTTP leading CRLF; SVCB hints bounds; feeds are loaded before the
  first packet (new start-config fields `feeds`, `feeds_preload_timeout_ms`).
- Upstream: WireGuard no longer goes direct (fail-open) while re-binding on a
  network change; SOCKS5 timeouts and resets mean "proxy unavailable", not
  "UDP unsupported"; `via` is always the path taken; proxy name lookups are
  bounded and cached; WireGuard encrypts outside the stack lock (p50 latency
  under load 540 → 120 µs); a replaced tunnel closes its last connection.
- Service and data: foreground status kept on a quick Stop→Start; warning
  for always-on lockdown with an excluded proxy app; NAT64 route changes
  restart the session; bounded ASN/TAXII parsing; credentials never follow
  redirects to other hosts or plain HTTP; unreadable settings fail closed
  instead of dropping the WireGuard/SOCKS5 upstream; foreground detection no
  longer marks the visible app as background; VACUUM only while idle.
- UI and export: SIEM batches refused with 400/413 are split instead of
  dropped, Splunk HEC configuration errors keep records queued; syslog
  header uses the event time; secret fields use password keyboards; drafts
  and dialogs survive rotation; safer back navigation; no duplicate screens;
  queued snackbars; lighter Overview. UX: "why blocked" sheet with Always
  allow, tappable DNS rows, Live/Paused and app filter in Activity, alert
  mutes and filters, Undo after blocking, host or whole-site choice,
  onboarding ends by starting inspection.
- **Breaking for SIEM dashboards:** `tls.version` is now `1.3` with
  `tls.version_protocol: tls`; `host.os.version` is the Android release (API
  level in `vigil.android.api_level`); alerts use
  `event.category: [intrusion_detection, network]` with `event.type` `denied`
  or `info` (not `indicator`) and gain `rule.name` and `destination.*`.

## 0.4.0 (2026-09-28): GitHub pre-release

- Connections show which path they took (direct, WireGuard, SOCKS5) and
  lookups which DNS transport answered (UDP, TCP, DoT, DoH).
- Network (ASN) labels from an offline iptoasn.com table, and opt-in alerts
  when an app contacts a network it never used before.
- Beaconing detection inside long-lived connections; alerts for unusual
  background upload volume.
- About 2× less CPU per GB relayed; connections are released immediately
  after they close (they were held for 10 s).
- One engine thread by default to save battery; new "Maximum throughput"
  setting.
- Toolchain: AGP 9.4, Kotlin 2.4, compileSdk/targetSdk 36, current AndroidX.

## 0.3.0 (2026-09-28): GitHub pre-release

- Encrypted upstream DNS: DNS over TLS and DNS over HTTPS (HTTP/2), with
  Quad9, Cloudflare, Google and Mullvad presets or a custom server;
  fail-closed unless plain fallback is enabled.
- JA4 threat matching: `ja4` feeds, `threat_ja4` alerts, optional blocking;
  STIX/TAXII 2.1 collections as feed sources (domains, IPs, JA4).
- Route inspected traffic through WireGuard or a SOCKS5 proxy (e.g. Orbot),
  fail-closed by default, so vigil works for people who already use a VPN.
- Room schema v3; `scripts/android-features.sh` on-device checks.

## 0.2.0 (2026-09-28): GitHub pre-release, release-signed APK

- Review fixes across engine, service and UI (details in `docs/STATUS.md`,
  "Review fixes"): resource caps, alert-storm protection, NAT64 coverage,
  DNS-over-TCP and UDP/53 IP-feed enforcement, real TCP resets, engine-error
  auto-restart, reliable and de-duplicated SIEM export, feed download races,
  Room schema v2, accessibility and contrast, onboarding.
- New JNI call `nativeShutdown`; new config fields `nat64_prefixes` and
  resource caps; invalid configs are rejected (`docs/EVENTS.md`).
- CI runs on GitHub Actions (engine and Android jobs green); the release APK is
  uploaded as the `vigil-apk` artifact.
- Handoff documentation: `docs/STATUS.md`, `docs/DEVELOPMENT.md`, `CLAUDE.md`.
- Release signing with a dedicated key (no longer debug-signed); reproducible
  release builds; pinned Rust toolchain; F-Droid metadata and recipe draft.
- `scripts/android-lifecycle.sh`: network switches, airplane mode, Doze,
  engine-error restart and restart budget, process death, Private DNS,
  always-on VPN at boot.

## 0.1.0 (2026-09-27): released as a GitHub pre-release (debug-signed APK)

First release.

- Rust engine: user-space TCP (smoltcp) and UDP relay over a TUN interface;
  per-app attribution; DNS inspection and sinkholing with CNAME-cloaking
  detection; TLS SNI, QUIC Initial SNI (v1/v2) and HTTP Host extraction; JA4
  fingerprints; threat, tracker and custom feeds; beaconing, hard-coded DNS and
  encrypted-DNS detection.
- Android app: local VPN service with always-on support and a Quick Settings
  tile; Room history; Compose UI (overview, activity, apps, alerts, feeds,
  rules, export); daily feed updates; SIEM export (syslog UDP/TCP/TLS with
  mTLS, HTTP NDJSON, Splunk HEC, Elasticsearch bulk).
- Tooling: Linux CLI host, network-namespace end-to-end tests, JNI smoke test,
  on-device test script and a throughput benchmark.
