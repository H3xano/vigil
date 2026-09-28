# Changelog

## Unreleased

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
