# Changelog

## Unreleased

- CI runs on GitHub Actions (engine and Android jobs green); the release APK is
  uploaded as the `vigil-apk` artifact.
- Handoff documentation: `docs/STATUS.md`, `docs/DEVELOPMENT.md`, `CLAUDE.md`.

## 0.1.0 (2026-09-27)

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
