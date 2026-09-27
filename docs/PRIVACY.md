# Privacy and threat model

## What vigil records

- For every connection: the app, destination address and port, destination
  name (see `domain_source`), protocol, TLS version, ALPN, JA4 fingerprint,
  byte counts, duration and verdict.
- For every DNS lookup: the app, name, type, response code and answers.
- For plain HTTP: only the method and the `Host` header. **Paths, query
  strings, headers and bodies are never recorded.**

Everything stays in the app's private storage. It is excluded from cloud
backups and device transfer, and pruned after the retention period (7 days by
default). No traffic data leaves the device unless you enable SIEM export.
Feed downloads and export use vigil's own sockets, which bypass its tunnel.

## What vigil downloads

vigil downloads its enabled threat feeds once a day, directly from their
publishers. Four built-in feeds are on by default: HaGeZi Threat Intelligence
(from `raw.githubusercontent.com`) and abuse.ch URLhaus, ThreatFox and Feodo
Tracker. Each download is a plain HTTPS GET with the User-Agent
`vigil/<version> (+feed updater)`, so the publisher (and GitHub) sees your
IP address, the time and that you use vigil, but nothing about your traffic.
Turn feeds off in Settings → Threat intelligence feeds to stop these
downloads; custom feeds go to the URL you enter, with the Authorization
header you configure.

SIEM export sends the records you select to the collector you configure.
Use `https://` or syslog over TLS: over plain `http://`, UDP or TCP the
records (and any Authorization header or token) cross the network
unencrypted, and the app warns about this.

## What vigil cannot see

- **Encrypted payloads.** vigil never decrypts TLS or QUIC and installs no
  certificates.
- **Real ECH destinations.** With Encrypted Client Hello, only the provider's
  public name (e.g. `cloudflare-ech.com`) is visible. Browsers also send a
  GREASE ECH extension on every handshake; that one hides nothing, and vigil
  does not report it as ECH.
- **Lookups made over DoH, DoT or DoQ,** including Android Private DNS in
  strict mode. vigil still names those connections from TLS/QUIC SNI, alerts
  on apps using encrypted DNS, and can optionally block well-known encrypted
  DNS endpoints so apps fall back to plain DNS.
- **Its own traffic.** vigil is excluded from its tunnel so it cannot loop.

## Attack surface

The engine parses untrusted bytes: DNS answers from the network and TLS, QUIC
and HTTP data from local apps. The parsers:

- are pure Rust with explicit bounds checks and no `unsafe`;
- limit buffering (a 64 KB ClientHello, a 16 KB HTTP head, a 64 KB QUIC
  CRYPTO stream, 16 compression-pointer jumps);
- are exercised with corrupted and truncated inputs in the unit tests.

`unsafe` is confined to the TUN file-descriptor I/O, the JNI handle and, in
the CLI, descriptor passing.

A malicious app cannot use vigil to reach anything it couldn't reach itself:
relayed connections go only to the destination the app addressed.
