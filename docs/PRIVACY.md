# Privacy and threat model

## What vigil records

- For every connection: the app, destination address and port, destination
  name (see `domain_source`), protocol, TLS version, ALPN, JA4 fingerprint,
  byte counts, duration, verdict, the path it took (direct, WireGuard or
  SOCKS5) and the network (autonomous system) that announces the address.
- For every DNS lookup: the app, name, type, response code, answers and how
  vigil forwarded it (UDP, TCP, DoT or DoH).
- Per app, the networks (AS numbers) it has used, with first and last time
  seen, for the optional new-network alerts. Like learned destinations they
  are kept for at least 90 days.
- For plain HTTP: only the method and the `Host` header. **Paths, query
  strings, headers and bodies are never recorded** (unless you turn on
  packet capture, below).

Everything stays in the app's private storage. It is excluded from cloud
backups and device transfer, and pruned after the retention period (7 days by
default). No traffic data leaves the device unless you enable SIEM export,
PCAP-over-IP streaming, or export a capture file.

## Packet capture (off by default)

With Settings → Packet capture → Record packets, the engine keeps the most
recent raw packets of every app (as they crossed vigil's VPN interface) in
memory, up to the buffer size you choose (16 MB by default), overwriting the
oldest. Such packets contain everything that is not encrypted: **plain HTTP
requests and responses in full (URLs, form data, cookies, pages), DNS lookups
and answers**, and the handshakes of encrypted connections. HTTPS, QUIC and
other encrypted contents stay encrypted.

- The packets are held in memory only, and discarded when capture is turned
  off or inspection stops or restarts. They are never written to storage,
  never backed up and never exported automatically.
- An export ("Export packets" on a connection, an alert or an app, or
  "Export all") writes a PCAPng file to the place you pick. vigil writes it
  to a temporary file in its private cache first and deletes that after
  copying. Where the file goes from there is up to you.
- **PCAP-over-IP streaming** (off by default, needs capture) serves the
  packets live, unencrypted and unauthenticated, to up to two clients that
  connect to the port (57012 by default). Anyone on the network who can reach
  that port receives them. vigil listens on the Wi-Fi address only by default
  (never on the cellular network; "all networks" and "this device" are
  options) and accepts an allowlist of client addresses, which you should
  set to your computer's. Use it on a trusted network and turn it off when
  done.
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
header you configure. TAXII 2.1 sources are polled with the same daily
update: vigil sends GET requests (User-Agent `vigil/<version> (+TAXII
poller)`, your credentials, and an `added_after` timestamp) to the API root
you entered. Credentials only ever go to the host you entered: a redirect to
another host is followed without them, a redirect from HTTPS to plain HTTP is
refused, and with credentials a TAXII discovery document's API roots on other
hosts (or over plain HTTP) are not used. JA4 fingerprints of your connections are matched on the device
and never sent anywhere.

The IP-to-ASN database is also on by default: once a week vigil downloads
iptoasn.com's `ip2asn-combined.tsv.gz` (about 9 MB, public domain under the
PDDL 1.0) with the same kind of plain GET, so iptoasn.com sees your IP
address and the time. The table stays on the device (about 46 MB on disk,
10 MB of memory while inspecting) and every address is looked up locally;
nothing about your connections is sent. Turn "IP to ASN" off under
Settings → Threat intelligence feeds to stop the download (connections then
show no network names, and new-network alerts stop).

## Where lookups go

vigil answers apps' DNS lookups itself and forwards them to a resolver: by
default the network's resolvers (or the ones you enter) over plain DNS, which
the network operator can read and alter. With Settings → Encrypted DNS they
go over DNS over TLS or DNS over HTTPS to the provider you choose (Quad9,
Cloudflare, Google, Mullvad or your own server), which then sees your
lookups and IP address instead. The providers' addresses are built in, so
no lookup is sent in cleartext to find them. If the encrypted server is
unreachable, lookups fail unless you allow a fallback to plain DNS. Lookups
an app sends to a DNS server of its own choosing still go there as sent.

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

vigil accepts incoming connections only for PCAP-over-IP streaming, and only
while it is on. The server reads nothing from clients (it only discards
what they send) and sends a fixed header plus packets, so a client can do no
more than receive the capture; clients not on the allowlist, and a third
client, are disconnected at once. Other apps on the phone can connect to it
as well when it listens on "this device" (loopback) or on an address they
can reach.
