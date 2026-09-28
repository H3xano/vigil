# Event schema

## Engine events (Rust → app)

The engine emits one JSON object per event with a `type` field. `vigil-cli`
prints them as JSON lines; the app polls them in batches (JSON arrays).

| type | fields |
|---|---|
| `flow` | `id`, `ts` (ms), `proto` (`tcp`/`udp`), `uid`, `src`, `dst_ip`, `dst_port`, `domain`, `domain_source` (`sni`, `quic`, `http`, `dns`), `app_proto` (`tls`, `quic`, `http`, `dot`, `doq`), `alpn`, `tls_version`, `ja4`, `ja4_match` (see below), `ech`, `http_method`, `verdict` (`allow`/`block`), `reason`, `tags` (`encrypted_dns`, `plaintext_http`, `ech`), `via` (`direct`, `wireguard`, `socks5`), `asn` (see below) |
| `flow_update` | `id`, `ts`, `tx`, `rx` (running totals of long-lived flows) |
| `flow_end` | `id`, `ts`, `tx` (bytes sent by the app), `rx`, `duration_ms`, `error` |
| `dns` | `ts`, `uid`, `qname`, `qtype`, `rcode`, `answers`, `verdict`, `reason`, `latency_ms`, `server` (`virtual` or the hard-coded resolver), `transport` (app → vigil: `udp`/`tcp`), `upstream` (vigil → resolver: `udp`, `tcp`, `dot`, `doh`; null when no resolver was asked) |
| `alert` | `ts`, `kind`, `severity` (`info`, `low`, `medium`, `high`), `uid`, `target`, `message`, `detail` |
| `stats` | packet/byte counters, active flows, DNS queries, blocked, dropped packets/events, DNS cache size, encrypted upstream DNS counters (below), `upstream` (see below) |
| `engine` | `state` (`started`, `stopped`, `error`), `message` |

The engine emits exactly one `flow_end` for every `flow`, with the same
`id`, including flows still open at shutdown (`error: "engine stopped"`).
Flow ids restart at 1 in each engine session. The queue is bounded
(20 000 events); when the consumer falls behind, the engine drops `stats`
and `flow_update` events first, but if none are near the front it drops the
oldest event of any type. **Consumers must therefore tolerate orphans**: a
`flow_end`, `flow_update` or `flow` whose partner was dropped. The
`dropped_events` counter in `stats` says whether that happened.

`flow_end.error` is null for an orderly close. Otherwise it describes the
end, for example `Connection reset by peer (os error 104)` (either side
reset; vigil resets the other side too), `idle timeout`, `connect: …`,
`socket: …`, `evicted: UDP flow limit reached`, or `engine stopped`.
Upstream paths add, for example, `connect: Connection refused (through
WireGuard)`, `connect: socks5 proxy 127.0.0.1:9050: Connection refused (os
error 111)` (proxy unreachable, fail closed), `connect: socks5: host
unreachable (reply 4)` (the proxy's answer about the destination) and
`socket: the SOCKS5 proxy does not relay UDP` (such UDP flows are then
absorbed until idle, like blocked ones). A flow
that the server resets before the app has sent anything is still reported
(`flow` with `verdict: allow`, then `flow_end` with the error).

In `dns` events, `rcode` is `REFUSED` (with `verdict: block`) when the app
queried a hard-coded resolver whose address is on an IP feed. Queries with
more than one question (or none) are answered REFUSED and not logged. DNS
over TCP to any resolver, not only the virtual one, is inspected and logged
with `transport: tcp`; such connections do not produce `flow` events, except
when the server's address itself is blocked for the app (`blocked_uids`, an
IP feed): the connection is then reset at connect time with a blocked
`flow` event, like any TCP connection. A message to a hard-coded resolver
that is not a standard query (unparseable, a response, or an opcode other
than QUERY) is never forwarded: it is answered REFUSED (the connection is
closed if it has no DNS header) and logged as a `dns` event with
`verdict: block`, `reason: "not a standard query (…)"` and, when unparseable,
an empty `qname`/`qtype`, plus a `hardcoded_dns` alert. (Over UDP such
payloads are relayed as ordinary UDP flows, with the usual policy checks
and `flow` events.)

`dns.upstream` is the transport that produced the answer: `udp` (or `tcp`
after a truncated UDP answer, and always `tcp` with a SOCKS5 upstream) for
plain DNS, `dot`/`doh` when
`encrypted_dns` is on. For a SERVFAIL caused by unreachable resolvers it
names the transport that failed, and `reason` says why (for example
`upstream unreachable (dot: dns.quad9.net (9.9.9.9:853): timed out)`). With
`fallback_plain`, an answer fetched in cleartext after the encrypted servers
failed has `upstream: udp`. Queries to hard-coded resolvers are always
forwarded as the app sent them (plain). Sinkholed and refused queries have
`upstream: null`.

`stats` carries the encrypted upstream counters (all 0 while it is off):
`encrypted_dns_ok` (answers over DoT/DoH), `encrypted_dns_failed` (queries
for which every encrypted server failed), `encrypted_dns_fallback` (of
those, answered in cleartext), `encrypted_dns_last_ok_ts`,
`encrypted_dns_last_error_ts` (ms, 0 = never) and `encrypted_dns_last_error`
(text or null).

`dst_ip` is always the address the app used. For NAT64 addresses (see
`nat64_prefixes` below) IP feeds are matched on the embedded IPv4 address,
and `threat_ip` alerts name that IPv4 address as `target`.

`domain_source` tells you how much to trust `domain`: `sni`, `quic` and `http`
are what the app itself sent. `dns` is a reverse lookup of the address in
recent DNS answers, which is ambiguous for shared CDN addresses, so it is
never used for blocking.

`via` is the upstream path of the flow's own connection (see `upstream`
below): `direct`, `wireguard` or `socks5`. It is `direct` in the tunnel and
proxy modes too for destinations outside the WireGuard peer's AllowedIPs,
and when the path is down with `fail_closed: false`. It is null when no
upstream connection was attempted (TCP flows blocked at the SYN gate, UDP
and QUIC flows blocked by policy or JA4). TCP flows blocked after the sniff
(by SNI, Host or JA4) name the path of the connection made at the SYN gate,
to which nothing of the app's was sent; with SOCKS5 `send_domain` that
connection is made lazily, so a blocked flow never contacts the proxy
(`via` is still `socks5`). For a failed connect it names the path that was
tried.

`asn` is the autonomous system announcing `dst_ip`, from a loaded ASN
table (feed category `asn`, see "Feed files"):

```json
"asn": {"number": 13335, "name": "CLOUDFLARENET", "country": "US"}
```

`name` is the table's AS description (may be empty) and `country` the ISO
code of the AS registration (null when unknown); it is not a geolocation
of the address. NAT64 addresses (see `nat64_prefixes`) and IPv4-mapped
IPv6 addresses are looked up by their IPv4 address. `asn` is null when no
table is loaded or the address is not in a routed range (private,
reserved, "not routed" rows with AS 0, gaps). It is looked up once, when
the flow opens, and is present on blocked flows too.

### JA4 matches

`ja4` is the FoxIO JA4 fingerprint of the client's TLS ClientHello (`t…`
over TCP, `q…` for QUIC Initials). When it is listed by a loaded feed, the
`flow` event carries

```json
"ja4_match": {"feed": "ja4-foxio", "rule": "t13d190900_9dc949149365_97f8aa674fd9", "label": "Sliver"}
```

`feed` is the feed id, `rule` the listed entry (the fingerprint itself, or
`a_b_*` for a wildcard entry) and `label` the feed's label for it (may be
null). Otherwise `ja4_match` is null. A match raises a `threat_ja4` alert; it
blocks only when the config sets `block_ja4_matches` (then `verdict` is
`block`, `reason` is `ja4:<feed> (<rule>)`, and the connection is reset
before the ClientHello reaches the server; for QUIC the datagrams are
dropped). A name on the user allowlist (from SNI, QUIC or HTTP Host) is
never blocked for its JA4, but is still flagged. JA4 identifies the TLS
library and its settings, not the program: benign software built on the
same library (e.g. Go's default `crypto/tls`, which Sliver also uses) has
the same fingerprint, which is why matching alerts only by default.

### Feed files

`nativeLoadFeedFile(handle, id, category, path)` takes one of the categories
`malware`, `phishing`, `c2` (threat: hits alert), `tracking`, `ads`, `custom`
(block only), `ja4` and `asn`. Unknown categories load as `tracking`. Lines are
recognised individually: hosts-file entries, plain domains (`*.` prefix
allowed), AdGuard `||domain^` rules, IP addresses and CIDR ranges, and JA4
fingerprints. A JA4 line is the fingerprint optionally followed by a label,
separated by whitespace, `#`, `,`, `;` or `|`:

```
# comment
t13d190900_9dc949149365_97f8aa674fd9  Sliver
t12i210700_76e208dd3e22_16bbda4055b2  # Cobalt Strike 4.9.1 (winhttp)
q13d0312h3_55b375c5d22e_*             any QUIC client with this cipher list
```

A fingerprint must follow the JA4 grammar: `a_b_c`, where `a` is 10
characters (`t`/`q`/`d`, version `13`/`12`/`11`/`10`/`s3`/`s2`/`d1`/`d2`/`d3`/`00`,
`d`/`i`, two-digit cipher and extension counts, two alphanumeric ALPN
characters) and `b`, `c` are 12 hex digits. Case is normalised except for
the ALPN characters. The only wildcard is a whole `c` section (`a_b_*`), which
matches any extension list; exact entries win over wildcards. Raw
(`ja4_r`) and original-order (`ja4_o`) forms are rejected. Labels are cut
at 80 bytes.

Feeds of category `ja4` accept JA4 lines only; any other non-comment line
counts as rejected. JA4 lines in feeds of other categories are matched too
(so one indicator file, e.g. from TAXII, can hold domains, addresses and
fingerprints). The summary returned by `nativeLoadFeedFile` (and by
`nativeInspectFeedFile`, which parses without an engine) is
`{id, domains, ip_ranges, ja4, rejected_lines, memory_bytes}`.

A feed of category `asn` is an IP-to-ASN table, not a blocklist: it never
blocks or alerts, it only fills the `asn` field of `flow` events. The
format is iptoasn.com's TSV (uncompressed; the app gunzips the download),
one range per line, IPv4 and IPv6 mixed:

```
range_start<TAB>range_end<TAB>AS_number<TAB>country_code<TAB>AS_description
1.0.0.0	1.0.0.255	13335	US	CLOUDFLARENET
1.0.1.0	1.0.3.255	0	None	Not routed
```

`AS_number` may carry an `AS` prefix; 0 marks unrouted space. The country
and description columns are optional (a country that is not two letters,
e.g. `None`, counts as unknown); descriptions are cut at 120 bytes. Rows
with fewer than three columns, unparseable addresses, an end before the
start or mixed address families are rejected. Rows may come in any order;
where ranges overlap, the one that starts first keeps the overlap. An AS
number keeps the first name and country seen. For `asn` feeds the summary's
`ip_ranges` counts the ranges mapped to an AS (adjacent ranges of one AS
merged) and `domains`/`ja4` are 0. The full iptoasn.com table (≈ 720 k
rows, 87 k ASes) takes 9.8 MB and parses in 0.17 s on an x86_64 host
(`vigil-cli asn FILE [IP…]` prints these numbers and looks addresses up).
Loading a second `asn` feed keeps both; the first (by id) that knows an
address wins.

### Upstream status (`stats.upstream`)

| field | meaning |
|---|---|
| `mode` | `direct`, `wireguard` or `socks5` |
| `state` | `up`; `connecting` (WireGuard handshake in progress); `idle` (no session or proxy contact yet and nothing pending: the tunnel connects on first use); `down` (WireGuard handshakes failing for 10 s or more, even if an older session has not expired; the endpoint cannot be resolved or reached; the SOCKS5 proxy could not be reached or refused the credentials) |
| `fail_closed` | as configured |
| `endpoint` | WireGuard: the peer address in use; SOCKS5: the server as configured |
| `handshake_age_s` | seconds since the last completed WireGuard handshake |
| `tx_bytes`, `rx_bytes` | WireGuard payload bytes through the tunnel (session totals) |
| `last_error` | last tunnel or proxy error, e.g. `socks5 proxy 127.0.0.1:9050: Connection refused (os error 111)` |
| `udp` | SOCKS5 only: `unknown` (not tried yet), `supported`, `unsupported` (the proxy refused UDP ASSOCIATE), `blocked` (configured) |

In direct mode it is `{"mode":"direct","state":"up","fail_closed":true}`
(other fields null).

### Alert kinds

| kind | severity | raised when |
|---|---|---|
| `threat_domain` | high | a lookup or connection matches a malware, phishing or C2 feed |
| `threat_ip` | high | a connection's address, or a hard-coded DNS server's address, matches a threat IP feed |
| `threat_ja4` | high | a TLS or QUIC ClientHello's JA4 fingerprint is listed by a feed. `target` is the fingerprint; `detail`: `ja4`, `rule`, `label`, `feed`, `dst` (`ip:port`), `domain`, `proto`, `blocked` |
| `beacon` | medium | ≥ 6 connections to one destination at a near-constant interval (10 s–1 h, jitter ≤ 15 % by default), or ≥ 6 bursts of data at such an interval inside one long-lived connection. `detail.kind` says which (see "Beaconing" below) |
| `encrypted_dns` | low | an app uses DoH, DoT or DoQ, so its lookups are invisible |
| `hardcoded_dns` | info | an app sends DNS to a server other than the system resolver |
| `new_destination` | info | (opt-in, app-side) after a 24 h learning period, an app contacts a domain it never used before |
| `exfil_volume` | medium (low when the foreground state is unknown) | (app-side) an app uploads an unusual volume while not in the foreground (see "Upload volume" below) |
| `new_asn` | low, medium | (opt-in, app-side, needs an ASN table) after a learning period (7 days by default, from the first network recorded for the app), an app contacts an autonomous system it never used before. `target` is `AS<number>`; `detail`: `asn`, `as_name`, `as_country`, `destination`, `dst_ip`, `known_networks`. Medium when the app had used at most 3 networks. At most 5 per app and 30 in total per hour; networks over the limit are learned without an alert |

#### Beaconing

`beacon` alerts come from two detectors that share the thresholds of the
`beacon` config section and the suppression key (kind, app, `target`), so
one destination raises at most one `beacon` alert per app and hour,
whichever detector saw it. `target` is the domain (else the address).

`detail.kind = "connections"`: new connections to the target at a regular
interval. `detail`: `interval_s` (mean), `jitter` (coefficient of
variation of the intervals, 0.05 = 5 %), `samples` (connections), `proto`.
Alerts stored by older versions have no `kind`.

`detail.kind = "intra_flow"`: one connection (TCP or UDP/QUIC) that stays
open and moves a burst of data at a regular interval, the way an implant
checks in over a kept-alive TLS or QUIC connection. `detail`: `interval_s`,
`jitter`, `samples` (bursts), `burst_bytes` (mean size of the completed
bursts, both directions), `flow_id` (the `flow` event's `id`), `dst`
(`ip:port`), `domain`, `proto` (`tls`, `quic`, `http`, `tcp`, `udp`…),
`age_s` (flow age when detected). Raised at most once per flow.

How it works: the engine samples the open flows' byte counters on every
housekeeping tick (`stats_interval_ms`, at most 1 s; nothing is added to the
packet path). A *burst* starts when bytes move after at least
`flow_idle_gap_s` of silence. The start times of the last 12 bursts are
judged like connection times; a silence longer than 3 × `max_interval_s`
restarts the series. Only flows older than `flow_min_age_s` whose lifetime
average rate is at most `flow_max_avg_bps` are watched (streaming, downloads
and uploads are not), at most `flow_max_tracked` at once. Timing resolution
is one tick. Not watched: blocked flows, and flows whose name as sent by the
app (SNI, QUIC, HTTP Host; not a DNS-derived name) is on `ignore_domains`
or the user allowlist (`allow_domains`); `ignore_domains` also exempts those
names from the connection detector.

False positives it avoids by design: push channels (FCM, Apple push,
Mozilla WebPush: on `ignore_domains` by default), protocol keep-alives of
chat apps and gRPC/HTTP/2 clients (WebSocket, HTTP/2, MQTT and QUIC pings are
tens of bytes, below `flow_min_burst_bytes`), a person chatting (irregular),
and bulk transfers (one continuous burst, and above the rate cap). An app
that polls its server every minute over a kept-alive connection with real
requests *is* reported: that is a beacon by definition, as for the
connection detector.

#### Upload volume

`exfil_volume` is computed by the app (`processing/ExfilDetector.kt`) from
the `flow_update`/`flow_end` byte counters, because it needs the app's
foreground state and its upload history over days. For each app it sums
the bytes uploaded while the app was **not** in the foreground over the
last 5 minutes and the last hour, and alerts when a window's upload is

1. at least the absolute floor (settings: 50 MB per hour by default, half
   of it for the 5-minute window), and
2. at least `factor` (3) × the app's baseline, when it has one: the 95th
   percentile of its hourly upload (all states) over the hours with any
   upload in the last 7 days, excluding the current hour; with fewer than
   3 such hours only the floor applies, and
3. one-way: the destination the app uploaded most to in the window sent
   back at most a quarter as much.

Foreground uploads never count. Without usage access the foreground state
is unknown; such uploads count, and the alert has severity `low`. A few
backup/sync apps (Google Photos, Drive, Dropbox, OneDrive, Nextcloud,
ownCloud, Synology, Amazon Photos, MEGA, Syncthing) are exempt. One alert
per app per 6 hours. The hourly history is kept in the app's files
(`exfil_baseline.json`, at most 500 apps × 168 hours), not in Room.

`target` is the top destination (domain, else address). `detail`: `window`
(`5 min` or `1 h`), `window_s`, `uploaded_bytes` (in the window, not in the
foreground), `baseline_bytes_per_hour` (null without enough history),
`floor_bytes`, `factor`, `destination`, `dest_tx_bytes`, `dest_rx_bytes`
(that destination in the window), `background` (`yes` or `unknown`),
`package`. The alert is stored, notified and exported like engine alerts.

Repeated alerts with the same kind, app and *finding* are suppressed for an
hour. For `threat_ja4` the finding is the fingerprint (one alert per
fingerprint and app, whatever the destinations). For `threat_domain` and `threat_ip` the finding is the matched feed
entry (for example `feed:urlhaus|evil.example`), not the full name, so a
malware generating thousands of names under one listed domain (DGA, DNS
tunnelling) raises one alert per app; `target` is the first name seen. For
the other kinds the finding is the `target`. The engine remembers at most
10 000 findings (the oldest are forgotten first, and may alert again) and
emits at most 120 alerts per minute in total; alerts beyond that budget
are dropped.

## Engine configuration (app → engine)

The configuration is one JSON object (`core/vigil-core/src/config.rs`,
mirrored by `EngineConfig.kt`); missing fields take their defaults. Fields
added after 0.1.0:

| field | type | default | meaning |
|---|---|---|---|
| `nat64_prefixes` | list of CIDR strings | `[]` | NAT64 prefixes of the current network, e.g. `"64:ff9b::/96"` or the carrier's own prefix. IPv6 destinations inside one are matched against IP feeds by their embedded IPv4 address (last 32 bits). `64:ff9b::/96` always applies, even if absent. Only /96 prefixes are supported; other lengths and unparseable entries are logged and ignored (they do not reject the config). |
| `max_udp_flows` | integer > 0 | 2048 | UDP NAT entries. When full, the flows idle for longest (1/32 of the table, at least one) are evicted: an open one ends with `flow_end.error` = `evicted: …`, one still being set up is dropped without events. |
| `max_tcp_flows` | integer > 0 | 4096 | TCP connections admitted or relaying. Further SYNs are answered with a RST. |
| `max_pending_connects` | integer > 0 | 256 | TCP connections waiting at the SYN gate (UID lookup and upstream connect, up to `tcp_connect_timeout_ms`). Further SYNs are answered with a RST. |
| `max_dns_inflight` | integer > 0 | 256 | DNS queries being answered at once. Further queries get SERVFAIL. |
| `block_ja4_matches` | bool | `false` | Reset connections (drop QUIC flows) whose JA4 fingerprint is on a feed, instead of only alerting. Allowlisted names are exempt. See "JA4 matches". |
| `encrypted_dns` | object | `{"mode":"off"}` | DoT/DoH for the virtual resolver's lookups. See "`encrypted_dns`" below. |
| `upstream` | object | `{"mode":"direct"}` | The path of every upstream socket: direct, WireGuard or SOCKS5. See "Upstream path" below. |

The four caps are read when the engine starts; a later config update does
not resize them.

### `beacon`

Thresholds of both beaconing detectors (see "Beaconing" above). The app
sends `enabled`, `min_events`, `max_jitter` and the interval bounds (from
the sensitivity setting) and leaves the `flow_*` fields and
`ignore_domains` at their defaults.

| field | type | default | meaning |
|---|---|---|---|
| `enabled` | bool | `true` | Both detectors. |
| `min_events` | integer | 6 | Connections (or bursts) needed before a series is judged (at least 3). |
| `max_jitter` | number | 0.15 | Largest coefficient of variation of the intervals. |
| `min_interval_s`, `max_interval_s` | number | 10, 3600 | Range of the mean interval. |
| `flow_enabled` | bool | `true` | The in-flow detector. |
| `flow_min_age_s` | number | 60 | Flows are watched once this old. |
| `flow_idle_gap_s` | number > 0 | 5 | Silence after which bytes start a new burst. |
| `flow_max_avg_bps` | number | 4096 | Flows whose lifetime average (bytes/s, both directions) is above this are not watched. |
| `flow_min_burst_bytes`, `flow_max_burst_bytes` | integer | 256, 65536 | Range of the mean burst size (bytes, both directions). |
| `flow_max_tracked` | integer | 512 | Flows watched at once; others are skipped until a slot frees. |
| `ignore_domains` | list of names | FCM (`mtalk.google.com`, `mtalk4.google.com`, `alt1-mtalk.google.com` … `alt8-mtalk.google.com`, `android.apis.google.com`), `push.apple.com`, `push.services.mozilla.com` | Names and their subdomains exempt from both detectors (a leading `*.` is accepted). A list replaces the defaults. |

### `encrypted_dns`

Forwards the virtual resolver's queries over DNS-over-TLS (RFC 7858) or
DNS-over-HTTPS (RFC 8484) instead of plain DNS to `upstream_dns`. Only the
transport changes: policy, sinkholing, CNAME-cloaking checks and `dns`
events work as before. Queries an app sends to a hard-coded resolver are
still forwarded to that resolver in cleartext. The TLS connections use the
`upstream` path like every other socket (see "Encrypted DNS over an upstream
path" below).

```json
"encrypted_dns": {
  "mode": "doh",
  "servers": [
    {"url": "https://dns.quad9.net/dns-query", "addrs": ["9.9.9.9", "149.112.112.112"]}
  ],
  "fallback_plain": false
}
```

| field | type | default | meaning |
|---|---|---|---|
| `mode` | `off`, `dot`, `doh` | `off` | `off` keeps plain DNS. |
| `servers` | list (1–8 when on) | `[]` | Tried in order; an address that failed is tried after the others for 30 s. |
| `servers[].url` | string | | DoH only: `https://host[:port][/path][?query]` (no credentials or fragment; an empty path means `/dns-query`). |
| `servers[].host` | string | | DoT: the TLS name (a hostname with at least two labels, or an IP literal). DoH: optional, must equal the URL's host. |
| `servers[].port` | integer | 853 (DoT), from the URL (DoH) | DoH: optional, must equal the URL's port. |
| `servers[].addrs` | list of IP strings (≤ 8) | `[]` | Bootstrap addresses to connect to. Required unless `host` is an IP literal or `fallback_plain` is true (then the name is looked up over plain `upstream_dns`, cached up to 1 h). |
| `fallback_plain` | bool | false | When every encrypted server fails, answer from `upstream_dns` in cleartext. When false, such queries get SERVFAIL and nothing leaves in cleartext. |
| `extra_root_ca_pem` | string | absent | PEM certificates trusted in addition to the built-in Mozilla roots (`webpki-roots`), for private resolvers and tests. |

TLS is rustls with the *ring* provider (TLS 1.2 and 1.3, session
resumption). The certificate must be valid for the server's name, which is
also sent as SNI (IP literals are verified against IP SANs and send no SNI).
DoT keeps up to two long-lived connections per server address and sends
many queries on each (matched by ID and question); DoH offers `h2` and
`http/1.1` via ALPN and uses one multiplexed HTTP/2 connection, or a pool
of up to six keep-alive HTTP/1.1 connections, per server address. Queries
use DNS ID 0 over DoH. Connections close after 30 s idle. A query tries at
most three server addresses within 8 s (4 s each). Answers that exceed a
UDP client's EDNS payload size (512 without EDNS) are returned truncated
(TC set) so the client retries over TCP, as with plain DNS.

**Validation** rejects: an unknown `mode`; `mode` other than `off` without
servers; more than 8 servers or 8 addresses per server; a DoH server
without a valid `https://` URL, or with a mismatching `host`/`port`; a DoT
server without a valid `host`, or with a `url`; port 0; unspecified or
multicast addresses; a server without `addrs` (and without an IP literal
host) unless `fallback_plain`; an `extra_root_ca_pem` without any valid
certificate. While `mode` is `off` only the server count is checked.

### Upstream path (`upstream`)

Where vigil's own upstream sockets go: TCP relay connections, UDP flows,
plain DNS to the configured (or app-chosen) resolvers and the DoT/DoH
connections of `encrypted_dns`. Inspection is the same in every mode.

```json
"upstream": {
  "mode": "wireguard",
  "fail_closed": true,
  "network_id": "432902426637",
  "wireguard": {
    "private_key": "<base64>", "peer_public_key": "<base64>", "preshared_key": "<base64, optional>",
    "endpoint": "vpn.example.com:51820",
    "addresses": ["10.64.0.2/32", "fd00::2/128"],
    "allowed_ips": ["0.0.0.0/0", "::/0"],
    "mtu": 1280, "persistent_keepalive": 25
  },
  "socks5": {
    "server": "127.0.0.1:9050", "username": "", "password": "",
    "send_domain": true, "udp": "auto"
  }
}
```

| field | default | meaning |
|---|---|---|
| `mode` | `direct` | `direct`: protected sockets on the underlying network (as before). `wireguard`: a user-space WireGuard tunnel (boringtun) with a client TCP/IP stack; one protected UDP socket to the peer. `socks5`: a SOCKS5 proxy. |
| `fail_closed` | `true` | While the tunnel or proxy is down, connections fail (the app gets a RST, DNS gets SERVFAIL). With `false` they go direct instead (see `stats.upstream.state` for "down"). |
| `network_id` | `""` | Opaque id of the underlying network (the app sends the network handle). When only this changes, WireGuard re-creates its socket and re-resolves the endpoint, keeping the session (roaming). |
| `wireguard.private_key`, `peer_public_key`, `preshared_key` | | base64 X25519 keys (32 bytes); the pre-shared key is optional (null, absent or empty). |
| `wireguard.endpoint` | | `host:port` or `[v6]:port`. Host names are resolved when the tunnel starts, on roaming and every 30 s while handshakes fail. IPv4 answers are preferred. |
| `wireguard.addresses` | | Tunnel addresses (CIDR; a bare address is a host route). At most one IPv4 and one IPv6. Destinations of a family without an address fail (apps fall back to the other family). |
| `wireguard.allowed_ips` | `[]` (everything) | Destinations routed through the peer, as wg-quick does; others go direct. Inner packets from other sources are dropped. |
| `wireguard.mtu` | 1420 | Tunnel MTU, 576..=65535 (the app sends 1280 unless the `.conf` sets one). |
| `wireguard.persistent_keepalive` | 0 | Seconds between keepalives (0 = off). |
| `socks5.server` | | `host:port` of the proxy (loopback works, e.g. Orbot's `127.0.0.1:9050`). |
| `socks5.username`, `password` | `""` | RFC 1929 credentials, at most 255 bytes each; a password needs a username. |
| `socks5.send_domain` | `false` | CONNECT by the TLS SNI or HTTP Host the app sent (the proxy resolves it; useful for Tor) instead of by address. The upstream connection is then made when the app's first bytes arrive (or after 3.5 s by address, for server-speaks-first protocols), so a failure resets an already accepted connection instead of refusing it. |
| `socks5.udp` | `auto` | `auto`: UDP flows use UDP ASSOCIATE (one association per flow); once the proxy refuses it, UDP is blocked. `block`: UDP is never relayed. Plain DNS always goes to the proxy as DNS over TCP. |

Changing `upstream` with `nativeUpdateConfig` takes effect at once for new
connections, UDP flows and DNS queries; open ones keep the path they were
opened on until they end (a replaced WireGuard tunnel lives until its last
connection closes). The app restarts the session only when the excluded
proxy app changes (that needs a new VPN interface).

### Encrypted DNS over an upstream path

`encrypted_dns` and `upstream` combine; neither replaces the other.

- **DoT/DoH connections** are opened through the upstream path: inside the
  WireGuard tunnel, or as TCP connections through the SOCKS5 proxy (CONNECT
  to the server's bootstrap address; `send_domain` does not apply). The
  proxy or tunnel peer sees only TLS. `fail_closed` applies to them as to
  any connection: with the path down they fail (SERVFAIL unless
  `fallback_plain`), never going direct. When the path changes, open
  encrypted DNS connections are dropped and new ones use the new path.
- **Plain DNS** (encrypted DNS off, `fallback_plain`, bootstrap lookups of
  server names, hard-coded resolvers) goes to `upstream_dns` or the
  app's resolver over the same path; with SOCKS5 always as DNS over TCP
  (`dns.upstream` = `tcp`).
- **Precedence** (as the app builds the config): when `encrypted_dns.mode`
  is not `off` it answers the virtual resolver's lookups, whatever
  `upstream_dns` holds. `upstream_dns` is chosen independently: the
  WireGuard configuration's DNS servers, else the custom resolvers, else
  public resolvers in tunnel and proxy modes (the network's resolver is
  usually unreachable through them), else the network's resolvers. It is
  then used only for the plain cases above.

**Validation.** `nativeStart` returns 0 and `nativeUpdateConfig` returns
false (and the running config is kept) when the JSON does not parse or:

- `beacon.max_jitter`, `beacon.min_interval_s` or `beacon.max_interval_s`
  is negative or not finite, or `min_interval_s > max_interval_s`;
- `beacon.flow_min_age_s` or `beacon.flow_max_avg_bps` is negative or not
  finite, `beacon.flow_idle_gap_s` is not positive and finite, or
  `flow_min_burst_bytes > flow_max_burst_bytes`;
- `mtu` is outside 576..=65535;
- `tcp_connect_timeout_ms` or `udp_idle_timeout_s` is 0;
- `upstream_dns` is empty;
- any of the four caps above is 0;
- `encrypted_dns` is invalid (see its section above);
- `upstream.mode` is `wireguard` or `socks5` without its section, a key is
  not base64 of 32 bytes, an endpoint or server is not `host:port`, an
  address or AllowedIPs entry is not a CIDR, there is no tunnel address or
  more than one per family, the WireGuard MTU is outside 576..=65535, or
  SOCKS5 credentials are too long or a password has no username.

UDP flows end `udp_idle_timeout_s` after the last datagram *received from
the server*; outbound datagrams alone do not keep a flow alive. A flow
that never received anything ends after 30 s (or the idle timeout, if
shorter). The app's next datagram starts a new flow on a fresh socket.

## Engine lifecycle (JNI)

`VigilNative` (Kotlin) ↔ `core/vigil-jni/src/lib.rs`:

| call | behaviour |
|---|---|
| `nativeStart(tunFd, configJson, bridge): Long` | 0 on failure (including an invalid config). |
| `nativeShutdown(handle): Boolean` | Stops the engine (TUN loop, relays, runtime), then queues a `flow_end` for every open flow and a final `engine` event with `state: stopped`. The handle stays valid: `nativePollEvents` keeps returning the remaining events and, once the queue is empty, returns null immediately instead of waiting. `nativeUpdateConfig` and `nativeRemoveFeed` return false, `nativeStats` and `nativeLoadFeedFile` return null. A second call is a no-op returning true; false only for a null handle. |
| `nativeStop(handle)` | Stops the engine if it is still running (same events as above, which are then lost with the handle) and frees the handle. Must be called exactly once, also after `nativeShutdown`. |

To keep the final `flow_end` events, call `nativeShutdown`, drain
`nativePollEvents` until it returns null, then call `nativeStop`.

## SIEM records (app → collector)

Exported records follow Elastic Common Schema field names so they index
without custom pipelines. A completed flow looks like this:

```json
{
  "@timestamp": "2026-09-27T18:06:02.114Z",
  "event": {"kind": "event", "category": ["network"], "type": ["connection"], "action": "allow",
            "duration": 514000000, "end": "2026-09-27T18:06:02.628Z", "dataset": "vigil.flow",
            "id": "5f0c3a9e1b7d4c2a8e6f1a2b3c4d5e6f"},
  "vigil": {"type": "flow", "flow_id": 17, "domain_source": "sni", "tags": []},
  "app": {"package": "com.android.chrome", "name": "Chrome", "uid": 10131, "system": true},
  "network": {"transport": "tcp", "protocol": "tls", "bytes": 5724},
  "source": {"ip": "10.111.222.1", "port": 40312, "bytes": 664},
  "destination": {"ip": "185.15.59.224", "port": 443, "domain": "en.wikipedia.org", "bytes": 5060},
  "tls": {"version": "TLS1.3", "next_protocol": "h2", "client": {"ja4": "t13d1516h2_8daaf6152771_d8a2da3f94cd", "server_name": "en.wikipedia.org"}, "ech": false},
  "host": {"id": "<install UUID>", "type": "mobile", "os": {"family": "android", "version": "35"}, "hostname": "Google Pixel 6"},
  "observer": {"vendor": "vigil", "product": "vigil", "version": "0.1.0"}
}
```

A flow whose JA4 is listed also carries `vigil.ja4_match` (`feed`, `rule`,
`label`). Flows carry the upstream path as `vigil.via` and, when the
engine knows the destination's autonomous system, ECS
`destination.as.number` and `destination.as.organization.name` plus
`vigil.asn_country` (the AS registration country). DNS records carry the
upstream transport as `vigil.upstream`. DNS records use `dns.question.name/type`, `dns.response_code` and
`dns.answers[].data`. Alerts use `event.kind: "alert"`, `event.severity`
(0–100) and `message`.

`event.id` is a deterministic hash of the install id and the record's content,
so a record re-sent after a lost response carries the same id and can be
deduplicated downstream (Elastic uses it as the document `_id`).

Transports:

- **Syslog:** RFC 5424, facility local0, severity mapped from the alert
  severity, APP-NAME `vigil`, MSGID `flow`/`dns`/`alert`, and the JSON record
  as the message. Timestamps carry at most six fractional digits. TCP and TLS
  use RFC 6587 octet counting. TLS sends SNI, verifies the server hostname
  and can present a KeyChain client certificate. Over UDP a message is capped
  at 8 KB: long string values of larger records are shortened (and
  `vigil.truncated` is set) so the JSON stays valid.
- **HTTP:** `ndjson` (one record per line, e.g. for Logstash/Vector/Fluent Bit
  HTTP inputs), `splunk_hec` (`{"time","sourcetype":"vigil:json","event":…}`),
  or `elastic_bulk` (`{"create":{"_id":<event.id>}}` action lines; point the
  URL at `…/<index>/_bulk`). An optional `Authorization` header is sent. For
  `_bulk`, only items that failed with 429/5xx are retried; 409 (already
  indexed) counts as delivered and other item errors as rejected.

Delivery: records wait in a bounded queue (10,000; the oldest are dropped and
counted when it overflows). The head batch is retried with backoff up to one
minute until it is delivered or export is turned off (queued records are then
counted as dropped). While the device is offline the exporter waits for a
network. Authentication errors (401/403) are retried once a minute until the
settings change; a batch refused with 400 is counted as rejected.

The export level selects what is sent: alerts only (the default), alerts and
DNS, or everything.
