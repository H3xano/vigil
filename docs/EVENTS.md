# Event schema

## Engine events (Rust → app)

The engine emits one JSON object per event with a `type` field. `vigil-cli`
prints them as JSON lines; the app polls them in batches (JSON arrays).

| type | fields |
|---|---|
| `flow` | `id`, `ts` (ms), `proto` (`tcp`/`udp`), `uid`, `src`, `dst_ip`, `dst_port`, `domain`, `domain_source` (`sni`, `quic`, `http`, `dns`), `app_proto` (`tls`, `quic`, `http`, `dot`, `doq`), `alpn`, `tls_version`, `ja4`, `ech`, `http_method`, `verdict` (`allow`/`block`), `reason`, `tags` (`encrypted_dns`, `plaintext_http`, `ech`) |
| `flow_update` | `id`, `ts`, `tx`, `rx` (running totals of long-lived flows) |
| `flow_end` | `id`, `ts`, `tx` (bytes sent by the app), `rx`, `duration_ms`, `error` |
| `dns` | `ts`, `uid`, `qname`, `qtype`, `rcode`, `answers`, `verdict`, `reason`, `latency_ms`, `server` (`virtual` or the hard-coded resolver), `transport` |
| `alert` | `ts`, `kind`, `severity` (`info`, `low`, `medium`, `high`), `uid`, `target`, `message`, `detail` |
| `stats` | packet/byte counters, active flows, DNS queries, blocked, dropped packets/events, DNS cache size |
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
`socket: …`, `evicted: UDP flow limit reached`, or `engine stopped`. A flow
that the server resets before the app has sent anything is still reported
(`flow` with `verdict: allow`, then `flow_end` with the error).

In `dns` events, `rcode` is `REFUSED` (with `verdict: block`) when the app
queried a hard-coded resolver whose address is on an IP feed. Queries with
more than one question (or none) are answered REFUSED and not logged. DNS
over TCP to any resolver, not only the virtual one, is inspected and logged
with `transport: tcp`; such connections do not produce `flow` events.

`dst_ip` is always the address the app used. For NAT64 addresses (see
`nat64_prefixes` below) IP feeds are matched on the embedded IPv4 address,
and `threat_ip` alerts name that IPv4 address as `target`.

`domain_source` tells you how much to trust `domain`: `sni`, `quic` and `http`
are what the app itself sent. `dns` is a reverse lookup of the address in
recent DNS answers, which is ambiguous for shared CDN addresses, so it is
never used for blocking.

### Alert kinds

| kind | severity | raised when |
|---|---|---|
| `threat_domain` | high | a lookup or connection matches a malware, phishing or C2 feed |
| `threat_ip` | high | a connection's address, or a hard-coded DNS server's address, matches a threat IP feed |
| `beacon` | medium | ≥ 6 connections to one destination at a near-constant interval (10 s–1 h, jitter ≤ 15 % by default) |
| `encrypted_dns` | low | an app uses DoH, DoT or DoQ, so its lookups are invisible |
| `hardcoded_dns` | info | an app sends DNS to a server other than the system resolver |
| `new_destination` | info | (opt-in, app-side) after a 24 h learning period, an app contacts a domain it never used before |

Repeated alerts with the same kind, app and *finding* are suppressed for an
hour. For `threat_domain` and `threat_ip` the finding is the matched feed
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
| `max_udp_flows` | integer > 0 | 2048 | UDP NAT entries. When full, the flow idle for longest is evicted (`flow_end.error` = `evicted: …`). |
| `max_tcp_flows` | integer > 0 | 4096 | TCP connections admitted or relaying. Further SYNs are answered with a RST. |
| `max_pending_connects` | integer > 0 | 256 | TCP connections waiting at the SYN gate (UID lookup and upstream connect, up to `tcp_connect_timeout_ms`). Further SYNs are answered with a RST. |
| `max_dns_inflight` | integer > 0 | 256 | DNS queries being answered at once. Further queries get SERVFAIL. |

The four caps are read when the engine starts; a later config update does
not resize them.

**Validation.** `nativeStart` returns 0 and `nativeUpdateConfig` returns
false (and the running config is kept) when the JSON does not parse or:

- `beacon.max_jitter`, `beacon.min_interval_s` or `beacon.max_interval_s`
  is negative or not finite, or `min_interval_s > max_interval_s`;
- `mtu` is outside 576..=65535;
- `tcp_connect_timeout_ms` or `udp_idle_timeout_s` is 0;
- `upstream_dns` is empty;
- any of the four caps above is 0.

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

DNS records use `dns.question.name/type`, `dns.response_code` and
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
