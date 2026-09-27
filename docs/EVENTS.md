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

Every `flow` is followed by exactly one `flow_end` with the same `id`. Flow
ids restart at 1 in each engine session.

`domain_source` tells you how much to trust `domain`: `sni`, `quic` and `http`
are what the app itself sent. `dns` is a reverse lookup of the address in
recent DNS answers, which is ambiguous for shared CDN addresses, so it is
never used for blocking.

### Alert kinds

| kind | severity | raised when |
|---|---|---|
| `threat_domain` | high | a lookup or connection matches a malware, phishing or C2 feed |
| `threat_ip` | high | a connection's address matches a threat IP feed |
| `beacon` | medium | ≥ 6 connections to one destination at a near-constant interval (10 s–1 h, jitter ≤ 15 % by default) |
| `encrypted_dns` | low | an app uses DoH, DoT or DoQ, so its lookups are invisible |
| `hardcoded_dns` | info | an app sends DNS to a server other than the system resolver |
| `new_destination` | info | (opt-in, app-side) after a 24 h learning period, an app contacts a domain it never used before |

Repeated alerts with the same kind, app and target are suppressed for an hour.

## SIEM records (app → collector)

Exported records follow Elastic Common Schema field names so they index
without custom pipelines. A completed flow looks like this:

```json
{
  "@timestamp": "2026-09-27T18:06:02.114Z",
  "event": {"kind": "event", "category": ["network"], "type": ["connection"], "action": "allow",
            "duration": 514000000, "end": "2026-09-27T18:06:02.628Z", "dataset": "vigil.flow"},
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

Transports:

- **Syslog:** RFC 5424, facility local0, severity mapped from the alert
  severity, APP-NAME `vigil`, MSGID `flow`/`dns`/`alert`, and the JSON record
  as the message. TCP and TLS use RFC 6587 octet counting. TLS verifies the
  server hostname and can present a KeyChain client certificate.
- **HTTP:** `ndjson` (one record per line, e.g. for Logstash/Vector/Fluent Bit
  HTTP inputs), `splunk_hec` (`{"time","sourcetype":"vigil:json","event":…}`),
  or `elastic_bulk` (`{"create":{}}` action lines; point the URL at
  `…/<index>/_bulk`). An optional `Authorization` header is sent.

The export level selects what is sent: alerts only (the default), alerts and
DNS, or everything.
