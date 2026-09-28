# Architecture

## Design decisions (and how they differ from the original sketch)

| Topic | Decision | Why |
|---|---|---|
| Split | Kotlin for the Android framework, UI and persistence; Rust for everything on the packet path | The JVM stays out of per-packet work, and Rust stays out of Android APIs. |
| TCP stack | `netstack-smoltcp` (smoltcp's TCP state machine), with **vigil owning the TUN loop** | smoltcp is mature. Owning the read/write loop lets vigil see, count, gate and drop every raw packet, which an opaque tun2socks library would not allow. |
| Vendored `netstack-smoltcp` | `core/vendor/netstack-smoltcp` (0.2.4 plus a small patch, via `[patch.crates-io]`) | Upstream cannot abort a connection, so resets reached apps as orderly FINs, and it reported a peer's RST as EOF. The patch adds `TcpStream::abort` (smoltcp sends a RST) and surfaces resets as `ConnectionReset`. Later patches: `shutdown()` completes once the FIN is queued, TIME-WAIT is 1 s (smoltcp scans every socket per packet), a new SYN replaces a lingering socket with the same 4-tuple, a direct input sender (`Stack::tcp_sender`), a poll loop that yields without a tokio driver turn, sockets that smoltcp resets back to LISTEN (a RST in SYN-RECEIVED) reaped as resets instead of lingering as listeners, and `TcpAbortHandle::closed()`. Changes are marked `vigil patch`. |
| UDP | vigil's own NAT, not the stack's | DNS and QUIC need per-datagram inspection, and per-flow tasks allow holding back the first QUIC datagrams until the SNI is known. |
| Loop avoidance | `addDisallowedApplication(self)` **and** `protect()` on every relay socket | Excluding the app also covers feed downloads and SIEM export, and `protect()` is kept as a second guard. |
| Attribution | `getConnectionOwnerUid` on Android 10+ only | `sock_diag` and `/proc/net` are blocked by SELinux for apps on modern Android, so the pre-API-29 fallback in the sketch does not work there. |
| Upcalls | Events are **polled** by Kotlin (a JSON batch per call, blocking up to 500 ms; once the first event arrives the poll collects for up to 20 ms more, so a busy engine wakes the JVM at most about 50 times a second). The only JVM upcalls are UID lookup and `protect`, made off the packet path. | No JNI callbacks on hot paths, and a slow consumer drops events instead of stalling traffic. |
| SYN handling | The SYN is held while vigil attributes the flow, checks policy and **connects upstream first** | Refused or unreachable destinations reach the app as a real RST. |
| Packet capture | An in-memory ring in the engine, attributed at export time; PCAP-over-IP served by the engine | The packet path stays a copy with no lookups, and only an explicit export touches storage. Streaming from Rust avoids a JNI crossing per packet. |
| Parsers | Hand-written, bounds-checked zero-copy readers instead of `nom` | They are small and dependency-free, and garbage-input tests show they never panic. |
| Feeds | Sorted string arena plus binary search per label | About 8 bytes of overhead per entry and no per-name allocation, streamed from disk. Better suited to phones than a trie or HashSet. |
| Upstream chaining | One dialer (`engine/upstream`) for every upstream socket: direct, WireGuard (boringtun + a client-side smoltcp interface) or SOCKS5 | Android allows one VPN, so users of a real VPN could not run vigil. Terminating flows in user space already gives vigil its own upstream sockets; only their egress changes, so inspection is identical in every mode. |
| WireGuard in user space | `boringtun` (vendored as an rlib) for Noise; smoltcp 0.12 (the version netstack-smoltcp already pulls in) for the tunnel's TCP/UDP | No kernel or root needed; the same crates cross-compile for all ABIs. Kernel WireGuard is used only as the e2e peer. |

## Engine data path (`core/vigil-core/src/engine`)

1. **Read loop** (`mod.rs`). Before the first read, the feed files of the
   start configuration (`feeds`) are loaded, for at most
   `feeds_preload_timeout_ms` (then they finish in the background), so
   blocklists apply from the first packet after a boot or restart. Each TUN
   read is one IP packet, parsed by
   `packet.rs`. Fragments and non-TCP/UDP packets are dropped and counted.
   IPv6 atomic fragments (offset 0, no more fragments) are whole packets and
   are processed; for TCP the fragment header is stripped before smoltcp.
   IPv6 TCP with other extension headers (smoltcp would misparse them) and
   SYN|RST segments are dropped, the former SYNs with a RST to the app.
   Interrupted reads are retried, ENOBUFS/ENOMEM back off (up to 1 s, 100
   times in a row); any other read error ends the session with an `engine`
   `error` event, and the app restarts it. The same happens when a panic
   ends the loop, or when any of the engine's long-running tasks (the TCP
   stack, the TUN writer, the accept loop, housekeeping) ends or panics.
2. **TCP SYN → gate** (`tcp.rs`). A connection's 4-tuple is registered from
   its first SYN until the connection ends, and retransmitted SYNs for it are
   dropped (smoltcp retransmits its own SYN-ACK), so a slow handshake never
   leads to a second upstream connection. SYNs beyond `max_pending_connects`
   gates or `max_tcp_flows` connections get a RST. The gate:
   - looks up the UID via the platform (Binder IPC, on a blocking thread);
   - admits DNS over TCP (port 53) to *any* address into vigil's resolver
     (virtual resolver: configured upstreams; other address: that server,
     with a `hardcoded_dns` alert, unless the server's address is blocked
     for the app by IP policy), and refuses other ports on the virtual
     resolver, including the Private DNS probe on 853. Messages to a
     hard-coded server that are not standard queries are refused, never
     relayed;
   - checks policy by IP (app block, IP feeds, DoT on 853);
   - connects upstream through the upstream dialer (a protected socket,
     created and protected on the blocking pool since `protect()` is a JNI
     upcall plus netd IPC; or a connection through the WireGuard tunnel or
     SOCKS5 proxy, see below).

   On success the SYN goes to smoltcp and the flow's metadata (including the
   connected upstream socket) is parked until smoltcp yields the stream. On
   failure the app gets a RST.
3. **Relay.** Server→client copying starts immediately, so server-speaks-first
   protocols work. The client→server direction first *sniffs*: it buffers data
   until a TLS ClientHello (across any number of records and segments) or an
   HTTP request head is complete, or 3 s pass. It then decides on the name
   (feeds, allow/deny, encrypted-DNS policy), emits the `flow` event, and
   either forwards the buffer and continues or resets the connection.
   Resets propagate: if the server resets, the app gets a RST (smoltcp
   abort); if the app resets, the upstream socket is closed with
   `SO_LINGER` 0, which sends a RST. That holds after the app has sent its
   FIN too (the relay then watches the app's socket for a reset), and a new
   SYN from the app on a half-closed connection's 4-tuple ends the old relay
   so the app's retransmitted SYN is admitted. Blocked names and the 2 h
   idle timeout reset both sides. A connection that ends before its `flow` was emitted
   (e.g. the server resets during the sniff window) is still reported.
4. **UDP port 53** (`dns.rs`). Queries are parsed, checked against policy and
   either sinkholed or forwarded. Queries to the virtual resolver go to the
   configured upstreams; queries to a hard-coded server go to that server and
   raise an alert, unless the server's address is on an IP feed (then
   REFUSED, plus a `threat_ip` alert for threat feeds). Queries with a
   question count other than one are refused, since only one question could
   be inspected. A truncated UDP answer is passed to the app as is (it
   retries over TCP within its own EDNS size); TCP clients get the answer
   fetched over TCP. Answers are checked for **CNAME cloaking**, and their
   addresses feed the IP→name cache used to label later connections.
   Protected upstream sockets are pooled (4 per resolver, at most 30 s old)
   and replies are matched on ID and question. At most `max_dns_inflight`
   queries run at once; others get SERVFAIL. A UDP/53 payload to another
   address that is not a DNS query is relayed as ordinary UDP (step 5).

   With `encrypted_dns` on, the virtual resolver's queries leave over
   DNS-over-TLS or DNS-over-HTTPS instead (`dns_upstream.rs`; only the
   forwarding call in `dns.rs` changes, inspection stays the same). TLS is
   rustls with the *ring* provider and the Mozilla roots. DoT pipelines
   queries over up to two long-lived connections per server address,
   rewriting IDs so concurrent clients cannot collide; DoH uses one
   multiplexed HTTP/2 connection (the `h2` crate), or keep-alive HTTP/1.1
   if the server does not offer `h2`. Without `fallback_plain` a failure is
   SERVFAIL and nothing is sent in cleartext; bootstrap addresses are part
   of the configuration. Every socket of that module is opened by
   `connect_encrypted_upstream`, and the TLS/HTTP code is generic over the
   stream type, so an upstream dialer (proxy, tunnel) plugs in at one
   place.
5. **Other UDP** (`udp.rs`). A NAT task runs per 5-tuple, up to
   `max_udp_flows` (then the longest idle 1/32 of the flows is evicted and
   their tasks stopped; at most 8 flows look up their UID or create their
   socket at once, so a UDP sprayer cannot occupy the blocking pool the TCP
   gate and `protect()` need). For ports 443
   and 80 the first datagrams are held (for at most 250 ms) while
   `QuicSniffer` decrypts Initial packets and reassembles shuffled CRYPTO
   frames. Blocked flows are absorbed until idle, so retries don't flood the
   event stream. Only datagrams from the server extend a flow's life (idle
   timeout after the last one, 30 s if there never was one), so a flow whose
   socket was stranded by a network change ends and the next datagram gets
   a fresh socket. Replies are read through one 64 KiB buffer per worker
   thread, not one per flow.
6. **Events** (`event.rs`) go into a bounded queue. When it is full, a
   `stats` or `flow_update` near the front is dropped, else the oldest event.
   Every `flow` gets exactly one `flow_end`, including at shutdown: the
   runtime is stopped first and the remaining open flows are ended after it,
   so no flow can open after the final sweep. Long flows emit `flow_update`
   with live byte counts.
7. **Per-app rules** (`policy.rs`). Besides apps blocked at all times, an
   app can be blocked on Wi-Fi, on mobile data, in the background or with
   the screen off (`app_rules`), and a domain can be allowed or blocked for
   one app (`app_domain_rules`). The conditions are evaluated against a
   device state the host pushes on its own (`Engine::set_device_state`,
   `nativeSetDeviceState`), because it changes on every app switch: one
   hash lookup per decision. The app block comes first (before any name is
   known, at the SYN gate and for UDP flows and DNS), then the app's allow
   and block rules, then the global lists and feeds. Every allowed relay and
   UDP flow is registered in the open-flow table with its UID, the name the
   app sent and a cut signal (`FlowCut`); after a state or rule change,
   `Shared::recheck_open_flows` walks that table and cuts the flows the
   per-app rules now block (the relay resets both sides, the UDP flow ends;
   `flow_end.error` = `blocked: <reason>`), and wakes UDP flows held blocked
   by a per-app rule so they re-decide. Per-app DNS decisions are answered with
   TTL 0 (and answers for names with a per-app rule get their TTLs zeroed),
   because Android's resolver cache is per network and shared by every app.
8. **Alerts** (`detect.rs`) are deduplicated per kind, app and finding for an
   hour (threat alerts by matched feed entry, so DGA names do not cause
   storms), in a table of at most 10 000 findings, with a global budget of
   120 alerts per minute. The beacon detector's table (20 000 series) is
   pruned at most once a minute when full; until then new targets are not
   tracked.

## Packet capture (`engine/capture`)

Off by default (`capture` in the config, Settings → Packet capture). While
off, the only cost is one relaxed atomic load per packet.

- **Hooks.** The TUN read loop records every packet it reads (what apps
  sent, including what vigil then drops, such as ICMP or blocked SYNs)
  before dispatching it, and the TUN writer every packet it writes
  (what vigil sent to apps: relayed data, DNS answers, RSTs). So the
  capture shows the app's side of each connection, exactly as the apps saw
  it; vigil's own upstream sockets (and anything encrypted by a WireGuard
  or SOCKS5 upstream) are not captured.
- **Ring.** One byte buffer of `buffer_bytes` (16 MiB by default, 128 MiB
  at most) holding variable-length records (a 16-byte header with the
  timestamp in µs, original and captured length, direction, then the
  packet cut at `snaplen`), the oldest overwritten first. Memory is exactly
  the buffer (allocated zeroed, so pages are committed as it fills), with no
  per-packet allocation. The clock is read under the ring's lock, so the
  ring is in time order across the reader and writer tasks.
- **Attribution, lazily.** The packet path does no lookups. The engine
  records *bindings* instead: a 5-tuple → UID at every UID lookup (the SYN
  gate, UDP flow set-up, each DNS query) and 5-tuple → flow id at every
  `flow` event (flows already open when capture is turned on are bound
  then). An export matches each packet's 5-tuple and time against them:
  the latest binding made before the packet, except that a
  connection-opening SYN (seen before its flow exists) takes the first one
  after it. Bindings older than the oldest packet held are pruned by
  housekeeping (at most 65 536 5-tuples).
- **Export** (`Engine::export_pcap`, JNI `nativeExportPcap`, `vigil-cli run
  --pcap-on-exit`): the ring is copied out under its lock (one memcpy),
  then filtered (flow ids, UIDs, time; AND-combined) and written as PCAPng
  outside it: a section header, one interface (LINKTYPE_RAW, µs
  timestamps) and an Enhanced Packet Block per packet, with the direction
  in `epb_flags` (outbound = sent by the app) and a `uid=… flow=…` comment
  when known. The app has the engine write to a private cache file and
  copies it to the document the user picked (Storage Access Framework).
- **PCAP-over-IP** (`capture.stream`): a TCP server in the engine (the
  packets are there; streaming them through the JVM would cost a JNI
  crossing per packet or a polling delay). It listens on the address the
  app passes (the Wi-Fi IPv4 address by default, never cellular; `0.0.0.0`
  or `127.0.0.1` on request), retrying every 5 s while the bind fails. Each
  client gets a classic PCAP header (LINKTYPE_RAW) and then every packet
  recorded from then on. The packet path only `try_send`s into a bounded
  queue per client (8192 packets / 8 MiB); a slow client loses packets
  (`stats.capture.stream.dropped`) and never slows traffic. At most two
  clients; others, and addresses outside the allowlist, are disconnected at
  once. The sockets belong to the app process, which is excluded from its
  own VPN, so they use the Wi-Fi network directly.

A capture lives as long as the engine session: turning capture off, and
every session restart (routes, excluded app, worker threads), discards it.

## Upstream paths (`engine/upstream`)

Every upstream socket comes from the dialer: `upstream::connect_relay`
(TCP relay, at the SYN gate), `connect_tcp` (DNS over TCP, and any other
engine code needing an upstream TCP connection) and `connect_udp` (UDP
flows and the pooled DNS sockets). The result is an `UpstreamTcp`
(`AsyncRead + AsyncWrite + Unpin + Send`) or an `UpstreamUdp` (send /
receive-with-callback), and says which path it took (`via`).

- **direct**: the protected sockets of `sock.rs`, unchanged. The relay
  splits them into tokio's owned halves as before, so this mode costs one
  enum match per read/write.
- **wireguard**: `wireguard.rs` keeps a smoltcp `Interface` (medium IP,
  the tunnel addresses) and its sockets behind one lock, and boringtun's
  `Tunn` behind another. A driver task owns the protected UDP socket to the
  endpoint: it decrypts datagrams (under the Noise lock) and queues the
  inner packets for smoltcp, polls smoltcp, takes what it emitted out of
  the stack lock and encrypts it under the Noise lock, and runs the
  WireGuard timers (handshake retries, keepalive, rekey) every 250 ms.
  Streams only copy bytes under the stack lock and wake the driver, so
  they do not wait behind encryption. TCP connects complete the tunnelled
  handshake before the SYN gate admits the app's SYN, so refusals stay
  faithful; resets map to smoltcp aborts both ways. Handshakes failing for
  10 s mark the tunnel down (an idle tunnel is not down), as does a failed
  attempt to open the socket; while down it retries every 15 s and
  re-creates the socket / re-resolves the endpoint every 30 s. A
  `network_id` change (the app sends the network handle) re-creates the
  socket at once; the session survives, the tunnel does not count as down
  meanwhile (packets wait in the queues), and the peer learns the new
  address from the next packet. The endpoint lookup has a 5 s timeout and
  keeps the last address if it fails. With `fail_closed: false`, the
  dialer generation that keys the pooled DNS sockets and encrypted DNS
  sessions changes whenever the tunnel goes down or comes back, so
  connections opened direct during an outage are not reused afterwards. A
  replaced tunnel's driver ends when its last connection does; dropping
  the tunnel runs a final pump so that connection's FIN or RST still
  reaches the peer.
- **socks5**: `socks5.rs` speaks CONNECT (by address, or by the sniffed
  SNI/Host with `send_domain`: the connection to the proxy and the
  authentication are made at the SYN gate, only the CONNECT waits for the
  app's first bytes) and UDP ASSOCIATE (one association per UDP flow; a
  refusal by reply code is remembered and UDP is blocked from then on).
  Plain DNS goes to the proxy as DNS over TCP. Only failures to use the
  proxy itself count as "down": lookup, connect, method selection or
  authentication failing or taking more than 7 s together, a reply taking
  more than 30 s, or an I/O error mid-negotiation (Tor restarting). A
  CONNECT refused by the destination (a reply code) is reported to the app
  like a direct refusal. A proxy host name is looked up with a 3 s timeout
  and cached for 5 minutes (re-resolved after a failed connect; the last
  address is kept if the lookup fails).
- **fail closed** (default): errors are returned, never replaced by a direct
  connection. With `fail_closed: false` the dialer goes direct while the path
  is down. WireGuard destinations outside AllowedIPs always go direct, as
  wg-quick routes them.

Loopback proxies work: sockets to 127.0.0.1 are protected like any other,
and the loopback route precedes the VPN's routing rules. A proxy *app* on
the same phone (Orbot) must be excluded from vigil's VPN, or its own
connections would loop back into the proxy; the app adds it with
`addDisallowedApplication`.

## Known engine limitations

- **QUIC names are sniffed only on UDP ports 443 and 80**, and only when
  the flow's first datagram is a QUIC Initial within the first 250 ms.
  HTTP/3 on other ports (e.g. advertised through Alt-Svc) and flows that
  start mid-connection (e.g. after connection migration) are relayed and
  shown by address, with a DNS-derived name at best.
- Resource caps (`max_*`) are fixed when the engine starts.
- Per-app conditions are as current as the host's device state. On Android
  the foreground app comes from usage stats, polled once a second while
  some app has a background rule and the screen is on, so an app's first
  connections after it comes to the screen can still be refused for up to
  about a second. Global lists and feeds are not re-applied to open
  connections (per-app rules are).
- DNS over TCP to port 53 of any address is treated as DNS. Other
  protocols on TCP/53 are not relayed transparently.
- IP fragments (other than IPv6 atomic fragments) are dropped, and ICMP is
  not relayed.
- WireGuard: one peer; no IP fragmentation inside the tunnel (datagrams
  larger than the tunnel MTU are dropped); destinations of a family without
  a tunnel address fail. A TCP connection's window through the tunnel is
  256 KiB (about 40 Mbit/s at 50 ms RTT), and there is no congestion control
  on the tunnelled side.
- SOCKS5: UDP needs a proxy with UDP ASSOCIATE (Tor has none: UDP is then
  blocked and QUIC falls back to TCP). DNS over TCP through the proxy
  opens a connection per query (slow through Tor). An answer larger than
  the app's UDP buffer is not truncated for it.

## Android app (`android/app/src/main/java/dev/vigil/inspector`)

- `vpn/VigilVpnService`: owns one *session* (TUN, engine handle, event pump,
  feed sync, config sync, device-state push, notification). Route changes
  re-establish the interface. It supports always-on VPN and a Quick
  Settings tile. The device state for per-app rules comes from the default
  network callback (Wi-Fi / mobile data), `ACTION_SCREEN_ON`/`OFF` and
  `processing/ForegroundTracker` (usage access); only changes are pushed.
- `data/AppRules`: per-app rules are stored by app key (package or
  `uid:<n>`) in the settings and resolved to UIDs by `vpn/ConfigFactory`;
  packages sharing a UID share one engine rule (their conditions merge).
- `engine/EngineHandle`: a read/write lock around the native handle, so
  `nativeStop` can never race a poll.
- `processing/EventProcessor`: batches each poll into one Room transaction,
  resolves UIDs to apps, tags background traffic, records (app, destination)
  pairs for novelty alerts, and feeds the SIEM exporter with completed flow
  records.
- `data/`: Room (flows, dns_queries, alerts, destinations, feeds), a single
  JSON settings document, feed downloads (atomic: download, validate with the
  Rust parser, then rename) and a daily WorkManager refresh with retention
  pruning.
- `export/`: ECS-shaped records, syslog/HTTP wire formats, and mTLS through
  KeyChain.
- `ui/`: Compose screens for Overview, Activity (connections/DNS), Apps (with
  per-app detail, blocking and network-access conditions), Alerts, Settings,
  Feeds, Export and Rules (global and per-app).

## Addresses

| | IPv4 | IPv6 |
|---|---|---|
| TUN | 10.111.222.1/24 | fd76:6967:696c::1/64 |
| Virtual resolver | 10.111.222.2 | fd76:6967:696c::2 |

With "keep local network traffic direct" (the default), routes cover all
public IPv4 space except RFC 1918, CGNAT, link-local, loopback and multicast,
plus the virtual subnet, and IPv6 `2000::/3`.
