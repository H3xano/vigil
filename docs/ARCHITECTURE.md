# Architecture

## Design decisions (and how they differ from the original sketch)

| Topic | Decision | Why |
|---|---|---|
| Split | Kotlin for the Android framework, UI and persistence; Rust for everything on the packet path | The JVM stays out of per-packet work, and Rust stays out of Android APIs. |
| TCP stack | `netstack-smoltcp` (smoltcp's TCP state machine), with **vigil owning the TUN loop** | smoltcp is mature. Owning the read/write loop lets vigil see, count, gate and drop every raw packet, which an opaque tun2socks library would not allow. |
| Vendored `netstack-smoltcp` | `core/vendor/netstack-smoltcp` (0.2.4 plus a small patch, via `[patch.crates-io]`) | Upstream cannot abort a connection, so resets reached apps as orderly FINs, and it reported a peer's RST as EOF. The patch adds `TcpStream::abort` (smoltcp sends a RST) and surfaces resets as `ConnectionReset`. Changes are marked `vigil patch`. |
| UDP | vigil's own NAT, not the stack's | DNS and QUIC need per-datagram inspection, and per-flow tasks allow holding back the first QUIC datagrams until the SNI is known. |
| Loop avoidance | `addDisallowedApplication(self)` **and** `protect()` on every relay socket | Excluding the app also covers feed downloads and SIEM export, and `protect()` is kept as a second guard. |
| Attribution | `getConnectionOwnerUid` on Android 10+ only | `sock_diag` and `/proc/net` are blocked by SELinux for apps on modern Android, so the pre-API-29 fallback in the sketch does not work there. |
| Upcalls | Events are **polled** by Kotlin (a JSON batch per call, blocking up to 500 ms). The only JVM upcalls are UID lookup and `protect`, made off the packet path. | No JNI callbacks on hot paths, and a slow consumer drops events instead of stalling traffic. |
| SYN handling | The SYN is held while vigil attributes the flow, checks policy and **connects upstream first** | Refused or unreachable destinations reach the app as a real RST. |
| Parsers | Hand-written, bounds-checked zero-copy readers instead of `nom` | They are small and dependency-free, and garbage-input tests show they never panic. |
| Feeds | Sorted string arena plus binary search per label | About 8 bytes of overhead per entry and no per-name allocation, streamed from disk. Better suited to phones than a trie or HashSet. |
| Upstream chaining | One dialer (`engine/upstream`) for every upstream socket: direct, WireGuard (boringtun + a client-side smoltcp interface) or SOCKS5 | Android allows one VPN, so users of a real VPN could not run vigil. Terminating flows in user space already gives vigil its own upstream sockets; only their egress changes, so inspection is identical in every mode. |
| WireGuard in user space | `boringtun` (vendored as an rlib) for Noise; smoltcp 0.12 (the version netstack-smoltcp already pulls in) for the tunnel's TCP/UDP | No kernel or root needed; the same crates cross-compile for all ABIs. Kernel WireGuard is used only as the e2e peer. |

## Engine data path (`core/vigil-core/src/engine`)

1. **Read loop** (`mod.rs`). Each TUN read is one IP packet, parsed by
   `packet.rs`. Fragments and non-TCP/UDP packets are dropped and counted.
   IPv6 atomic fragments (offset 0, no more fragments) are whole packets and
   are processed; for TCP the fragment header is stripped before smoltcp.
   Interrupted reads are retried, ENOBUFS/ENOMEM back off (up to 1 s, 100
   times in a row); any other read error ends the session with an `engine`
   `error` event, and the app restarts it.
2. **TCP SYN → gate** (`tcp.rs`). A connection's 4-tuple is registered from
   its first SYN until the connection ends, and retransmitted SYNs for it are
   dropped (smoltcp retransmits its own SYN-ACK), so a slow handshake never
   leads to a second upstream connection. SYNs beyond `max_pending_connects`
   gates or `max_tcp_flows` connections get a RST. The gate:
   - looks up the UID via the platform (Binder IPC, on a blocking thread);
   - admits DNS over TCP (port 53) to *any* address into vigil's resolver
     (virtual resolver: configured upstreams; other address: that server,
     with a `hardcoded_dns` alert), and refuses other ports on the virtual
     resolver, including the Private DNS probe on 853;
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
   `SO_LINGER` 0, which sends a RST. Blocked names and the 2 h idle timeout
   reset both sides. A connection that ends before its `flow` was emitted
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
5. **Other UDP** (`udp.rs`). A NAT task runs per 5-tuple, up to
   `max_udp_flows` (then the flow idle for longest is evicted). For ports 443
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
7. **Alerts** (`detect.rs`) are deduplicated per kind, app and finding for an
   hour (threat alerts by matched feed entry, so DGA names do not cause
   storms), in a table of at most 10 000 findings, with a global budget of
   120 alerts per minute. The beacon detector's table (20 000 series) is
   pruned at most once a minute when full; until then new targets are not
   tracked.

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
- **wireguard**: `wireguard.rs` keeps boringtun's `Tunn`, a smoltcp
  `Interface` (medium IP, the tunnel addresses) and its sockets behind one
  lock. A driver task owns the protected UDP socket to the endpoint: it
  decrypts datagrams into smoltcp, polls smoltcp, encrypts what it emits and
  runs the WireGuard timers (handshake retries, keepalive, rekey) every
  250 ms. TCP connects complete the tunnelled handshake before the SYN gate
  admits the app's SYN, so refusals stay faithful; resets map to smoltcp
  aborts both ways. Handshakes failing for 10 s mark the tunnel down (an
  idle tunnel is not down); while down it retries every 15 s and re-creates
  the socket / re-resolves the endpoint every 30 s. A `network_id` change
  (the app sends the network handle) re-creates the socket at once; the
  session survives and the peer learns the new address from the next
  packet. A replaced tunnel's driver ends when its last connection does.
- **socks5**: `socks5.rs` speaks CONNECT (by address, or by the sniffed
  SNI/Host with `send_domain`, which defers the connect to the app's first
  bytes) and UDP ASSOCIATE (one association per UDP flow; the proxy's
  refusal is remembered and UDP is blocked from then on). Plain DNS goes to
  the proxy as DNS over TCP. Only failures to use the proxy itself (connect,
  handshake, authentication) count as "down"; a CONNECT refused by the
  destination is reported to the app like a direct refusal.
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
  feed sync, config sync, notification). Route changes re-establish the
  interface. It supports always-on VPN and a Quick Settings tile.
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
  per-app detail and blocking), Alerts, Settings, Feeds, Export and Rules.

## Addresses

| | IPv4 | IPv6 |
|---|---|---|
| TUN | 10.111.222.1/24 | fd76:6967:696c::1/64 |
| Virtual resolver | 10.111.222.2 | fd76:6967:696c::2 |

With "keep local network traffic direct" (the default), routes cover all
public IPv4 space except RFC 1918, CGNAT, link-local, loopback and multicast,
plus the virtual subnet, and IPv6 `2000::/3`.
