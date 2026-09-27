# Architecture

## Design decisions (and how they differ from the original sketch)

| Topic | Decision | Why |
|---|---|---|
| Split | Kotlin for the Android framework, UI and persistence; Rust for everything on the packet path | The JVM stays out of per-packet work, and Rust stays out of Android APIs. |
| TCP stack | `netstack-smoltcp` (smoltcp's TCP state machine), with **vigil owning the TUN loop** | smoltcp is mature. Owning the read/write loop lets vigil see, count, gate and drop every raw packet, which an opaque tun2socks library would not allow. |
| UDP | vigil's own NAT, not the stack's | DNS and QUIC need per-datagram inspection, and per-flow tasks allow holding back the first QUIC datagrams until the SNI is known. |
| Loop avoidance | `addDisallowedApplication(self)` **and** `protect()` on every relay socket | Excluding the app also covers feed downloads and SIEM export, and `protect()` is kept as a second guard. |
| Attribution | `getConnectionOwnerUid` on Android 10+ only | `sock_diag` and `/proc/net` are blocked by SELinux for apps on modern Android, so the pre-API-29 fallback in the sketch does not work there. |
| Upcalls | Events are **polled** by Kotlin (a JSON batch per call, blocking up to 500 ms). The only JVM upcalls are UID lookup and `protect`, made off the packet path. | No JNI callbacks on hot paths, and a slow consumer drops events instead of stalling traffic. |
| SYN handling | The SYN is held while vigil attributes the flow, checks policy and **connects upstream first** | Refused or unreachable destinations reach the app as a real RST. |
| Parsers | Hand-written, bounds-checked zero-copy readers instead of `nom` | They are small and dependency-free, and garbage-input tests show they never panic. |
| Feeds | Sorted string arena plus binary search per label | About 8 bytes of overhead per entry and no per-name allocation, streamed from disk. Better suited to phones than a trie or HashSet. |

## Engine data path (`core/vigil-core/src/engine`)

1. **Read loop** (`mod.rs`). Each TUN read is one IP packet, parsed by
   `packet.rs`. Fragments and non-TCP/UDP packets are dropped and counted.
2. **TCP SYN → gate** (`tcp.rs`). Retransmitted SYNs are ignored while a
   decision is pending. The gate:
   - looks up the UID via the platform (Binder IPC, on a blocking thread);
   - answers DNS-over-TCP to the virtual resolver locally and refuses other
     ports there, including the Private DNS probe on 853;
   - checks policy by IP (app block, IP feeds, DoT on 853);
   - connects upstream with a protected socket.

   On success the SYN goes to smoltcp and the flow's metadata (including the
   connected upstream socket) is parked until smoltcp yields the stream. On
   failure the app gets a RST.
3. **Relay.** Server→client copying starts immediately, so server-speaks-first
   protocols work. The client→server direction first *sniffs*: it buffers data
   until a TLS ClientHello (across any number of records and segments) or an
   HTTP request head is complete, or 3 s pass. It then decides on the name
   (feeds, allow/deny, encrypted-DNS policy), emits the `flow` event, and
   either forwards the buffer and continues or closes the connection.
4. **UDP port 53** (`dns.rs`). Queries are parsed, checked against policy and
   either sinkholed or forwarded. Queries to the virtual resolver go to the
   configured upstreams; queries to a hard-coded server go to that server and
   raise an alert. Truncated answers are retried over TCP. Answers are checked
   for **CNAME cloaking**, and their addresses feed the IP→name cache used to
   label later connections.
5. **Other UDP** (`udp.rs`). A NAT task runs per 5-tuple. For port 443 the
   first datagrams are held (for at most 250 ms) while `QuicSniffer` decrypts
   Initial packets and reassembles shuffled CRYPTO frames. Blocked flows are
   absorbed until idle, so retries don't flood the event stream.
6. **Events** (`event.rs`) go into a bounded queue that drops the oldest when
   full. Every `flow` has exactly one `flow_end`, including at shutdown, and
   long flows emit `flow_update` with live byte counts.

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
