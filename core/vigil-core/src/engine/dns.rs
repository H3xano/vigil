//! DNS: inspection, sinkholing (including CNAME-cloaked trackers), upstream
//! forwarding and IP→name learning.

use super::upstream::{self, UpstreamUdp};
use super::{dns_upstream, Shared};
use crate::event::{now_ms, DnsEvent, Event, Severity, Verdict};
use crate::packet::PROTO_UDP;
use crate::policy::{BlockReason, Decision};
use crate::proto::dns::{self, RData};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UDP_TIMEOUT: Duration = Duration::from_millis(2500);
const TCP_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_CLIENT_IDLE: Duration = Duration::from_secs(30);
const MAX_UPSTREAMS_TRIED: usize = 3;

/// Idle protected sockets kept per upstream resolver.
const POOL_PER_SERVER: usize = 4;
/// Resolvers for which sockets are pooled (hard-coded ones included).
const POOL_SERVERS: usize = 32;
/// Pooled sockets are replaced after this long, so a network change
/// (which leaves a connected UDP socket with a stale source address)
/// cannot pin queries to the old network for long.
const POOL_MAX_AGE: Duration = Duration::from_secs(30);

struct Pooled {
    sock: UpstreamUdp,
    created: Instant,
    /// Upstream dialer generation the socket was made with.
    generation: u64,
}

/// Reusable protected UDP sockets to upstream resolvers, so a query does not
/// normally need a new socket and a `protect()` upcall.
#[derive(Default)]
pub(crate) struct UpstreamPool {
    idle: Mutex<HashMap<SocketAddr, Vec<Pooled>>>,
}

impl UpstreamPool {
    fn take(&self, server: SocketAddr) -> Option<Pooled> {
        let mut idle = self.idle.lock();
        let socks = idle.get_mut(&server)?;
        while let Some(p) = socks.pop() {
            if p.created.elapsed() < POOL_MAX_AGE {
                return Some(p);
            }
        }
        None
    }

    fn put(&self, server: SocketAddr, p: Pooled) {
        if p.created.elapsed() >= POOL_MAX_AGE {
            return;
        }
        let mut idle = self.idle.lock();
        if !idle.contains_key(&server) && idle.len() >= POOL_SERVERS {
            return;
        }
        let socks = idle.entry(server).or_default();
        if socks.len() < POOL_PER_SERVER {
            socks.push(p);
        }
    }

    /// Drops sockets past their age.
    pub fn expire(&self) {
        self.idle.lock().retain(|_, socks| {
            socks.retain(|p| p.created.elapsed() < POOL_MAX_AGE);
            !socks.is_empty()
        });
    }
}

pub(crate) async fn handle_udp_query(
    shared: &Arc<Shared>,
    query: &[u8],
    src: SocketAddr,
    dst: SocketAddr,
    upstream: Option<SocketAddr>,
) -> Option<Vec<u8>> {
    let uid = shared.lookup_uid(PROTO_UDP, src, dst).await;
    answer(shared, query, uid, upstream, "udp").await
}

/// Serves DNS over TCP: to the virtual resolver (`upstream = None`) or to a
/// server the app addressed directly.
pub(crate) async fn serve_tcp(
    shared: &Arc<Shared>,
    mut stream: netstack_smoltcp::TcpStream,
    uid: Option<u32>,
    upstream: Option<SocketAddr>,
) {
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(TCP_CLIENT_IDLE, stream.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
        match tokio::time::timeout(TCP_CLIENT_IDLE, stream.read_exact(&mut q)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let resp = match shared.limits.dns.clone().try_acquire_owned() {
            Ok(_permit) => answer(shared, &q, uid, upstream, "tcp").await,
            Err(_) => dns::servfail_response(&q),
        };
        let Some(resp) = resp else {
            return;
        };
        let mut out = (resp.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&resp);
        if stream.write_all(&out).await.is_err() {
            return;
        }
    }
}

/// Answers one query. `upstream = None` means the virtual resolver (use the
/// configured upstreams); otherwise the app addressed that server directly.
async fn answer(
    shared: &Arc<Shared>,
    query: &[u8],
    uid: Option<u32>,
    upstream: Option<SocketAddr>,
    transport: &'static str,
) -> Option<Vec<u8>> {
    let started = Instant::now();
    let parsed = dns::parse(query);
    let Some(msg) = parsed.as_ref().filter(|m| !m.is_response && m.opcode == 0) else {
        return match upstream {
            // Not a standard query, so nothing vigil could inspect: never
            // relayed blind to a hard-coded server (a channel around the
            // policy), but refused and reported.
            Some(server) => {
                refuse_uninspectable(shared, query, parsed.as_ref(), uid, server, transport)
            }
            None => dns::servfail_response(query),
        };
    };
    // Only the first question could be inspected, so a query with several
    // (which no real resolver answers anyway) could smuggle a blocked name.
    let [q] = &msg.questions[..] else {
        return dns::refused_response(query);
    };
    shared.stats.dns_queries.fetch_add(1, Relaxed);
    let server_label = upstream
        .map(|s| s.to_string())
        .unwrap_or_else(|| "virtual".into());
    if let Some(server) = upstream {
        let ip = server.ip().to_string();
        shared.alert(
            "hardcoded_dns",
            Severity::Info,
            uid,
            &ip,
            &ip,
            format!("App bypasses the system resolver and queries {server} directly"),
            serde_json::json!({ "qname": q.name }),
        );
    }
    let mut ev = DnsEvent {
        ts: now_ms(),
        uid,
        qname: q.name.clone(),
        qtype: dns::qtype_name(q.qtype),
        rcode: String::new(),
        answers: Vec::new(),
        verdict: Verdict::Allow,
        reason: None,
        latency_ms: 0,
        server: server_label,
        transport,
        upstream: None,
    };

    let decision = shared.policy.read().check_domain(uid, &q.name);
    if let Decision::Block(reason) = decision {
        return sinkhole(shared, query, &mut ev, &reason, &q.name, started);
    }
    if let Some(server) = upstream {
        // The resolver itself may be listed (e.g. a C2 DNS server).
        let decision = shared.policy.read().check_ip(uid, server.ip());
        if let Decision::Block(reason) = decision {
            return refuse_server(shared, query, &mut ev, &reason, server, started);
        }
    }

    // Hard-coded servers are asked the way the app asked them (plain); the
    // virtual resolver's upstream may be encrypted (dns_upstream.rs).
    let forwarded = match upstream {
        Some(s) => forward(shared, query, &[s], transport)
            .await
            .ok_or(("udp", "upstream unreachable".to_string())),
        None => dns_upstream::forward(shared, query, transport).await,
    };
    let resp = match forwarded {
        Ok((resp, via)) => {
            ev.upstream = Some(via);
            resp
        }
        Err((via, reason)) => {
            ev.upstream = Some(via);
            ev.rcode = "SERVFAIL".into();
            ev.reason = Some(reason);
            ev.latency_ms = started.elapsed().as_millis() as u64;
            shared.emit(Event::Dns(ev));
            return dns::servfail_response(query);
        }
    };
    let Some(r) = dns::parse(&resp) else {
        ev.rcode = "unparsed".into();
        shared.emit(Event::Dns(ev));
        return Some(resp);
    };

    // CNAME cloaking: a first-party name aliased to a listed tracker.
    {
        let policy = shared.policy.read();
        for rec in &r.answers {
            if let RData::Cname(target) = &rec.data {
                if let Decision::Block(mut reason) = policy.check_domain(uid, target) {
                    drop(policy);
                    reason.rule = Some(format!(
                        "{} via CNAME {target}",
                        reason.rule.unwrap_or_default()
                    ));
                    return sinkhole(shared, query, &mut ev, &reason, &q.name, started);
                }
            }
        }
    }

    // A name with a per-app rule is answered differently per app, and
    // Android's resolver cache is shared by all apps: keep it uncached.
    let per_app_name = {
        let policy = shared.policy.read();
        policy.has_app_domain_rule(&q.name)
            || r.answers
                .iter()
                .any(|a| matches!(&a.data, RData::Cname(t) if policy.has_app_domain_rule(t)))
    };
    let mut resp = resp;
    if per_app_name {
        dns::zero_ttls(&mut resp);
    }

    let now = Instant::now();
    let ttl = r.min_ttl().unwrap_or(300);
    for ip in r.answer_ips() {
        shared.dns_cache.insert(ip, &q.name, ttl, now);
    }
    ev.rcode = dns::rcode_name(r.rcode).into();
    ev.answers = r
        .answers
        .iter()
        .filter_map(|a| match &a.data {
            RData::A(ip) => Some(ip.to_string()),
            RData::Aaaa(ip) => Some(ip.to_string()),
            RData::Cname(n) => Some(format!("CNAME {n}")),
            RData::Hints(h) => Some(
                h.iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
            RData::Other => None,
        })
        .take(16)
        .collect();
    ev.latency_ms = started.elapsed().as_millis() as u64;
    shared.emit(Event::Dns(ev));
    Some(resp)
}

fn sinkhole(
    shared: &Shared,
    query: &[u8],
    ev: &mut DnsEvent,
    reason: &BlockReason,
    qname: &str,
    started: Instant,
) -> Option<Vec<u8>> {
    let cfg = shared.config();
    shared.stats.blocked.fetch_add(1, Relaxed);
    // A block for one app (or a name with per-app rules) must not reach
    // Android's resolver cache, which every app shares: TTL 0. It also makes
    // unblocking (e.g. the app coming to the foreground) take effect at once.
    let ttl = if reason.is_per_app() || shared.policy.read().has_app_domain_rule(qname) {
        0
    } else {
        cfg.sinkhole_ttl
    };
    let resp = dns::sinkhole_response(query, cfg.sinkhole, ttl);
    ev.verdict = Verdict::Block;
    ev.reason = Some(reason.describe());
    ev.rcode = match cfg.sinkhole {
        dns::SinkholeMode::Nxdomain => "NXDOMAIN".into(),
        dns::SinkholeMode::NullIp => "NOERROR".into(),
    };
    ev.latency_ms = started.elapsed().as_millis() as u64;
    if reason.is_threat() {
        // Keyed by the listed entry, not the name: DGA and DNS tunnelling
        // produce endless distinct names under one listed domain.
        shared.alert(
            "threat_domain",
            Severity::High,
            ev.uid,
            &reason.alert_key(),
            qname,
            format!("Lookup of {qname} sinkholed: listed by {}", reason.describe()),
            serde_json::json!({ "category": reason.category.map(|c| c.as_str()), "qtype": ev.qtype }),
        );
    }
    shared.emit(Event::Dns(ev.clone()));
    resp
}

/// Refuses a message to a hard-coded resolver that is not a standard query
/// (unparseable, a response, or another opcode): REFUSED if it has a DNS
/// header, else nothing (the TCP connection is closed). Reported as a
/// blocked `dns` event and a `hardcoded_dns` alert.
fn refuse_uninspectable(
    shared: &Shared,
    query: &[u8],
    msg: Option<&dns::Message>,
    uid: Option<u32>,
    server: SocketAddr,
    transport: &'static str,
) -> Option<Vec<u8>> {
    let why = match msg {
        None => "unparseable DNS message".to_string(),
        Some(m) if m.is_response => "DNS response sent as a query".to_string(),
        Some(m) => format!("DNS opcode {}", m.opcode),
    };
    let q = msg.and_then(|m| m.first_question());
    shared.stats.blocked.fetch_add(1, Relaxed);
    let resp = dns::refused_response(query);
    shared.emit(Event::Dns(DnsEvent {
        ts: now_ms(),
        uid,
        qname: q.map(|q| q.name.clone()).unwrap_or_default(),
        qtype: q.map(|q| dns::qtype_name(q.qtype)).unwrap_or_default(),
        rcode: if resp.is_some() { "REFUSED" } else { "" }.into(),
        answers: Vec::new(),
        verdict: Verdict::Block,
        reason: Some(format!("not a standard query ({why})")),
        latency_ms: 0,
        server: server.to_string(),
        transport,
        upstream: None,
    }));
    let ip = server.ip().to_string();
    shared.alert(
        "hardcoded_dns",
        Severity::Info,
        uid,
        &ip,
        &ip,
        format!("App bypasses the system resolver and queries {server} directly"),
        serde_json::json!({ "qname": q.map(|q| q.name.clone()), "refused": why }),
    );
    resp
}

/// Answers REFUSED for a query addressed to a listed resolver.
fn refuse_server(
    shared: &Shared,
    query: &[u8],
    ev: &mut DnsEvent,
    reason: &BlockReason,
    server: SocketAddr,
    started: Instant,
) -> Option<Vec<u8>> {
    shared.stats.blocked.fetch_add(1, Relaxed);
    ev.verdict = Verdict::Block;
    ev.reason = Some(reason.describe());
    ev.rcode = "REFUSED".into();
    ev.latency_ms = started.elapsed().as_millis() as u64;
    if reason.is_threat() {
        let target = reason
            .rule
            .clone()
            .unwrap_or_else(|| server.ip().to_string());
        shared.alert(
            "threat_ip",
            Severity::High,
            ev.uid,
            &reason.alert_key(),
            &target,
            format!(
                "DNS query to {server} refused: listed by {}",
                reason.describe()
            ),
            serde_json::json!({ "dst": server.to_string(), "qname": ev.qname, "category": reason.category.map(|c| c.as_str()) }),
        );
    }
    shared.emit(Event::Dns(ev.clone()));
    dns::refused_response(query)
}

async fn query_udp(shared: &Shared, query: &[u8], server: SocketAddr) -> io::Result<Vec<u8>> {
    // Sockets from before an upstream path change are not reused.
    let generation = shared.upstream.generation();
    let p = match shared
        .dns_upstreams
        .take(server)
        .filter(|p| p.generation == generation)
    {
        Some(p) => {
            p.sock.drain();
            p
        }
        None => Pooled {
            sock: upstream::connect_udp(shared, server).await?,
            created: Instant::now(),
            generation,
        },
    };
    p.sock.send(query).await?;
    let deadline = tokio::time::Instant::now() + UDP_TIMEOUT;
    loop {
        let reply = tokio::time::timeout_at(
            deadline,
            p.sock
                .recv_with(|d| dns::answers_query(query, d).then(|| d.to_vec())),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns timeout"))??;
        // Stray datagrams (other IDs, late answers to earlier queries on a
        // reused socket) are skipped.
        if let Some(resp) = reply {
            shared.dns_upstreams.put(server, p);
            return Ok(resp);
        }
    }
}

async fn query_tcp(shared: &Shared, query: &[u8], server: SocketAddr) -> io::Result<Vec<u8>> {
    let fut = async {
        let mut s = upstream::connect_tcp(shared, server).await?;
        let mut msg = (query.len() as u16).to_be_bytes().to_vec();
        msg.extend_from_slice(query);
        s.write_all(&msg).await?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await?;
        let mut resp = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut resp).await?;
        Ok(resp)
    };
    tokio::time::timeout(TCP_TIMEOUT, fut)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns tcp timeout"))?
}

/// Sends `query` in cleartext to the first responsive server. A truncated
/// UDP answer is returned as is to UDP clients (they retry over TCP
/// themselves, within their own EDNS size) and retried over TCP for TCP
/// clients. Returns the answer and how it was fetched (`udp` or `tcp`).
pub(super) async fn forward(
    shared: &Shared,
    query: &[u8],
    servers: &[SocketAddr],
    transport: &'static str,
) -> Option<(Vec<u8>, &'static str)> {
    if query.len() < 12 {
        return None;
    }
    for &server in servers.iter().take(MAX_UPSTREAMS_TRIED) {
        if shared.upstream.dns_over_tcp() {
            // SOCKS5: DNS goes through the proxy as DNS over TCP.
            match query_tcp(shared, query, server).await {
                Ok(resp) => return Some((resp, "tcp")),
                Err(e) => log::debug!("dns upstream {server} (tcp): {e}"),
            }
            continue;
        }
        match query_udp(shared, query, server).await {
            Ok(resp) => {
                if transport == "tcp" && dns::is_truncated(&resp) {
                    if let Ok(full) = query_tcp(shared, query, server).await {
                        return Some((full, "tcp"));
                    }
                }
                return Some((resp, "udp"));
            }
            Err(e) => log::debug!("dns upstream {server}: {e}"),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_shared;
    use super::*;
    use crate::config::Config;
    use crate::intel::parse_feed;
    use crate::policy::{FeedCategory, LoadedFeed};

    /// A resolver on loopback that answers every query with a sinkhole-style
    /// answer, optionally with the TC bit set. Returns its address.
    async fn fake_resolver(truncate: bool) -> SocketAddr {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, from)) = s.recv_from(&mut buf).await {
                let mut resp =
                    dns::sinkhole_response(&buf[..n], dns::SinkholeMode::NullIp, 5).unwrap();
                if truncate {
                    resp[2] |= 0x02;
                }
                let _ = s.send_to(&resp, from).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn refuses_multi_question_queries() {
        let shared = test_shared(Config::default());
        let q = dns::build_query(1, "a.example", dns::TYPE_A);
        let mut two = q.clone();
        two[5] = 2;
        two.extend_from_slice(&q[12..]);
        let r = answer(&shared, &two, None, None, "udp").await.unwrap();
        assert_eq!(dns::parse(&r).unwrap().rcode, dns::RCODE_REFUSED);
        let mut none = q[..12].to_vec();
        none[5] = 0;
        let r = answer(&shared, &none, None, None, "udp").await.unwrap();
        assert_eq!(dns::parse(&r).unwrap().rcode, dns::RCODE_REFUSED);
    }

    #[tokio::test]
    async fn truncated_answers_reach_udp_clients_as_truncated() {
        let server = fake_resolver(true).await;
        let shared = test_shared(Config {
            upstream_dns: vec![server],
            ..Default::default()
        });
        let q = dns::build_query(2, "big.example", dns::TYPE_TXT);
        let r = answer(&shared, &q, None, None, "udp").await.unwrap();
        assert!(dns::is_truncated(&r), "UDP client must see TC and retry");
    }

    #[tokio::test]
    async fn upstream_sockets_are_reused() {
        let server = fake_resolver(false).await;
        let shared = test_shared(Config {
            upstream_dns: vec![server],
            ..Default::default()
        });
        for id in 0..5u16 {
            let q = dns::build_query(id, "a.example", dns::TYPE_A);
            let r = answer(&shared, &q, None, None, "udp").await.unwrap();
            assert!(dns::answers_query(&q, &r));
        }
        assert_eq!(shared.dns_upstreams.idle.lock()[&server].len(), 1);
    }

    /// A resolver on loopback that counts what it receives and answers
    /// every message with a response to it.
    async fn counting_resolver() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap();
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = n.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((len, from)) = s.recv_from(&mut buf).await {
                seen.fetch_add(1, Relaxed);
                let mut resp = buf[..len].to_vec();
                if resp.len() > 2 {
                    resp[2] |= 0x80;
                }
                let _ = s.send_to(&resp, from).await;
            }
        });
        (addr, n)
    }

    #[tokio::test]
    async fn uninspectable_messages_to_hardcoded_resolvers_are_refused() {
        let (server, received) = counting_resolver().await;
        let shared = test_shared(Config::default());
        let q = dns::build_query(4, "tunnel.example", dns::TYPE_TXT);
        let mut response = q.clone();
        response[2] |= 0x80; // QR
        let mut notify = q.clone();
        notify[2] = (notify[2] & 0x87) | (4 << 3); // opcode NOTIFY
        for (msg, rcode) in [(&response, "REFUSED"), (&notify, "REFUSED")] {
            let r = answer(&shared, msg, Some(10123), Some(server), "tcp")
                .await
                .unwrap();
            assert_eq!(dns::parse(&r).unwrap().rcode, dns::RCODE_REFUSED);
            let events = shared.events.poll(100, Duration::ZERO);
            assert!(
                events.iter().any(|e| matches!(e, Event::Dns(d)
                    if d.verdict == Verdict::Block && d.rcode == rcode
                        && d.qname == "tunnel.example"
                        && d.reason.as_deref().is_some_and(|r| r.starts_with("not a standard query")))),
                "{events:?}"
            );
        }
        // Too short for a DNS header: no answer at all (connection closed).
        assert!(
            answer(&shared, b"\x01\x02junk", Some(10123), Some(server), "tcp")
                .await
                .is_none()
        );
        let events = shared.events.poll(100, Duration::ZERO);
        assert!(events.iter().any(|e| matches!(e, Event::Dns(d)
            if d.verdict == Verdict::Block && d.qname.is_empty())));
        assert!(events
            .iter()
            .all(|e| !matches!(e, Event::Alert(a) if a.kind != "hardcoded_dns")));
        // Nothing reached the server; a real query still does.
        assert_eq!(received.load(Relaxed), 0);
        let r = answer(&shared, &q, Some(10123), Some(server), "tcp").await;
        assert!(r.is_some());
        assert_eq!(received.load(Relaxed), 1);
    }

    #[tokio::test]
    async fn per_app_decisions_are_never_cached_by_the_os() {
        use crate::config::{AppDomainRule, DeviceState, DomainAction};
        let server = fake_resolver(false).await; // answers with TTL 5
        let shared = test_shared(Config {
            upstream_dns: vec![server],
            deny_domains: vec!["denied.example".into()],
            blocked_uids: vec![10999],
            app_rules: vec![crate::config::AppRule {
                uid: 10300,
                block_screen_off: true,
                ..Default::default()
            }],
            app_domain_rules: vec![
                AppDomainRule {
                    uid: 10123,
                    domain: "denied.example".into(),
                    action: DomainAction::Allow,
                },
                AppDomainRule {
                    uid: 10200,
                    domain: "shop.example".into(),
                    action: DomainAction::Block,
                },
            ],
            ..Default::default()
        });
        let ask = |name: &'static str, uid: u32| {
            let shared = shared.clone();
            async move {
                let q = dns::build_query(9, name, dns::TYPE_A);
                let r = answer(&shared, &q, Some(uid), None, "udp").await.unwrap();
                let p = dns::parse(&r).unwrap();
                let ev = shared
                    .events
                    .poll(100, Duration::ZERO)
                    .into_iter()
                    .find_map(|e| match e {
                        Event::Dns(d) => Some(d),
                        _ => None,
                    })
                    .unwrap();
                (ev.verdict, ev.reason, p.answers[0].ttl)
            }
        };
        // Global deny: sinkholed for other apps, with TTL 0 because one app
        // has an allow rule for the name (a cached sinkhole would reach it)...
        let (v, reason, ttl) = ask("denied.example", 10200).await;
        assert_eq!(
            (v, reason.as_deref(), ttl),
            (Verdict::Block, Some("custom (denied.example)"), 0)
        );
        // ...and that app gets the real answer, uncached too.
        let (v, _, ttl) = ask("denied.example", 10123).await;
        assert_eq!((v, ttl), (Verdict::Allow, 0));
        // Per-app block rule.
        let (v, reason, ttl) = ask("www.shop.example", 10200).await;
        assert_eq!(
            (v, reason.as_deref(), ttl),
            (Verdict::Block, Some("app domain rule (shop.example)"), 0)
        );
        let (v, _, ttl) = ask("www.shop.example", 10123).await;
        assert_eq!((v, ttl), (Verdict::Allow, 0));
        // Names without per-app rules keep their TTLs.
        let (v, _, ttl) = ask("news.example", 10123).await;
        assert_eq!((v, ttl), (Verdict::Allow, 5));
        // App blocks: always and by a condition, TTL 0.
        let (v, reason, ttl) = ask("news.example", 10999).await;
        assert_eq!(
            (v, reason.as_deref(), ttl),
            (Verdict::Block, Some("app"), 0)
        );
        let (v, _, _) = ask("news.example", 10300).await;
        assert_eq!(v, Verdict::Allow);
        shared.policy.write().set_state(&DeviceState {
            screen_on: false,
            ..Default::default()
        });
        let (v, reason, ttl) = ask("news.example", 10300).await;
        assert_eq!(
            (v, reason.as_deref(), ttl),
            (Verdict::Block, Some("app rule: screen off"), 0)
        );
        // Unlisted sinkholes keep the configured TTL.
        let cfg = Config {
            upstream_dns: vec![server],
            deny_domains: vec!["denied.example".into()],
            ..Default::default()
        };
        shared.policy.write().apply_config(&cfg);
        let (_, _, ttl) = ask("denied.example", 10200).await;
        assert_eq!(ttl, 60);
    }

    #[tokio::test]
    async fn listed_hardcoded_resolver_is_refused_with_alert() {
        let server = fake_resolver(false).await;
        let shared = test_shared(Config::default());
        shared.policy.write().set_feed(
            "c2ips",
            LoadedFeed {
                category: FeedCategory::C2,
                feed: parse_feed("127.0.0.0/8\n"),
            },
        );
        let q = dns::build_query(3, "a.example", dns::TYPE_A);
        let r = answer(&shared, &q, Some(10123), Some(server), "udp")
            .await
            .unwrap();
        assert_eq!(dns::parse(&r).unwrap().rcode, dns::RCODE_REFUSED);
        let events = shared.events.poll(100, Duration::ZERO);
        assert!(events
            .iter()
            .any(|e| matches!(e, Event::Alert(a) if a.kind == "threat_ip")));
        assert!(events.iter().any(
            |e| matches!(e, Event::Dns(d) if d.verdict == Verdict::Block && d.rcode == "REFUSED")
        ));
    }
}
