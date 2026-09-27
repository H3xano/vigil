//! DNS: inspection, sinkholing (including CNAME-cloaked trackers), upstream
//! forwarding and IP→name learning.

use super::tcp::connect_protected;
use super::Shared;
use crate::event::{now_ms, DnsEvent, Event, Severity, Verdict};
use crate::packet::PROTO_UDP;
use crate::policy::{BlockReason, Decision};
use crate::proto::dns::{self, RData};
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UDP_TIMEOUT: Duration = Duration::from_millis(2500);
const TCP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_UPSTREAMS_TRIED: usize = 3;

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

/// Serves DNS-over-TCP addressed to the virtual resolver.
pub(crate) async fn serve_tcp(
    shared: &Arc<Shared>,
    mut stream: netstack_smoltcp::TcpStream,
    uid: Option<u32>,
) {
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
        if stream.read_exact(&mut q).await.is_err() {
            return;
        }
        let Some(resp) = answer(shared, &q, uid, None, "tcp").await else {
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
    let cfg = shared.config();
    let started = Instant::now();
    let parsed = dns::parse(query).filter(|m| !m.is_response && m.opcode == 0);
    let Some(q) = parsed.as_ref().and_then(|m| m.first_question()).cloned() else {
        // Not a query we understand: relay it untouched to where it was going.
        return match upstream {
            Some(server) => forward(shared, query, &[server]).await.map(|(r, _)| r),
            None => dns::servfail_response(query),
        };
    };
    shared.stats.dns_queries.fetch_add(1, Relaxed);
    let server_label = upstream
        .map(|s| s.to_string())
        .unwrap_or_else(|| "virtual".into());
    if let Some(server) = upstream {
        shared.alert(
            "hardcoded_dns",
            Severity::Info,
            uid,
            &server.ip().to_string(),
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
    };

    let decision = shared.policy.read().check_domain(uid, &q.name);
    if let Decision::Block(reason) = decision {
        return sinkhole(shared, query, &mut ev, &reason, &q.name, started);
    }

    let servers: Vec<SocketAddr> = match upstream {
        Some(s) => vec![s],
        None => cfg.upstream_dns.clone(),
    };
    let Some((resp, _server)) = forward(shared, query, &servers).await else {
        ev.rcode = "SERVFAIL".into();
        ev.reason = Some("upstream unreachable".into());
        ev.latency_ms = started.elapsed().as_millis() as u64;
        shared.emit(Event::Dns(ev));
        return dns::servfail_response(query);
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
    let resp = dns::sinkhole_response(query, cfg.sinkhole, cfg.sinkhole_ttl);
    ev.verdict = Verdict::Block;
    ev.reason = Some(reason.describe());
    ev.rcode = match cfg.sinkhole {
        dns::SinkholeMode::Nxdomain => "NXDOMAIN".into(),
        dns::SinkholeMode::NullIp => "NOERROR".into(),
    };
    ev.latency_ms = started.elapsed().as_millis() as u64;
    if reason.is_threat() {
        shared.alert(
            "threat_domain",
            Severity::High,
            ev.uid,
            qname,
            format!("Lookup of {qname} sinkholed: listed by {}", reason.describe()),
            serde_json::json!({ "category": reason.category.map(|c| c.as_str()), "qtype": ev.qtype }),
        );
    }
    shared.emit(Event::Dns(ev.clone()));
    resp
}

fn protected_udp(shared: &Shared, server: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let s = std::net::UdpSocket::bind(bind)?;
    if !shared.platform.protect(s.as_raw_fd()) {
        return Err(io::Error::other("could not protect socket"));
    }
    s.set_nonblocking(true)?;
    s.connect(server)?;
    tokio::net::UdpSocket::from_std(s)
}

async fn query_udp(shared: &Shared, query: &[u8], server: SocketAddr) -> io::Result<Vec<u8>> {
    let sock = protected_udp(shared, server)?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + UDP_TIMEOUT;
    loop {
        let n = tokio::time::timeout_at(deadline, sock.recv(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns timeout"))??;
        // Ignore stray datagrams with a different ID.
        if n >= 2 && buf[..2] == query[..2] {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

async fn query_tcp(shared: &Shared, query: &[u8], server: SocketAddr) -> io::Result<Vec<u8>> {
    let fut = async {
        let mut s = connect_protected(shared, server).await?;
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

/// Sends `query` to the first responsive server. Truncated UDP answers are
/// retried over TCP.
async fn forward(
    shared: &Shared,
    query: &[u8],
    servers: &[SocketAddr],
) -> Option<(Vec<u8>, SocketAddr)> {
    if query.len() < 12 {
        return None;
    }
    for &server in servers.iter().take(MAX_UPSTREAMS_TRIED) {
        match query_udp(shared, query, server).await {
            Ok(resp) => {
                let truncated = resp.len() >= 4 && resp[2] & 0x02 != 0;
                if truncated {
                    if let Ok(full) = query_tcp(shared, query, server).await {
                        return Some((full, server));
                    }
                }
                return Some((resp, server));
            }
            Err(e) => log::debug!("dns upstream {server}: {e}"),
        }
    }
    None
}
