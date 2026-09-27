//! UDP: per-flow NAT over protected sockets, with QUIC SNI extraction.

use super::tcp::{decide_named, emit_closed_flow, mark_blocked, observe_allowed};
use super::{dns, FlowCounters, FlowKey, GaugeGuard, Shared};
use crate::event::{now_ms, FlowEvent, Verdict};
use crate::intel::is_special;
use crate::packet::{self, UdpInfo, PROTO_UDP};
use crate::policy::{Decision, Policy, DOT_PORT};
use crate::proto::quic::{self, QuicSniffer};
use crate::proto::tls::{self, Sniff};
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const FLOW_QUEUE: usize = 256;
/// How long the first QUIC datagrams may be held back while the ClientHello
/// is reassembled.
const QUIC_SNIFF_WINDOW: Duration = Duration::from_millis(250);

pub(crate) fn on_packet(shared: &Arc<Shared>, u: UdpInfo, payload: &[u8]) {
    let cfg = shared.config();
    let to_virtual = cfg.is_virtual_dns(u.dst.ip());
    if u.dst.port() == 53 {
        // Every plain DNS query is inspected — including ones sent to
        // hard-coded resolvers, which are then relayed to that resolver.
        let s = shared.clone();
        let query = payload.to_vec();
        let upstream = if to_virtual { None } else { Some(u.dst) };
        tokio::spawn(async move {
            if let Some(resp) = dns::handle_udp_query(&s, &query, u.src, u.dst, upstream).await {
                if let Some(pkt) = packet::build_udp(u.dst, u.src, &resp) {
                    s.send_to_tun(pkt);
                }
            }
        });
        return;
    }
    if to_virtual || is_special(u.dst.ip()) {
        shared.stats.dropped_packets.fetch_add(1, Relaxed);
        return;
    }
    let key = (u.src, u.dst);
    let mut flows = shared.udp_flows.lock();
    if let Some(tx) = flows.get(&key) {
        if tx.try_send(payload.to_vec()).is_err() {
            shared.stats.dropped_packets.fetch_add(1, Relaxed);
        }
        return;
    }
    let (tx, rx) = mpsc::channel(FLOW_QUEUE);
    let _ = tx.try_send(payload.to_vec());
    flows.insert(key, tx);
    drop(flows);
    let s = shared.clone();
    tokio::spawn(async move {
        flow(&s, key, rx).await;
        s.udp_flows.lock().remove(&key);
    });
}

fn protected_udp(shared: &Shared, dst: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    let bind: SocketAddr = if dst.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let sock = std::net::UdpSocket::bind(bind)?;
    if !shared.platform.protect(sock.as_raw_fd()) {
        return Err(io::Error::other("could not protect socket"));
    }
    sock.set_nonblocking(true)?;
    sock.connect(dst)?;
    tokio::net::UdpSocket::from_std(sock)
}

async fn flow(shared: &Arc<Shared>, key: FlowKey, mut rx: mpsc::Receiver<Vec<u8>>) {
    let _active = GaugeGuard::new(&shared.stats.udp_active);
    let (src, dst) = key;
    let cfg = shared.config();
    let idle = Duration::from_secs(cfg.udp_idle_timeout_s.max(5));
    let uid = shared.lookup_uid(PROTO_UDP, src, dst).await;
    shared.stats.flows_total.fetch_add(1, Relaxed);

    let mut ev = FlowEvent {
        id: shared.next_flow_id(),
        ts: now_ms(),
        proto: "udp",
        uid,
        src: src.to_string(),
        dst_ip: dst.ip().to_string(),
        dst_port: dst.port(),
        ..Default::default()
    };
    if let Some(name) = shared.dns_cache.lookup(dst.ip(), Instant::now()) {
        ev.domain = Some(name);
        ev.domain_source = Some("dns");
    }

    // Hold back the first datagrams of a QUIC connection until the
    // ClientHello has been recovered, so blocking happens before any byte
    // leaves the device.
    let mut held: Vec<Vec<u8>> = Vec::new();
    if dst.port() == 443 || dst.port() == 80 {
        let mut sniffer = QuicSniffer::new();
        let deadline = tokio::time::Instant::now() + QUIC_SNIFF_WINDOW;
        loop {
            let Ok(Some(d)) = tokio::time::timeout_at(deadline, rx.recv()).await else { break };
            let res = if held.is_empty() && !quic::looks_like_initial(&d) { Sniff::NotMatched } else { sniffer.feed(&d) };
            held.push(d);
            match res {
                Sniff::Found(ch) => {
                    ev.app_proto = Some("quic");
                    if let Some(sni) = ch.sni.clone() {
                        ev.domain = Some(sni);
                        ev.domain_source = Some("quic");
                    }
                    ev.alpn = ch.alpn.first().cloned();
                    ev.tls_version = Some(tls::version_name(ch.max_version()));
                    ev.ja4 = Some(ch.ja4('q'));
                    ev.ech = ch.ech;
                    if ch.ech {
                        ev.tags.push("ech");
                    }
                    break;
                }
                Sniff::NotMatched => break,
                Sniff::NeedMore => {}
            }
        }
    } else if let Some(d) = rx.recv().await {
        held.push(d);
    }

    let mut decision = shared.policy.read().check_ip(uid, dst.ip());
    if dst.port() == DOT_PORT {
        ev.tags.push("encrypted_dns");
        ev.app_proto = Some("doq");
        if decision == Decision::Allow && shared.policy.read().block_encrypted_dns {
            decision = Decision::Block(Policy::encrypted_dns_block());
        }
    }
    if decision == Decision::Allow {
        if let Some(r) = decide_named(shared, &mut ev) {
            decision = Decision::Block(r);
        }
    }
    if let Decision::Block(reason) = decision {
        mark_blocked(shared, &mut ev, &reason);
        emit_closed_flow(shared, ev, None);
        // Keep absorbing the flow's datagrams so retries don't produce a
        // stream of new flow events.
        while let Ok(Some(_)) = tokio::time::timeout(idle, rx.recv()).await {}
        return;
    }

    let sock = match protected_udp(shared, dst) {
        Ok(s) => s,
        Err(e) => {
            ev.verdict = Some(Verdict::Allow);
            emit_closed_flow(shared, ev, Some(format!("socket: {e}")));
            return;
        }
    };
    ev.verdict = Some(Verdict::Allow);
    let id = ev.id;
    let counters = FlowCounters::new();
    shared.open_flow(ev.clone(), &counters);
    observe_allowed(shared, &ev);

    let mut error = None;
    for d in held.drain(..) {
        counters.tx.fetch_add(d.len() as u64, Relaxed);
        if let Err(e) = sock.send(&d).await {
            error = Some(e.to_string());
        }
    }
    let mut buf = vec![0u8; 65_536];
    let mut deadline = tokio::time::Instant::now() + idle;
    loop {
        tokio::select! {
            d = rx.recv() => {
                let Some(d) = d else { break };
                counters.tx.fetch_add(d.len() as u64, Relaxed);
                deadline = tokio::time::Instant::now() + idle;
                if let Err(e) = sock.send(&d).await {
                    // ICMP errors surface here (e.g. port unreachable); keep going.
                    error = Some(e.to_string());
                }
            }
            r = sock.recv(&mut buf) => {
                match r {
                    Ok(n) => {
                        counters.rx.fetch_add(n as u64, Relaxed);
                        deadline = tokio::time::Instant::now() + idle;
                        if let Some(pkt) = packet::build_udp(dst, src, &buf[..n]) {
                            shared.send_to_tun(pkt);
                        }
                    }
                    Err(e) => {
                        error = Some(e.to_string());
                        if e.kind() != io::ErrorKind::ConnectionRefused {
                            break;
                        }
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => break,
        }
    }
    shared.finish_flow(id, error);
}
