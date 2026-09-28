//! UDP: per-flow NAT over protected sockets, with QUIC SNI extraction.

use super::tcp::{check_ja4, decide_named, emit_closed_flow, mark_blocked, observe_allowed};
use super::{dns, sock, FlowCounters, FlowKey, GaugeGuard, Shared};
use crate::event::{now_ms, FlowEvent, Verdict};
use crate::intel::is_special;
use crate::packet::{self, UdpInfo, PROTO_UDP};
use crate::policy::{Decision, Policy, DOT_PORT};
use crate::proto::dns as dns_proto;
use crate::proto::quic::{self, QuicSniffer};
use crate::proto::tls::{self, Sniff};
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const FLOW_QUEUE: usize = 256;
/// How long the first QUIC datagrams may be held back while the ClientHello
/// is reassembled.
const QUIC_SNIFF_WINDOW: Duration = Duration::from_millis(250);
/// Lifetime of a flow that has never received a reply (capped by the
/// configured idle timeout).
const NO_REPLY_IDLE: Duration = Duration::from_secs(30);

struct FlowEntry {
    tx: mpsc::Sender<Vec<u8>>,
    /// Distinguishes this flow from a later one with the same key.
    generation: u64,
    /// `Shared::ticks()` of the last datagram in either direction.
    last_active: Arc<AtomicU64>,
}

/// The UDP NAT table: one entry per (app socket, destination).
#[derive(Default)]
pub(crate) struct FlowTable {
    flows: HashMap<FlowKey, FlowEntry>,
    next_generation: u64,
}

impl FlowTable {
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Removes the least recently active flow. Its task sees its queue
    /// close and ends the flow.
    fn evict_idlest(&mut self) -> Option<FlowKey> {
        let key = self
            .flows
            .iter()
            .min_by_key(|(_, f)| f.last_active.load(Relaxed))
            .map(|(k, _)| *k)?;
        self.flows.remove(&key);
        Some(key)
    }

    fn remove(&mut self, key: &FlowKey, generation: u64) {
        if self
            .flows
            .get(key)
            .is_some_and(|f| f.generation == generation)
        {
            self.flows.remove(key);
        }
    }
}

/// Whether a UDP/53 payload is a DNS query vigil can inspect. Anything else
/// on port 53 is relayed as ordinary UDP.
fn is_dns_query(payload: &[u8]) -> bool {
    dns_proto::parse(payload).is_some_and(|m| !m.is_response && m.opcode == 0)
}

pub(crate) fn on_packet(shared: &Arc<Shared>, u: UdpInfo, payload: &[u8]) {
    let cfg = shared.config();
    let to_virtual = cfg.is_virtual_dns(u.dst.ip());
    if u.dst.port() == 53 && (to_virtual || is_dns_query(payload)) {
        // Every plain DNS query is inspected — including ones sent to
        // hard-coded resolvers, which are then relayed to that resolver.
        let Ok(permit) = shared.limits.dns.clone().try_acquire_owned() else {
            log::debug!("too many DNS queries in flight; SERVFAIL");
            if let Some(pkt) = dns_proto::servfail_response(payload)
                .and_then(|resp| packet::build_udp(u.dst, u.src, &resp))
            {
                shared.send_to_tun(pkt);
            }
            return;
        };
        let s = shared.clone();
        let query = payload.to_vec();
        let upstream = if to_virtual { None } else { Some(u.dst) };
        tokio::spawn(async move {
            let _permit = permit;
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
    let now = shared.ticks();
    let mut table = shared.udp_flows.lock();
    if let Some(f) = table.flows.get(&key) {
        f.last_active.store(now, Relaxed);
        if f.tx.try_send(payload.to_vec()).is_err() {
            shared.stats.dropped_packets.fetch_add(1, Relaxed);
        }
        return;
    }
    if table.len() >= shared.limits.udp_flows {
        if let Some((src, dst)) = table.evict_idlest() {
            log::debug!("UDP flow table full; evicted {src} -> {dst}");
        }
    }
    let (tx, rx) = mpsc::channel(FLOW_QUEUE);
    let _ = tx.try_send(payload.to_vec());
    let generation = table.next_generation;
    table.next_generation += 1;
    let last_active = Arc::new(AtomicU64::new(now));
    table.flows.insert(
        key,
        FlowEntry {
            tx,
            generation,
            last_active: last_active.clone(),
        },
    );
    drop(table);
    let s = shared.clone();
    tokio::spawn(async move {
        flow(&s, key, rx, &last_active).await;
        s.udp_flows.lock().remove(&key, generation);
    });
}

async fn flow(
    shared: &Arc<Shared>,
    key: FlowKey,
    mut rx: mpsc::Receiver<Vec<u8>>,
    last_active: &AtomicU64,
) {
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
            let Ok(Some(d)) = tokio::time::timeout_at(deadline, rx.recv()).await else {
                break;
            };
            let res = if held.is_empty() && !quic::looks_like_initial(&d) {
                Sniff::NotMatched
            } else {
                sniffer.feed(&d)
            };
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
                    ev.ech = ch.ech_active();
                    if ch.ech_active() {
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
    let ja4_block = check_ja4(shared, &mut ev);
    if decision == Decision::Allow {
        if let Some(r) = decide_named(shared, &mut ev).or(ja4_block) {
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

    let sock = match sock::connect_udp(shared.platform.clone(), dst).await {
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
    // Only replies extend a flow's life. A flow that only sends (e.g. after
    // a network change left its socket on the old network, or to a dead
    // peer) ends after the idle timeout, or sooner if it never had a
    // reply; its next datagram starts a fresh flow and socket.
    let mut deadline = tokio::time::Instant::now() + idle.min(NO_REPLY_IDLE);
    loop {
        tokio::select! {
            d = rx.recv() => {
                let Some(d) = d else {
                    error.get_or_insert_with(|| "evicted: UDP flow limit reached".into());
                    break;
                };
                counters.tx.fetch_add(d.len() as u64, Relaxed);
                if let Err(e) = sock.send(&d).await {
                    // ICMP errors surface here (e.g. port unreachable); keep going.
                    error = Some(e.to_string());
                }
            }
            r = sock::recv_with(&sock, |data| (data.len(), packet::build_udp(dst, src, data))) => {
                match r {
                    Ok((n, pkt)) => {
                        counters.rx.fetch_add(n as u64, Relaxed);
                        deadline = tokio::time::Instant::now() + idle;
                        last_active.store(shared.ticks(), Relaxed);
                        if let Some(pkt) = pkt {
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

#[cfg(test)]
mod tests {
    use super::super::tests::test_shared;
    use super::*;
    use crate::config::Config;
    use crate::event::Event;

    fn udp(src_port: u16, dst: &str) -> (UdpInfo, Vec<u8>) {
        let pkt = packet::build_udp(
            format!("10.111.222.1:{src_port}").parse().unwrap(),
            dst.parse().unwrap(),
            b"payload",
        )
        .unwrap();
        let ip = packet::parse_ip(&pkt).unwrap();
        (packet::parse_udp(&pkt, &ip).unwrap(), pkt)
    }

    #[tokio::test]
    async fn flow_table_is_capped_by_evicting_the_idlest() {
        let shared = test_shared(Config {
            max_udp_flows: 3,
            ..Default::default()
        });
        for port in 1..=10u16 {
            let (u, pkt) = udp(port, "192.0.2.1:9999");
            on_packet(&shared, u, &pkt[u.payload_offset..u.payload_end]);
            assert!(shared.udp_flows.lock().len() <= 3);
        }
        let keys: Vec<u16> = shared
            .udp_flows
            .lock()
            .flows
            .keys()
            .map(|(s, _)| s.port())
            .collect();
        assert_eq!(keys.len(), 3);
        // Evicted flows end with a reason (and every flow gets its end).
        tokio::time::sleep(Duration::from_millis(500)).await;
        let events = shared.events.poll(1000, Duration::ZERO);
        let ended: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                Event::FlowEnd(f) => f.error.clone(),
                _ => None,
            })
            .collect();
        assert!(
            ended
                .iter()
                .any(|e| e.contains("evicted") || e.contains("socket")),
            "{events:?}"
        );
    }

    #[test]
    fn port_53_non_dns_is_not_a_query() {
        let q = dns_proto::build_query(1, "a.example", dns_proto::TYPE_A);
        assert!(is_dns_query(&q));
        assert!(!is_dns_query(
            b"\x01\x02 not dns at all, e.g. a VPN or game"
        ));
        let resp = dns_proto::servfail_response(&q).unwrap();
        assert!(!is_dns_query(&resp));
    }
}
