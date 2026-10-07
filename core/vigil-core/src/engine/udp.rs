//! UDP: per-flow NAT over protected sockets, with QUIC SNI extraction.

use super::tcp::{check_ja4, decide_named, emit_closed_flow, mark_blocked, observe_allowed};
use super::{dns, upstream, FlowCounters, FlowCut, FlowKey, GaugeGuard, Shared};
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
/// UDP flows setting up at once (UID lookup, socket creation). Both run on
/// the blocking pool (16 threads), which the TCP gate and `protect()` need
/// too, and neither can be cancelled once started: without a bound, a
/// sprayer of new UDP flows starved them.
pub(crate) const UDP_SETUP_CONCURRENCY: usize = 8;
/// Share of a full flow table evicted at once (the longest idle flows), so
/// finding them, a scan of the table, is not repeated for every new flow.
const EVICT_FRACTION: usize = 32;
const EVICTED: &str = "evicted: UDP flow limit reached";

struct FlowEntry {
    tx: mpsc::Sender<Vec<u8>>,
    /// Distinguishes this flow from a later one with the same key.
    generation: u64,
    /// `Shared::ticks()` of the last datagram in either direction.
    last_active: Arc<AtomicU64>,
    /// Stops the flow's task when the entry is evicted.
    task: tokio::task::AbortHandle,
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

    /// Removes the least recently active flows (1/EVICT_FRACTION of the
    /// table, at least one) and stops their tasks: a flow still setting up
    /// ends there, an open one gets its `flow_end` (see `FlowEnd`).
    /// Returns how many were evicted and how many queued datagrams went
    /// with them.
    fn evict_idlest(&mut self) -> (usize, u64) {
        let n = (self.flows.len() / EVICT_FRACTION).max(1);
        let mut by_age: Vec<(u64, FlowKey)> = self
            .flows
            .iter()
            .map(|(k, f)| (f.last_active.load(Relaxed), *k))
            .collect();
        if n < by_age.len() {
            by_age.select_nth_unstable(n - 1);
            by_age.truncate(n);
        }
        let mut queued = 0;
        for (_, key) in &by_age {
            if let Some(f) = self.flows.remove(key) {
                queued += (f.tx.max_capacity() - f.tx.capacity()) as u64;
                f.task.abort();
            }
        }
        (by_age.len(), queued)
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
        let (n, queued) = table.evict_idlest();
        shared.stats.dropped_packets.fetch_add(queued, Relaxed);
        log::debug!("UDP flow table full; evicted {n} flows");
    }
    let (tx, mut rx) = mpsc::channel(FLOW_QUEUE);
    let _ = tx.try_send(payload.to_vec());
    let generation = table.next_generation;
    table.next_generation += 1;
    let last_active = Arc::new(AtomicU64::new(now));
    let s = shared.clone();
    let la = last_active.clone();
    // Spawned under the table lock: the task removes its entry when done,
    // which must not happen before the entry is inserted.
    let task = tokio::spawn(async move {
        flow(&s, key, &mut rx, &la).await;
        s.udp_flows.lock().remove(&key, generation);
        // Datagrams that arrived after the flow's last read are dropped;
        // count them (later ones are counted by `on_packet`).
        rx.close();
        let mut left = 0;
        while rx.try_recv().is_ok() {
            left += 1;
        }
        s.stats.dropped_packets.fetch_add(left, Relaxed);
    });
    table.flows.insert(
        key,
        FlowEntry {
            tx,
            generation,
            last_active,
            task: task.abort_handle(),
        },
    );
}

/// Ends an open flow exactly once: with the given error at a normal end,
/// or as evicted if the flow's task is aborted.
struct FlowEnd<'a> {
    shared: &'a Shared,
    id: Option<u64>,
}

impl FlowEnd<'_> {
    fn finish(mut self, error: Option<String>) {
        if let Some(id) = self.id.take() {
            self.shared.finish_flow(id, error);
        }
    }
}

impl Drop for FlowEnd<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            // Tasks are also dropped when the engine shuts down.
            let why = if self.shared.shut_down.load(Relaxed) {
                super::SHUTDOWN_REASON
            } else {
                EVICTED
            };
            self.shared.finish_flow(id, Some(why.into()));
        }
    }
}

/// Runs a UDP flow's setup step (UID lookup, socket creation: blocking-pool
/// work that cannot be cancelled) under a `udp_setup` permit. The step runs
/// in a task of its own that owns the permit, so an evicted flow (whose task
/// is aborted) keeps counting against the cap until the work has ended.
/// None if the engine is shutting down.
async fn setup<T: Send + 'static>(
    shared: &Shared,
    work: impl std::future::Future<Output = T> + Send + 'static,
) -> Option<T> {
    let permit = shared.limits.udp_setup.clone().acquire_owned().await.ok()?;
    tokio::spawn(async move {
        let out = work.await;
        drop(permit);
        out
    })
    .await
    .ok()
}

/// One UDP flow. May be aborted at any await (eviction): nothing is
/// reported before the flow is opened, and an open flow is ended by its
/// `FlowEnd` guard.
async fn flow(
    shared: &Arc<Shared>,
    key: FlowKey,
    rx: &mut mpsc::Receiver<Vec<u8>>,
    last_active: &AtomicU64,
) {
    let _active = GaugeGuard::new(&shared.stats.udp_active);
    let (src, dst) = key;
    let cfg = shared.config();
    let idle = Duration::from_secs(cfg.udp_idle_timeout_s.max(5));
    // Subscribed before the policy decision, so a device state or rule
    // change landing after it still releases a flow held blocked.
    let mut changed = shared.app_rules_changed.subscribe();
    let uid = {
        let s = shared.clone();
        let Some(uid) = setup(
            shared,
            async move { s.lookup_uid(PROTO_UDP, src, dst).await },
        )
        .await
        else {
            return;
        };
        uid
    };
    shared.stats.flows_total.fetch_add(1, Relaxed);

    let mut ev = FlowEvent {
        id: shared.next_flow_id(),
        ts: now_ms(),
        proto: "udp",
        uid,
        src: src.to_string(),
        dst_ip: dst.ip().to_string(),
        dst_port: dst.port(),
        asn: shared.policy.read().asn_lookup(dst.ip()),
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
        let name = match ev.domain_source {
            Some("sni" | "http" | "quic") => ev.domain.clone(),
            _ => None,
        };
        mark_blocked(shared, &mut ev, &reason);
        emit_closed_flow(shared, ev, None);
        // Keep absorbing the flow's datagrams so retries don't produce a
        // stream of new flow events. A per-app block ends as soon as the
        // device state or the rules lift it, so the app's next datagram is
        // decided again (e.g. once it is in the foreground).
        if reason.is_per_app() {
            loop {
                tokio::select! {
                    r = tokio::time::timeout(idle, rx.recv()) => {
                        if !matches!(r, Ok(Some(_))) {
                            break;
                        }
                    }
                    r = changed.changed() => {
                        if r.is_err()
                            || shared.policy.read().recheck_open(uid, name.as_deref()).is_none()
                        {
                            break;
                        }
                    }
                }
            }
        } else {
            while let Ok(Some(_)) = tokio::time::timeout(idle, rx.recv()).await {}
        }
        return;
    }

    ev.via = Some(shared.upstream.via());
    let connected = {
        let s = shared.clone();
        let Some(c) = setup(shared, async move { upstream::connect_udp(&s, dst).await }).await
        else {
            return;
        };
        c
    };
    let sock = match connected {
        Ok(s) => s,
        Err(e) => {
            ev.verdict = Some(Verdict::Allow);
            let blocked = upstream::is_udp_blocked(&e);
            emit_closed_flow(shared, ev, Some(format!("socket: {e}")));
            if blocked {
                // The upstream path cannot carry UDP: absorb the flow like a
                // blocked one (apps then fall back, e.g. QUIC to TCP).
                while let Ok(Some(_)) = tokio::time::timeout(idle, rx.recv()).await {}
            }
            return;
        }
    };
    ev.via = Some(sock.via());
    ev.verdict = Some(Verdict::Allow);
    let counters = FlowCounters::new();
    let end = FlowEnd {
        shared,
        id: Some(ev.id),
    };
    let cut = FlowCut::new();
    shared.open_cuttable_flow(ev.clone(), &counters, &cut);
    if let Some(e) = cut.cut_error_now() {
        // Blocked by a per-app rule while the socket was set up (e.g. the
        // app went to the background): nothing is sent, learnt or alerted.
        end.finish(Some(e));
        return;
    }
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
                    error.get_or_insert_with(|| EVICTED.into());
                    break;
                };
                counters.tx.fetch_add(d.len() as u64, Relaxed);
                if let Err(e) = sock.send(&d).await {
                    // ICMP errors surface here (e.g. port unreachable); keep going.
                    error = Some(e.to_string());
                }
            }
            r = sock.recv_with(|data| (data.len(), packet::build_udp(dst, src, data))) => {
                match r {
                    Ok((n, pkt)) => {
                        counters.rx.fetch_add(n as u64, Relaxed);
                        deadline = tokio::time::Instant::now()
                            .checked_add(idle)
                            .unwrap_or(deadline);
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
            e = cut.cut_error() => {
                // Blocked by a per-app rule: the app's next datagram starts
                // a new flow, which is refused.
                error = Some(e);
                break;
            }
        }
    }
    end.finish(error);
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

    fn flow_events(events: &[Event]) -> Vec<&FlowEvent> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Flow(f) => Some(f),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn evicted_flows_stop_before_setting_up() {
        let shared = test_shared(Config {
            max_udp_flows: 3,
            ..Default::default()
        });
        // A single-threaded runtime: no flow task runs before the loop ends,
        // so the seven evicted ones are stopped before their UID lookup.
        for port in 1..=10u16 {
            let (u, pkt) = udp(port, "192.0.2.1:9999");
            on_packet(&shared, u, &pkt[u.payload_offset..u.payload_end]);
            assert!(shared.udp_flows.lock().len() <= 3);
        }
        let mut keys: Vec<u16> = shared
            .udp_flows
            .lock()
            .flows
            .keys()
            .map(|(s, _)| s.port())
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec![8, 9, 10]);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let events = shared.events.poll(1000, Duration::ZERO);
        let mut ports: Vec<u16> = flow_events(&events)
            .iter()
            .map(|f| f.src.rsplit(':').next().unwrap().parse().unwrap())
            .collect();
        ports.sort_unstable();
        assert_eq!(ports, vec![8, 9, 10], "{events:?}");
        assert!(shared.stats.udp_active.load(Relaxed) <= 3);
        // Their queued first datagrams count as dropped.
        assert_eq!(shared.stats.dropped_packets.load(Relaxed), 7);
    }

    #[tokio::test]
    async fn a_full_table_evicts_its_idlest_share_at_once() {
        let n = 2 * EVICT_FRACTION;
        let shared = test_shared(Config {
            max_udp_flows: n,
            ..Default::default()
        });
        for port in 1..=n as u16 {
            let (u, pkt) = udp(port, "192.0.2.1:9999");
            on_packet(&shared, u, &pkt[u.payload_offset..u.payload_end]);
        }
        // Ports 5 and 3 idle for longest, the others more recently active.
        for (key, f) in shared.udp_flows.lock().flows.iter() {
            let t = match key.0.port() {
                5 => 1,
                3 => 2,
                p => 1000 + p as u64,
            };
            f.last_active.store(t, Relaxed);
        }
        let (u, pkt) = udp(1000, "192.0.2.1:9999");
        on_packet(&shared, u, &pkt[u.payload_offset..u.payload_end]);
        let table = shared.udp_flows.lock();
        assert_eq!(table.len(), n - 1, "two evicted, one added");
        let ports: Vec<u16> = table.flows.keys().map(|(s, _)| s.port()).collect();
        assert!(!ports.contains(&5) && !ports.contains(&3));
        assert!(ports.contains(&1000));
    }

    #[test]
    fn open_flows_end_once_even_when_aborted() {
        let shared = test_shared(Config::default());
        let c = FlowCounters::new();
        for id in [1, 2] {
            shared.open_flow(
                FlowEvent {
                    id,
                    ..Default::default()
                },
                &c,
            );
        }
        FlowEnd {
            shared: &shared,
            id: Some(1),
        }
        .finish(Some("timeout".into()));
        // Dropped without finish: the task was aborted by an eviction.
        drop(FlowEnd {
            shared: &shared,
            id: Some(2),
        });
        let ends: Vec<(u64, Option<String>)> = shared
            .events
            .poll(100, Duration::ZERO)
            .into_iter()
            .filter_map(|e| match e {
                Event::FlowEnd(f) => Some((f.id, f.error)),
                _ => None,
            })
            .collect();
        assert_eq!(
            ends,
            vec![(1, Some("timeout".into())), (2, Some(EVICTED.into()))]
        );
    }

    /// Waits for the next `flow` or `flow_end` event.
    async fn next_flow_event(shared: &Shared) -> Event {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let found = shared
                .events
                .poll(1, Duration::from_millis(50))
                .into_iter()
                .find(|e| matches!(e, Event::Flow(_) | Event::FlowEnd(_)));
            if let Some(e) = found {
                return e;
            }
            assert!(Instant::now() < deadline, "no flow event");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn per_app_conditions_end_and_hold_udp_flows() {
        use super::super::tests::test_shared_uid;
        use crate::config::{AppRule, DeviceState, NetworkType};
        let state = |network| DeviceState {
            network,
            ..Default::default()
        };
        let shared = test_shared_uid(
            Config {
                app_rules: vec![AppRule {
                    uid: 10123,
                    block_wifi: true,
                    ..Default::default()
                }],
                device_state: Some(state(NetworkType::Cellular)),
                ..Default::default()
            },
            10123,
        );
        let send = || {
            let (u, pkt) = udp(41000, "192.0.2.1:9999");
            on_packet(&shared, u, &pkt[u.payload_offset..u.payload_end]);
        };
        send();
        let Event::Flow(f) = next_flow_event(&shared).await else {
            panic!("expected a flow")
        };
        assert_eq!((f.uid, f.verdict), (Some(10123), Some(Verdict::Allow)));
        // On Wi-Fi the app is blocked: its open flow ends.
        shared.policy.write().set_state(&state(NetworkType::Wifi));
        shared.recheck_open_flows();
        let Event::FlowEnd(end) = next_flow_event(&shared).await else {
            panic!("expected the flow's end")
        };
        assert_eq!(end.id, f.id);
        assert_eq!(end.error.as_deref(), Some("blocked: app rule: wifi"));
        for _ in 0..100 {
            if shared.udp_flows.lock().len() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Its next datagram is refused, and the flow held blocked...
        send();
        let Event::Flow(b) = next_flow_event(&shared).await else {
            panic!("expected a blocked flow")
        };
        assert_eq!(b.verdict, Some(Verdict::Block));
        assert_eq!(b.reason.as_deref(), Some("app rule: wifi"));
        let Event::FlowEnd(_) = next_flow_event(&shared).await else {
            panic!("blocked flows end at once")
        };
        send();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(shared.udp_flows.lock().len(), 1, "held, not a new flow");
        // ...until the condition lifts: then the next datagram is allowed.
        shared
            .policy
            .write()
            .set_state(&state(NetworkType::Cellular));
        shared.recheck_open_flows();
        for _ in 0..100 {
            if shared.udp_flows.lock().len() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(shared.udp_flows.lock().len(), 0, "blocked flow released");
        send();
        let Event::Flow(a) = next_flow_event(&shared).await else {
            panic!("expected a flow")
        };
        assert_eq!(a.verdict, Some(Verdict::Allow));
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

    #[test]
    fn flows_dropped_at_shutdown_end_as_stopped() {
        let shared = test_shared(Config::default());
        shared.open_flow(
            FlowEvent {
                id: 1,
                ..Default::default()
            },
            &FlowCounters::new(),
        );
        shared.shut_down.store(true, Relaxed);
        // The runtime drops the flow's task: not an eviction.
        drop(FlowEnd {
            shared: &shared,
            id: Some(1),
        });
        let ends: Vec<_> = shared
            .events
            .poll(100, Duration::ZERO)
            .into_iter()
            .filter_map(|e| match e {
                Event::FlowEnd(f) => Some(f.error),
                _ => None,
            })
            .collect();
        assert_eq!(ends, vec![Some(super::super::SHUTDOWN_REASON.into())]);
    }

    /// A platform whose UID lookups take a while (as on a busy device).
    struct SlowUid;

    impl crate::platform::Platform for SlowUid {
        fn owner_uid(
            &self,
            _: u8,
            _: std::net::SocketAddr,
            _: std::net::SocketAddr,
        ) -> Option<u32> {
            std::thread::sleep(Duration::from_millis(400));
            None
        }

        fn protect(&self, _: std::os::fd::RawFd) -> bool {
            true
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn evicted_flows_keep_their_setup_slot_until_the_lookup_ends() {
        let (tx, _rx) = mpsc::channel(64);
        let shared = Arc::new(Shared::new(
            Config {
                max_udp_flows: 2,
                ..Default::default()
            },
            Arc::new(SlowUid),
            tx,
        ));
        let free = || shared.limits.udp_setup.available_permits();
        for port in 1..=3u16 {
            let (u, pkt) = udp(port, "192.0.2.1:9999");
            on_packet(&shared, u, &pkt[u.payload_offset..u.payload_end]);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // The third flow evicted the first, whose lookup still runs on the
        // blocking pool: it still counts against the cap.
        assert_eq!(shared.udp_flows.lock().len(), 2);
        assert_eq!(free(), UDP_SETUP_CONCURRENCY - 3);
        // Released once the blocking work has ended.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(free() > UDP_SETUP_CONCURRENCY - 3, "{}", free());
    }

    /// Attributes every flow to UID 10123, and moves that app to the
    /// background while its socket is being created (after the flow was
    /// decided), without the recheck that would normally follow.
    struct BackgroundDuringSetup(std::sync::OnceLock<std::sync::Weak<Shared>>);

    impl crate::platform::Platform for BackgroundDuringSetup {
        fn owner_uid(
            &self,
            _: u8,
            _: std::net::SocketAddr,
            _: std::net::SocketAddr,
        ) -> Option<u32> {
            Some(10123)
        }

        fn protect(&self, _: std::os::fd::RawFd) -> bool {
            if let Some(s) = self.0.get().and_then(|w| w.upgrade()) {
                s.policy.write().set_state(&crate::config::DeviceState {
                    foreground_uids: Some(vec![]),
                    ..Default::default()
                });
            }
            true
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn held_datagrams_are_not_sent_when_the_flow_is_cut_at_open() {
        use crate::config::{AppRule, DeviceState};
        let (tx, _rx) = mpsc::channel(64);
        let platform = Arc::new(BackgroundDuringSetup(Default::default()));
        let shared = Arc::new(Shared::new(
            Config {
                app_rules: vec![AppRule {
                    uid: 10123,
                    block_background: true,
                    ..Default::default()
                }],
                device_state: Some(DeviceState {
                    foreground_uids: Some(vec![10123]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            platform.clone(),
            tx,
        ));
        platform.0.set(Arc::downgrade(&shared)).unwrap();
        let (u, pkt) = udp(42000, "192.0.2.1:9999");
        on_packet(&shared, u, &pkt[u.payload_offset..u.payload_end]);
        let Event::Flow(f) = next_flow_event(&shared).await else {
            panic!("expected a flow")
        };
        assert_eq!(f.verdict, Some(Verdict::Allow));
        let Event::FlowEnd(end) = next_flow_event(&shared).await else {
            panic!("expected the flow's end")
        };
        assert_eq!(end.error.as_deref(), Some("blocked: app rule: background"));
        assert_eq!(end.tx, 0, "a held datagram was sent");
    }
}
