//! WireGuard upstream: boringtun does the Noise handshake and the transport
//! encryption; a second, client-side smoltcp interface carries the relayed
//! TCP connections and UDP flows inside the tunnel (like onetun/wireproxy).
//!
//! ```text
//!  relay/DNS ──► WgTcpStream / WgUdp ──► smoltcp (tunnel addresses)
//!                                           │ IP packets
//!                                        boringtun ◄──► one protected UDP socket ◄──► peer
//! ```
//!
//! One driver task owns the UDP socket: it feeds received datagrams through
//! boringtun into smoltcp, polls smoltcp, encrypts what smoltcp emits, and
//! runs the WireGuard timers (handshake, keepalive, rekey). Streams and
//! sockets lock the smoltcp state briefly and wake the driver; the Noise
//! state has its own lock, so encryption and decryption (driver only) run
//! without holding the streams up.

use super::super::sock;
use crate::config::upstream::{decode_key, Cidr, WireGuardConfig};
use crate::platform::Platform;
use boringtun::noise::{errors::WireGuardError, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use parking_lot::Mutex;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::Notify;

/// Receive window of a tunnelled TCP connection. Unlike the app-side stack
/// (loopback RTT), this one talks to the internet, so its window bounds the
/// throughput (256 KiB at 50 ms RTT ≈ 40 Mbit/s). Pages are only touched as
/// the ring buffer fills.
const TCP_RX_BUF: usize = 256 * 1024;
const TCP_TX_BUF: usize = 128 * 1024;
const UDP_BUF: usize = 32 * 1024;
const UDP_SLOTS: usize = 32;
/// WireGuard timer resolution (boringtun rounds to seconds internally).
const TIMER_TICK: Duration = Duration::from_millis(250);
/// Closed-but-lingering TCP sockets are dropped after this long.
const ORPHAN_LINGER: Duration = Duration::from_secs(30);
/// Unacknowledged data older than this ends a tunnelled TCP connection.
const TCP_TIMEOUT: Duration = Duration::from_secs(120);
/// Upper bound on sockets in the tunnel stack (the engine's own caps are
/// lower; this guards against leaks).
const MAX_SOCKETS: usize = 16_384;
/// Packets queued between smoltcp and boringtun in either direction.
const MAX_QUEUE: usize = 4096;
/// Handshakes failing for this long mark the tunnel down.
const DOWN_AFTER: Duration = Duration::from_secs(10);
/// A session this old is no longer usable (WireGuard REJECT_AFTER_TIME).
const SESSION_MAX_AGE: Duration = Duration::from_secs(180);
/// While down, a new handshake is forced at least this often (boringtun
/// itself stops retrying after 90 s without traffic).
const RETRY_DOWN: Duration = Duration::from_secs(15);
/// While down, the socket is re-created and the endpoint re-resolved at most
/// this often.
const REBIND_DOWN: Duration = Duration::from_secs(30);
/// Retry delay after the socket could not be created or the endpoint not
/// resolved.
const OPEN_RETRY: Duration = Duration::from_secs(5);
/// Time allowed to look up the endpoint's name.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Room for a WireGuard header and tag around any IP packet.
const WG_BUF: usize = 65_536 + 256;
/// Datagrams handled per wakeup before yielding.
const RECV_BATCH: usize = 64;

/// smoltcp device backed by two packet queues.
struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct QRx(Vec<u8>);
struct QTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for QRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for QTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut p = vec![0u8; len];
        let r = f(&mut p);
        self.0.push_back(p);
        r
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = QRx;
    type TxToken<'a> = QTx<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(QRx, QTx<'_>)> {
        if self.tx.len() >= MAX_QUEUE {
            return None;
        }
        let p = self.rx.pop_front()?;
        Some((QRx(p), QTx(&mut self.tx)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<QTx<'_>> {
        (self.tx.len() < MAX_QUEUE).then_some(QTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

struct TcpTrack {
    port: u16,
    last: tcp::State,
    /// Ended without an orderly close (RST, refused, timeout).
    reset: bool,
    /// The stream was dropped; the socket lingers until closed.
    orphaned: Option<Instant>,
}

/// The smoltcp interface and its sockets (the lock streams take).
struct Stack {
    iface: Interface,
    dev: QueueDevice,
    sockets: SocketSet<'static>,
    tcp: HashMap<SocketHandle, TcpTrack>,
    ports: HashSet<u16>,
    next_port: u16,
}

/// The Noise state, behind its own lock: encryption and decryption run
/// there without blocking the streams (only the driver and `stats` take it).
struct Noise {
    tunn: Tunn,
    buf: Vec<u8>,
    last_timer: Instant,
    hs: Handshakes,
}

impl Noise {
    fn session_valid(&self) -> bool {
        self.tunn
            .time_since_last_handshake()
            .is_some_and(|age| age < SESSION_MAX_AGE)
    }
}

/// Handshake bookkeeping for the up/down state.
#[derive(Default)]
struct Handshakes {
    /// Since when a handshake has been attempted without completing.
    pending_since: Option<Instant>,
    /// Last initiation sent.
    last_init: Option<Instant>,
}

impl Handshakes {
    fn on_send(&mut self, p: &[u8]) {
        // Message type 1 (little-endian u32) is a handshake initiation.
        if p.len() == 148 && p[..4] == [1, 0, 0, 0] {
            let now = Instant::now();
            self.pending_since.get_or_insert(now);
            self.last_init = Some(now);
        }
    }

    /// Clears the pending state once a handshake completed after it began.
    /// `age` comes from boringtun's coarse timers, hence the tolerance.
    fn settle(&mut self, age: Option<Duration>) {
        if let (Some(p), Some(age)) = (self.pending_since, age) {
            if age < p.elapsed() + Duration::from_secs(1) {
                self.pending_since = None;
            }
        }
    }

    /// Handshakes have been failing for a while (even if an older session
    /// has not expired yet: the peer may have vanished).
    fn failing(&self) -> bool {
        self.pending_since
            .is_some_and(|t| t.elapsed() >= DOWN_AFTER)
    }
}

impl Stack {
    fn alloc_port(&mut self) -> io::Result<u16> {
        for _ in 0..16_384 {
            let p = self.next_port;
            self.next_port = if p == u16::MAX { 49_152 } else { p + 1 };
            if self.ports.insert(p) {
                return Ok(p);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "wireguard: no free local port",
        ))
    }

    /// Polls smoltcp and updates the TCP bookkeeping. Must follow every
    /// change of socket or device state that should take effect.
    fn poll(&mut self) {
        self.iface.poll(
            smoltcp::time::Instant::now(),
            &mut self.dev,
            &mut self.sockets,
        );
        let mut dead = Vec::new();
        for (&h, tr) in self.tcp.iter_mut() {
            let state = self.sockets.get::<tcp::Socket>(h).state();
            if state != tr.last {
                use tcp::State::*;
                if state == Closed && !matches!(tr.last, LastAck | TimeWait | Closed | Listen) {
                    tr.reset = true;
                }
                tr.last = state;
            }
            if let Some(t) = tr.orphaned {
                if matches!(state, tcp::State::Closed | tcp::State::TimeWait)
                    || t.elapsed() >= ORPHAN_LINGER
                {
                    dead.push(h);
                }
            }
        }
        for h in dead {
            if let Some(tr) = self.tcp.remove(&h) {
                self.ports.remove(&tr.port);
            }
            self.sockets.remove(h);
        }
    }
}

#[derive(Default)]
struct Net {
    sock: Option<Arc<UdpSocket>>,
    endpoint: Option<SocketAddr>,
    last_open: Option<Instant>,
    /// The last attempt to open the socket failed. Only then does a missing
    /// socket make the tunnel down: while it is being re-created (roaming)
    /// the session stays usable and packets wait in the queues.
    open_failed: bool,
    last_error: Option<String>,
}

/// A running WireGuard tunnel with its client stack.
pub(crate) struct WgTunnel {
    stack: Mutex<Stack>,
    noise: Mutex<Noise>,
    net: Mutex<Net>,
    /// Wakes the driver (new data to send, window updates, closes).
    notify: Arc<Notify>,
    /// Re-create the UDP socket (network change or send failure).
    rebind: AtomicBool,
    /// Counts changes between down and not down (see [`Self::health_epoch`]).
    epoch: AtomicU64,
    allowed: Vec<Cidr>,
    endpoint_spec: String,
    platform: Arc<dyn Platform>,
    has_v4: bool,
    has_v6: bool,
}

/// Status for `stats` events.
pub(crate) struct WgStatus {
    pub state: &'static str,
    pub endpoint: Option<SocketAddr>,
    pub handshake_age_s: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_error: Option<String>,
}

fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    h.finish()
}

impl WgTunnel {
    /// Creates the tunnel and spawns its driver. Must be called inside the
    /// engine's runtime. The config must have passed validation.
    pub fn start(cfg: &WireGuardConfig, platform: Arc<dyn Platform>) -> io::Result<Arc<Self>> {
        let invalid = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, m.to_string());
        let private = decode_key(&cfg.private_key).ok_or_else(|| invalid("bad private key"))?;
        let peer = decode_key(&cfg.peer_public_key).ok_or_else(|| invalid("bad peer key"))?;
        let addrs = cfg.tunnel_addresses().map_err(|e| invalid(&e))?;
        let allowed = cfg.allowed().map_err(|e| invalid(&e))?;
        let keepalive = (cfg.persistent_keepalive > 0).then_some(cfg.persistent_keepalive);
        let seed = random_u64();
        let tunn = Tunn::new(
            StaticSecret::from(private),
            PublicKey::from(peer),
            cfg.preshared(),
            keepalive,
            (seed as u32) >> 8,
            None,
        );
        let mut dev = QueueDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu: cfg.mtu as usize,
        };
        let mut icfg = IfaceConfig::new(HardwareAddress::Ip);
        icfg.random_seed = seed.rotate_left(17);
        let mut iface = Interface::new(icfg, &mut dev, smoltcp::time::Instant::now());
        let (mut has_v4, mut has_v6) = (false, false);
        iface.update_ip_addrs(|a| {
            for c in &addrs {
                if a.push(IpCidr::new(IpAddress::from(c.addr), c.prefix))
                    .is_ok()
                {
                    has_v4 |= c.addr.is_ipv4();
                    has_v6 |= c.addr.is_ipv6();
                }
            }
        });
        // Medium::Ip has no neighbours; the gateway only has to exist.
        for c in &addrs {
            let r = match c.addr {
                IpAddr::V4(a) => iface.routes_mut().add_default_ipv4_route(a).map(|_| ()),
                IpAddr::V6(a) => iface.routes_mut().add_default_ipv6_route(a).map(|_| ()),
            };
            if r.is_err() {
                log::warn!("wireguard: route table full");
            }
        }
        let t = Arc::new(Self {
            stack: Mutex::new(Stack {
                iface,
                dev,
                sockets: SocketSet::new(Vec::new()),
                tcp: HashMap::new(),
                ports: HashSet::new(),
                next_port: 49_152 + (seed % 16_000) as u16,
            }),
            noise: Mutex::new(Noise {
                tunn,
                buf: vec![0u8; WG_BUF],
                last_timer: Instant::now(),
                hs: Handshakes::default(),
            }),
            net: Mutex::new(Net::default()),
            notify: Arc::new(Notify::new()),
            rebind: AtomicBool::new(false),
            epoch: AtomicU64::new(0),
            allowed,
            endpoint_spec: cfg.endpoint.clone(),
            platform,
            has_v4,
            has_v6,
        });
        tokio::spawn(drive(Arc::downgrade(&t), t.notify.clone()));
        Ok(t)
    }

    /// Whether `ip` is routed through the peer (AllowedIPs; empty = all).
    pub fn routes(&self, ip: IpAddr) -> bool {
        self.allowed.is_empty() || self.allowed.iter().any(|c| c.contains(ip))
    }

    /// Whether AllowedIPs route any address of `ip`'s family. A typical
    /// provider config (`0.0.0.0/0` only) routes no IPv6 at all: that is
    /// not a split tunnel, and with fail_closed such traffic is refused
    /// rather than sent direct.
    pub fn routes_family(&self, ip: IpAddr) -> bool {
        let v4 = ip.to_canonical().is_ipv4();
        self.allowed.is_empty() || self.allowed.iter().any(|c| c.addr.is_ipv4() == v4)
    }

    /// The handshake has been failing (or the endpoint is unusable) for a
    /// while. An idle tunnel without a session is *not* down, nor is one
    /// whose socket is being re-created after a network change.
    pub fn is_down(&self) -> bool {
        let failing = self.noise.lock().hs.failing();
        let net = self.net.lock();
        failing || (net.sock.is_none() && net.open_failed)
    }

    /// Changes whenever the tunnel goes down or comes back. Connections
    /// pooled by the engine (DNS sockets, encrypted DNS sessions) are keyed
    /// on it, so ones opened direct while the tunnel was down (fail-open)
    /// are not reused once it is back, nor tunnelled ones while it is down.
    pub fn health_epoch(&self) -> u64 {
        self.epoch.load(Relaxed)
    }

    /// Network changed: re-create the socket and re-resolve the endpoint.
    /// Sessions survive (WireGuard roams on the next authenticated packet).
    pub fn roam(&self) {
        self.rebind.store(true, Relaxed);
        self.notify.notify_one();
    }

    pub fn status(&self) -> WgStatus {
        let (age, tx, rx, valid, pending) = {
            let n = self.noise.lock();
            let (age, tx, rx, _, _) = n.tunn.stats();
            (age, tx, rx, n.session_valid(), n.hs.pending_since)
        };
        let down = self.is_down();
        let net = self.net.lock();
        WgStatus {
            state: if down {
                "down"
            } else if valid {
                "up"
            } else if pending.is_some() || net.sock.is_none() {
                "connecting"
            } else {
                "idle"
            },
            endpoint: net.endpoint,
            handshake_age_s: age.map(|d| d.as_secs()),
            tx_bytes: tx as u64,
            rx_bytes: rx as u64,
            last_error: net.last_error.clone(),
        }
    }

    fn set_error(&self, e: String) {
        log::debug!("wireguard: {e}");
        self.net.lock().last_error = Some(e);
    }

    fn check_family(&self, ip: IpAddr) -> io::Result<()> {
        if (ip.is_ipv4() && !self.has_v4) || (ip.is_ipv6() && !self.has_v6) {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "wireguard: no IPv{} address on the tunnel",
                    if ip.is_ipv4() { 4 } else { 6 }
                ),
            ));
        }
        Ok(())
    }

    /// Opens a TCP connection through the tunnel. Resolves once the
    /// three-way handshake completes; a RST from the destination gives
    /// `ConnectionRefused`. Dropping the future aborts the attempt.
    pub async fn connect_tcp(self: &Arc<Self>, dst: SocketAddr) -> io::Result<WgTcpStream> {
        self.check_family(dst.ip())?;
        let handle = {
            let mut g = self.stack.lock();
            let st = &mut *g;
            if st.sockets.iter().count() >= MAX_SOCKETS {
                return Err(io::Error::other("wireguard: too many sockets"));
            }
            let port = st.alloc_port()?;
            let mut s = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF]),
                tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF]),
            );
            s.set_nagle_enabled(false);
            s.set_timeout(Some(smoltcp::time::Duration::from_secs(
                TCP_TIMEOUT.as_secs(),
            )));
            if let Err(e) = s.connect(st.iface.context(), IpEndpoint::from(dst), port) {
                st.ports.remove(&port);
                return Err(io::Error::other(format!("wireguard: connect: {e}")));
            }
            let h = st.sockets.add(s);
            st.tcp.insert(
                h,
                TcpTrack {
                    port,
                    last: tcp::State::SynSent,
                    reset: false,
                    orphaned: None,
                },
            );
            st.poll();
            h
        };
        self.notify.notify_one();
        // Until established, dropping the stream (e.g. on timeout) aborts.
        let mut stream = WgTcpStream {
            tun: self.clone(),
            handle,
            reset_on_close: true,
        };
        poll_fn(|cx| {
            let mut g = self.stack.lock();
            let s = g.sockets.get_mut::<tcp::Socket>(handle);
            match s.state() {
                tcp::State::SynSent | tcp::State::SynReceived => {
                    s.register_send_waker(cx.waker());
                    Poll::Pending
                }
                tcp::State::Closed => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "Connection refused (through WireGuard)",
                ))),
                _ => Poll::Ready(Ok(())),
            }
        })
        .await?;
        stream.reset_on_close = false;
        Ok(stream)
    }

    /// A UDP socket in the tunnel exchanging datagrams with `dst`.
    pub fn connect_udp(self: &Arc<Self>, dst: SocketAddr) -> io::Result<WgUdp> {
        self.check_family(dst.ip())?;
        let handle = {
            let mut g = self.stack.lock();
            let st = &mut *g;
            if st.sockets.iter().count() >= MAX_SOCKETS {
                return Err(io::Error::other("wireguard: too many sockets"));
            }
            let port = st.alloc_port()?;
            let buf = || {
                udp::PacketBuffer::new(
                    vec![udp::PacketMetadata::EMPTY; UDP_SLOTS],
                    vec![0u8; UDP_BUF],
                )
            };
            let mut s = udp::Socket::new(buf(), buf());
            if let Err(e) = s.bind(port) {
                st.ports.remove(&port);
                return Err(io::Error::other(format!("wireguard: bind: {e}")));
            }
            let h = st.sockets.add(s);
            (h, port)
        };
        Ok(WgUdp {
            tun: self.clone(),
            handle: handle.0,
            port: handle.1,
            dst: IpEndpoint::from(dst),
        })
    }

    // --- driver side -------------------------------------------------------

    /// Sends one encrypted datagram, noting handshake initiations.
    fn send_datagram(&self, sock: &UdpSocket, hs: &mut Handshakes, p: &[u8]) {
        hs.on_send(p);
        // A direct send(2): tokio's try_send reports WouldBlock until the
        // reactor has seen the socket writable, which would drop the first
        // handshake of a new socket. A full UDP buffer drops the datagram.
        match socket2::SockRef::from(sock).send(p) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            // An ICMP error from the peer's address, or a datagram too
            // large for the path (re-creating the socket would not make it
            // fit): keep the socket.
            Err(e) if !needs_rebind(&e) => self.set_error(format!("send: {e}")),
            Err(e) => {
                // Typically the network went away under the socket.
                self.set_error(format!("send: {e}"));
                self.rebind.store(true, Relaxed);
            }
        }
    }

    /// Timers, smoltcp poll and encryption of everything smoltcp emitted.
    /// smoltcp's output is taken out of the stack lock (into `out`, the
    /// driver's reusable queue) and encrypted under the Noise lock only, so
    /// streams are not held up by the encryption. Returns how long the
    /// driver may sleep.
    fn pump(&self, sock: Option<&UdpSocket>, out: &mut VecDeque<Vec<u8>>) -> Duration {
        let delay = {
            let mut g = self.stack.lock();
            let st = &mut *g;
            st.poll();
            if sock.is_some() {
                std::mem::swap(&mut st.dev.tx, out);
            }
            st.iface
                .poll_delay(smoltcp::time::Instant::now(), &st.sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(TIMER_TICK)
                .min(TIMER_TICK)
        };
        let Some(sock) = sock else {
            // No socket yet (or being re-created): keep smoltcp's packets
            // queued rather than letting boringtun emit a handshake that
            // would be lost (it would only retry after REKEY_TIMEOUT).
            return TIMER_TICK;
        };
        let mut g = self.noise.lock();
        let n = &mut *g;
        let now = Instant::now();
        if now.duration_since(n.last_timer) >= TIMER_TICK {
            n.last_timer = now;
            match n.tunn.update_timers(&mut n.buf) {
                TunnResult::WriteToNetwork(p) => self.send_datagram(sock, &mut n.hs, p),
                TunnResult::Err(WireGuardError::ConnectionExpired) => {}
                TunnResult::Err(e) => log::debug!("wireguard timers: {e:?}"),
                _ => {}
            }
            n.hs.settle(n.tunn.time_since_last_handshake());
            if n.hs.failing() && n.hs.last_init.map_or(true, |t| t.elapsed() >= RETRY_DOWN) {
                // Keep trying while down, so the tunnel comes back on its own.
                if let TunnResult::WriteToNetwork(p) =
                    n.tunn.format_handshake_initiation(&mut n.buf, true)
                {
                    self.send_datagram(sock, &mut n.hs, p);
                }
            }
        }
        while let Some(pkt) = out.pop_front() {
            match n.tunn.encapsulate(&pkt, &mut n.buf) {
                TunnResult::WriteToNetwork(p) => self.send_datagram(sock, &mut n.hs, p),
                TunnResult::Err(e) => log::debug!("wireguard encapsulate: {e:?}"),
                _ => {}
            }
        }
        delay
    }

    /// Reads and decrypts queued datagrams (a batch) under the Noise lock,
    /// then hands the inner packets to smoltcp's queue (the next pump
    /// processes them). `inner` is the driver's reusable queue.
    fn receive(
        &self,
        sock: &UdpSocket,
        rbuf: &mut [u8],
        endpoint: Option<SocketAddr>,
        inner: &mut VecDeque<Vec<u8>>,
    ) {
        {
            let mut g = self.noise.lock();
            let n = &mut *g;
            let from = endpoint.map(|e| e.ip());
            for _ in 0..RECV_BATCH {
                let len = match sock.try_recv(rbuf) {
                    Ok(len) => len,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        if e.kind() != io::ErrorKind::ConnectionRefused {
                            self.rebind.store(true, Relaxed);
                        }
                        self.set_error(format!("receive: {e}"));
                        break;
                    }
                };
                match n.tunn.decapsulate(from, &rbuf[..len], &mut n.buf) {
                    TunnResult::WriteToNetwork(p) => {
                        self.send_datagram(sock, &mut n.hs, p);
                        // Flush packets queued while the handshake was pending.
                        while let TunnResult::WriteToNetwork(p) =
                            n.tunn.decapsulate(None, &[], &mut n.buf)
                        {
                            self.send_datagram(sock, &mut n.hs, p);
                        }
                    }
                    TunnResult::WriteToTunnelV4(p, src) => {
                        if self.accepts(src.into()) {
                            inner.push_back(p.to_vec());
                        }
                    }
                    TunnResult::WriteToTunnelV6(p, src) => {
                        if self.accepts(src.into()) {
                            inner.push_back(p.to_vec());
                        }
                    }
                    TunnResult::Done => {}
                    TunnResult::Err(e) => log::debug!("wireguard decapsulate: {e:?}"),
                }
            }
            n.hs.settle(n.tunn.time_since_last_handshake());
        }
        if inner.is_empty() {
            return;
        }
        let mut st = self.stack.lock();
        let room = MAX_QUEUE.saturating_sub(st.dev.rx.len());
        st.dev.rx.extend(inner.drain(..).take(room));
    }

    /// Cryptokey routing: inner packets must come from AllowedIPs.
    fn accepts(&self, src: IpAddr) -> bool {
        self.routes(src)
    }

    /// Resolves the endpoint (within [`RESOLVE_TIMEOUT`]; the last address
    /// is kept when the lookup fails, e.g. on a network whose DNS is not up
    /// yet) and opens a protected UDP socket to it.
    async fn open_socket(&self, last: Option<SocketAddr>) -> io::Result<(UdpSocket, SocketAddr)> {
        let ep = match super::resolve(&self.endpoint_spec, RESOLVE_TIMEOUT).await {
            // Prefer IPv4: more networks route it.
            Ok(addrs) => addrs
                .iter()
                .find(|a| a.is_ipv4())
                .copied()
                .unwrap_or(addrs[0]),
            Err(e) => match last {
                Some(a) => {
                    log::info!("wireguard: {e}; keeping endpoint {a}");
                    a
                }
                None => return Err(e),
            },
        };
        let s = sock::connect_udp(self.platform.clone(), ep).await?;
        Ok((s, ep))
    }

    /// After a new socket: announce ourselves from the new address.
    fn after_rebind(&self, sock: &UdpSocket) {
        let mut g = self.noise.lock();
        let n = &mut *g;
        if n.session_valid() {
            // A keepalive is enough for the peer to learn the new endpoint.
            if let TunnResult::WriteToNetwork(p) = n.tunn.encapsulate(&[], &mut n.buf) {
                self.send_datagram(sock, &mut n.hs, p);
            }
        }
    }
}

impl Drop for WgTunnel {
    /// The last reference is gone (a replaced tunnel's last connection
    /// ended): one final pump, so the FIN or RST queued by that
    /// connection's close still reaches the peer. The driver cannot do it:
    /// it only holds a weak reference and exits.
    fn drop(&mut self) {
        let Some(sock) = self.net.get_mut().sock.clone() else {
            return;
        };
        if !self.noise.get_mut().session_valid() {
            return;
        }
        let mut out = VecDeque::new();
        for _ in 0..2 {
            self.pump(Some(&sock), &mut out);
        }
    }
}

/// The driver task. Holds only a weak reference between iterations, so it
/// ends once the tunnel is replaced and its last connection is gone.
async fn drive(weak: Weak<WgTunnel>, notify: Arc<Notify>) {
    let mut rbuf = vec![0u8; 65_536];
    let mut queue = VecDeque::new();
    let mut sock: Option<Arc<UdpSocket>> = None;
    let mut endpoint = None;
    let mut next_open = Instant::now();
    let mut was_down = false;
    loop {
        let Some(t) = weak.upgrade() else {
            return;
        };
        let down = t.is_down();
        if down != was_down {
            was_down = down;
            t.epoch.fetch_add(1, Relaxed);
            log::info!(
                "wireguard: tunnel {}",
                if down { "down" } else { "back up" }
            );
        }
        let down_long = down
            && t.net
                .lock()
                .last_open
                .is_some_and(|o| o.elapsed() >= REBIND_DOWN);
        if t.rebind.swap(false, Relaxed) || (sock.is_some() && down_long) {
            sock = None;
            t.net.lock().sock = None;
            next_open = Instant::now();
        }
        if sock.is_none() && Instant::now() >= next_open {
            let r = t.open_socket(endpoint).await;
            let mut net = t.net.lock();
            net.last_open = Some(Instant::now());
            match r {
                Ok((s, ep)) => {
                    log::info!("wireguard: endpoint {ep}");
                    let s = Arc::new(s);
                    net.sock = Some(s.clone());
                    net.endpoint = Some(ep);
                    net.open_failed = false;
                    drop(net);
                    t.after_rebind(&s);
                    sock = Some(s);
                    endpoint = Some(ep);
                }
                Err(e) => {
                    net.last_error = Some(format!("endpoint {}: {e}", t.endpoint_spec));
                    net.open_failed = true;
                    log::warn!("wireguard: endpoint {}: {e}", t.endpoint_spec);
                    next_open = Instant::now() + OPEN_RETRY;
                }
            }
        }
        let delay = t.pump(sock.as_deref(), &mut queue);
        drop(t);
        match &sock {
            Some(s) => {
                tokio::select! {
                    _ = notify.notified() => {}
                    _ = tokio::time::sleep(delay) => {}
                    r = s.readable() => {
                        if r.is_ok() {
                            if let Some(t) = weak.upgrade() {
                                t.receive(s, &mut rbuf, endpoint, &mut queue);
                            }
                        }
                    }
                }
            }
            None => {
                tokio::select! {
                    _ = notify.notified() => {}
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }
    }
}

/// A TCP connection through the tunnel.
pub(crate) struct WgTcpStream {
    tun: Arc<WgTunnel>,
    handle: SocketHandle,
    /// Abort (RST) instead of close (FIN) when dropped.
    reset_on_close: bool,
}

impl WgTcpStream {
    pub fn set_reset_on_close(&mut self) {
        self.reset_on_close = true;
    }
}

/// Whether a send error means the socket should be re-created. Not for an
/// ICMP error from the peer's address (`ConnectionRefused`), nor for a
/// datagram too large to send (`EMSGSIZE`): a new socket would hit it again,
/// and rebinding over and over would only disrupt the tunnel.
fn needs_rebind(e: &io::Error) -> bool {
    e.kind() != io::ErrorKind::ConnectionRefused && e.raw_os_error() != Some(libc::EMSGSIZE)
}

fn reset_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionReset,
        "Connection reset by peer (through WireGuard)",
    )
}

impl AsyncRead for WgTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut g = self.tun.stack.lock();
        let st = &mut *g;
        let reset = st.tcp.get(&self.handle).is_some_and(|t| t.reset);
        let s = st.sockets.get_mut::<tcp::Socket>(self.handle);
        if s.can_recv() {
            let n = s
                .recv_slice(buf.initialize_unfilled())
                .map_err(|e| io::Error::other(format!("wireguard: recv: {e}")))?;
            buf.advance(n);
            // The window opened: the driver polls smoltcp, which tells the
            // peer (not done here: a full poll under the stack lock on
            // every read of every stream would serialise them).
            drop(g);
            self.tun.notify.notify_one();
            return Poll::Ready(Ok(()));
        }
        if reset {
            return Poll::Ready(Err(reset_error()));
        }
        if !s.may_recv() {
            return Poll::Ready(Ok(())); // FIN received: EOF
        }
        s.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for WgTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut g = self.tun.stack.lock();
        let st = &mut *g;
        let reset = st.tcp.get(&self.handle).is_some_and(|t| t.reset);
        let s = st.sockets.get_mut::<tcp::Socket>(self.handle);
        if reset {
            return Poll::Ready(Err(reset_error()));
        }
        if !s.may_send() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wireguard: connection closed",
            )));
        }
        if s.can_send() {
            let n = s
                .send_slice(buf)
                .map_err(|e| io::Error::other(format!("wireguard: send: {e}")))?;
            drop(g);
            self.tun.notify.notify_one();
            return Poll::Ready(Ok(n));
        }
        s.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.tun
            .stack
            .lock()
            .sockets
            .get_mut::<tcp::Socket>(self.handle)
            .close();
        self.tun.notify.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for WgTcpStream {
    fn drop(&mut self) {
        let mut g = self.tun.stack.lock();
        let st = &mut *g;
        let s = st.sockets.get_mut::<tcp::Socket>(self.handle);
        if self.reset_on_close {
            s.abort();
        } else {
            s.close();
        }
        if let Some(tr) = st.tcp.get_mut(&self.handle) {
            tr.orphaned = Some(Instant::now());
        }
        drop(g);
        self.tun.notify.notify_one();
    }
}

/// A UDP flow through the tunnel.
pub(crate) struct WgUdp {
    tun: Arc<WgTunnel>,
    handle: SocketHandle,
    port: u16,
    dst: IpEndpoint,
}

impl WgUdp {
    /// Queues a datagram. A full send buffer drops it, like a full qdisc.
    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        let mut g = self.tun.stack.lock();
        let s = g.sockets.get_mut::<udp::Socket>(self.handle);
        match s.send_slice(data, self.dst) {
            Ok(()) | Err(udp::SendError::BufferFull) => {}
            Err(e) => return Err(io::Error::other(format!("wireguard: send: {e}"))),
        }
        drop(g);
        self.tun.notify.notify_one();
        Ok(data.len())
    }

    /// Waits for a datagram from `dst` and passes it to `f`.
    pub async fn recv_with<T>(&self, mut f: impl FnMut(&[u8]) -> T) -> io::Result<T> {
        let dst = self.dst;
        poll_fn(|cx| {
            let mut g = self.tun.stack.lock();
            let s = g.sockets.get_mut::<udp::Socket>(self.handle);
            loop {
                match s.recv() {
                    Ok((d, meta)) if meta.endpoint == dst => return Poll::Ready(Ok(f(d))),
                    Ok(_) => continue, // from someone else: dropped
                    Err(_) => {
                        s.register_recv_waker(cx.waker());
                        return Poll::Pending;
                    }
                }
            }
        })
        .await
    }

    pub fn drain(&self) {
        let mut g = self.tun.stack.lock();
        let s = g.sockets.get_mut::<udp::Socket>(self.handle);
        while s.recv().is_ok() {}
    }
}

impl Drop for WgUdp {
    fn drop(&mut self) {
        let mut g = self.tun.stack.lock();
        g.sockets.remove(self.handle);
        g.ports.remove(&self.port);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::NullPlatform;
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn oversized_datagrams_do_not_rebind() {
        assert!(!needs_rebind(&io::Error::from_raw_os_error(libc::EMSGSIZE)));
        assert!(!needs_rebind(&io::Error::from(
            io::ErrorKind::ConnectionRefused
        )));
        assert!(needs_rebind(&io::Error::from_raw_os_error(
            libc::ENETUNREACH
        )));
        assert!(needs_rebind(&io::Error::from_raw_os_error(libc::EBADF)));
    }

    fn b64(k: &[u8; 32]) -> String {
        base64::engine::general_purpose::STANDARD.encode(k)
    }

    /// A user-space WireGuard peer on loopback whose inner side is a
    /// smoltcp stack with a TCP echo server on 10.9.0.1:7 and a UDP echo on
    /// 10.9.0.1:9: exercises handshake, encryption both ways, the client
    /// stack, resets and UDP, without any privileges.
    struct Peer {
        addr: SocketAddr,
        public: String,
        /// Connections the peer saw closed by the client (FIN).
        fins: Arc<std::sync::atomic::AtomicUsize>,
    }

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::from([seed; 32]);
        let public = PublicKey::from(&secret);
        (secret.to_bytes(), public.to_bytes())
    }

    async fn start_peer(client_public: [u8; 32]) -> Peer {
        let (sk, pk) = keypair(7);
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_nonblocking(true).unwrap();
        let addr = udp.local_addr().unwrap();
        let fins = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let f = fins.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(peer_loop(udp, sk, client_public, f));
        });
        Peer {
            addr,
            public: b64(&pk),
            fins,
        }
    }

    async fn peer_loop(
        sock: std::net::UdpSocket,
        sk: [u8; 32],
        client: [u8; 32],
        fins: Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let sock = UdpSocket::from_std(sock).unwrap();
        let mut tunn = Tunn::new(
            StaticSecret::from(sk),
            PublicKey::from(client),
            None,
            None,
            1,
            None,
        );
        let mut dev = QueueDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu: 1420,
        };
        let mut iface = Interface::new(
            IfaceConfig::new(HardwareAddress::Ip),
            &mut dev,
            smoltcp::time::Instant::now(),
        );
        iface.update_ip_addrs(|a| {
            a.push(IpCidr::new(IpAddress::v4(10, 9, 0, 1), 24)).unwrap();
        });
        let mut sockets = SocketSet::new(Vec::new());
        let mut listeners = Vec::new();
        let listen = |sockets: &mut SocketSet<'static>| {
            let mut s = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 65536]),
                tcp::SocketBuffer::new(vec![0; 65536]),
            );
            s.listen(7).unwrap();
            sockets.add(s)
        };
        listeners.push(listen(&mut sockets));
        let ubuf = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 16384]);
        let mut us = udp::Socket::new(ubuf(), ubuf());
        us.bind(9).unwrap();
        let uh = sockets.add(us);
        let mut client: Option<SocketAddr> = None;
        let mut buf = vec![0u8; WG_BUF];
        let mut rbuf = vec![0u8; 65536];
        loop {
            // Datagrams in.
            while let Ok((n, from)) = sock.try_recv_from(&mut rbuf) {
                client = Some(from);
                match tunn.decapsulate(Some(from.ip()), &rbuf[..n], &mut buf) {
                    TunnResult::WriteToNetwork(p) => {
                        sock.send_to(p, from).await.unwrap();
                        while let TunnResult::WriteToNetwork(p) =
                            tunn.decapsulate(None, &[], &mut buf)
                        {
                            sock.send_to(p, from).await.unwrap();
                        }
                    }
                    TunnResult::WriteToTunnelV4(p, _) => dev.rx.push_back(p.to_vec()),
                    _ => {}
                }
            }
            iface.poll(smoltcp::time::Instant::now(), &mut dev, &mut sockets);
            // Echo services. Port 7 resets connections whose data starts with "RST".
            for &h in &listeners {
                let s = sockets.get_mut::<tcp::Socket>(h);
                let room = (s.send_capacity() - s.send_queue()).min(4096);
                if s.can_recv() && room > 0 {
                    let mut b = [0u8; 4096];
                    let n = s.recv_slice(&mut b[..room]).unwrap();
                    if b[..n].starts_with(b"RST!") {
                        s.abort();
                    } else {
                        s.send_slice(&b[..n]).unwrap();
                    }
                }
                if s.state() == tcp::State::CloseWait {
                    fins.fetch_add(1, Relaxed);
                    s.close();
                }
            }
            if !listeners
                .iter()
                .any(|&h| sockets.get::<tcp::Socket>(h).state() == tcp::State::Listen)
            {
                listeners.push(listen(&mut sockets));
            }
            let u = sockets.get_mut::<udp::Socket>(uh);
            while let Ok((d, meta)) = u.recv() {
                let d = d.to_vec();
                u.send_slice(&d, meta.endpoint).unwrap();
            }
            iface.poll(smoltcp::time::Instant::now(), &mut dev, &mut sockets);
            while let Some(p) = dev.tx.pop_front() {
                if let (TunnResult::WriteToNetwork(out), Some(c)) =
                    (tunn.encapsulate(&p, &mut buf), client)
                {
                    sock.send_to(out, c).await.unwrap();
                }
            }
            if let TunnResult::WriteToNetwork(p) = tunn.update_timers(&mut buf) {
                if let Some(c) = client {
                    sock.send_to(p, c).await.unwrap();
                }
            }
            tokio::select! {
                _ = sock.readable() => {}
                _ = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
        }
    }

    fn client_cfg(peer: &Peer, private: [u8; 32]) -> WireGuardConfig {
        WireGuardConfig {
            private_key: b64(&private),
            peer_public_key: peer.public.clone(),
            endpoint: peer.addr.to_string(),
            addresses: vec!["10.9.0.2/32".into()],
            mtu: 1420,
            ..Default::default()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_and_udp_through_a_userspace_peer() {
        let (csk, cpk) = keypair(3);
        let peer = start_peer(cpk).await;
        let t = WgTunnel::start(&client_cfg(&peer, csk), Arc::new(NullPlatform)).unwrap();
        assert_eq!(t.status().state, "connecting");
        let dst: SocketAddr = "10.9.0.1:7".parse().unwrap();
        let mut s = tokio::time::timeout(Duration::from_secs(10), t.connect_tcp(dst))
            .await
            .expect("connect timed out")
            .unwrap();
        // Larger than one window, to exercise flow control both ways.
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let (mut r, mut w) = tokio::io::split(&mut s);
        let send = async {
            w.write_all(&data).await.unwrap();
        };
        let recv = async {
            let mut got = vec![0u8; data.len()];
            r.read_exact(&mut got).await.unwrap();
            got
        };
        let (_, got) =
            tokio::time::timeout(Duration::from_secs(20), async { tokio::join!(send, recv) })
                .await
                .expect("echo timed out");
        assert!(got == data, "echoed data differs");
        let st = t.status();
        assert_eq!(st.state, "up");
        assert!(st.handshake_age_s.is_some());
        assert!(st.tx_bytes >= data.len() as u64 && st.rx_bytes >= data.len() as u64);

        // A reset by the far end surfaces as ConnectionReset.
        let mut s2 = t.connect_tcp(dst).await.unwrap();
        s2.write_all(b"RST! please").await.unwrap();
        let mut b = [0u8; 16];
        let e = tokio::time::timeout(Duration::from_secs(5), s2.read(&mut b))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionReset);

        // A closed port is refused.
        let e = t
            .connect_tcp("10.9.0.1:8".parse().unwrap())
            .await
            .err()
            .unwrap();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);

        // No IPv6 address on the tunnel: refused locally.
        let e = t
            .connect_tcp("[fd00::1]:7".parse().unwrap())
            .await
            .err()
            .unwrap();
        assert_eq!(e.kind(), io::ErrorKind::AddrNotAvailable);

        // UDP echo.
        let u = t.connect_udp("10.9.0.1:9".parse().unwrap()).unwrap();
        u.send(b"hello udp").unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), u.recv_with(|d| d.to_vec()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, b"hello udp");

        // Sockets are released.
        drop((s, s2, u));
        tokio::time::sleep(Duration::from_millis(500)).await;
        let st = t.stack.lock();
        assert!(st.sockets.iter().count() <= 1, "lingering sockets");
    }

    async fn echo_once(t: &Arc<WgTunnel>) -> WgTcpStream {
        let mut s = tokio::time::timeout(
            Duration::from_secs(10),
            t.connect_tcp("10.9.0.1:7".parse().unwrap()),
        )
        .await
        .expect("connect timed out")
        .unwrap();
        s.write_all(b"hi").await.unwrap();
        let mut b = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut b))
            .await
            .unwrap()
            .unwrap();
        s
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn roaming_is_not_down() {
        let (csk, cpk) = keypair(3);
        let peer = start_peer(cpk).await;
        let t = WgTunnel::start(&client_cfg(&peer, csk), Arc::new(NullPlatform)).unwrap();
        let s = echo_once(&t).await;
        // A network change: nothing may count the tunnel down meanwhile.
        let watch = {
            let t = t.clone();
            tokio::spawn(async move {
                let until = Instant::now() + Duration::from_millis(300);
                while Instant::now() < until {
                    assert!(!t.is_down(), "down while roaming");
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
        };
        t.roam();
        drop(echo_once(&t).await);
        watch.await.unwrap();
        // The state while the socket is being re-created (a slow endpoint
        // lookup) with a valid session: up, not down.
        let old = t.net.lock().sock.take();
        assert!(!t.is_down());
        assert_eq!(t.status().state, "up");
        // Only a failed attempt to re-create it makes the tunnel down.
        t.net.lock().open_failed = true;
        assert!(t.is_down());
        let mut net = t.net.lock();
        net.open_failed = false;
        net.sock = old;
        drop(net);
        drop(s);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replaced_tunnel_closes_its_last_connection() {
        let (csk, cpk) = keypair(3);
        let peer = start_peer(cpk).await;
        let t = WgTunnel::start(&client_cfg(&peer, csk), Arc::new(NullPlatform)).unwrap();
        let s = echo_once(&t).await;
        let fins = peer.fins.load(Relaxed);
        // The dialer lets go of the tunnel (config change); the connection
        // keeps it alive until it ends.
        drop(t);
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(s);
        for _ in 0..80 {
            if peer.fins.load(Relaxed) > fins {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the peer never saw the FIN of the replaced tunnel's last connection");
    }

    /// Lock contention benchmark (run with `cargo test --release -- --ignored
    /// wg_bench --nocapture`): a bulk echo on some tunnelled streams while
    /// small round trips on another are timed. The in-process test peer is
    /// single-threaded and caps the bulk rate; the round-trip latencies
    /// show how long streams wait behind the driver.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn wg_bench_latency_under_load() {
        const BULK: usize = 64 << 20;
        const BULK_STREAMS: usize = 3;
        let (csk, cpk) = keypair(3);
        let peer = start_peer(cpk).await;
        let t = WgTunnel::start(&client_cfg(&peer, csk), Arc::new(NullPlatform)).unwrap();
        let dst: SocketAddr = "10.9.0.1:7".parse().unwrap();
        // The test peer listens with one socket at a time: connect in turn.
        let mut probe = t.connect_tcp(dst).await.unwrap();
        let mut streams = Vec::new();
        for _ in 0..BULK_STREAMS {
            streams.push(t.connect_tcp(dst).await.unwrap());
        }
        let started = Instant::now();
        let mut bulk = Vec::new();
        for s in streams {
            bulk.push(tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(s);
                let writer = tokio::spawn(async move {
                    let chunk = vec![7u8; 16 * 1024];
                    let mut sent = 0;
                    while sent < BULK {
                        w.write_all(&chunk).await.unwrap();
                        sent += chunk.len();
                    }
                    w
                });
                let mut b = vec![0u8; 64 * 1024];
                let mut got = 0;
                while got < BULK {
                    let n = r.read(&mut b).await.unwrap();
                    assert!(n > 0);
                    got += n;
                }
                writer.await.unwrap();
            }));
        }
        let mut rtts = Vec::new();
        let mut b = [0u8; 64];
        while bulk.iter().any(|h| !h.is_finished()) {
            let t0 = Instant::now();
            probe.write_all(&[1u8; 64]).await.unwrap();
            probe.read_exact(&mut b).await.unwrap();
            rtts.push(t0.elapsed());
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let elapsed = started.elapsed();
        for h in bulk {
            h.await.unwrap();
        }
        rtts.sort();
        let pct = |p: usize| rtts[(rtts.len() * p / 100).min(rtts.len() - 1)];
        let mb = (BULK * BULK_STREAMS) as f64 / 1e6;
        eprintln!(
            "wg_bench: {mb:.0} MB echoed in {elapsed:.2?} ({:.1} MB/s); probe RTT p50 {:.2?} p90 {:.2?} p99 {:.2?} max {:.2?} ({} samples)",
            mb / elapsed.as_secs_f64(),
            pct(50),
            pct(90),
            pct(99),
            rtts[rtts.len() - 1],
            rtts.len()
        );
    }

    #[tokio::test]
    async fn dead_peer_marks_the_tunnel_down() {
        let (csk, _) = keypair(3);
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = Peer {
            addr: dead.local_addr().unwrap(),
            public: b64(&keypair(9).1),
            fins: Default::default(),
        };
        let t = WgTunnel::start(&client_cfg(&peer, csk), Arc::new(NullPlatform)).unwrap();
        let connect = t.connect_tcp("10.9.0.1:7".parse().unwrap());
        assert!(tokio::time::timeout(Duration::from_millis(1500), connect)
            .await
            .is_err());
        assert!(!t.is_down(), "not down before DOWN_AFTER");
        // The attempt sent a handshake initiation to the dead peer.
        let mut b = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(2), dead.recv(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 148);
        assert_eq!(b[0], 1);
        let epoch = t.health_epoch();
        t.noise.lock().hs.pending_since = Some(Instant::now() - DOWN_AFTER);
        assert!(t.is_down());
        assert_eq!(t.status().state, "down");
        // The driver notices within a tick: pooled connections are renewed.
        for _ in 0..40 {
            if t.health_epoch() != epoch {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_ne!(t.health_epoch(), epoch);
        // Everything inside the tunnel is routed there; AllowedIPs narrows it.
        assert!(t.routes("8.8.8.8".parse().unwrap()));
    }
}
