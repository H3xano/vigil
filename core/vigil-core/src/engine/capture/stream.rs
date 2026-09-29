//! PCAP-over-IP: a TCP server that streams captured packets as a classic
//! PCAP file to up to [`MAX_CLIENTS`] clients (Wireshark's PCAP-over-IP
//! interface, or `nc host port | wireshark -k -i -`).
//!
//! The sockets are the app's own; on Android the app is excluded from its
//! VPN, so they use the Wi-Fi network directly, like any local server.
//! A client that does not keep up loses packets (counted), never slowing
//! the packet path: each client has a bounded queue that the packet path
//! only ever `try_send`s into, and a client whose socket stalls for
//! [`WRITE_TIMEOUT`] is dropped.
//!
//! Connections from the device itself (loopback, or one of its own
//! addresses) come from some app on the phone, and any app with INTERNET
//! could otherwise read every app's packets. They are accepted only if
//! [`Platform::local_stream_client_allowed`] approves the UID owning the
//! connecting socket: on Android the shell (`adb forward`) or root.

use super::pcap::pcap_global_header;
use crate::config::capture::StreamConfig;
use crate::config::upstream::Cidr;
use crate::platform::Platform;
use bytes::Bytes;
use parking_lot::Mutex;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// Clients served at once; further connections are closed at once.
pub const MAX_CLIENTS: usize = 2;
/// Packets queued per client.
const CLIENT_QUEUE: usize = 8192;
/// Bytes queued per client.
const CLIENT_QUEUE_BYTES: usize = 8 * 1024 * 1024;
/// Delay before retrying a failed bind (e.g. the Wi-Fi address is gone).
const REBIND_DELAY: Duration = Duration::from_secs(5);
/// A client whose socket accepts nothing for this long is disconnected, so
/// a stalled client does not hold its slot forever.
const WRITE_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_secs(2)
} else {
    Duration::from_secs(10)
};

struct Client {
    id: u64,
    tx: mpsc::Sender<Bytes>,
    queued: Arc<AtomicUsize>,
    task: tokio::task::AbortHandle,
}

/// `stats.capture.stream` (see docs/EVENTS.md).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct StreamStats {
    /// `address:port` while listening, else null.
    pub listening: Option<String>,
    pub clients: u64,
    /// Packets queued for clients (summed over clients).
    pub sent: u64,
    /// Packets not sent to a slow client (its queue was full).
    pub dropped: u64,
    /// Connections refused (not on the allowlist, an app on the device
    /// other than the shell or root, or too many clients).
    pub rejected: u64,
    /// Why the server is not listening (bind failure, no address).
    pub error: Option<String>,
}

#[derive(Default)]
struct Server {
    config: Option<(StreamConfig, u32)>,
    task: Option<tokio::task::AbortHandle>,
}

/// Connected clients and the server task.
#[derive(Default)]
pub(crate) struct Hub {
    clients: Mutex<Vec<Client>>,
    count: AtomicUsize,
    next_id: AtomicU64,
    sent: AtomicU64,
    dropped: AtomicU64,
    rejected: AtomicU64,
    server: Mutex<Server>,
    status: Mutex<(Option<String>, Option<String>)>,
}

impl Hub {
    /// Whether any client is connected (cheap; checked per packet).
    #[inline]
    pub fn has_clients(&self) -> bool {
        self.count.load(Relaxed) != 0
    }

    /// Queues one PCAP record for every client; slow clients lose it.
    pub fn send(&self, record: Bytes) {
        let clients = self.clients.lock();
        for c in clients.iter() {
            let len = record.len();
            if c.queued.load(Relaxed) + len > CLIENT_QUEUE_BYTES
                || c.tx.try_send(record.clone()).is_err()
            {
                self.dropped.fetch_add(1, Relaxed);
            } else {
                c.queued.fetch_add(len, Relaxed);
                self.sent.fetch_add(1, Relaxed);
            }
        }
    }

    fn remove(&self, id: u64) {
        let mut clients = self.clients.lock();
        clients.retain(|c| c.id != id);
        self.count.store(clients.len(), Relaxed);
    }

    fn disconnect_all(&self) {
        let mut clients = self.clients.lock();
        for c in clients.drain(..) {
            c.task.abort();
        }
        self.count.store(0, Relaxed);
    }

    pub fn stats(&self) -> StreamStats {
        let (listening, error) = self.status.lock().clone();
        StreamStats {
            listening,
            clients: self.count.load(Relaxed) as u64,
            sent: self.sent.load(Relaxed),
            dropped: self.dropped.load(Relaxed),
            rejected: self.rejected.load(Relaxed),
            error,
        }
    }

    /// Starts, restarts or stops the server for `config` (None: off). Must
    /// run inside the engine's runtime when starting one. `platform`
    /// identifies clients connecting from the device itself.
    pub fn apply(
        self: &Arc<Self>,
        config: Option<(&StreamConfig, u32)>,
        platform: &Arc<dyn Platform>,
    ) {
        let mut server = self.server.lock();
        let wanted = config.map(|(c, s)| (c.clone(), s));
        if server.config == wanted {
            return;
        }
        if let Some(t) = server.task.take() {
            t.abort();
        }
        self.disconnect_all();
        *self.status.lock() = (None, None);
        server.config = wanted.clone();
        let Some((cfg, snaplen)) = wanted else {
            return;
        };
        let Some(ip) = cfg.bind_addr() else {
            *self.status.lock() = (None, Some("no address to listen on".into()));
            return;
        };
        if tokio::runtime::Handle::try_current().is_err() {
            *self.status.lock() = (None, Some("engine not running".into()));
            return;
        }
        let hub = self.clone();
        let addr = SocketAddr::new(ip, cfg.port);
        let allow = cfg.allowlist();
        let platform = platform.clone();
        server.task = Some(tokio::spawn(serve(hub, addr, allow, snaplen, platform)).abort_handle());
    }

    /// Stops the server and disconnects every client.
    pub fn stop(&self) {
        let mut server = self.server.lock();
        if let Some(t) = server.task.take() {
            t.abort();
        }
        server.config = None;
        self.disconnect_all();
        *self.status.lock() = (None, None);
    }
}

fn bind(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let domain = socket2::Domain::for_address(addr);
    let s = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    s.set_reuse_address(true)?;
    if addr.is_ipv6() {
        // "::" also accepts IPv4 clients.
        let _ = s.set_only_v6(false);
    }
    s.bind(&addr.into())?;
    s.listen(4)?;
    s.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(s.into())
}

fn allowed(allow: &[Cidr], ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    allow.is_empty() || allow.iter().any(|c| c.contains(ip))
}

/// Whether `peer` is the device itself: loopback, the address it connected
/// to (the kernel picks the destination as source for local connections),
/// or any other address of one of the device's interfaces.
fn is_local_peer(peer: IpAddr, local: IpAddr) -> bool {
    let peer = peer.to_canonical();
    peer.is_loopback() || peer == local.to_canonical() || interface_addrs().contains(&peer)
}

/// Addresses of the device's network interfaces (empty if unavailable).
fn interface_addrs() -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list freed by freeifaddrs; the
    // entries are only read while the list is alive.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            let a = (*cur).ifa_addr;
            if !a.is_null() {
                match (*a).sa_family as libc::c_int {
                    libc::AF_INET => {
                        let sin = &*(a as *const libc::sockaddr_in);
                        out.push(IpAddr::from(
                            u32::from_be(sin.sin_addr.s_addr).to_be_bytes(),
                        ));
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(a as *const libc::sockaddr_in6);
                        out.push(IpAddr::from(sin6.sin6_addr.s6_addr).to_canonical());
                    }
                    _ => {}
                }
            }
            cur = (*cur).ifa_next;
        }
        libc::freeifaddrs(head);
    }
    out
}

/// For a connection from the device itself: whether the app that opened it
/// may read the stream. The UID lookup (Binder IPC on Android) runs off the
/// async workers.
async fn local_client_allowed(
    platform: &Arc<dyn Platform>,
    peer: SocketAddr,
    local: SocketAddr,
) -> (bool, Option<u32>) {
    let src = SocketAddr::new(peer.ip().to_canonical(), peer.port());
    let dst = SocketAddr::new(local.ip().to_canonical(), local.port());
    let p = platform.clone();
    let uid = tokio::task::spawn_blocking(move || p.owner_uid(6, src, dst))
        .await
        .ok()
        .flatten();
    (platform.local_stream_client_allowed(uid), uid)
}

async fn serve(
    hub: Arc<Hub>,
    addr: SocketAddr,
    allow: Vec<Cidr>,
    snaplen: u32,
    platform: Arc<dyn Platform>,
) {
    let listener = loop {
        match bind(addr) {
            Ok(l) => break l,
            Err(e) => {
                log::warn!("PCAP-over-IP: cannot listen on {addr}: {e}");
                *hub.status.lock() = (None, Some(format!("listen on {addr}: {e}")));
                tokio::time::sleep(REBIND_DELAY).await;
            }
        }
    };
    let local = listener.local_addr().unwrap_or(addr);
    log::info!("PCAP-over-IP: listening on {local}");
    *hub.status.lock() = (Some(local.to_string()), None);
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                log::warn!("PCAP-over-IP accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if !allowed(&allow, peer.ip()) {
            log::info!("PCAP-over-IP: refused {peer} (not on the allowlist)");
            hub.rejected.fetch_add(1, Relaxed);
            continue;
        }
        let sock_local = sock.local_addr().unwrap_or(local);
        if is_local_peer(peer.ip(), sock_local.ip()) {
            let (ok, uid) = local_client_allowed(&platform, peer, sock_local).await;
            if !ok {
                let who = uid.map_or("unknown".to_string(), |u| u.to_string());
                log::info!("PCAP-over-IP: refused {peer} (an app on this device, uid {who})");
                hub.rejected.fetch_add(1, Relaxed);
                continue;
            }
        }
        let (tx, rx) = mpsc::channel(CLIENT_QUEUE);
        let queued = Arc::new(AtomicUsize::new(0));
        let id = hub.next_id.fetch_add(1, Relaxed);
        {
            let mut clients = hub.clients.lock();
            if clients.len() >= MAX_CLIENTS {
                drop(clients);
                log::info!("PCAP-over-IP: refused {peer} (already {MAX_CLIENTS} clients)");
                hub.rejected.fetch_add(1, Relaxed);
                continue;
            }
            // Spawned under the lock: the task's own `remove` cannot run
            // before the client is listed.
            let h = hub.clone();
            let q = queued.clone();
            let task = tokio::spawn(async move {
                if let Err(e) = client(sock, rx, &q, snaplen).await {
                    log::info!("PCAP-over-IP: client {peer}: {e}");
                }
                h.remove(id);
                log::info!("PCAP-over-IP: client {peer} disconnected");
            });
            clients.push(Client {
                id,
                tx,
                queued,
                task: task.abort_handle(),
            });
            hub.count.store(clients.len(), Relaxed);
        }
        log::info!("PCAP-over-IP: client {peer} connected");
    }
}

/// Sends the PCAP header, then queued records, until the client closes the
/// connection or the hub drops it.
async fn client(
    sock: tokio::net::TcpStream,
    mut rx: mpsc::Receiver<Bytes>,
    queued: &AtomicUsize,
    snaplen: u32,
) -> std::io::Result<()> {
    let _ = sock.set_nodelay(true);
    let (mut r, mut w) = sock.into_split();
    write(&mut w, &pcap_global_header(snaplen)).await?;
    let mut discard = [0u8; 512];
    loop {
        tokio::select! {
            rec = rx.recv() => {
                let Some(rec) = rec else { return Ok(()) };
                queued.fetch_sub(rec.len(), Relaxed);
                write(&mut w, &rec).await?;
            }
            n = r.read(&mut discard) => {
                // The client sends nothing; EOF or an error means it left.
                if n? == 0 {
                    return Ok(());
                }
            }
        }
    }
}

/// Writes `buf`, failing if the client accepts nothing for [`WRITE_TIMEOUT`].
async fn write(w: &mut tokio::net::tcp::OwnedWriteHalf, buf: &[u8]) -> std::io::Result<()> {
    match tokio::time::timeout(WRITE_TIMEOUT, w.write_all(buf)).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "write stalled, disconnecting",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::capture::pcap::pcap_record;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    fn null() -> Arc<dyn Platform> {
        Arc::new(crate::platform::NullPlatform)
    }

    /// Attributes every socket to `uid` under the default (Android) policy,
    /// recording the lookups.
    struct Owner {
        uid: Option<u32>,
        calls: Mutex<Vec<(u8, SocketAddr, SocketAddr)>>,
    }

    impl Platform for Owner {
        fn owner_uid(&self, proto: u8, src: SocketAddr, dst: SocketAddr) -> Option<u32> {
            self.calls.lock().push((proto, src, dst));
            self.uid
        }

        fn protect(&self, _fd: std::os::fd::RawFd) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn local_clients_must_be_shell_or_root() {
        for (uid, ok) in [
            (Some(10123), false),
            (None, false),
            (Some(2000), true),
            (Some(0), true),
        ] {
            let owner = Arc::new(Owner {
                uid,
                calls: Mutex::new(Vec::new()),
            });
            let platform: Arc<dyn Platform> = owner.clone();
            let hub = Arc::new(Hub::default());
            // The allowlist admits loopback; the owner check still applies.
            hub.apply(Some((&cfg(0, &["127.0.0.1"]), 1500)), &platform);
            let addr = listening(&hub).await;
            let mut s = TcpStream::connect(addr).await.unwrap();
            let me = s.local_addr().unwrap();
            let mut header = [0u8; 24];
            if ok {
                s.read_exact(&mut header).await.unwrap();
                wait_clients(&hub, 1).await;
                assert_eq!(hub.stats().rejected, 0);
            } else {
                assert_eq!(s.read(&mut header).await.unwrap(), 0, "uid {uid:?}");
                assert_eq!(hub.stats().rejected, 1);
                assert_eq!(hub.stats().clients, 0);
            }
            // Looked up as the connecting app's socket: its end, then ours.
            assert_eq!(*owner.calls.lock(), vec![(6, me, addr)]);
            hub.stop();
        }
    }

    #[test]
    fn local_peers() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(is_local_peer(ip("127.0.0.1"), ip("127.0.0.1")));
        assert!(is_local_peer(ip("::1"), ip("::")));
        assert!(is_local_peer(ip("::ffff:127.0.0.5"), ip("::")));
        assert!(is_local_peer(ip("192.0.2.7"), ip("192.0.2.7")));
        assert!(is_local_peer(ip("::ffff:192.0.2.7"), ip("192.0.2.7")));
        assert!(!is_local_peer(ip("192.0.2.8"), ip("192.0.2.7")));
        assert!(interface_addrs().contains(&ip("127.0.0.1")));
    }

    /// Fills a client that never reads until its socket stalls.
    async fn stall(hub: &Hub) {
        let rec = Bytes::from(pcap_record(1, 60_000, &vec![7u8; 60_000]));
        for _ in 0..2000 {
            hub.send(rec.clone());
            tokio::task::yield_now().await;
            if hub.stats().dropped > 0 {
                return;
            }
        }
        panic!("never stalled: {:?}", hub.stats());
    }

    #[tokio::test]
    async fn stalled_client_releases_its_slot() {
        let hub = Arc::new(Hub::default());
        hub.apply(Some((&cfg(0, &[]), 65535)), &null());
        let addr = listening(&hub).await;
        let _stalled = TcpStream::connect(addr).await.unwrap();
        wait_clients(&hub, 1).await;
        stall(&hub).await;
        for _ in 0..(WRITE_TIMEOUT.as_millis() / 10 + 300) {
            if hub.stats().clients == 0 {
                hub.stop();
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("stalled client kept: {:?}", hub.stats());
    }

    #[tokio::test]
    async fn stop_aborts_client_tasks() {
        let hub = Arc::new(Hub::default());
        hub.apply(Some((&cfg(0, &[]), 65535)), &null());
        let addr = listening(&hub).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        wait_clients(&hub, 1).await;
        // The client task is blocked in a write: dropping its queue alone
        // would not end it before the write timeout.
        stall(&hub).await;
        hub.stop();
        let drained = tokio::time::timeout(WRITE_TIMEOUT / 2, async {
            let mut buf = vec![0u8; 1 << 16];
            while s.read(&mut buf).await.unwrap_or(0) != 0 {}
        })
        .await;
        assert!(drained.is_ok(), "connection not closed by stop");
        assert_eq!(hub.stats().clients, 0);
    }

    fn cfg(port: u16, allow: &[&str]) -> StreamConfig {
        StreamConfig {
            enabled: true,
            port,
            bind: "127.0.0.1".into(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
        }
    }

    async fn listening(hub: &Hub) -> SocketAddr {
        for _ in 0..200 {
            if let Some(a) = hub.stats().listening {
                return a.parse().unwrap();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("not listening: {:?}", hub.stats());
    }

    async fn wait_clients(hub: &Hub, n: u64) {
        for _ in 0..200 {
            if hub.stats().clients == n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("clients: {:?}", hub.stats());
    }

    #[tokio::test]
    async fn streams_header_and_packets_to_clients() {
        let hub = Arc::new(Hub::default());
        hub.apply(Some((&cfg(0, &[]), 1500)), &null());
        let addr = listening(&hub).await;
        let mut a = TcpStream::connect(addr).await.unwrap();
        let mut header = [0u8; 24];
        a.read_exact(&mut header).await.unwrap();
        assert_eq!(header, pcap_global_header(1500));
        wait_clients(&hub, 1).await;
        hub.send(Bytes::from(pcap_record(5_000_000, 3, &[1, 2, 3])));
        let mut rec = [0u8; 19];
        a.read_exact(&mut rec).await.unwrap();
        assert_eq!(&rec[..], &pcap_record(5_000_000, 3, &[1, 2, 3])[..]);

        // A second client; a third is refused.
        let mut b = TcpStream::connect(addr).await.unwrap();
        b.read_exact(&mut header).await.unwrap();
        wait_clients(&hub, 2).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(c.read(&mut buf).await.unwrap(), 0, "third client closed");
        assert_eq!(hub.stats().rejected, 1);

        // A client leaving frees its slot.
        drop(a);
        wait_clients(&hub, 1).await;
        hub.send(Bytes::from(pcap_record(6_000_000, 1, &[9])));
        let mut rec = [0u8; 17];
        b.read_exact(&mut rec).await.unwrap();
        assert_eq!(rec[16], 9);

        // Turning the stream off disconnects everyone.
        hub.apply(None, &null());
        assert_eq!(b.read(&mut buf).await.unwrap(), 0);
        assert_eq!(hub.stats().listening, None);
    }

    #[tokio::test]
    async fn slow_client_loses_packets_not_the_engine() {
        let hub = Arc::new(Hub::default());
        hub.apply(Some((&cfg(0, &[]), 65535)), &null());
        let addr = listening(&hub).await;
        // Connects but never reads: its socket buffers and then its queue
        // fill up; sending never blocks and the excess is counted.
        let _slow = TcpStream::connect(addr).await.unwrap();
        wait_clients(&hub, 1).await;
        let rec = Bytes::from(pcap_record(1, 60_000, &vec![7u8; 60_000]));
        let started = std::time::Instant::now();
        for _ in 0..1000 {
            hub.send(rec.clone());
            tokio::task::yield_now().await;
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        let s = hub.stats();
        assert!(s.dropped > 0, "{s:?}");
        assert_eq!(s.sent + s.dropped, 1000);
        assert!(s.sent < 1000);
    }

    #[tokio::test]
    async fn allowlist_refuses_other_clients() {
        let hub = Arc::new(Hub::default());
        hub.apply(Some((&cfg(0, &["192.0.2.0/24"]), 65535)), &null());
        let addr = listening(&hub).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 24];
        assert_eq!(s.read(&mut buf).await.unwrap(), 0);
        assert_eq!(hub.stats().rejected, 1);
        assert_eq!(hub.stats().clients, 0);
        assert!(allowed(&[], "10.0.0.1".parse().unwrap()));
        assert!(allowed(
            &[Cidr::parse("127.0.0.1").unwrap()],
            "::ffff:127.0.0.1".parse().unwrap()
        ));
        // Re-applying the same config keeps the server (and its port).
        hub.apply(Some((&cfg(0, &["192.0.2.0/24"]), 65535)), &null());
        assert_eq!(listening(&hub).await, addr);
        hub.stop();
        assert_eq!(hub.stats().listening, None);
    }

    #[tokio::test]
    async fn no_bind_address_reports_why() {
        let hub = Arc::new(Hub::default());
        let mut c = cfg(57012, &[]);
        c.bind.clear();
        hub.apply(Some((&c, 65535)), &null());
        let s = hub.stats();
        assert_eq!(s.listening, None);
        assert!(s.error.unwrap().contains("no address"));
        // An address that is not local: bind fails, retried later.
        c.bind = "192.0.2.1".into();
        hub.apply(Some((&c, 65535)), &null());
        for _ in 0..200 {
            if hub.stats().error.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(hub.stats().error.unwrap().contains("192.0.2.1:57012"));
        hub.stop();
    }
}
