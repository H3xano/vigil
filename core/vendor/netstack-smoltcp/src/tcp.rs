use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
};

use futures::Stream;
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::Device,
    socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState},
    storage::RingBuffer,
    time::{Duration, Instant},
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Address, Ipv6Address,
        TcpPacket,
    },
};
use spin::Mutex as SpinMutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{
        mpsc::{unbounded_channel, Receiver, Sender, UnboundedReceiver, UnboundedSender},
        Notify,
    },
};
use tracing::{error, trace};

use crate::{
    device::VirtualDevice,
    packet::{AnyIpPktFrame, IpPacket},
    Runner,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TcpSocketState {
    Normal,
    Close,
    Closing,
    Closed,
}

struct TcpSocketControl {
    send_buffer: RingBuffer<'static, u8>,
    send_waker: Option<Waker>,
    recv_buffer: RingBuffer<'static, u8>,
    recv_waker: Option<Waker>,
    recv_state: TcpSocketState,
    send_state: TcpSocketState,
    // vigil patch: abort requested by the owner of the stream.
    abort: bool,
    // vigil patch: the connection ended without an orderly close (RST from
    // the peer, or a smoltcp timeout).
    reset: bool,
    // vigil patch: last state observed, to tell a reset from an orderly close.
    last_state: TcpState,
    // vigil patch: when the socket was first seen in TIME-WAIT.
    time_wait_since: Option<Instant>,
}

// vigil patch: how long a socket stays in TIME-WAIT before it is removed.
// smoltcp keeps it for 10 s with both buffers allocated, and every socket in
// the set is scanned for every packet, so short connections piled up (about
// 0.5 GB and a collapsing request rate at a few hundred connections a
// second). On a virtual link to a local app, 1 s still absorbs a
// retransmitted FIN; a later one gets a RST.
const TIME_WAIT_REAP: Duration = Duration::from_secs(1);

struct TcpSocketCreation {
    control: SharedControl,
    socket: TcpSocket<'static>,
    // vigil patch: the connection's addresses (app side, destination).
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
}

// vigil patch: removes older sockets for the 4-tuple of a new connection.
// A SYN reaches the stack only once vigil's previous connection with the
// same addresses has ended, but its socket may still be in TIME-WAIT (or
// LAST-ACK). The app may reuse the port by then (it closed second, so it
// kept no TIME-WAIT itself), and the old socket, first in the set, would
// swallow the new SYN, leaving the new connection hanging.
fn remove_stale_sockets(
    sockets: &mut HashMap<SocketHandle, SharedControl>,
    socket_set: &mut SocketSet<'static>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
) {
    let (local, remote) = (IpEndpoint::from(dst_addr), IpEndpoint::from(src_addr));
    let stale: Vec<SocketHandle> = sockets
        .keys()
        .copied()
        .filter(|h| {
            let socket = socket_set.get::<TcpSocket>(*h);
            socket.local_endpoint() == Some(local) && socket.remote_endpoint() == Some(remote)
        })
        .collect();
    for handle in stale {
        trace!("replacing a stale socket for {} <-> {}", src_addr, dst_addr);
        if let Some(control) = sockets.remove(&handle) {
            let mut control = control.lock();
            control.send_state = TcpSocketState::Closed;
            control.recv_state = TcpSocketState::Closed;
            if let Some(waker) = control.send_waker.take() {
                waker.wake();
            }
            if let Some(waker) = control.recv_waker.take() {
                waker.wake();
            }
        }
        socket_set.remove(handle);
    }
}

type SharedNotify = Arc<Notify>;
type SharedControl = Arc<SpinMutex<TcpSocketControl>>;

struct TcpListenerRunner;

impl TcpListenerRunner {
    #[allow(clippy::too_many_arguments)]
    fn create(
        device: VirtualDevice,
        iface: Interface,
        iface_ingress_tx: UnboundedSender<Vec<u8>>,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        tcp_rx: Receiver<AnyIpPktFrame>,
        stream_tx: UnboundedSender<TcpStream>,
        sockets: HashMap<SocketHandle, SharedControl>,
        tcp_recv_buffer_size: u32,
        tcp_send_buffer_size: u32,
    ) -> Runner {
        Runner::new(async move {
            let notify = Arc::new(Notify::new());
            let (socket_tx, socket_rx) = unbounded_channel::<TcpSocketCreation>();
            let res = tokio::select! {
                v = Self::handle_packet(notify.clone(), iface_ingress_tx, iface_ingress_tx_avail.clone(), tcp_rx, stream_tx, socket_tx, tcp_recv_buffer_size, tcp_send_buffer_size) => v,
                v = Self::handle_socket(notify, device, iface, iface_ingress_tx_avail, sockets, socket_rx) => v,
            };
            res?;
            trace!("VirtDevice::poll thread exited");
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_packet(
        notify: SharedNotify,
        iface_ingress_tx: UnboundedSender<Vec<u8>>,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        mut tcp_rx: Receiver<AnyIpPktFrame>,
        stream_tx: UnboundedSender<TcpStream>,
        socket_tx: UnboundedSender<TcpSocketCreation>,
        tcp_recv_buffer_size: u32,
        tcp_send_buffer_size: u32,
    ) -> std::io::Result<()> {
        while let Some(frame) = tcp_rx.recv().await {
            let packet = match IpPacket::new_checked(frame.as_slice()) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid TCP IP packet: {:?}", err,);
                    continue;
                }
            };

            // Specially handle icmp packet by TCP interface.
            if matches!(packet.protocol(), IpProtocol::Icmp | IpProtocol::Icmpv6) {
                iface_ingress_tx
                    .send(frame)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
                iface_ingress_tx_avail.store(true, Ordering::Release);
                notify.notify_one();
                continue;
            }

            let src_ip = packet.src_addr();
            let dst_ip = packet.dst_addr();
            let payload = packet.payload();

            let packet = match TcpPacket::new_checked(payload) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid TCP err: {err}, src_ip: {src_ip}, dst_ip: {dst_ip}, payload: {payload:?}");
                    continue;
                }
            };
            let src_port = packet.src_port();
            let dst_port = packet.dst_port();

            let src_addr = SocketAddr::new(src_ip, src_port);
            let dst_addr = SocketAddr::new(dst_ip, dst_port);

            // TCP first handshake packet, create a new Connection
            if packet.syn() && !packet.ack() {
                let mut socket = TcpSocket::new(
                    TcpSocketBuffer::new(vec![0u8; tcp_recv_buffer_size as usize]),
                    TcpSocketBuffer::new(vec![0u8; tcp_send_buffer_size as usize]),
                );
                socket.set_keep_alive(Some(Duration::from_secs(28)));
                // FIXME: It should follow system's setting. 7200 is Linux's default.
                socket.set_timeout(Some(Duration::from_secs(7200)));
                // NO ACK delay
                // socket.set_ack_delay(None);

                if let Err(err) = socket.listen(dst_addr) {
                    error!("listen error: {:?}", err);
                    continue;
                }

                trace!("created TCP connection for {} <-> {}", src_addr, dst_addr);

                let control = Arc::new(SpinMutex::new(TcpSocketControl {
                    send_buffer: RingBuffer::new(vec![0u8; tcp_send_buffer_size as usize]),
                    send_waker: None,
                    recv_buffer: RingBuffer::new(vec![0u8; tcp_recv_buffer_size as usize]),
                    recv_waker: None,
                    recv_state: TcpSocketState::Normal,
                    send_state: TcpSocketState::Normal,
                    abort: false,
                    reset: false,
                    last_state: TcpState::Listen,
                    time_wait_since: None,
                }));

                stream_tx
                    .send(TcpStream {
                        src_addr,
                        dst_addr,
                        notify: notify.clone(),
                        control: control.clone(),
                    })
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
                socket_tx
                    .send(TcpSocketCreation {
                        control,
                        socket,
                        src_addr,
                        dst_addr,
                    })
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
            }

            // Pipeline tcp stream packet
            iface_ingress_tx
                .send(frame)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
            iface_ingress_tx_avail.store(true, Ordering::Release);
            notify.notify_one();
        }
        Ok(())
    }

    async fn handle_socket(
        notify: SharedNotify,
        mut device: VirtualDevice,
        mut iface: Interface,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        mut sockets: HashMap<SocketHandle, SharedControl>,
        mut socket_rx: UnboundedReceiver<TcpSocketCreation>,
    ) -> std::io::Result<()> {
        let mut socket_set = SocketSet::new(vec![]);
        loop {
            while let Ok(TcpSocketCreation {
                control,
                socket,
                src_addr,
                dst_addr,
            }) = socket_rx.try_recv()
            {
                remove_stale_sockets(&mut sockets, &mut socket_set, src_addr, dst_addr);
                let handle = socket_set.add(socket);
                sockets.insert(handle, control);
            }

            let before_poll = Instant::now();
            let updated_sockets = iface.poll(before_poll, &mut device, &mut socket_set);
            if matches!(
                updated_sockets,
                smoltcp::iface::PollResult::SocketStateChanged
            ) {
                trace!("VirtDevice::poll costed {}", Instant::now() - before_poll);
            }

            // Check all the sockets' status
            let mut sockets_to_remove = Vec::new();
            let mut any_time_wait = false;

            for (socket_handle, control) in sockets.iter() {
                let socket_handle = *socket_handle;
                let socket = socket_set.get_mut::<TcpSocket>(socket_handle);
                let mut control = control.lock();

                // vigil patch: reap sockets that were in TIME-WAIT long enough.
                let reap = socket.state() == TcpState::TimeWait && {
                    any_time_wait = true;
                    let since = *control.time_wait_since.get_or_insert(before_poll);
                    before_poll - since >= TIME_WAIT_REAP
                };

                // Remove the socket only when it is in the closed state.
                if socket.state() == TcpState::Closed || reap {
                    sockets_to_remove.push(socket_handle);

                    // vigil patch: an orderly close reaches CLOSED from
                    // LAST-ACK or TIME-WAIT (or never left LISTEN); anything
                    // else is a reset by the peer or a timeout.
                    if !control.abort
                        && !matches!(
                            control.last_state,
                            TcpState::LastAck
                                | TcpState::TimeWait
                                | TcpState::Closed
                                | TcpState::Listen
                        )
                    {
                        control.reset = true;
                    }

                    control.send_state = TcpSocketState::Closed;
                    control.recv_state = TcpSocketState::Closed;

                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                    if let Some(waker) = control.recv_waker.take() {
                        waker.wake();
                    }

                    trace!("closed TCP connection");
                    continue;
                }

                // vigil patch: abort on request. smoltcp sends the RST on
                // the next poll (the socket is CLOSED with its tuple still
                // set, so poll_at is "now") and the socket is recycled then.
                if control.abort {
                    trace!("aborting TCP connection, {:?}", socket.state());
                    socket.abort();
                    control.send_state = TcpSocketState::Closed;
                    control.recv_state = TcpSocketState::Closed;
                    control.last_state = TcpState::Closed;
                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                    if let Some(waker) = control.recv_waker.take() {
                        waker.wake();
                    }
                    continue;
                }
                control.last_state = socket.state();

                // SHUT_WR — only close once the send_buffer has been fully
                // drained into the smoltcp socket.  Closing earlier transitions
                // the socket to FIN_WAIT_1, making can_send() return false, so
                // the send loop below never runs and the remaining data is lost.
                if matches!(control.send_state, TcpSocketState::Close)
                    && control.send_buffer.is_empty()
                {
                    trace!("closing TCP Write Half, {:?}", socket.state());

                    socket.close();
                    control.send_state = TcpSocketState::Closing;
                    // vigil patch: the FIN is queued, so shutdown() is done
                    // (like shutdown(2)); it used to wait for CLOSED, i.e.
                    // for the end of TIME-WAIT, holding the relay 10 s.
                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                }

                // Check if readable
                let mut wake_receiver = false;
                while socket.can_recv() && !control.recv_buffer.is_full() {
                    let result = socket.recv(|buffer| {
                        let n = control.recv_buffer.enqueue_slice(buffer);
                        (n, ())
                    });

                    match result {
                        Ok(..) => wake_receiver = true,
                        Err(err) => {
                            error!("socket recv error: {:?}, {:?}", err, socket.state());

                            // Don't know why. Abort the connection.
                            socket.abort();

                            if matches!(control.recv_state, TcpSocketState::Normal) {
                                control.recv_state = TcpSocketState::Closed;
                            }
                            wake_receiver = true;

                            // The socket will be recycled in the next poll.
                            break;
                        }
                    }
                }

                // If socket is not in ESTABLISH, FIN-WAIT-1, FIN-WAIT-2,
                // the local client have closed our receiver.
                let states = [
                    TcpState::Listen,
                    TcpState::SynReceived,
                    TcpState::Established,
                    TcpState::FinWait1,
                    TcpState::FinWait2,
                ];
                if matches!(control.recv_state, TcpSocketState::Normal)
                    && !socket.may_recv()
                    && !states.contains(&socket.state())
                {
                    trace!("closed TCP Read Half, {:?}", socket.state());

                    // Let TcpStream::poll_read returns EOF.
                    control.recv_state = TcpSocketState::Closed;
                    wake_receiver = true;
                }

                if wake_receiver && control.recv_waker.is_some() {
                    if let Some(waker) = control.recv_waker.take() {
                        waker.wake();
                    }
                }

                // Check if writable
                let mut wake_sender = false;
                while socket.can_send() && !control.send_buffer.is_empty() {
                    let result = socket.send(|buffer| {
                        let n = control.send_buffer.dequeue_slice(buffer);
                        (n, ())
                    });

                    match result {
                        Ok(..) => wake_sender = true,
                        Err(err) => {
                            error!("socket send error: {:?}, {:?}", err, socket.state());

                            // Don't know why. Abort the connection.
                            socket.abort();

                            if matches!(control.send_state, TcpSocketState::Normal) {
                                control.send_state = TcpSocketState::Closed;
                            }
                            wake_sender = true;

                            // The socket will be recycled in the next poll.
                            break;
                        }
                    }
                }

                if wake_sender && control.send_waker.is_some() {
                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                }
            }

            for socket_handle in sockets_to_remove {
                sockets.remove(&socket_handle);
                socket_set.remove(socket_handle);
            }

            // Ensure every loop iteration yields to the runtime. When egress
            // capacity is available OR when `poll_delay` returns ZERO ("re-poll
            // now"), this loop otherwise takes no `.await`, so under an active
            // flow it busy-spins. Because `handle_socket` and `handle_packet`
            // are arms of one `tokio::select!` future, a never-yielding
            // `handle_socket` never returns control to the sibling SYN-accept
            // arm: one core pins flat at 100% and new inbound connections are
            // starved (observed as connect timeouts with no SYN-ACK). A
            // cooperative `yield_now()` keeps the re-poll just as prompt while
            // letting `handle_packet` make progress. The timed-park path and the
            // 5 ms idle fallback are unchanged, so there is no missed-wake risk.
            //
            // vigil patch: yield with `yield_once` rather than tokio's
            // `yield_now`, see there.
            if iface_ingress_tx_avail.load(Ordering::Acquire) {
                yield_once().await;
            } else {
                let mut next_duration = iface
                    .poll_delay(before_poll, &socket_set)
                    .unwrap_or(Duration::from_millis(5));
                // vigil patch: wake up to reap TIME-WAIT sockets.
                if any_time_wait {
                    next_duration = next_duration.min(TIME_WAIT_REAP);
                }
                if next_duration != Duration::ZERO {
                    let _ = tokio::time::timeout(
                        tokio::time::Duration::from(next_duration),
                        notify.notified(),
                    )
                    .await;
                } else {
                    yield_once().await;
                }
            }
        }
    }
}

// vigil patch: returns to the executor once, rescheduling the task at once.
// Tokio's `yield_now` defers the task until the worker has polled its I/O
// driver and timers (an epoll_wait and several clock reads), and this loop
// yields for about every packet under load, so that turn cost more than the
// packet itself. A self-wake still lets the sibling `handle_packet` arm run
// and other tasks too (tokio polls its driver every 61 scheduler ticks).
async fn yield_once() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if yielded {
            return Poll::Ready(());
        }
        yielded = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await
}

pub struct TcpListener {
    stream_rx: UnboundedReceiver<TcpStream>,
}

impl TcpListener {
    pub(super) fn new(
        tcp_rx: Receiver<AnyIpPktFrame>,
        stack_tx: Sender<AnyIpPktFrame>,
        mtu: usize,
        tcp_recv_buffer_size: u32,
        tcp_send_buffer_size: u32,
    ) -> std::io::Result<(Runner, Self)> {
        let (mut device, iface_ingress_tx, iface_ingress_tx_avail) =
            VirtualDevice::new(stack_tx, mtu);
        let iface = Self::create_interface(&mut device)?;

        let (stream_tx, stream_rx) = unbounded_channel();

        let runner = TcpListenerRunner::create(
            device,
            iface,
            iface_ingress_tx,
            iface_ingress_tx_avail,
            tcp_rx,
            stream_tx,
            HashMap::new(),
            tcp_recv_buffer_size,
            tcp_send_buffer_size,
        );

        Ok((runner, Self { stream_rx }))
    }

    fn create_interface<D>(device: &mut D) -> std::io::Result<Interface>
    where
        D: Device + ?Sized,
    {
        let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random();
        let mut iface = Interface::new(iface_config, device, Instant::now());
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0))
                .expect("iface IPv4");
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0))
                .expect("iface IPv6");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;
        iface.set_any_ip(true);
        Ok(iface)
    }
}

impl Stream for TcpListener {
    type Item = (TcpStream, SocketAddr, SocketAddr);

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.stream_rx.poll_recv(cx).map(|stream| {
            stream.map(|stream| {
                let local_addr = *stream.local_addr();
                let remote_addr: SocketAddr = *stream.remote_addr();
                (stream, local_addr, remote_addr)
            })
        })
    }
}

pub struct TcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    notify: SharedNotify,
    control: SharedControl,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut control = self.control.lock();

        if matches!(control.recv_state, TcpSocketState::Normal) {
            control.recv_state = TcpSocketState::Close;
        }

        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }

        self.notify.notify_one();
    }
}

impl TcpStream {
    pub fn local_addr(&self) -> &SocketAddr {
        &self.src_addr
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.dst_addr
    }

    // vigil patch.
    /// Aborts the connection: buffered data is discarded and a RST is sent
    /// to the peer. Subsequent reads return EOF and writes fail.
    pub fn abort(&self) {
        self.abort_handle().abort();
    }

    // vigil patch.
    /// A handle that can abort the connection after the stream has been
    /// split or moved.
    pub fn abort_handle(&self) -> TcpAbortHandle {
        TcpAbortHandle {
            notify: self.notify.clone(),
            control: self.control.clone(),
        }
    }
}

// vigil patch.
/// Aborts a [`TcpStream`]'s connection from anywhere; see [`TcpStream::abort`].
#[derive(Clone)]
pub struct TcpAbortHandle {
    notify: SharedNotify,
    control: SharedControl,
}

impl TcpAbortHandle {
    pub fn abort(&self) {
        let mut control = self.control.lock();
        if matches!(control.recv_state, TcpSocketState::Closed)
            && matches!(control.send_state, TcpSocketState::Closed)
        {
            return; // already gone
        }
        control.abort = true;
        drop(control);
        self.notify.notify_one();
    }

    /// Whether the connection ended without an orderly close (the peer
    /// reset it or it timed out).
    pub fn is_reset(&self) -> bool {
        self.control.lock().reset
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut control = self.control.lock();

        // Read from buffer
        if control.recv_buffer.is_empty() {
            // If socket is already closed / half closed, just return EOF directly.
            if matches!(control.recv_state, TcpSocketState::Closed) {
                // vigil patch: report a reset as such, not as EOF.
                if control.reset {
                    return Err(std::io::ErrorKind::ConnectionReset.into()).into();
                }
                return Ok(()).into();
            }

            // Nothing could be read. Wait for notify.
            if let Some(old_waker) = control.recv_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
        }

        let recv_buf = buf.initialize_unfilled();
        let n = control.recv_buffer.dequeue_slice(recv_buf);
        buf.advance(n);

        if n > 0 {
            self.notify.notify_one();
        }

        Ok(()).into()
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut control = self.control.lock();

        // If state == Close | Closing | Closed, the TCP stream WR half is closed.
        if !matches!(control.send_state, TcpSocketState::Normal) {
            // vigil patch: distinguish a reset peer from a closed stream.
            let kind = if control.reset {
                std::io::ErrorKind::ConnectionReset
            } else {
                std::io::ErrorKind::BrokenPipe
            };
            return Err(kind.into()).into();
        }

        // Write to buffer

        if control.send_buffer.is_full() {
            if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
        }

        let n = control.send_buffer.enqueue_slice(buf);

        if n > 0 {
            self.notify.notify_one();
        }

        Ok(n).into()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Ok(()).into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut control = self.control.lock();

        // vigil patch: done once the FIN is queued (Closing), not only at CLOSED.
        if matches!(
            control.send_state,
            TcpSocketState::Closing | TcpSocketState::Closed
        ) {
            return Ok(()).into();
        }

        // SHUT_WR
        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }

        if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
            if !old_waker.will_wake(cx.waker()) {
                old_waker.wake();
            }
        }

        self.notify.notify_one();

        Poll::Pending
    }
}
