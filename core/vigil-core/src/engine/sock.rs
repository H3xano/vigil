//! Upstream sockets: creation and `protect()` off the async workers, and
//! datagram reception without a large per-socket buffer.

use crate::platform::Platform;
use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

/// Largest UDP payload.
const MAX_DATAGRAM: usize = 65_535;

thread_local! {
    /// One receive buffer per worker thread, used only inside synchronous
    /// sections (never across an `.await`).
    static RECV_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; MAX_DATAGRAM]);
}

fn protect(platform: &dyn Platform, fd: i32) -> io::Result<()> {
    if platform.protect(fd) {
        Ok(())
    } else {
        Err(io::Error::other("could not protect socket"))
    }
}

/// Runs socket setup that includes `protect()` (a JNI upcall plus netd IPC
/// on Android) on the blocking pool.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| io::Error::other(format!("socket setup: {e}")))?
}

/// A protected, not yet connected TCP socket for `dst`'s address family.
pub(crate) async fn protected_tcp(
    platform: Arc<dyn Platform>,
    dst: SocketAddr,
) -> io::Result<tokio::net::TcpSocket> {
    blocking(move || {
        let sock = if dst.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        protect(&*platform, sock.as_raw_fd())?;
        Ok(sock)
    })
    .await
}

/// Connects a protected TCP socket to `dst`.
pub(crate) async fn connect_tcp(
    platform: Arc<dyn Platform>,
    dst: SocketAddr,
) -> io::Result<tokio::net::TcpStream> {
    let stream = protected_tcp(platform, dst).await?.connect(dst).await?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// A protected UDP socket connected to `dst`.
pub(crate) async fn connect_udp(
    platform: Arc<dyn Platform>,
    dst: SocketAddr,
) -> io::Result<tokio::net::UdpSocket> {
    let sock = blocking(move || {
        let bind: SocketAddr = if dst.is_ipv4() {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let sock = std::net::UdpSocket::bind(bind)?;
        protect(&*platform, sock.as_raw_fd())?;
        sock.set_nonblocking(true)?;
        sock.connect(dst)?;
        Ok(sock)
    })
    .await?;
    tokio::net::UdpSocket::from_std(sock)
}

/// Receives one datagram and passes it to `f` without allocating a buffer
/// per socket: the data lives in a per-thread 64 KiB buffer, so datagrams
/// of any size arrive whole.
pub(crate) async fn recv_with<T>(
    sock: &tokio::net::UdpSocket,
    mut f: impl FnMut(&[u8]) -> T,
) -> io::Result<T> {
    loop {
        sock.readable().await?;
        let r = RECV_BUF.with(|b| {
            let mut b = b.borrow_mut();
            sock.try_recv(&mut b).map(|n| f(&b[..n]))
        });
        match r {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            other => return other,
        }
    }
}

/// Discards any datagrams already queued on `sock` (stale replies on a
/// reused socket).
pub(crate) fn drain(sock: &tokio::net::UdpSocket) {
    RECV_BUF.with(|b| {
        let mut b = b.borrow_mut();
        for _ in 0..64 {
            match sock.try_recv(&mut b) {
                Ok(_) => continue,
                // WouldBlock, or a queued ICMP error: either way, done.
                Err(_) => break,
            }
        }
    });
}

/// Makes the next close of `stream` send a RST instead of a FIN.
pub(crate) fn set_reset_on_close(stream: &tokio::net::TcpStream) {
    let _ = socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::NullPlatform;

    #[tokio::test]
    async fn udp_large_datagrams_arrive_whole() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock = connect_udp(Arc::new(NullPlatform), server.local_addr().unwrap())
            .await
            .unwrap();
        let client = sock.local_addr().unwrap();
        let big = vec![0xabu8; 60_000];
        server.send_to(b"stale", client).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        drain(&sock);
        server.send_to(&big, client).await.unwrap();
        let got = recv_with(&sock, |d| d.to_vec()).await.unwrap();
        assert_eq!(got.len(), big.len());
    }

    struct Refuse;
    impl Platform for Refuse {
        fn owner_uid(&self, _: u8, _: SocketAddr, _: SocketAddr) -> Option<u32> {
            None
        }
        fn protect(&self, _: i32) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn unprotectable_sockets_fail() {
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(connect_udp(Arc::new(Refuse), dst).await.is_err());
        assert!(connect_tcp(Arc::new(Refuse), dst).await.is_err());
    }
}
