//! Non-blocking packet I/O over a TUN file descriptor.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tokio::io::unix::AsyncFd;

pub struct TunDevice {
    fd: AsyncFd<OwnedFd>,
}

impl TunDevice {
    /// Takes a *duplicate* of `fd`, so the caller keeps ownership of its
    /// descriptor (Android's `ParcelFileDescriptor` closes its own).
    /// Must be called within a Tokio runtime.
    pub fn from_raw_fd_dup(fd: RawFd) -> io::Result<Self> {
        let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = unsafe { OwnedFd::from_raw_fd(dup) };
        let flags = unsafe { libc::fcntl(dup, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(dup, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd: AsyncFd::new(owned)? })
    }

    /// Reads one packet.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| {
                let n = unsafe { libc::read(inner.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Writes one packet.
    pub async fn send(&self, pkt: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
                let n = unsafe { libc::write(inner.as_raw_fd(), pkt.as_ptr().cast(), pkt.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}
