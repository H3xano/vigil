//! Host services the engine needs but cannot provide itself.

use std::net::SocketAddr;
use std::os::fd::RawFd;

pub trait Platform: Send + Sync + 'static {
    /// Linux UID owning the socket `src → dst` (`proto` is 6 or 17).
    /// On Android this is `ConnectivityManager.getConnectionOwnerUid`.
    /// May block briefly (Binder IPC); the engine calls it off the packet path.
    fn owner_uid(&self, proto: u8, src: SocketAddr, dst: SocketAddr) -> Option<u32>;

    /// Excludes an outbound socket from the tunnel, so relayed traffic
    /// doesn't loop back into it. On Android this is `VpnService.protect`.
    /// Returns false if the socket could not be protected.
    fn protect(&self, fd: RawFd) -> bool;
}

/// Platform for hosts where the tunnel cannot loop (e.g. the TUN device lives
/// in another network namespace) and no UID attribution exists.
pub struct NullPlatform;

impl Platform for NullPlatform {
    fn owner_uid(&self, _proto: u8, _src: SocketAddr, _dst: SocketAddr) -> Option<u32> {
        None
    }

    fn protect(&self, _fd: RawFd) -> bool {
        true
    }
}
