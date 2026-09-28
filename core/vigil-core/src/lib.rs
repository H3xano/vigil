//! vigil-core: the packet-processing engine of the vigil on-device network
//! inspector.
//!
//! The host (the Android app, or `vigil-cli` on Linux) creates a TUN
//! interface and hands its file descriptor to [`engine::Engine`], which
//! terminates every TCP and UDP flow in user space, attributes it to an app,
//! extracts the destination name (DNS, TLS SNI, QUIC SNI, HTTP Host),
//! applies the blocking policy, relays the traffic over ordinary sockets and
//! streams structured [`event::Event`]s back to the host.

pub mod asn;
pub mod config;
pub mod detect;
pub mod dnscache;
pub mod engine;
pub mod event;
pub mod intel;
pub mod packet;
pub mod platform;
pub mod policy;
pub mod proto;
pub mod tun;

pub use config::Config;
pub use engine::{Engine, FeedSummary};
pub use event::{Event, EventQueue};
pub use platform::{NullPlatform, Platform};
pub use policy::FeedCategory;
