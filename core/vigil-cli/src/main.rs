//! vigil-cli: runs the vigil engine on Linux.
//!
//! The engine is the same one that ships in the Android app; on Linux the
//! TUN device either is created directly (`--tun`, needs CAP_NET_ADMIN) or is
//! received over a Unix socket (`--fd-socket`) from a process inside another
//! network namespace, which lets the whole data path be tested without root:
//! see `scripts/e2e-netns.sh`.

use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use vigil_core::proto::{quic, tls};
use vigil_core::{Config, Engine, Event, FeedCategory, NullPlatform};

const USAGE: &str = "\
usage:
  vigil-cli run (--tun NAME | --fd-socket PATH) [options]
      --config FILE          engine configuration (JSON; missing fields use defaults);
                             re-read on SIGHUP and applied like nativeUpdateConfig
      --feed ID:CATEGORY:FILE  load a blocklist (category: ads|tracking|malware|phishing|c2|custom)
      --upstream IP:PORT     upstream resolver (repeatable; overrides config)
      --no-stats             suppress periodic stats events
  vigil-cli parse-feed FILE   parse a blocklist and print a summary
  vigil-cli quic-probe IP:PORT SNI   send one QUIC Initial carrying SNI
  vigil-cli default-config    print the default configuration
  vigil-cli wg-keypair        print a new WireGuard key pair (base64 private, public)
";

static STOP: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

extern "C" fn on_hup(_: libc::c_int) {
    RELOAD.store(true, Ordering::SeqCst);
}

fn wg_keypair() -> io::Result<()> {
    use std::io::Read;
    let mut random = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let (private, public) = vigil_core::config::upstream::keypair_from(random);
    println!("{private} {public}");
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => run(&args[1..]),
        Some("parse-feed") => parse_feed(&args[1..]),
        Some("quic-probe") => quic_probe(&args[1..]),
        Some("wg-keypair") => wg_keypair(),
        Some("default-config") => {
            println!(
                "{}",
                serde_json::to_string_pretty(&Config::default()).unwrap()
            );
            Ok(())
        }
        _ => {
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("vigil-cli: {e}");
        std::process::exit(1);
    }
}

fn parse_category(s: &str) -> io::Result<FeedCategory> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("unknown category {s}")))
}

fn run(args: &[String]) -> io::Result<()> {
    let mut tun_name = None;
    let mut fd_socket = None;
    let mut config = Config::default();
    let mut feeds = Vec::new();
    let mut upstreams = Vec::new();
    let mut stats = true;
    let mut config_path = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || {
            it.next().cloned().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("{a} needs a value"))
            })
        };
        match a.as_str() {
            "--tun" => tun_name = Some(val()?),
            "--fd-socket" => fd_socket = Some(val()?),
            "--config" => {
                let path = val()?;
                config = read_config(&path)?;
                config_path = Some(path);
            }
            "--feed" => feeds.push(val()?),
            "--upstream" => upstreams.push(
                val()?
                    .parse::<SocketAddr>()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
            ),
            "--no-stats" => stats = false,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown option {other}\n{USAGE}"),
                ))
            }
        }
    }
    if !upstreams.is_empty() {
        config.upstream_dns = upstreams.clone();
    }
    let tun: OwnedFd = match (tun_name, fd_socket) {
        (Some(name), None) => open_tun(&name)?,
        (None, Some(path)) => receive_fd(&path)?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("need exactly one of --tun / --fd-socket\n{USAGE}"),
            ))
        }
    };
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, on_hup as *const () as libc::sighandler_t);
    }

    let engine = Engine::start(tun.as_raw_fd(), config, Arc::new(NullPlatform))?;
    drop(tun); // the engine holds its own duplicate
    for spec in feeds {
        let mut parts = spec.splitn(3, ':');
        let (Some(id), Some(cat), Some(path)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--feed wants ID:CATEGORY:FILE",
            ));
        };
        let summary =
            engine.load_feed_file(id, parse_category(cat)?, std::path::Path::new(path))?;
        eprintln!(
            "vigil-cli: feed {}",
            serde_json::to_string(&summary).unwrap()
        );
    }
    eprintln!("vigil-cli: engine running");
    let events = engine.events();
    let stdout = io::stdout();
    while !STOP.load(Ordering::SeqCst) {
        if RELOAD.swap(false, Ordering::SeqCst) {
            if let Some(path) = &config_path {
                let result = read_config(path).and_then(|mut c| {
                    if !upstreams.is_empty() {
                        c.upstream_dns = upstreams.clone();
                    }
                    engine
                        .update_config(c)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                });
                match result {
                    Ok(()) => eprintln!("vigil-cli: config reloaded"),
                    Err(e) => eprintln!("vigil-cli: config not reloaded: {e}"),
                }
            }
        }
        let batch = events.poll(256, Duration::from_millis(200));
        let mut out = stdout.lock();
        for e in batch {
            if !stats && matches!(e, Event::Stats(_)) {
                continue;
            }
            writeln!(out, "{}", serde_json::to_string(&e).unwrap())?;
        }
        out.flush()?;
    }
    eprintln!("vigil-cli: stopping");
    engine.stop();
    for e in events.poll(usize::MAX, Duration::from_millis(0)) {
        println!("{}", serde_json::to_string(&e).unwrap());
    }
    Ok(())
}

fn read_config(path: &str) -> io::Result<Config> {
    let text = std::fs::read_to_string(path)?;
    Config::from_json(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn open_tun(name: &str) -> io::Result<OwnedFd> {
    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut ifr = [0u8; 40];
    let n = name.len().min(15);
    ifr[..n].copy_from_slice(&name.as_bytes()[..n]);
    ifr[16..18].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());
    if unsafe { libc::ioctl(fd, TUNSETIFF as _, ifr.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

/// Accepts one connection on a Unix socket and receives a descriptor via
/// SCM_RIGHTS.
fn receive_fd(path: &str) -> io::Result<OwnedFd> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    eprintln!("vigil-cli: waiting for TUN descriptor on {path}");
    let (conn, _) = listener.accept()?;
    let mut data = [0u8; 16];
    let mut cmsg = [0u8; 64];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr().cast();
    msg.msg_controllen = cmsg.len() as _;
    if unsafe { libc::recvmsg(conn.as_raw_fd(), &mut msg, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let hdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if hdr.is_null() || unsafe { (*hdr).cmsg_type } != libc::SCM_RIGHTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no descriptor received",
        ));
    }
    let fd: RawFd = unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(hdr) as *const RawFd) };
    let _ = std::fs::remove_file(path);
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn parse_feed(args: &[String]) -> io::Result<()> {
    let path = args
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, USAGE))?;
    let started = std::time::Instant::now();
    let feed =
        vigil_core::intel::parse_feed_reader(io::BufReader::new(std::fs::File::open(path)?))?;
    println!(
        "{}",
        serde_json::json!({
            "domains": feed.domains.len(),
            "ip_ranges": feed.ips.len(),
            "rejected_lines": feed.rejected,
            "memory_bytes": feed.domains.memory_bytes(),
            "parse_ms": started.elapsed().as_millis() as u64,
        })
    );
    Ok(())
}

fn quic_probe(args: &[String]) -> io::Result<()> {
    let (Some(dst), Some(sni)) = (args.first(), args.get(1)) else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, USAGE));
    };
    let dst: SocketAddr = dst
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let hello = tls::build_client_hello(Some(sni), &["h3"], 0);
    let dcid: [u8; 8] =
        std::array::from_fn(|i| (std::process::id() as u8).wrapping_add(i as u8 * 31));
    let pkt = quic::seal_initial(quic::VERSION_1, &dcid, 0, &[(0, &hello)]);
    let sock = UdpSocket::bind(if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
    sock.set_read_timeout(Some(Duration::from_secs(3)))?;
    sock.send_to(&pkt, dst)?;
    let mut buf = [0u8; 2048];
    match sock.recv_from(&mut buf) {
        Ok((n, from)) => println!("reply: {n} bytes from {from}"),
        Err(e) => println!("no reply: {e}"),
    }
    Ok(())
}
