//! JNI bindings for `dev.vigil.inspector.engine.VigilNative`.
//!
//! Design notes:
//! * The engine is owned by a boxed pointer passed to Kotlin as a `long`.
//! * Events flow Rust → Kotlin by *polling* (`nativePollEvents` blocks for up
//!   to a timeout and returns a JSON array), so no engine thread ever calls
//!   into the JVM on the hot path.
//! * The only upcalls are UID attribution and socket protection, made through
//!   a Kotlin `PlatformBridge` object from threads attached as daemons; each
//!   upcall runs inside a JNI local frame so references never accumulate.
//! * Every entry point catches panics: unwinding across FFI would abort the
//!   app.

use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::RawFd;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration;
use vigil_core::config::parse_feed_category;
use vigil_core::config::DeviceState;
use vigil_core::engine::capture::CaptureFilter;
use vigil_core::{Config, Engine, Platform};

struct JniPlatform {
    vm: JavaVM,
    bridge: jni::objects::GlobalRef,
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

impl JniPlatform {
    fn with_env<T>(&self, default: T, f: impl FnOnce(&mut JNIEnv) -> jni::errors::Result<T>) -> T {
        let Ok(mut env) = self.vm.attach_current_thread_as_daemon() else {
            return default;
        };
        let r = env.with_local_frame(16, |env| f(env));
        match r {
            Ok(v) => v,
            Err(e) => {
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_describe();
                    let _ = env.exception_clear();
                }
                log::warn!("platform upcall failed: {e}");
                default
            }
        }
    }
}

impl Platform for JniPlatform {
    fn owner_uid(&self, proto: u8, src: SocketAddr, dst: SocketAddr) -> Option<u32> {
        let uid = self.with_env(-1, |env| {
            let s = env.byte_array_from_slice(&ip_bytes(src.ip()))?;
            let d = env.byte_array_from_slice(&ip_bytes(dst.ip()))?;
            env.call_method(
                self.bridge.as_obj(),
                "ownerUid",
                "(I[BI[BI)I",
                &[
                    JValue::Int(proto as jint),
                    JValue::Object(&s),
                    JValue::Int(src.port() as jint),
                    JValue::Object(&d),
                    JValue::Int(dst.port() as jint),
                ],
            )?
            .i()
        });
        (uid >= 0).then_some(uid as u32)
    }

    fn protect(&self, fd: RawFd) -> bool {
        self.with_env(false, |env| {
            env.call_method(self.bridge.as_obj(), "protect", "(I)Z", &[JValue::Int(fd)])?
                .z()
        })
    }
}

fn guard<T>(default: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| {
        log::error!("panic in JNI entry point");
        default
    })
}

fn engine<'a>(handle: jlong) -> Option<&'a Engine> {
    if handle == 0 {
        None
    } else {
        // SAFETY: handles are produced by `nativeStart` and invalidated only by
        // `nativeStop`; Kotlin serialises stop against other calls.
        Some(unsafe { &*(handle as *const Engine) })
    }
}

/// The engine behind `handle` if it is still running (not shut down).
fn running<'a>(handle: jlong) -> Option<&'a Engine> {
    engine(handle).filter(|e| !e.is_shut_down())
}

fn jstr(env: &mut JNIEnv, s: &JString) -> Option<String> {
    env.get_string(s).ok().map(Into::into)
}

fn new_jstring(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn init_logging() {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("vigil-core")
            .with_max_level(log::LevelFilter::Info),
    );
}

#[no_mangle]
pub extern "system" fn Java_dev_vigil_inspector_engine_VigilNative_nativeVersion<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
) -> jstring {
    new_jstring(&mut env, env!("CARGO_PKG_VERSION"))
}

#[no_mangle]
pub extern "system" fn Java_dev_vigil_inspector_engine_VigilNative_nativeStart<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    tun_fd: jint,
    config_json: JString<'l>,
    bridge: JObject<'l>,
) -> jlong {
    init_logging();
    guard(0, || {
        let Some(json) = jstr(&mut env, &config_json) else {
            return 0;
        };
        let config = match Config::from_json(&json) {
            Ok(c) => c,
            Err(e) => {
                log::error!("invalid config: {e}");
                return 0;
            }
        };
        let (Ok(vm), Ok(bridge)) = (env.get_java_vm(), env.new_global_ref(&bridge)) else {
            return 0;
        };
        let platform = Arc::new(JniPlatform { vm, bridge });
        match Engine::start(tun_fd, config, platform) {
            Ok(engine) => Box::into_raw(Box::new(engine)) as jlong,
            Err(e) => {
                log::error!("engine start failed: {e}");
                0
            }
        }
    })
}

/// Stops the engine (TUN loop, relays, runtime) and queues a `flow_end` for
/// every open flow and a final `stopped` event, but keeps the handle valid:
/// `nativePollEvents` still drains the queue (without waiting once it is
/// empty), other calls become no-ops. `nativeStop` must still be called to
/// free the handle. Calling it again is a no-op; returns true unless the
/// handle is null.
#[no_mangle]
pub extern "system" fn Java_dev_vigil_inspector_engine_VigilNative_nativeShutdown<'l>(
    _env: JNIEnv<'l>,
    _c: JClass<'l>,
    handle: jlong,
) -> jboolean {
    guard(JNI_FALSE, || match engine(handle) {
        Some(e) => {
            e.shutdown();
            JNI_TRUE
        }
        None => JNI_FALSE,
    })
}

/// Stops the engine if still running and frees the handle.
#[no_mangle]
pub extern "system" fn Java_dev_vigil_inspector_engine_VigilNative_nativeStop<'l>(
    _env: JNIEnv<'l>,
    _c: JClass<'l>,
    handle: jlong,
) {
    guard((), || {
        if handle != 0 {
            let engine = unsafe { Box::from_raw(handle as *mut Engine) };
            engine.stop();
        }
    })
}

/// Blocks up to `timeout_ms` and returns a JSON array of events, or null if
/// none arrived.
#[no_mangle]
pub extern "system" fn Java_dev_vigil_inspector_engine_VigilNative_nativePollEvents<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    handle: jlong,
    max: jint,
    timeout_ms: jint,
) -> jstring {
    let json = guard(None, || {
        let e = engine(handle)?;
        let batch = e.events().poll(
            max.max(1) as usize,
            Duration::from_millis(timeout_ms.max(0) as u64),
        );
        if batch.is_empty() {
            None
        } else {
            serde_json::to_string(&batch).ok()
        }
    });
    match json {
        Some(j) => new_jstring(&mut env, &j),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_vigil_inspector_engine_VigilNative_nativeUpdateConfig<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    handle: jlong,
    config_json: JString<'l>,
) -> jboolean {
    guard(JNI_FALSE, || {
        let (Some(e), Some(json)) = (running(handle), jstr(&mut env, &config_json)) else {
            return JNI_FALSE;
        };
        match Config::from_json(&json).and_then(|c| e.update_config(c)) {
            Ok(()) => JNI_TRUE,
            Err(err) => {
                log::error!("config rejected: {err}");
                JNI_FALSE
            }
        }
    })
}

/// Installs the device state per-app conditions are evaluated against
/// (`{"network": "wifi"|"cellular"|"other"|"none", "screen_on": bool,
/// "foreground_uids": [..] | null}`). Open connections the new state blocks
/// are cut. Cheap: call it whenever the state changes. Returns false if the
/// JSON is invalid or the engine is not running.
#[no_mangle]
pub extern "system" fn Java_dev_vigil_inspector_engine_VigilNative_nativeSetDeviceState<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    handle: jlong,
    state_json: JString<'l>,
) -> jboolean {
    guard(JNI_FALSE, || {
        let (Some(e), Some(json)) = (running(handle), jstr(&mut env, &state_json)) else {
            return JNI_FALSE;
        };
        match DeviceState::from_json(&json) {
            Ok(state) => {
                e.set_device_state(state);
                JNI_TRUE
            }
            Err(err) => {
                log::error!("device state rejected: {err}");
                JNI_FALSE
            }
        }
    })
}

/// Loads a feed from a file. Returns a JSON summary, or null on error.
#[no_mangle]
pub extern "system" fn Java_dev_vigil_inspector_engine_VigilNative_nativeLoadFeedFile<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    handle: jlong,
    id: JString<'l>,
    category: JString<'l>,
    path: JString<'l>,
) -> jstring {
    let out = guard(None, || {
        let e = running(handle)?;
        let id = jstr(&mut env, &id)?;
        let cat = jstr(&mut env, &category)?;
        let path = jstr(&mut env, &path)?;
        // An unknown category fails the load instead of silently loading
        // the feed as another category.
        let Some(category) = parse_feed_category(&cat) else {
            log::warn!("feed {id}: unknown category {cat:?}");
            return None;
        };
        match e.load_feed_file(&id, category, std::path::Path::new(&path)) {
            Ok(summary) => serde_json::to_string(&summary).ok(),
            Err(err) => {
                log::warn!("feed {id}: {err}");
                None
            }
        }
    });
    match out {
        Some(j) => new_jstring(&mut env, &j),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_vigil_inspector_engine_VigilNative_nativeRemoveFeed<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    handle: jlong,
    id: JString<'l>,
) -> jboolean {
    guard(JNI_FALSE, || match (running(handle), jstr(&mut env, &id)) {
        (Some(e), Some(id)) if e.remove_feed(&id) => JNI_TRUE,
        _ => JNI_FALSE,
    })
}

#[no_mangle]
pub extern "system" fn Java_dev_vigil_inspector_engine_VigilNative_nativeStats<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    handle: jlong,
) -> jstring {
    let out = guard(None, || {
        running(handle).and_then(|e| serde_json::to_string(&e.stats()).ok())
    });
    match out {
        Some(j) => new_jstring(&mut env, &j),
        None => std::ptr::null_mut(),
    }
}

/// Writes the captured packets matching `filter_json` (`{"flow_ids",
/// "uids", "since_ms", "until_ms"}`, all optional) to `path` as PCAPng.
/// Returns a JSON summary `{packets, bytes, first_ts, last_ts,
/// truncated_by_ring}`, or null on error (bad handle or filter, I/O). Works
/// after `nativeShutdown` too (until `nativeStop`). Blocks for the write:
/// call from a background thread.
#[no_mangle]
pub extern "system" fn Java_dev_vigil_inspector_engine_VigilNative_nativeExportPcap<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    handle: jlong,
    filter_json: JString<'l>,
    path: JString<'l>,
) -> jstring {
    let out = guard(None, || {
        let e = engine(handle)?;
        let filter = jstr(&mut env, &filter_json)?;
        let path = jstr(&mut env, &path)?;
        let filter: CaptureFilter = match serde_json::from_str(&filter) {
            Ok(f) => f,
            Err(err) => {
                log::warn!("pcap export: bad filter: {err}");
                return None;
            }
        };
        match e.export_pcap(&filter, std::path::Path::new(&path)) {
            Ok(summary) => serde_json::to_string(&summary).ok(),
            Err(err) => {
                log::warn!("pcap export: {err}");
                None
            }
        }
    });
    match out {
        Some(j) => new_jstring(&mut env, &j),
        None => std::ptr::null_mut(),
    }
}

/// Parses a feed file without an engine (validates downloads). Returns a JSON
/// summary `{domains, ip_ranges, ja4, rejected_lines}` or null. Domains, IP
/// ranges and JA4 fingerprints are all recognised (the file's category is
/// not known here).
#[no_mangle]
pub extern "system" fn Java_dev_vigil_inspector_engine_VigilNative_nativeInspectFeedFile<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    path: JString<'l>,
) -> jstring {
    let out = guard(None, || {
        let path = jstr(&mut env, &path)?;
        let file = std::io::BufReader::new(std::fs::File::open(path).ok()?);
        let feed = vigil_core::intel::parse_feed_reader(file).ok()?;
        Some(
            serde_json::json!({
                "domains": feed.domains.len(),
                "ip_ranges": feed.ips.len(),
                "ja4": feed.ja4.len(),
                "rejected_lines": feed.rejected,
            })
            .to_string(),
        )
    });
    match out {
        Some(j) => new_jstring(&mut env, &j),
        None => std::ptr::null_mut(),
    }
}
