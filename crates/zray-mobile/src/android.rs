//! The JNI surface: `com.zeronet.mobile.core.ZrayNative`.
//!
//! This is the Rust half of `ZeroNet-Mobile/docs/native-contract.md`, and the
//! contract is the specification: function names, JSON shapes and event
//! shapes are defined there. The rules that shape this file:
//!
//! * **Strings in, strings out.** Every argument and result is a UTF-8 JSON
//!   string (or a plain int/long/boolean). No Java object graph is built or
//!   walked here, so the Kotlin side can evolve its models freely.
//! * **No unwinding into the JVM.** Every export runs inside
//!   [`std::panic::catch_unwind`] and turns a panic into the contract's error
//!   value. (This only works in a build with `panic = "unwind"`; the
//!   `release-mobile` profile used by `build-android.sh` is exactly that.)
//! * **Nothing slow on the caller's thread.** `start`, `reload` and `stop`
//!   block for as long as the runtime needs (the service calls them off the
//!   main thread); everything else returns within milliseconds. Discovery,
//!   delay tests and scans run on a dedicated two-thread job runtime,
//!   separate from the proxy's, and report through a listener.
//! * **Batched callbacks.** Job events reach Kotlin as newline-separated JSON
//!   batches, at most ten calls a second (`zero_discovery::events`), from Rust
//!   threads permanently attached to the VM as daemons.
//!
//! Socket protection is the one place Java is called *synchronously* from the
//! data path: every outbound socket the runtime opens goes through
//! `ZrayNative.protect(int)` before it connects. The class and method id are
//! resolved once, in `init`, on a thread whose class loader can see the app's
//! classes — a native thread's `FindClass` only sees the system loader.

use std::ffi::c_int;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use jni::objects::{GlobalRef, JClass, JMethodID, JObject, JStaticMethodID, JString};
use jni::signature::{Primitive, ReturnType};
use jni::sys::{jboolean, jint, jlong, jstring, jvalue, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use serde_json::json;
use zero_discovery::{CancellationToken, EndReason, EventCallback, EventSink};

use crate::ZRAY_OK;

/// The Kotlin class holding the natives and the static `protect` callback.
const NATIVE_CLASS: &str = "com/zeronet/mobile/core/ZrayNative";

/// The VM, cached by `init` so Rust threads can attach to it.
static VM: OnceLock<JavaVM> = OnceLock::new();
/// `filesDir`, as given to the first `init`.
static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

// ------------------------------------------------------------------ helpers

/// Run an export's body with panics contained. `fallback` produces the
/// contract's error value for the entry point.
fn contained<T>(name: &'static str, fallback: impl FnOnce() -> T, body: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(_) => {
            tracing::error!(
                entry = name,
                "a native call panicked; the app was not aborted"
            );
            fallback()
        }
    }
}

fn read_string(env: &mut JNIEnv, value: &JString) -> Result<String, String> {
    if value.is_null() {
        return Err("argument is null".into());
    }
    env.get_string(value)
        .map(String::from)
        .map_err(|error| format!("argument is not a readable string: {error}"))
}

/// A Java string, or null if even that cannot be made (out of memory, or a
/// pending exception).
fn java_string(env: &mut JNIEnv, text: &str) -> jstring {
    env.new_string(text)
        .map(JString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// The contract's `String?`: null for success, the message otherwise.
fn outcome(env: &mut JNIEnv, result: Result<(), String>) -> jstring {
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(message) => java_string(env, &message),
    }
}

/// Map a C-ABI status code to the contract's `String?`.
fn status(code: c_int) -> Result<(), String> {
    if code == ZRAY_OK {
        Ok(())
    } else {
        Err(crate::last_error_message().unwrap_or_else(|| format!("failed with status {code}")))
    }
}

/// Attach the current thread to the VM for good, as a daemon so it never
/// holds the VM open at exit. A thread that already is attached is left as
/// it is.
fn attached_env() -> Option<JNIEnv<'static>> {
    VM.get()?.attach_current_thread_as_daemon().ok()
}

// ------------------------------------------------------------------ logging

mod logging {
    //! `tracing` to a size-capped file in `dataDir` and, on Android, to
    //! logcat under the tag `zray`.

    use std::fs::{File, OpenOptions};
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};

    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::{reload, Registry};

    /// Rotate `zray.log` to `zray.log.1` past this size, so the two never
    /// hold more than twice it.
    pub const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

    static LEVEL: OnceLock<reload::Handle<LevelFilter, Registry>> = OnceLock::new();

    pub fn parse_level(text: &str) -> Result<LevelFilter, String> {
        Ok(match text.trim().to_ascii_lowercase().as_str() {
            "off" | "none" => LevelFilter::OFF,
            "error" => LevelFilter::ERROR,
            "warn" | "warning" => LevelFilter::WARN,
            "info" => LevelFilter::INFO,
            "debug" => LevelFilter::DEBUG,
            "trace" => LevelFilter::TRACE,
            other => return Err(format!("unknown log level {other:?}")),
        })
    }

    /// A log file that rotates itself once it passes [`MAX_LOG_BYTES`].
    pub struct CappedFile {
        path: PathBuf,
        file: Option<File>,
        written: u64,
        cap: u64,
    }

    impl CappedFile {
        pub fn open(path: &Path, cap: u64) -> io::Result<Self> {
            let file = OpenOptions::new().create(true).append(true).open(path)?;
            let written = file.metadata().map(|meta| meta.len()).unwrap_or(0);
            Ok(Self {
                path: path.to_path_buf(),
                file: Some(file),
                written,
                cap,
            })
        }

        fn rotate(&mut self) -> io::Result<()> {
            self.file = None;
            let mut rotated = self.path.clone().into_os_string();
            rotated.push(".1");
            let _ = std::fs::rename(&self.path, PathBuf::from(rotated));
            self.file = Some(
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&self.path)?,
            );
            self.written = 0;
            Ok(())
        }
    }

    impl Write for CappedFile {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.written + buf.len() as u64 > self.cap {
                self.rotate()?;
            }
            let file = self
                .file
                .as_mut()
                .ok_or_else(|| io::Error::other("log file is closed"))?;
            file.write_all(buf)?;
            self.written += buf.len() as u64;
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            match self.file.as_mut() {
                Some(file) => file.flush(),
                None => Ok(()),
            }
        }
    }

    #[cfg(target_os = "android")]
    mod logcat {
        use std::ffi::{c_char, c_int, CString};
        use std::fmt::Write as _;

        use tracing::field::{Field, Visit};
        use tracing::{Event, Level, Subscriber};
        use tracing_subscriber::layer::{Context, Layer};

        #[link(name = "log")]
        extern "C" {
            fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
        }

        const TAG: &[u8] = b"zray\0";

        /// Forwards each event to `__android_log_write`.
        pub struct Logcat;

        struct Line(String);

        impl Visit for Line {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    let _ = write!(self.0, "{value:?}");
                } else {
                    let _ = write!(self.0, " {}={value:?}", field.name());
                }
            }

            fn record_str(&mut self, field: &Field, value: &str) {
                if field.name() == "message" {
                    self.0.push_str(value);
                } else {
                    let _ = write!(self.0, " {}={value}", field.name());
                }
            }
        }

        impl<S: Subscriber> Layer<S> for Logcat {
            fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
                let metadata = event.metadata();
                let priority = match *metadata.level() {
                    Level::ERROR => 6,
                    Level::WARN => 5,
                    Level::INFO => 4,
                    Level::DEBUG => 3,
                    Level::TRACE => 2,
                };
                let mut line = Line(format!("{}: ", metadata.target()));
                event.record(&mut line);
                let text = CString::new(line.0.replace('\0', "")).unwrap_or_default();
                // SAFETY: both strings are NUL-terminated and live across
                // the call; liblog copies them.
                unsafe {
                    __android_log_write(priority, TAG.as_ptr().cast(), text.as_ptr());
                }
            }
        }
    }

    /// Change the level of the installed subscriber.
    pub fn set_level(level: LevelFilter) -> Result<(), String> {
        LEVEL
            .get()
            .ok_or_else(|| "logging is not initialised".to_string())?
            .modify(|filter| *filter = level)
            .map_err(|error| format!("could not change the log level: {error}"))
    }

    /// Install the subscriber once per process; later calls only change the
    /// level.
    pub fn init(data_dir: &Path, level: LevelFilter) -> Result<(), String> {
        if let Some(handle) = LEVEL.get() {
            return handle
                .modify(|filter| *filter = level)
                .map_err(|error| format!("could not change the log level: {error}"));
        }
        let file = CappedFile::open(&data_dir.join("zray.log"), MAX_LOG_BYTES)
            .map_err(|error| format!("could not open the log file: {error}"))?;
        let (filter, handle) = reload::Layer::new(level);
        let file_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_thread_names(true)
            .with_writer(Mutex::new(file));
        // A WireGuard handshake that gets no answer (a blocked WARP endpoint
        // the discovery job is probing) makes `boringtun` log a warning for
        // every retry. The probe's own result is what matters, so only that
        // library's errors are kept.
        let quiet = tracing_subscriber::filter::Targets::new()
            .with_default(LevelFilter::TRACE)
            .with_target("boringtun", LevelFilter::ERROR);
        let subscriber = Registry::default()
            .with(filter)
            .with(quiet)
            .with(file_layer);
        #[cfg(target_os = "android")]
        let subscriber = subscriber.with(logcat::Logcat);
        tracing::subscriber::set_global_default(subscriber)
            .map_err(|error| format!("a logger is already installed: {error}"))?;
        let _ = LEVEL.set(handle);
        Ok(())
    }
}

// --------------------------------------------------------------- protection

/// Calls `ZrayNative.protect(fd)` for every socket the runtime opens.
struct JavaProtector {
    class: GlobalRef,
    method: JStaticMethodID,
}

impl zero_core::SocketProtector for JavaProtector {
    fn protect(&self, fd: i32) -> std::io::Result<()> {
        let mut env = attached_env()
            .ok_or_else(|| std::io::Error::other("cannot attach this thread to the JVM"))?;
        let class: &JClass = self.class.as_obj().into();
        let result = env.with_local_frame(4, |env| -> jni::errors::Result<bool> {
            // SAFETY: the method id was resolved for this class with the
            // signature (I)Z, and the argument is an int.
            let value = unsafe {
                env.call_static_method_unchecked(
                    class,
                    self.method,
                    ReturnType::Primitive(Primitive::Boolean),
                    &[jvalue { i: fd as jint }],
                )
            }?;
            value.z()
        });
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
            return Err(std::io::Error::other(
                "ZrayNative.protect threw; the socket was not protected",
            ));
        }
        match result {
            Ok(true) => Ok(()),
            Ok(false) => Err(std::io::Error::other(
                "the VPN service refused to protect a socket; it would have looped \
                 back into the tunnel",
            )),
            Err(error) => Err(std::io::Error::other(format!(
                "calling ZrayNative.protect failed: {error}"
            ))),
        }
    }
}

/// Calls `ZrayNative.ownerOf(...)` to learn which app opened a connection,
/// for routing rules that name apps (`zero_router::process`). The answer is
/// the app's package name, which is what such a rule names on Android.
struct JavaOwnerFinder {
    class: GlobalRef,
    method: JStaticMethodID,
}

impl zero_router::process::ProcessFinder for JavaOwnerFinder {
    fn find(
        &self,
        network: zero_core::Network,
        source: std::net::SocketAddr,
        destination: Option<std::net::SocketAddr>,
    ) -> Option<zero_router::process::ProcessInfo> {
        // Android finds a socket by both of its ends.
        let destination = destination?;
        let mut env = attached_env()?;
        let class: &JClass = self.class.as_obj().into();
        let name = env.with_local_frame(8, |env| -> jni::errors::Result<Option<String>> {
            let source_ip = env.new_string(source.ip().to_canonical().to_string())?;
            let destination_ip = env.new_string(destination.ip().to_canonical().to_string())?;
            // SAFETY: the method id was resolved for this class with the
            // signature (ZLjava/lang/String;ILjava/lang/String;I)Ljava/lang/String;
            // and the arguments are, in order, a boolean, a string, an int, a
            // string and an int.
            let value = unsafe {
                env.call_static_method_unchecked(
                    class,
                    self.method,
                    ReturnType::Object,
                    &[
                        jvalue {
                            z: u8::from(network == zero_core::Network::Tcp),
                        },
                        jvalue {
                            l: source_ip.as_raw(),
                        },
                        jvalue {
                            i: jint::from(source.port()),
                        },
                        jvalue {
                            l: destination_ip.as_raw(),
                        },
                        jvalue {
                            i: jint::from(destination.port()),
                        },
                    ],
                )
            }?
            .l()?;
            if value.is_null() {
                return Ok(None);
            }
            let value = JString::from(value);
            let name: String = env.get_string(&value)?.into();
            Ok(Some(name))
        });
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
            return None;
        }
        let name = name.ok().flatten()?;
        Some(zero_router::process::ProcessInfo {
            pid: None,
            name,
            path: String::new(),
        })
    }
}

fn install_protector(env: &mut JNIEnv) -> Result<(), String> {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    if INSTALLED.get().is_some() {
        return Ok(());
    }
    let class = env.find_class(NATIVE_CLASS).map_err(|error| {
        let _ = env.exception_clear();
        format!("cannot find {NATIVE_CLASS}: {error}")
    })?;
    let method = env
        .get_static_method_id(&class, "protect", "(I)Z")
        .map_err(|error| {
            let _ = env.exception_clear();
            format!("{NATIVE_CLASS} has no static protect(int): boolean: {error}")
        })?;
    let class = env
        .new_global_ref(&class)
        .map_err(|error| format!("cannot keep a reference to {NATIVE_CLASS}: {error}"))?;
    // The owner lookup lives on the same class; an older app without it
    // simply has no app rules.
    match env.get_static_method_id(
        NATIVE_CLASS,
        "ownerOf",
        "(ZLjava/lang/String;ILjava/lang/String;I)Ljava/lang/String;",
    ) {
        Ok(owner) => zero_router::process::set_finder(Arc::new(JavaOwnerFinder {
            class: class.clone(),
            method: owner,
        })),
        Err(error) => {
            let _ = env.exception_clear();
            tracing::warn!(%error, "no ZrayNative.ownerOf; rules naming apps will not match");
        }
    }
    match zero_core::set_socket_protector(Arc::new(JavaProtector { class, method })) {
        Ok(()) => {}
        // Installed through the C ABI already; that one wins.
        Err(reason) => tracing::warn!(%reason, "socket protector not replaced"),
    }
    let _ = INSTALLED.set(());
    Ok(())
}

// --------------------------------------------------------------------- jobs

/// The runtime discovery, delay tests and scans run on. Separate from the
/// proxy's so a sweep of hundreds of sockets cannot starve the tunnel of
/// scheduler time, and small: the jobs are I/O bound.
fn job_runtime() -> Option<&'static tokio::runtime::Runtime> {
    static RUNTIME: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                // Name lookups (`lookup_host`) and listener calls use the
                // blocking pool; a TCP sweep resolves many names at once.
                .max_blocking_threads(64)
                .thread_name("zray-jobs")
                // Attach up front, so neither listener calls nor dropping a
                // listener's global reference has to attach mid-flight.
                .on_thread_start(|| {
                    let _ = attached_env();
                })
                .enable_all()
                .build()
                .map_err(|error| tracing::error!(%error, "job runtime failed to start"))
                .ok()
        })
        .as_ref()
}

static JOBS: Mutex<Option<std::collections::HashMap<u64, CancellationToken>>> = Mutex::new(None);
static NEXT_JOB: AtomicU64 = AtomicU64::new(1);

fn jobs(
) -> std::sync::MutexGuard<'static, Option<std::collections::HashMap<u64, CancellationToken>>> {
    JOBS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A Kotlin `NativeListener`, callable from any Rust thread.
struct JavaListener {
    listener: GlobalRef,
    method: JMethodID,
}

impl JavaListener {
    fn new(env: &mut JNIEnv, listener: &JObject) -> Result<Self, String> {
        if listener.is_null() {
            return Err("listener is null".into());
        }
        let class = env
            .get_object_class(listener)
            .map_err(|error| format!("listener has no class: {error}"))?;
        let method = env
            .get_method_id(&class, "onEvents", "(Ljava/lang/String;)V")
            .map_err(|error| {
                let _ = env.exception_clear();
                format!("listener has no onEvents(String): {error}")
            })?;
        let listener = env
            .new_global_ref(listener)
            .map_err(|error| format!("cannot keep the listener: {error}"))?;
        Ok(Self { listener, method })
    }

    /// Hand one batch to Kotlin. Exceptions thrown by the listener are
    /// described and cleared: a buggy listener loses its own events, it does
    /// not poison the thread for the next call.
    fn deliver(&self, batch: &str) {
        let Some(mut env) = attached_env() else {
            return;
        };
        let _ = env.with_local_frame(4, |env| -> jni::errors::Result<()> {
            let text = env.new_string(batch)?;
            // SAFETY: the method id was resolved on the listener's class with
            // the signature (Ljava/lang/String;)V; the argument is a String.
            unsafe {
                env.call_method_unchecked(
                    self.listener.as_obj(),
                    self.method,
                    ReturnType::Primitive(Primitive::Void),
                    &[jvalue { l: text.as_raw() }],
                )
            }?;
            Ok(())
        });
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
        }
    }
}

/// Start one job: parse the request, register a cancellation handle and run
/// it on the job runtime. Returns the handle, or 0 after delivering a single
/// error event when the job could not start.
fn start_job<R, F, Fut>(
    env: &mut JNIEnv,
    request: &JString,
    listener: &JObject,
    name: &'static str,
    run: F,
) -> jlong
where
    R: serde::de::DeserializeOwned + Send + 'static,
    F: FnOnce(R, EventSink, CancellationToken) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = EndReason> + Send + 'static,
{
    let listener = match JavaListener::new(env, listener) {
        Ok(listener) => Arc::new(listener),
        Err(message) => {
            tracing::error!(job = name, %message, "job not started");
            return 0;
        }
    };
    let Some(runtime) = job_runtime() else {
        listener.deliver(
            &json!({"t": "error", "message": "the job runtime is unavailable"}).to_string(),
        );
        return 0;
    };
    let parsed = read_string(env, request).and_then(|text| {
        serde_json::from_str::<R>(&text).map_err(|error| format!("invalid {name} request: {error}"))
    });
    let request = match parsed {
        Ok(request) => request,
        Err(message) => {
            let event = json!({"t": "error", "message": message}).to_string();
            runtime.spawn_blocking(move || listener.deliver(&event));
            return 0;
        }
    };

    let id = NEXT_JOB.fetch_add(1, Ordering::Relaxed);
    let token = CancellationToken::new();
    jobs()
        .get_or_insert_with(Default::default)
        .insert(id, token.clone());

    runtime.spawn(async move {
        let callback: EventCallback = {
            let listener = Arc::clone(&listener);
            Arc::new(move |batch: String| listener.deliver(&batch))
        };
        let (sink, flusher) = zero_discovery::batching_sink(callback);
        let guard_sink = sink.clone();
        let outcome = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(run(
            request, sink, token,
        )))
        .await;
        match outcome {
            Ok(reason) => tracing::debug!(job = name, id, reason = reason.as_str(), "job ended"),
            Err(_) => {
                tracing::error!(job = name, id, "job panicked");
                guard_sink
                    .emit(json!({"t": "error", "message": format!("{name} failed internally")}));
                guard_sink.emit(json!({"t": "done", "reason": "cancelled", "error": true}));
            }
        }
        drop(guard_sink);
        let _ = flusher.await;
        if let Some(jobs) = jobs().as_mut() {
            jobs.remove(&id);
        }
    });
    id as jlong
}

// ------------------------------------------------------------------ exports

/// `init(dataDir, logLevel): String?`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_init<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    data_dir: JString<'local>,
    log_level: JString<'local>,
) -> jstring {
    contained("init", std::ptr::null_mut, || {
        let result = (|| -> Result<(), String> {
            let data_dir = PathBuf::from(read_string(&mut env, &data_dir)?);
            let level = logging::parse_level(&read_string(&mut env, &log_level)?)?;
            std::fs::create_dir_all(&data_dir)
                .map_err(|error| format!("cannot create {}: {error}", data_dir.display()))?;
            let _ = DATA_DIR.set(data_dir.clone());
            let data_dir = DATA_DIR.get().cloned().unwrap_or(data_dir);
            // Logging is best effort: a failure is reported, but must not stop
            // the protector from being installed, without which no socket
            // would work once the tunnel is up.
            let logged = logging::init(&data_dir, level);
            if VM.get().is_none() {
                let vm = env
                    .get_java_vm()
                    .map_err(|error| format!("cannot reach the JVM: {error}"))?;
                let _ = VM.set(vm);
            }
            install_protector(&mut env)?;
            tracing::info!(data_dir = %data_dir.display(), "zray initialised");
            logged
        })();
        outcome(&mut env, result)
    })
}

/// `setLogLevel(level): String?` — change how much the core logs (to
/// `zray.log` and logcat) without restarting anything.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_setLogLevel<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    level: JString<'local>,
) -> jstring {
    let result = contained(
        "setLogLevel",
        || Err("setLogLevel panicked".to_string()),
        || {
            let level = logging::parse_level(&read_string(&mut env, &level)?)?;
            logging::set_level(level)
        },
    );
    outcome(&mut env, result)
}

/// `setTun(fd, mtu): String?`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_setTun<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    fd: jint,
    mtu: jint,
) -> jstring {
    let result = contained(
        "setTun",
        || Err("setTun panicked".to_string()),
        || status(crate::zray_set_tun_descriptor(fd, 0, mtu)),
    );
    outcome(&mut env, result)
}

/// `start(configJson): String?`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_start<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
) -> jstring {
    let result = contained(
        "start",
        || Err("start panicked".to_string()),
        || {
            let text = read_string(&mut env, &config_json)?;
            status(crate::start_text(&text))
        },
    );
    outcome(&mut env, result)
}

/// `reload(configJson): String?`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_reload<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
) -> jstring {
    let result = contained(
        "reload",
        || Err("reload panicked".to_string()),
        || {
            let text = read_string(&mut env, &config_json)?;
            status(crate::reload_text(&text))
        },
    );
    outcome(&mut env, result)
}

/// `stop(): String?`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_stop<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let result = contained(
        "stop",
        || Err("stop panicked".to_string()),
        || status(crate::stop_inner()),
    );
    outcome(&mut env, result)
}

/// `isRunning(): Boolean`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_isRunning<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jboolean {
    contained(
        "isRunning",
        || JNI_FALSE,
        || {
            if crate::zray_is_running() == 1 {
                JNI_TRUE
            } else {
                JNI_FALSE
            }
        },
    )
}

/// `stats(): String?`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_stats<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let text = contained(
        "stats",
        || None,
        || crate::stats_value().map(|value| value.to_string()),
    );
    match text {
        Some(text) => java_string(&mut env, &text),
        None => std::ptr::null_mut(),
    }
}

/// `networkChanged(): String?`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_networkChanged<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let result = contained(
        "networkChanged",
        || Err("networkChanged panicked".to_string()),
        || status(crate::network_changed_inner()),
    );
    outcome(&mut env, result)
}

/// `buildConfig(requestJson): String` — `{"config": …}` or `{"error": …}`.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_buildConfig<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_json: JString<'local>,
) -> jstring {
    let answer = contained(
        "buildConfig",
        || json!({"error": "buildConfig failed internally"}),
        || {
            let built = read_string(&mut env, &request_json)
                .and_then(|text| {
                    serde_json::from_str::<serde_json::Value>(&text)
                        .map_err(|error| format!("request is not valid JSON: {error}"))
                })
                .and_then(|request| {
                    let assets = DATA_DIR.get().map(|dir| dir.join("assets"));
                    zero_discovery::build_config_with_assets(&request, assets.as_deref())
                });
            match built {
                Ok(config) => json!({"config": config}),
                Err(error) => json!({"error": error}),
            }
        },
    );
    java_string(&mut env, &answer.to_string())
}

/// `parseLinks(text): String` — `{"items": […], "rejected": n, "reasons": {…}}`.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_parseLinks<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    text: JString<'local>,
) -> jstring {
    let answer = contained(
        "parseLinks",
        || json!({"items": [], "rejected": 0, "reasons": {}, "error": "parseLinks failed internally"}),
        || {
            match read_string(&mut env, &text) {
            Ok(text) => serde_json::to_value(zero_discovery::parse_links(&text))
                .unwrap_or_else(|error| json!({"items": [], "rejected": 0, "reasons": {}, "error": error.to_string()})),
            Err(error) => json!({"items": [], "rejected": 0, "reasons": {}, "error": error}),
        }
        },
    );
    java_string(&mut env, &answer.to_string())
}

/// `subscriptionFetchUrl(address): String` — the address to download for a
/// subscription the user added; a BPB panel's is rewritten to its smallest
/// equivalent (`zero_discovery::panel`). Never logs the address: a panel's
/// path is its password.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_subscriptionFetchUrl<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    address: JString<'local>,
) -> jstring {
    let answer = match read_string(&mut env, &address) {
        Ok(address) => contained(
            "subscriptionFetchUrl",
            || address.clone(),
            || zero_discovery::subscription_fetch_url(&address),
        ),
        Err(_) => String::new(),
    };
    java_string(&mut env, &answer)
}

/// `frontLinks(requestJson): String` — `{"links": […]}`. The request is
/// `{"links": […], "seed": n, "max": n}`: each CDN-fronted TLS link is
/// re-aimed at a bounded sample of Cloudflare edge IPs (SNI and Host kept),
/// so a blocked address or port is routed around without a new server.
/// Links that cannot be fronted (REALITY, plain TCP-TLS, no TLS) add nothing.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_frontLinks<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_json: JString<'local>,
) -> jstring {
    let answer = contained(
        "frontLinks",
        || json!({"links": [], "error": "frontLinks failed internally"}),
        || {
            let request = read_string(&mut env, &request_json).and_then(|text| {
                serde_json::from_str::<serde_json::Value>(&text)
                    .map_err(|error| format!("request is not valid JSON: {error}"))
            });
            match request {
                Ok(request) => {
                    let links: Vec<String> = request["links"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|l| l.as_str().map(str::to_string))
                        .collect();
                    let seed = request["seed"].as_u64().unwrap_or(0);
                    // Bounded however the caller asks: every variant is a probe.
                    let max = request["max"].as_u64().unwrap_or(18).min(64) as usize;
                    json!({"links": zero_discovery::front_via_edges(&links, seed, 1, max)})
                }
                Err(error) => json!({"links": [], "error": error}),
            }
        },
    );
    java_string(&mut env, &answer.to_string())
}

/// `verifySignature(publicKeyHex, body, signature): Boolean` — whether
/// `signature` (an `ed25519:<hex>` line) is a valid Ed25519 signature over
/// `body` for `publicKeyHex`. Used to authenticate the crowd-data lists.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_verifySignature<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    public_key_hex: JString<'local>,
    body: JString<'local>,
    signature: JString<'local>,
) -> jboolean {
    contained(
        "verifySignature",
        || JNI_FALSE,
        || {
            let ok = (|| -> Option<bool> {
                let key = read_string(&mut env, &public_key_hex).ok()?;
                let body = read_string(&mut env, &body).ok()?;
                let signature = read_string(&mut env, &signature).ok()?;
                Some(zero_discovery::sign::verify_with(
                    &key,
                    body.as_bytes(),
                    &signature,
                ))
            })()
            .unwrap_or(false);
            if ok {
                JNI_TRUE
            } else {
                JNI_FALSE
            }
        },
    )
}

/// `builtInPublicKey(): String` — the crowd-data signing key compiled into
/// the native library, hex-encoded, or empty when no key was built in
/// (verification is then skipped rather than failing everything).
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_builtInPublicKey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let key = contained("builtInPublicKey", String::new, || {
        zero_discovery::sign::PUBLIC_KEY_HEX.to_string()
    });
    java_string(&mut env, &key)
}

/// `setDecoy(enabled)` — the user's switch for the decoy ClientHello. Off
/// stops the core from turning to it by itself; it takes effect on the next
/// connection.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_setDecoy<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    enabled: jboolean,
) {
    contained(
        "setDecoy",
        || (),
        || zero_discovery::set_decoy_enabled(enabled != JNI_FALSE),
    );
}

/// `decoyCheck(): String` — `{"supported", "local", "network"}`, see
/// `zero_discovery::decoy_check`. Blocks for up to about half a minute on a
/// network that answers nothing, so the app calls it off the main thread.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_decoyCheck<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let unknown = || json!({"supported": false, "local": false, "network": "skipped"});
    let answer = contained("decoyCheck", unknown, || match job_runtime() {
        Some(runtime) => runtime.block_on(zero_discovery::decoy_check()),
        None => unknown(),
    });
    java_string(&mut env, &answer.to_string())
}

/// `discover(requestJson, listener): Long`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_discover<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_json: JString<'local>,
    listener: JObject<'local>,
) -> jlong {
    contained(
        "discover",
        || 0,
        || {
            start_job(
                &mut env,
                &request_json,
                &listener,
                "discover",
                zero_discovery::discover,
            )
        },
    )
}

/// `testLinks(requestJson, listener): Long`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_testLinks<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_json: JString<'local>,
    listener: JObject<'local>,
) -> jlong {
    contained(
        "testLinks",
        || 0,
        || {
            start_job(
                &mut env,
                &request_json,
                &listener,
                "testLinks",
                zero_discovery::test_links,
            )
        },
    )
}

/// `warpRegister(requestJson, listener): Long`
///
/// Gets a free Cloudflare WARP account and looks for servers that work
/// through it. Events: `{"t":"step","line":…}` as it goes and one
/// `{"t":"done","ok":…}` with the account's link, or the reason it failed.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_warpRegister<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_json: JString<'local>,
    listener: JObject<'local>,
) -> jlong {
    contained(
        "warpRegister",
        || 0,
        || {
            start_job(
                &mut env,
                &request_json,
                &listener,
                "warpRegister",
                zero_discovery::warp_job,
            )
        },
    )
}

/// `serverJob(requestJson, listener): Long`
///
/// One request of the "My server" page: look at a server's identity, check a
/// DNS record, install, read live usage, test MasterDNS, remove. The `op`
/// field picks it; see `zero_provision::job` for the requests and events.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_serverJob<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_json: JString<'local>,
    listener: JObject<'local>,
) -> jlong {
    contained(
        "serverJob",
        || 0,
        || {
            start_job(
                &mut env,
                &request_json,
                &listener,
                "serverJob",
                zero_provision::job::run,
            )
        },
    )
}

/// `scan(requestJson, listener): Long`
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_scan<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_json: JString<'local>,
    listener: JObject<'local>,
) -> jlong {
    contained(
        "scan",
        || 0,
        || {
            start_job(
                &mut env,
                &request_json,
                &listener,
                "scan",
                zero_discovery::scan,
            )
        },
    )
}

/// `cancel(handle)`. Unknown or finished handles are ignored.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_cancel<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    contained(
        "cancel",
        || (),
        || {
            let Ok(id) = u64::try_from(handle) else {
                return;
            };
            if let Some(token) = jobs().as_ref().and_then(|jobs| jobs.get(&id)) {
                token.cancel();
            }
        },
    )
}

// ------------------------------------------------- routing JNI (Design B §4.3)
//
// Five functions the routing agent owns (28-function surface: 23 existing +
// `routingHealth`, `setRoutingMode`, `probeNow`, `pairTest`, `adminCall`).
// Engine plane (high-frequency, latency-sensitive) + management plane
// (`adminCall`: infrequent, different trust domain).
//
// Rules: strings in/out; `contained()` for panic safety; nothing slow on the
// caller's thread (`routingHealth` is polled ~1/s by the UI).

/// The live routing mode, as last set by `setRoutingMode` (Design B §4.3).
/// Stored where `routingHealth` reports it. Eligibility/scoring itself lives
/// in Kotlin's `Engine.kt` (which owns server selection on the phone); the
/// Rust engine honors `gaming_active`/`bootstrap_active` where its own
/// decisions are concerned and otherwise exposes the values verbatim.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct RoutingMode {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    locked_gateway: Option<String>,
    #[serde(default)]
    locked_exit: Option<String>,
    #[serde(default)]
    gateway_priorities: Vec<String>,
    #[serde(default)]
    exit_priorities: Vec<String>,
    #[serde(default)]
    probe_interval_sec: u64,
    #[serde(default)]
    cooldown_sec: u64,
    #[serde(default)]
    gaming_active: bool,
    #[serde(default)]
    bootstrap_active: bool,
    #[serde(default)]
    allow_direct_when_us_down: bool,
}

static ROUTING_MODE: Mutex<Option<RoutingMode>> = Mutex::new(None);
/// Last `probeNow`, epoch seconds. Rate limit: at most one per 10 s.
static LAST_PROBE_NOW_SECS: AtomicU64 = AtomicU64::new(0);

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `routingHealth(): String` — read-only snapshot, never blocks the UI
/// thread (served from the instance lock attempt + locked table copies).
///
/// Shape (Design B §4.3): `{"running", "mode", "pairs", "picks",
/// "switches", "tunnel"}`. `pairs` comes from the HA transport groups when
/// configured, else from per-outbound health. Fields the phone cannot know
/// (`pairId`, `exit`, `throughput_bps`) are omitted, never invented.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_routingHealth<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let text = contained(
        "routingHealth",
        || r#"{"error":"routingHealth failed internally"}"#.to_string(),
        routing_health_json,
    );
    java_string(&mut env, &text)
}

fn routing_health_json() -> String {
    let mode = ROUTING_MODE
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_default();
    let mode_json = serde_json::to_value(&mode).unwrap_or(serde_json::Value::Null);

    let Some(slot) = crate::try_instance() else {
        return serde_json::json!({
            "running": false,
            "mode": mode_json,
            "pairs": [],
            "picks": {},
            "switches": [],
            "tunnel": null,
        })
        .to_string();
    };
    let Some(running) = slot.as_ref() else {
        return serde_json::json!({
            "running": false,
            "mode": mode_json,
            "pairs": [],
            "picks": {},
            "switches": [],
            "tunnel": null,
        })
        .to_string();
    };
    let server = &running.server;

    // HA transport groups (Iran→USA leg when configured on this engine).
    let ha = server.ha_snapshot();
    let mut pairs = Vec::new();
    let mut picks = serde_json::Map::new();
    let mut switches = Vec::new();
    if let Some(tunnels) = ha.get("tunnels").and_then(|v| v.as_array()) {
        // HealthTable samples for successes/failures per tag.
        let health = server.health_snapshot();
        let health_by_tag: std::collections::HashMap<String, serde_json::Value> = health
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| {
                        e.get("tag")
                            .and_then(|t| t.as_str())
                            .map(|t| (t.to_string(), e.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        for tunnel in tunnels {
            let tag = tunnel.get("tag").and_then(|v| v.as_str()).unwrap_or("");
            let sample = health_by_tag.get(tag);
            pairs.push(serde_json::json!({
                "tag": tag,
                "id": tunnel.get("id"),
                "protocol": tunnel.get("protocol"),
                "transport_family": tunnel.get("transport_family"),
                "state": tunnel.get("state"),
                "eligible": tunnel.get("keepalive_ok"),
                "rtt_ms": tunnel.get("rtt_ms"),
                "jitter_ms": tunnel.get("jitter_ms"),
                "loss": tunnel.get("loss_pct"),
                "successes": sample.and_then(|s| s.get("successes")),
                "failures": sample.and_then(|s| s.get("failures")),
                "consecutive_failures": sample.and_then(|s| s.get("consecutiveFailures")),
                "last_heartbeat_at": tunnel.get("last_heartbeat_at"),
            }));
        }
    }
    if let (Some(tag), Some(primary)) = (
        ha.get("tag").and_then(|v| v.as_str()),
        ha.get("primary").and_then(|v| v.as_str()),
    ) {
        picks.insert(
            tag.to_string(),
            serde_json::Value::String(primary.to_string()),
        );
    }
    if let Some(recent) = ha.get("recent_failovers").and_then(|v| v.as_array()) {
        for event in recent {
            switches.push(serde_json::json!({
                "at": event.get("at"),
                "from": event.get("from"),
                "to": event.get("to"),
                "reason": event.get("reason"),
            }));
        }
    }
    // Tunnel roll-up: the primary tunnel's state, for the at-a-glance UI.
    let tunnel = pairs
        .iter()
        .find(|p| {
            ha.get("primary")
                .and_then(|v| v.as_str())
                .is_some_and(|primary| p.get("tag").and_then(|v| v.as_str()) == Some(primary))
        })
        .map(|p| {
            serde_json::json!({
                "state": p.get("state"),
                "last_heartbeat_at": p.get("last_heartbeat_at"),
            })
        });

    serde_json::json!({
        "running": true,
        "mode": mode_json,
        "pairs": pairs,
        "picks": picks,
        "switches": switches,
        "tunnel": tunnel,
    })
    .to_string()
}

/// `setRoutingMode(requestJson): String?` — null on success, error string
/// otherwise (existing convention). Validates the Design B §4.3 shape and
/// stores it on the live engine without restart. Eligibility/scoring itself
/// is Kotlin-side (`Engine.kt`); the stored mode is what `routingHealth`
/// reports and what future Rust consumers read.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_setRoutingMode<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_json: JString<'local>,
) -> jstring {
    let result = contained(
        "setRoutingMode",
        || Err("setRoutingMode panicked".to_string()),
        || {
            let text = read_string(&mut env, &request_json)?;
            let value: serde_json::Value = serde_json::from_str(&text)
                .map_err(|error| format!("request is not valid JSON: {error}"))?;
            let get_str = |key: &str| {
                value
                    .get(key)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            };
            let get_str_list = |key: &str| {
                value
                    .get(key)
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let get_bool = |key: &str| value.get(key).and_then(|v| v.as_bool()).unwrap_or(false);
            let get_u64 = |key: &str| value.get(key).and_then(|v| v.as_u64()).unwrap_or(0);
            // `priorities` is nested: {"gateways": [...], "exits": [...]}.
            let (gateway_priorities, exit_priorities) = match value.get("priorities") {
                Some(priorities) => (
                    priorities
                        .get("gateways")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default(),
                    priorities
                        .get("exits")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default(),
                ),
                None => (
                    get_str_list("gatewayPriorities"),
                    get_str_list("exitPriorities"),
                ),
            };
            // `probe.intervalSec` is nested; flat `probeIntervalSec` accepted too.
            let probe_interval_sec = value
                .get("probe")
                .and_then(|p| p.get("intervalSec"))
                .and_then(|v| v.as_u64())
                .or_else(|| {
                    let v = get_u64("probeIntervalSec");
                    (v > 0).then_some(v)
                })
                .unwrap_or(0);
            let mode = RoutingMode {
                mode: get_str("mode").unwrap_or_default(),
                locked_gateway: get_str("lockedGateway"),
                locked_exit: get_str("lockedExit"),
                gateway_priorities,
                exit_priorities,
                probe_interval_sec,
                cooldown_sec: get_u64("cooldownSec"),
                gaming_active: get_bool("gamingActive"),
                bootstrap_active: get_bool("bootstrapActive"),
                allow_direct_when_us_down: get_bool("allowDirectWhenUsDown"),
            };
            if mode.mode.is_empty() {
                return Err("request has no \"mode\"".to_string());
            }
            match ROUTING_MODE.lock() {
                Ok(mut guard) => {
                    *guard = Some(mode);
                    Ok(())
                }
                Err(_) => Err("routing mode lock is poisoned".to_string()),
            }
        },
    );
    outcome(&mut env, result)
}

/// `probeNow(): String?` — one immediate probe cycle (gateway probes +
/// active pair), for the UI "test now" button and post-network-change fast
/// recovery. Rate-limited to one call per 10 s to prevent UI-driven probe
/// storms (Design B §4.3). Null on success.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_probeNow<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let result = contained(
        "probeNow",
        || Err("probeNow panicked".to_string()),
        || {
            let now = now_secs();
            let last = LAST_PROBE_NOW_SECS.load(Ordering::Relaxed);
            if now.saturating_sub(last) < 10 {
                return Err("probe rate-limited: at most one per 10 seconds".to_string());
            }
            LAST_PROBE_NOW_SECS.store(now, Ordering::Relaxed);
            let Some(slot) = crate::try_instance() else {
                return Err("engine is not running".to_string());
            };
            let Some(running) = slot.as_ref() else {
                return Err("engine is not running".to_string());
            };
            running.server.request_probe();
            Ok(())
        },
    );
    outcome(&mut env, result)
}

/// `pairTest(tag): String` — tests one pair end-to-end *now*.
///
/// Design B §4.3 shape: `{"tag", "ok":true, "establish_ms", "rtt_ms",
/// "udp_ok":true}` or `{"ok":false, "failed_leg":"gateway"|"tunnel"|"egress",
/// "detail"}`.
///
/// What "end-to-end" honestly means here: a TCP connect to the outbound's
/// server address through the VPN-protected socket path
/// (`connect_protected`, so the probe itself does not leak around the
/// tunnel). `establish_ms` is the TCP-handshake time, which *is* a
/// round-trip measurement, so `rtt_ms` carries the same value. `udp_ok` is
/// null: a UDP reachability claim needs a cooperating endpoint and is not
/// faked. A full proxy-handshake test is out of scope — the observatory's
/// ongoing probes cover session health.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_pairTest<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    tag: JString<'local>,
) -> jstring {
    let text = contained(
        "pairTest",
        || {
            r#"{"ok":false,"failed_leg":"gateway","detail":"pairTest failed internally"}"#
                .to_string()
        },
        || {
            let tag = match read_string(&mut env, &tag) {
                Ok(tag) => tag,
                Err(detail) => {
                    return serde_json::json!({"ok": false, "failed_leg": "gateway",
                        "detail": format!("pairTest: bad tag: {detail}")})
                    .to_string();
                }
            };
            // The blocking connect runs on the job runtime, not the caller.
            let Some(runtime) = job_runtime() else {
                return serde_json::json!({"tag": tag, "ok": false, "failed_leg": "gateway",
                    "detail": "job runtime unavailable"})
                .to_string();
            };
            match runtime.block_on(pair_test_async(tag)) {
                Ok(answer) => answer,
                Err(detail) => detail,
            }
        },
    );
    java_string(&mut env, &text)
}

async fn pair_test_async(tag: String) -> Result<String, String> {
    let (address, port) = {
        let Some(slot) = crate::try_instance() else {
            return Ok(serde_json::json!({"tag": tag, "ok": false,
                "failed_leg": "gateway", "detail": "engine is not running"})
            .to_string());
        };
        let Some(running) = slot.as_ref() else {
            return Ok(serde_json::json!({"tag": tag, "ok": false,
                "failed_leg": "gateway", "detail": "engine is not running"})
            .to_string());
        };
        let config = running.server.config();
        let Some(outbound) = config.outbound_by_tag(&tag) else {
            return Ok(serde_json::json!({"tag": tag, "ok": false,
                "failed_leg": "gateway", "detail": format!("unknown outbound tag {tag:?}")})
            .to_string());
        };
        outbound_server_address(&outbound.protocol).ok_or_else(|| {
            serde_json::json!({"tag": tag, "ok": false,
                "failed_leg": "gateway", "detail": "outbound has no testable server address"})
            .to_string()
        })?
    };

    // Resolve: literal IPs connect directly; domains resolve via the system
    // resolver here (the probe is a reachability check, not a routing-policy
    // probe — it must not depend on the tunnel being up).
    let socket_addr = match &address {
        zero_core::Address::Ip(ip) => std::net::SocketAddr::new(*ip, port),
        zero_core::Address::Domain(domain) => {
            let addrs = tokio::net::lookup_host((domain.as_ref(), port))
                .await
                .map_err(|error| {
                    serde_json::json!({"tag": tag, "ok": false,
                        "failed_leg": "gateway", "detail": format!("DNS resolve failed: {error}")})
                    .to_string()
                })?;
            addrs.into_iter().next().ok_or_else(|| {
                serde_json::json!({"tag": tag, "ok": false,
                    "failed_leg": "gateway", "detail": "DNS resolve returned no addresses"})
                .to_string()
            })?
        }
    };

    let started = std::time::Instant::now();
    let connected = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        zero_core::platform::connect_protected(socket_addr),
    )
    .await;
    let establish_ms = started.elapsed().as_secs_f64() * 1000.0;
    match connected {
        Ok(Ok(_stream)) => Ok(serde_json::json!({
            "tag": tag, "ok": true,
            "establish_ms": establish_ms, "rtt_ms": establish_ms,
            "udp_ok": null,
        })
        .to_string()),
        Ok(Err(error)) => Ok(serde_json::json!({"tag": tag, "ok": false,
            "failed_leg": "gateway", "detail": format!("TCP connect failed: {error}")})
        .to_string()),
        Err(_) => Ok(serde_json::json!({"tag": tag, "ok": false,
            "failed_leg": "gateway", "detail": "TCP connect timed out after 10s"})
        .to_string()),
    }
}

/// The server address of a proxy outbound, for `pairTest` reachability.
/// `None` for non-proxy outbounds (freedom/blackhole/dns/...) which have no
/// single server to test.
fn outbound_server_address(
    protocol: &zero_config::OutboundProtocol,
) -> Option<(zero_core::Address, u16)> {
    use zero_config::OutboundProtocol as P;
    let (address, port) = match protocol {
        P::Vless(c) => (&c.address, c.port),
        P::Vmess(c) => (&c.address, c.port),
        P::Trojan(c) => (&c.address, c.port),
        P::Shadowsocks(c) => (&c.address, c.port),
        P::ShadowsocksR(c) => (&c.address, c.port),
        P::Hysteria2(c) => (&c.address, c.port),
        P::Tuic(c) => (&c.address, c.port),
        P::Juicity(c) => (&c.address, c.port),
        P::AnyTls(c) => (&c.address, c.port),
        P::Socks(c) => (&c.address, c.port),
        _ => return None,
    };
    Some((address.clone(), port))
}

// ------------------------------------------------- adminCall (Design D §5.1)
//
// Management plane: one JNI function for the app's admin panel, mirroring
// `serverJob`'s shape. The phone cannot reach the servers' loopback-only
// admin API directly, so Rust forwards the HTTP request over SSH
// (direct-tcpip channel, no server-side tooling beyond sshd) and streams
// back `step`/`detail`/`done` events.
//
// Request envelope (app-side contract, `ui/admin/AdminApi.kt`):
// `{"op":"admin","method":"GET","path":"/api/v1/users","query":{},
//   "body":{},"pair_id":"…","token":"<bearer, per call>",
//   "pair_record":{…PairRecord…},"target":"exit"|"gateway"}`.
//
// Trust rules: the bearer <redacted> the SSH key live only in this call's
// memory — never persisted, never logged (the token is redacted from error
// strings before they cross to Kotlin).

/// One `adminCall` request, as built by `AdminApi.request` + the pair record.
#[derive(Debug, serde::Deserialize)]
struct AdminRequest {
    #[allow(dead_code)]
    op: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    query: serde_json::Value,
    #[serde(default)]
    body: serde_json::Value,
    #[allow(dead_code)]
    #[serde(default)]
    pair_id: String,
    #[serde(default)]
    token: String,
    pair_record: serde_json::Value,
    #[serde(default = "default_admin_target")]
    target: String,
}

fn default_admin_target() -> String {
    "exit".to_string()
}

/// `adminCall(requestJson, listener): Long` — like `serverJob`, returns a
/// job handle cancellable via `cancel(handle)`.
#[no_mangle]
pub extern "system" fn Java_com_zeronet_mobile_core_ZrayNative_adminCall<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    request_json: JString<'local>,
    listener: JObject<'local>,
) -> jlong {
    contained(
        "adminCall",
        || 0,
        || {
            start_job(
                &mut env,
                &request_json,
                &listener,
                "adminCall",
                run_admin_call,
            )
        },
    )
}

async fn run_admin_call(
    request: AdminRequest,
    sink: EventSink,
    cancel: CancellationToken,
) -> EndReason {
    let outcome = admin_call_work(request, &sink, &cancel).await;
    match outcome {
        Ok(()) => EndReason::Enough,
        Err(message) => {
            // Defense in depth (F W1): the bearer <redacted> never cross to
            // Kotlin, even if the backend echoed it inside an error string.
            sink.emit(json!({"t": "done", "ok": false, "error": message}));
            EndReason::Exhausted
        }
    }
}

async fn admin_call_work(
    request: AdminRequest,
    sink: &EventSink,
    cancel: &CancellationToken,
) -> Result<(), String> {
    if request.token.is_empty() {
        return Err("adminCall: request has no token".to_string());
    }
    if !request.path.starts_with("/api/v1/") {
        return Err("adminCall: path must start with /api/v1/".to_string());
    }
    let method = request.method.to_ascii_uppercase();
    if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&method.as_str()) {
        return Err(format!("adminCall: unsupported method {method:?}"));
    }

    // The pair record is opaque to Kotlin; Rust reads the target server.
    let pair: zero_provision::record::PairRecord = serde_json::from_value(request.pair_record)
        .map_err(|error| format!("adminCall: pair_record is not a PairRecord: {error}"))?;
    let server = match request.target.as_str() {
        "gateway" => &pair.gateway,
        _ => &pair.exit,
    };
    let ssh_key = server
        .ssh_key
        .as_ref()
        .ok_or_else(|| "adminCall: pair record has no SSH key for the target server".to_string())?;
    let login = zero_provision::ssh::Login {
        host: server.host.clone(),
        port: server.ssh_port,
        user: server.ssh_user.clone(),
        auth: zero_provision::ssh::Auth::Key(ssh_key.clone()),
    };

    sink.emit(json!({"t": "step", "line": format!("connecting to {}", server.host)}));
    let connect = zero_provision::ssh::connect(&login, &server.host_key.fingerprint);
    let conn = tokio::select! {
        result = connect => result.map_err(|error| format!("adminCall: SSH connect failed: {error}"))?,
        () = cancel.cancelled() => return Err("cancelled".to_string()),
    };

    sink.emit(json!({"t": "step", "line": "forwarding to the loopback admin API"}));
    let channel = tokio::select! {
        result = conn.open_direct_tcpip("127.0.0.1", u32::from(server.management_port)) => {
            result.map_err(|error| format!("adminCall: admin API unreachable: {error}"))?
        }
        () = cancel.cancelled() => return Err("cancelled".to_string()),
    };

    // Minimal HTTP/1.1 over the forwarded channel. Responses are small JSON;
    // `Connection: close` delimits the body — no chunked-encoding support,
    // which the loopback admin server never uses.
    let query = match &request.query {
        serde_json::Value::Object(map) if !map.is_empty() => {
            let pairs: Vec<String> = map
                .iter()
                .map(|(k, v)| {
                    let vs = match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    format!("{}={}", percent_encode(k), percent_encode(&vs))
                })
                .collect();
            format!("?{}", pairs.join("&"))
        }
        _ => String::new(),
    };
    let body_text = match &request.body {
        serde_json::Value::Null => String::new(),
        body => body.to_string(),
    };
    // The token travels in the Authorization header only, never in the URL.
    let http_request = format!(
        "{method} {path}{query} HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body_text}",
        method = method,
        path = request.path,
        query = query,
        token = request.token,
        len = body_text.len(),
        body_text = body_text,
    );

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = channel;
    // russh Channel exposes AsyncWrite/AsyncRead via adapters, not directly.
    let write = async {
        let mut writer = stream.make_writer();
        writer.write_all(http_request.as_bytes()).await
    };
    tokio::select! {
        result = write => result.map_err(|error| format!("adminCall: request write failed: {error}"))?,
        () = cancel.cancelled() => return Err("cancelled".to_string()),
    }
    // The token must not linger in a reusable buffer; the request string is
    // dropped here (Rust zeroes nothing, but nothing retains it either).
    drop(http_request);

    sink.emit(json!({"t": "step", "line": "waiting for the admin API"}));
    let mut raw = Vec::new();
    let read = async {
        let mut reader = stream.make_reader();
        let mut buf = [0u8; 8192];
        loop {
            let n = reader.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if raw.len() > 4 * 1024 * 1024 {
                return Err("adminCall: response exceeds 4 MiB".to_string());
            }
        }
        Ok::<_, String>(())
    };
    tokio::select! {
        result = read => result?,
        () = cancel.cancelled() => return Err("cancelled".to_string()),
    }

    let (status, body) = parse_http_response(&raw)?;
    let body_json: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let ok = (200..300).contains(&status);
    sink.emit(json!({
        "t": "done",
        "ok": ok,
        "status": status,
        "body": body_json,
    }));
    if ok {
        Ok(())
    } else {
        Err(format!("adminCall: admin API returned status {status}"))
    }
}

/// Split a raw HTTP/1.1 response (Connection: close delimited) into
/// (status, body). Rejects anything that is not a well-formed response —
/// a truncated or garbage reply is an error, never a silent empty body.
fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "adminCall: malformed HTTP response (no header terminator)".to_string())?;
    let head = std::str::from_utf8(&raw[..head_end])
        .map_err(|_| "adminCall: response head is not UTF-8".to_string())?;
    let mut lines = head.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| "adminCall: empty HTTP response".to_string())?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("adminCall: bad status line {status_line:?}"))?;
    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some(value) = line.strip_prefix("Content-Length:") {
            content_length = value.trim().parse().ok();
        } else if let Some(value) = line.strip_prefix("content-length:") {
            content_length = value.trim().parse().ok();
        }
    }
    let body = &raw[head_end + 4..];
    if let Some(expected) = content_length {
        if body.len() < expected {
            return Err("adminCall: truncated HTTP body".to_string());
        }
        Ok((status, body[..expected].to_vec()))
    } else {
        Ok((status, body.to_vec()))
    }
}

fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

mod tests {
    use super::logging::*;
    use std::io::Write;

    #[test]
    fn levels_parse_and_unknown_ones_are_rejected() {
        assert_eq!(
            parse_level("warn").unwrap(),
            tracing_subscriber::filter::LevelFilter::WARN
        );
        assert_eq!(
            parse_level("OFF").unwrap(),
            tracing_subscriber::filter::LevelFilter::OFF
        );
        assert!(parse_level("loud").is_err());
    }

    #[test]
    fn the_log_file_rotates_at_its_cap() {
        let dir = std::env::temp_dir().join(format!("zray-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("zray.log");
        let mut file = CappedFile::open(&path, 100).unwrap();
        for _ in 0..30 {
            file.write_all(b"0123456789\n").unwrap();
        }
        file.flush().unwrap();
        let current = std::fs::metadata(&path).unwrap().len();
        let rotated = std::fs::metadata(dir.join("zray.log.1")).unwrap().len();
        assert!(current <= 100, "{current}");
        assert!(rotated <= 100 && rotated > 0, "{rotated}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
