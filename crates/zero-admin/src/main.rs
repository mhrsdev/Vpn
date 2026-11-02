//! zray-admin: the ZeroNet operator management plane.
//!
//! Usage:
//!   zray-admin serve [--config /etc/zeronet-admin/config.json]
//!   zray-admin migrate [--config ...]
//!   zray-admin init-layout            # create /etc/zeronet-admin + /var/lib/zeronet-admin
//!   zray-admin set-password           # read password from stdin, store argon2id hash
//!   zray-admin unit                   # print the systemd unit
//!
//! The API binds loopback-only. Remote access is via SSH port-forward.

use std::path::PathBuf;
use zero_admin::{config::AdminConfig, provision};

fn usage() -> ! {
    eprintln!("usage: zray-admin <serve|migrate|init-layout|set-password|unit> [--config PATH]");
    std::process::exit(2);
}

fn config_path_arg() -> PathBuf {
    let mut args = std::env::args().skip(1);
    let mut path = PathBuf::from("/etc/zeronet-admin/config.json");
    while let Some(a) = args.next() {
        if a == "--config" {
            path = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
        }
    }
    path
}

/// Load the full runtime config: on-disk JSON + 0600 secret files.
fn load_config(path: &PathBuf) -> Result<AdminConfig, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let disk: zero_admin::config::OnDiskConfig =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))?;
    let dir = path
        .parent()
        .unwrap_or(std::path::Path::new("/etc/zeronet-admin"));
    let read_secret = |name: &str| {
        std::fs::read_to_string(dir.join(name))
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("read {name}: {e}"))
    };
    let usage_salt: [u8; 32] = hex::decode(&disk.usage_salt_hex)
        .map_err(|e| format!("bad usage_salt_hex: {e}"))?
        .try_into()
        .map_err(|_| "usage_salt_hex must be 64 hex chars".to_string())?;
    let db_key: [u8; 32] = std::fs::read(dir.join("db.key"))
        .map_err(|e| format!("read db.key: {e}"))?
        .try_into()
        .map_err(|_| "db.key must be 32 bytes".to_string())?;
    let engine_token = std::fs::read_to_string("/etc/zray/management.token")
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("read /etc/zray/management.token: {e}"))?;
    let collector_token = std::fs::read_to_string(dir.join("collector.token"))
        .map(|s| s.trim().to_string())
        .ok();
    Ok(AdminConfig {
        role: disk.role,
        mode: disk.mode,
        listen: disk.listen,
        sub_listen: disk.sub_listen,
        db_path: dir.join("../../var/lib/zeronet-admin/admin.db"),
        db_key,
        admin_token: zero_admin::secrets::SecretString::new(read_secret("admin.token")?),
        collector_token: collector_token.map(zero_admin::secrets::SecretString::new),
        users_dir: PathBuf::from("/etc/zray/users"),
        engine_mgmt: disk.engine_mgmt,
        engine_token: zero_admin::secrets::SecretString::new(engine_token),
        usage_salt,
        collector_target: disk.collector_target,
        poll_interval_secs: disk.poll_interval_secs,
        install_id: disk.install_id,
        exit_host: disk.exit_host,
        sub_port: disk.sub_port,
        version: env!("CARGO_PKG_VERSION").to_string(),
        started_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    })
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| usage());
    match cmd.as_str() {
        "init-layout" => {
            let paths = provision::default_paths();
            if let Err(e) = provision::ensure_layout(&paths) {
                eprintln!("init-layout failed: {e}");
                std::process::exit(1);
            }
            println!("layout ready: {}", paths.etc_dir.display());
        }
        "unit" => {
            print!(
                "{}",
                provision::unit_file("/usr/local/bin/zray-admin", "zray-admin")
            );
        }
        "migrate" => {
            let cfg = config_path_arg();
            let dir = cfg
                .parent()
                .unwrap_or(std::path::Path::new("/etc/zeronet-admin"));
            let db_path = dir.join("../../var/lib/zeronet-admin/admin.db");
            if let Err(e) = provision::migrate_db(&db_path) {
                eprintln!("migrate failed: {e}");
                std::process::exit(1);
            }
            println!("migrated: {}", db_path.display());
        }
        "set-password" => {
            use std::io::Read;
            let cfg = config_path_arg();
            let dir = cfg
                .parent()
                .unwrap_or(std::path::Path::new("/etc/zeronet-admin"));
            let db_path = dir.join("../../var/lib/zeronet-admin/admin.db");
            let mut pw = String::new();
            std::io::stdin().read_to_string(&mut pw).unwrap_or_default();
            let pw = pw.trim_end_matches(['\r', '\n']);
            if pw.len() < 8 {
                eprintln!("password must be at least 8 characters");
                std::process::exit(1);
            }
            let hash = match zero_admin::crypto::hash_password(pw) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("hash failed: {e}");
                    std::process::exit(1);
                }
            };
            // The plaintext never touches disk: only the argon2id hash.
            let conn = match zero_admin::db::open(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("open db: {e}");
                    std::process::exit(1);
                }
            };
            if let Err(e) = zero_admin::store::set_setting(&conn, "panel.password_hash", &hash) {
                eprintln!("store hash: {e}");
                std::process::exit(1);
            }
            println!("panel password set");
        }
        "serve" => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                if let Err(e) = serve().await {
                    eprintln!("serve failed: {e}");
                    std::process::exit(1);
                }
            });
        }
        _ => usage(),
    }
}

async fn serve() -> Result<(), String> {
    let cfg_path = config_path_arg();
    let config = load_config(&cfg_path)?;
    // Loopback-only enforcement for the API listener (defense in depth:
    // ManagementConfig-style validation, api.rs:29 precedent).
    if !config.listen.ip().is_loopback() {
        return Err(format!(
            "refusing to bind the admin API to non-loopback {}",
            config.listen
        ));
    }
    let state = zero_admin::api::AppState::new(config.clone()).map_err(|e| e.to_string())?;
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|e| format!("bind {}: {e}", config.listen))?;
    eprintln!(
        "zray-admin listening on {} (loopback API + panel)",
        config.listen
    );

    // Optional public subscription listener: serves ONLY GET /s/{token}.
    if let Some(sub_listen) = config.sub_listen {
        let st = state.clone();
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(sub_listen).await {
                Ok(l) => {
                    eprintln!(
                        "zray-admin subscription listener on {sub_listen} (/s/{{token}} only)"
                    );
                    zero_admin::api::serve(st, l, true).await;
                }
                Err(e) => eprintln!("sub listener bind failed: {e}"),
            }
        });
    }

    // Background: usage polling, sweepers, route ingestion, collector.
    let bg = state.clone();
    tokio::spawn(async move {
        zero_admin::poller::run(bg).await;
    });

    zero_admin::api::serve(state, listener, false).await;
    Ok(())
}
