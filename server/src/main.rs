pub use s4_macros as authenticated;

use crate::logger::{ascii, log, success, warn};
use duckdb::DuckdbConnectionManager;
use r2d2::Pool;
use rocket::response::Redirect;
use std::env;
use std::fs;
use std::path::Path;
#[cfg(test)]
use std::sync::MutexGuard;
use std::sync::{Arc, LazyLock, Mutex};

#[macro_use]
extern crate rocket;

mod api;
mod config;
mod file_watcher;
mod logger;
mod utils;

pub type DbPool = Pool<DuckdbConnectionManager>;

static CONFIG: LazyLock<Arc<Mutex<Option<config::Config>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));

#[cfg(test)]
static TEST_CONFIG_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[cfg(test)]
pub(crate) fn test_config_lock() -> MutexGuard<'static, ()> {
    TEST_CONFIG_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[get("/")]
fn version() -> &'static str {
    "S4 // API v0.1.0"
}

#[get("/")]
fn redir_api() -> Redirect {
    Redirect::to(uri!("/api/"))
}

#[get("/<_all>")]
fn redir_api_all(_all: String) -> Redirect {
    Redirect::to(uri!("/api/"))
}

fn create_db_pool(db_path: &str) -> DbPool {
    let manager = DuckdbConnectionManager::file(db_path).unwrap();
    Pool::builder()
        .max_size(10)
        .build(manager)
        .expect("Failed to create database connection pool")
}

#[tokio::main]
async fn main() {
    log("Loading config...");
    CONFIG.lock().unwrap().replace(config::config().await);
    let config = CONFIG.lock().unwrap();
    let config_ref = config.as_ref().unwrap();
    log("Preparing folders...");
    create_path_recursive(Option::from(config_ref.mount().to_string()));

    let mount = config_ref.mount().to_string();
    let port = config_ref.port();
    let host = config_ref.host().to_string();
    let startup_sync = config_ref.startup_sync();
    let auto_sync = config_ref.auto_sync();
    drop(config);

    log("Creating database connection pool...");
    let db_path = format!("{}/{}", mount, "s4.db");
    let pool = create_db_pool(&db_path);

    db_integrity(&pool).await;

    if startup_sync {
        log("Startup sync enabled. Scanning files directory...");
        sync_files_from_disk(&pool, &mount);
        success("File sync completed.");
    }

    if auto_sync {
        file_watcher::start_file_watcher(pool.clone(), mount.clone());
    }

    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--sync") {
        log("Sync mode enabled via flag. Scanning files directory...");
        sync_files_from_disk(&pool, &mount);
        success("File sync completed.");
    }

    log("Building server...");
    let api = rocket::build()
        .configure(
            rocket::Config::figment()
                .merge(("port", port))
                .merge(("address", host)),
        )
        .manage(pool)
        .mount(
            "/api",
            routes![
                version,
                api::user_key::generate_user_key,
                api::user_key::user_key_get,
                api::user_key::user_key_delete,
                api::user_key::user_key_delete_body,
                api::check_auth::check_auth,
                api::check_auth::check_auth_post,
                api::file::get::get_file,
                api::file::post::create_file,
                api::file::put::put_file
            ],
        )
        .mount("/", routes![redir_api, redir_api_all]);

    log("Starting server...");
    println!("");
    ascii();
    api.launch().await.unwrap();
}

pub async fn db_integrity(pool: &DbPool) {
    log("Connecting to DB for checks...");
    let conn = pool.get().expect("Failed to get connection from pool");

    log("Running DB schema checks...");
    let schema = include_str!("./sql/schema.sql");
    conn.execute_batch(schema).unwrap();

    log("Checking system users existance...");
    let mut stmt = conn
        .prepare("SELECT COUNT(*) FROM users WHERE id IN ('admin','everyone')")
        .unwrap();
    let existing: i64 = stmt.query_row([], |row| row.get(0)).unwrap();

    if existing < 2 {
        log("Missing system users detected, inserting...");
        let baseusers = include_str!("./sql/baseuser.sql");
        conn.execute_batch(baseusers).unwrap();
        success("System users inserted successfully.");
    }

    log("Checking root file existance...");
    let mut stmt = conn
        .prepare("SELECT COUNT(*) FROM files WHERE id = 'root'")
        .unwrap();
    let existing_root: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
    if existing_root < 1 {
        log("Missing root file detected, inserting...");
        let rootfile = include_str!("./sql/root.sql");
        conn.execute_batch(rootfile).unwrap();
        success("Root file inserted successfully.");
    }

    success("Database integrity check completed.");
}

pub fn create_path_recursive(relative_path_to_exec: Option<String>) {
    if let Some(path_str) = relative_path_to_exec {
        let path = Path::new(&path_str);
        fs::create_dir_all(path).expect("Failed to create directories");

        let files_path_str = format!("{}/{}", &path_str, "files");
        let backups_path_str = format!("{}/{}", &path_str, "backups");
        let path2 = Path::new(&files_path_str);
        fs::create_dir_all(path2).expect("Failed to create directories (files)");
        let path3 = Path::new(&backups_path_str);
        fs::create_dir_all(path3).expect("Failed to create directories (backups)");
    }
}

fn generate_file_id() -> String {
    use base64::Engine;
    use rand::{Rng, distr::Alphanumeric, rng};
    use std::time::{SystemTime, UNIX_EPOCH};

    let random_part: String = rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX_EPOCH")
        .as_secs()
        .to_string();

    let ts_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ts.as_bytes());

    format!("f.{}.{}", random_part, ts_b64)
}

fn generate_perm_id() -> String {
    use base64::Engine;
    use rand::{Rng, distr::Alphanumeric, rng};
    use std::time::{SystemTime, UNIX_EPOCH};

    let random_part: String = rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX_EPOCH")
        .as_secs()
        .to_string();

    let ts_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ts.as_bytes());

    format!("fp.{}.{}", random_part, ts_b64)
}

pub fn sync_files_from_disk(pool: &DbPool, mount: &str) {
    let files_dir = Path::new(mount).join("files");
    if !files_dir.exists() {
        warn("Files directory does not exist, skipping sync.");
        return;
    }

    let conn = pool.get().expect("Failed to get connection from pool");

    let mut entries: Vec<(String, bool)> = Vec::new();
    collect_entries(&files_dir, &files_dir, &mut entries);

    let mut created_files = 0;
    let mut created_perms = 0;

    for (virtual_path, is_dir) in &entries {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM files WHERE path = ?",
                duckdb::params![virtual_path],
                |row| row.get(0),
            )
            .unwrap_or(0);

        if exists == 0 {
            let file_id = generate_file_id();
            let file_type = if *is_dir { "folder" } else { "file" };
            let link_target = virtual_path.trim_start_matches('/');

            let metadata = if *is_dir { "{}" } else { "{}" };

            conn.execute(
                "INSERT INTO files (id, path, metadata, type, mime_type, size, link, link_target, cache, cache_dur, created_at, updated_at) VALUES (?, ?, ?, ?, NULL, 0, 'local', ?, FALSE, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                duckdb::params![file_id, virtual_path, metadata, file_type, link_target],
            ).expect("Failed to insert file entry");

            created_files += 1;

            let perm_id = generate_perm_id();
            conn.execute(
                "INSERT INTO file_perms (id, permission_id, path, recursive, read, created_at) VALUES (?, 'everyone', ?, ?, TRUE, CURRENT_TIMESTAMP)",
                duckdb::params![perm_id, virtual_path, is_dir],
            ).expect("Failed to insert file permission");

            created_perms += 1;
        }
    }

    log(&format!(
        "Synced {} files/folders, created {} permissions.",
        created_files, created_perms
    ));
}

fn collect_entries(base: &Path, dir: &Path, entries: &mut Vec<(String, bool)>) {
    if let Ok(read_dir) = fs::read_dir(dir) {
        for entry_result in read_dir {
            if let Ok(entry) = entry_result {
                let path = entry.path();
                let relative = path.strip_prefix(base).unwrap_or(&path);
                let virtual_path = format!("/{}", relative.to_string_lossy().replace('\\', "/"));

                if path.is_dir() {
                    entries.push((virtual_path.clone(), true));
                    collect_entries(base, &path, entries);
                } else {
                    entries.push((virtual_path, false));
                }
            }
        }
    }
}
