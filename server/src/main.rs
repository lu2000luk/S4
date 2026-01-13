pub use s4_macros as authenticated;

use crate::logger::{ascii, log, success};
use duckdb::DuckdbConnectionManager;
use r2d2::Pool;
use rocket::response::Redirect;
use std::fs;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};

#[macro_use]
extern crate rocket;

mod api;
mod config;
mod logger;
mod utils;

pub type DbPool = Pool<DuckdbConnectionManager>;

static CONFIG: LazyLock<Arc<Mutex<Option<config::Config>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));

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
    create_path_recursive(Option::from(config_ref.mount.clone().unwrap()));

    let mount = config_ref.mount.clone().unwrap();
    let port = config_ref.port.clone();
    let host = config_ref.host.clone();
    drop(config);

    log("Creating database connection pool...");
    let db_path = format!("{}/{}", mount, "s4.db");
    let pool = create_db_pool(&db_path);

    db_integrity(&pool).await;

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
                api::check_auth::check_auth_post
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
