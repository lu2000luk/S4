use crate::logger::{log, success};
use duckdb::Connection;
use rocket::response::Redirect;
use std::fs;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};

#[macro_use]
extern crate rocket;

mod config;
mod logger;

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

#[tokio::main]
async fn main() {
    log("Loading config...");
    CONFIG.lock().unwrap().replace(config::config().await);
    let config = CONFIG.lock().unwrap();
    let config_ref = config.as_ref().unwrap();
    log("Preparing folders...");
    create_path_recursive(Option::from(config_ref.mount.clone().unwrap()));
    log("Building server...");
    let api = rocket::build()
        .configure(
            rocket::Config::figment()
                .merge(("port", config_ref.port.clone()))
                .merge(("address", config_ref.host.clone())),
        )
        .mount("/api", routes![version])
        .mount("/", routes![redir_api, redir_api_all]);
    db_integrity(config_ref.mount.clone().unwrap()).await;
    log("Starting server...");
    api.launch().await.unwrap();
}

pub async fn db_integrity(mount: String) {
    let db_path = format!("{}/{}", mount, "s4.db");
    log("Connecting to DB for checks...");
    let db_config = duckdb::Config::default()
        .access_mode(duckdb::AccessMode::ReadWrite)
        .unwrap();
    let conn = Connection::open_with_flags(db_path, db_config).unwrap();
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
