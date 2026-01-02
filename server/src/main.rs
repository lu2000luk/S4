use crate::logger::{log, success};
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
        .mount("/", routes![redir_api]);
    log("Starting server...");
    api.launch().await.unwrap();
    success(
        format!(
            "Server started at http://{:?}:{:?}",
            config_ref.host.clone(),
            config_ref.port.clone()
        )
        .as_str(),
    );
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
