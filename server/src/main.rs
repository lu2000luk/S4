use std::sync::{Arc, LazyLock, Mutex};
use crate::logger::{log, success};
use std::fs;
use std::path::Path;

mod config;
mod logger;

static CONFIG: LazyLock<Arc<Mutex<Option<config::Config>>>> = LazyLock::new(|| Arc::new(Mutex::new(None)));
#[tokio::main]
async fn main() {
    log("Loading config...");
    CONFIG.lock().unwrap().replace(config::config().await);
    success("Config loaded");
    log("Preparing file system...");
    create_path_recursive(Option::from(CONFIG.lock().unwrap().as_ref().unwrap().mount.clone()));
    success("File system prepared");

}

pub fn create_path_recursive(relative_path_to_exec: Option<String>) {
    if let Some(path_str) = relative_path_to_exec {
        let path = Path::new(&path_str);
        fs::create_dir_all(path).expect("Failed to create directories");
    }
}
