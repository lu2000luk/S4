use std::path::PathBuf;
use std::thread;

use duckdb::DuckdbConnectionManager;
use notify::{Event, EventKind, RecursiveMode, Watcher};

use crate::logger::{log, success, warn};
use crate::{DbPool, generate_file_id, generate_perm_id};

pub fn start_file_watcher(pool: DbPool, mount: String) {
    let files_dir = PathBuf::from(&mount).join("files");
    if !files_dir.exists() {
        warn("Files directory does not exist, skipping file watcher.");
        return;
    }

    let canonical_files_dir = match files_dir.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            warn(&format!("Failed to canonicalize files directory: {}", e));
            return;
        }
    };

    log("Starting file system watcher for automatic sync...");
    log(&format!(
        "Watching directory: {}",
        canonical_files_dir.display()
    ));

    let pool_clone = pool.clone();

    thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_watcher(&pool_clone, &canonical_files_dir);
        }));

        if let Err(panic_err) = result {
            let msg = if let Some(s) = panic_err.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = panic_err.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "unknown panic".to_string()
            };
            warn(&format!("File watcher thread panicked: {}", msg));
        }
    });
}

fn run_watcher(pool: &DbPool, files_dir: &PathBuf) {
    let (tx, rx) = std::sync::mpsc::channel();

    let mut watcher = match notify::recommended_watcher(tx) {
        Ok(w) => w,
        Err(e) => {
            warn(&format!("Failed to create file watcher: {}", e));
            return;
        }
    };

    if let Err(e) = watcher.watch(files_dir, RecursiveMode::Recursive) {
        warn(&format!("Failed to watch files directory: {}", e));
        return;
    }

    success("File watcher started successfully.");

    for result in rx {
        match result {
            Ok(event) => {
                handle_event(pool, files_dir, &event);
            }
            Err(e) => {
                warn(&format!("Watch error: {}", e));
            }
        }
    }
}

fn handle_event(pool: &DbPool, files_dir: &PathBuf, event: &Event) {
    let conn = match pool.get() {
        Ok(c) => c,
        Err(_) => return,
    };

    for path in &event.paths {
        let canonical_path = match path.canonicalize() {
            Ok(p) => p,
            Err(_) => {
                if matches!(event.kind, EventKind::Remove(_)) {
                    path.clone()
                } else {
                    continue;
                }
            }
        };

        let relative = match canonical_path.strip_prefix(files_dir) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let relative_str = relative.to_string_lossy().replace('\\', "/");
        if relative_str.is_empty()
            || relative_str.starts_with(".s4")
            || relative_str.starts_with("backups")
        {
            continue;
        }

        let virtual_path = format!("/{}", relative_str);

        let is_dir = if matches!(event.kind, EventKind::Remove(_)) {
            false
        } else {
            canonical_path.is_dir()
        };

        match event.kind {
            EventKind::Create(_) => {
                sync_entry(&conn, &virtual_path, is_dir);
            }
            EventKind::Remove(_) => {
                remove_entry(&conn, &virtual_path);
            }
            EventKind::Modify(_) => {
                if !is_dir {
                    sync_entry(&conn, &virtual_path, is_dir);
                }
            }
            _ => {}
        }
    }
}

fn sync_entry(
    conn: &r2d2::PooledConnection<DuckdbConnectionManager>,
    virtual_path: &str,
    is_dir: bool,
) {
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM files WHERE path = ?",
            duckdb::params![virtual_path],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if exists == 0 {
        let file_id = generate_file_id();
        let file_type = if is_dir { "folder" } else { "file" };
        let link_target = virtual_path.trim_start_matches('/');
        let metadata = "{}";

        match conn.execute(
            "INSERT INTO files (id, path, metadata, type, mime_type, size, link, link_target, cache, cache_dur, created_at, updated_at) VALUES (?, ?, ?, ?, NULL, 0, 'local', ?, FALSE, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            duckdb::params![file_id, virtual_path, metadata, file_type, link_target],
        ) {
            Ok(_) => {
                let perm_id = generate_perm_id();
                let _ = conn.execute(
                    "INSERT INTO file_perms (id, permission_id, path, recursive, read, created_at) VALUES (?, 'everyone', ?, ?, TRUE, CURRENT_TIMESTAMP)",
                    duckdb::params![perm_id, virtual_path, is_dir],
                );
                log(&format!("Auto-sync: added {}", virtual_path));
            }
            Err(e) => {
                warn(&format!("Auto-sync: failed to add {}: {}", virtual_path, e));
            }
        }
    } else {
        let _ = conn.execute(
            "UPDATE files SET updated_at = CURRENT_TIMESTAMP WHERE path = ?",
            duckdb::params![virtual_path],
        );
    }
}

fn remove_entry(conn: &r2d2::PooledConnection<DuckdbConnectionManager>, virtual_path: &str) {
    match conn.execute(
        "DELETE FROM files WHERE path = ?",
        duckdb::params![virtual_path],
    ) {
        Ok(_) => {
            let _ = conn.execute(
                "DELETE FROM file_perms WHERE path = ?",
                duckdb::params![virtual_path],
            );
            log(&format!("Auto-sync: removed {}", virtual_path));
        }
        Err(e) => {
            warn(&format!(
                "Auto-sync: failed to remove {}: {}",
                virtual_path, e
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use duckdb::DuckdbConnectionManager;
    use r2d2::Pool;
    use std::fs;
    use std::path::PathBuf;

    fn test_pool() -> (Pool<DuckdbConnectionManager>, tempfile::TempDir) {
        let temp = tempfile::tempdir().unwrap();
        let mount = temp.path().to_str().unwrap().to_string();
        let files_dir = PathBuf::from(&mount).join("files");
        fs::create_dir_all(&files_dir).unwrap();

        let db_path = temp.path().join("s4.db");
        let manager = DuckdbConnectionManager::file(db_path.to_str().unwrap()).unwrap();
        let pool = Pool::builder().max_size(1).build(manager).unwrap();

        let conn = pool.get().unwrap();
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS permissions (id VARCHAR PRIMARY KEY, weight INTEGER NOT NULL, is_root BOOLEAN NOT NULL DEFAULT FALSE, create_api_key BOOLEAN NOT NULL DEFAULT FALSE, create_user BOOLEAN NOT NULL DEFAULT FALSE, delete_user BOOLEAN NOT NULL DEFAULT FALSE, edit_user BOOLEAN NOT NULL DEFAULT FALSE, view_user BOOLEAN NOT NULL DEFAULT FALSE, bypass_weight BOOLEAN NOT NULL DEFAULT FALSE, max_action_size INT8, max_backup_size INT8, total_storage_size INT8, max_create_users INT8, convert_file BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS file_perms (id VARCHAR PRIMARY KEY, permission_id VARCHAR NOT NULL, path VARCHAR NOT NULL, bypass_weight BOOLEAN NOT NULL DEFAULT FALSE, recursive BOOLEAN NOT NULL DEFAULT FALSE, read BOOLEAN NOT NULL DEFAULT FALSE, delete BOOLEAN NOT NULL DEFAULT FALSE, write BOOLEAN NOT NULL DEFAULT FALSE, create_file BOOLEAN NOT NULL DEFAULT FALSE, create_folder BOOLEAN NOT NULL DEFAULT FALSE, create_link BOOLEAN NOT NULL DEFAULT FALSE, create_backup BOOLEAN NOT NULL DEFAULT FALSE, create_with_weight BOOLEAN NOT NULL DEFAULT FALSE, generate_link BOOLEAN NOT NULL DEFAULT FALSE, encrypt BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS users (id VARCHAR PRIMARY KEY, username VARCHAR NOT NULL UNIQUE, password_hash VARCHAR NOT NULL, is_everyone BOOLEAN NOT NULL DEFAULT FALSE, permission_id VARCHAR NOT NULL, created_by_id VARCHAR, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS files (id VARCHAR PRIMARY KEY, path VARCHAR NOT NULL UNIQUE, metadata JSON DEFAULT '{}', type VARCHAR NOT NULL, mime_type VARCHAR, size BIGINT NOT NULL DEFAULT 0, link VARCHAR, link_target VARCHAR, cache BOOLEAN NOT NULL DEFAULT FALSE, cache_dur BIGINT NOT NULL DEFAULT 0, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS backups (id VARCHAR PRIMARY KEY, path VARCHAR NOT NULL, size BIGINT NOT NULL, created_at TIMESTAMP NOT NULL, created_by_id VARCHAR NOT NULL, file_id VARCHAR NOT NULL);
            CREATE TABLE IF NOT EXISTS keys (id VARCHAR PRIMARY KEY, key VARCHAR NOT NULL UNIQUE, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, owner_id VARCHAR NOT NULL, permission_id VARCHAR NOT NULL);
            CREATE TABLE IF NOT EXISTS links (id VARCHAR PRIMARY KEY, file_id VARCHAR NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, expires_at TIMESTAMP, access_count INTEGER NOT NULL DEFAULT 0, max_access_count INTEGER, created_by_id VARCHAR NOT NULL, password_hash VARCHAR);
        ").unwrap();

        conn.execute_batch("
            INSERT OR IGNORE INTO permissions (id, weight, is_root) VALUES ('admin_perm', 100, TRUE);
            INSERT OR IGNORE INTO permissions (id, weight, is_root) VALUES ('everyone_perm', 0, FALSE);
            INSERT OR IGNORE INTO users (id, username, password_hash, is_everyone, permission_id) VALUES ('admin', 'admin', 'hash', FALSE, 'admin_perm');
            INSERT OR IGNORE INTO users (id, username, password_hash, is_everyone, permission_id) VALUES ('everyone', 'everyone', 'hash', TRUE, 'everyone_perm');
        ").unwrap();

        (pool, temp)
    }

    #[test]
    fn test_sync_entry_inserts_new_file() {
        let (pool, _temp) = test_pool();
        let conn = pool.get().unwrap();

        let virtual_path = "/test-file.txt";
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM files WHERE path = ?",
                duckdb::params![virtual_path],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 0);

        super::sync_entry(&conn, virtual_path, false);

        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM files WHERE path = ?",
                duckdb::params![virtual_path],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1);

        let perm_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM file_perms WHERE path = ?",
                duckdb::params![virtual_path],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(perm_exists, 1);
    }

    #[test]
    fn test_sync_entry_inserts_new_folder() {
        let (pool, _temp) = test_pool();
        let conn = pool.get().unwrap();

        let virtual_path = "/test-folder";
        super::sync_entry(&conn, virtual_path, true);

        let r#type: String = conn
            .query_row(
                "SELECT type FROM files WHERE path = ?",
                duckdb::params![virtual_path],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(r#type, "folder");
    }

    #[test]
    fn test_sync_entry_updates_existing_file() {
        let (pool, _temp) = test_pool();
        let conn = pool.get().unwrap();

        let virtual_path = "/existing.txt";
        super::sync_entry(&conn, virtual_path, false);

        let initial_updated: String = conn
            .query_row(
                "SELECT updated_at FROM files WHERE path = ?",
                duckdb::params![virtual_path],
                |row| row.get(0),
            )
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));

        super::sync_entry(&conn, virtual_path, false);

        let new_updated: String = conn
            .query_row(
                "SELECT updated_at FROM files WHERE path = ?",
                duckdb::params![virtual_path],
                |row| row.get(0),
            )
            .unwrap();

        assert!(new_updated >= initial_updated);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM files WHERE path = ?",
                duckdb::params![virtual_path],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_remove_entry_deletes_file_and_perms() {
        let (pool, _temp) = test_pool();
        let conn = pool.get().unwrap();

        let virtual_path = "/to-remove.txt";
        super::sync_entry(&conn, virtual_path, false);

        super::remove_entry(&conn, virtual_path);

        let file_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM files WHERE path = ?",
                duckdb::params![virtual_path],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(file_exists, 0);

        let perm_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM file_perms WHERE path = ?",
                duckdb::params![virtual_path],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(perm_exists, 0);
    }

    #[test]
    fn test_handle_event_create_file() {
        let (pool, temp) = test_pool();
        let mount = temp.path().to_str().unwrap().to_string();
        let files_dir = PathBuf::from(&mount).join("files").canonicalize().unwrap();

        let new_file = files_dir.join("new-test.txt");
        fs::write(&new_file, "content").unwrap();

        let event = Event {
            kind: EventKind::Create(notify::event::CreateKind::File),
            paths: vec![new_file.clone()],
            attrs: Default::default(),
        };

        handle_event(&pool, &files_dir, &event);

        let conn = pool.get().unwrap();
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM files WHERE path = ?",
                duckdb::params!["/new-test.txt"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1);
    }

    #[test]
    fn test_handle_event_remove_file() {
        let (pool, temp) = test_pool();
        let mount = temp.path().to_str().unwrap().to_string();
        let files_dir = PathBuf::from(&mount).join("files").canonicalize().unwrap();

        let conn = pool.get().unwrap();
        super::sync_entry(&conn, "/existing.txt", false);
        drop(conn);

        let removed_file = files_dir.join("existing.txt");
        let event = Event {
            kind: EventKind::Remove(notify::event::RemoveKind::File),
            paths: vec![removed_file],
            attrs: Default::default(),
        };

        handle_event(&pool, &files_dir, &event);

        let conn = pool.get().unwrap();
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM files WHERE path = ?",
                duckdb::params!["/existing.txt"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 0);
    }

    #[test]
    fn test_handle_event_ignores_s4_and_backups() {
        let (pool, temp) = test_pool();
        let files_dir = PathBuf::from(temp.path())
            .join("files")
            .canonicalize()
            .unwrap();

        let s4_path = files_dir.join(".s4");
        fs::create_dir_all(&s4_path).unwrap();

        let event = Event {
            kind: EventKind::Create(notify::event::CreateKind::Folder),
            paths: vec![s4_path],
            attrs: Default::default(),
        };

        handle_event(&pool, &files_dir, &event);

        let conn = pool.get().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_start_file_watcher_skips_missing_directory() {
        let (pool, temp) = test_pool();
        let mount = temp.path().to_str().unwrap().to_string();

        let nonexistent = PathBuf::from(&mount).join("nonexistent");
        let bad_mount = nonexistent.to_str().unwrap().to_string();

        start_file_watcher(pool, bad_mount);

        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
