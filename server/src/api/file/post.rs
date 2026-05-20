use std::path::Path;

use duckdb::params;
use mime_type::MimeFormat;
use rocket::State;
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::{Deserialize, Serialize, json::Json};
use s4_macros::post;

use crate::{
    DbPool,
    utils::permissions::{
        FilePermType, FilePermission, PermissionEngine, load_engine_sync, perms_from_key_sync,
    },
};

#[derive(Debug, Deserialize)]
pub struct CreateFileData {
    #[serde(alias = "url", alias = "location", alias = "path")]
    source: String,
    metadata: Option<serde_json::Value>,
    mime_type: Option<String>,
    r#type: Option<String>,
    #[serde(alias = "perms", alias = "permissions")]
    permissions: Option<std::collections::HashMap<String, FilePermsInput>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FilePermsInput {
    bypass_weight: Option<bool>,
    recursive: Option<bool>,
    read: Option<bool>,
    delete: Option<bool>,
    write: Option<bool>,
    create_file: Option<bool>,
    create_folder: Option<bool>,
    create_link: Option<bool>,
    create_backup: Option<bool>,
    create_with_weight: Option<bool>,
    generate_link: Option<bool>,
    encrypt: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct CreatedFileResponse {
    id: String,
    path: String,
    r#type: String,
    link: Option<String>,
    link_target: String,
    mime_type: Option<String>,
    metadata: serde_json::Value,
    size: i64,
}

fn detect_link_type(source: &str) -> &'static str {
    let lower = source.to_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return "http";
    }
    if lower.starts_with("ftp://") {
        return "ftp";
    }
    if lower.starts_with("data:") {
        return "base64_data_url";
    }
    if source.contains(".git/") || source.contains('#') || source.contains("::") {
        return "git";
    }
    "local"
}

fn detect_mime_type(path: &str, provided: Option<String>) -> Option<String> {
    if let Some(mime) = provided {
        if !mime.is_empty() {
            return Some(mime);
        }
    }
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .and_then(mime_type::MimeType::from_ext)
        .map(|mime| mime.to_string())
}

fn normalize_file_path(path: &str) -> Result<String, status::Custom<String>> {
    let trimmed = path.trim();
    if trimmed.contains('\0') {
        return Err(status::Custom(
            Status::BadRequest,
            "ERROR Invalid file path".to_string(),
        ));
    }
    let replaced = trimmed.replace('\\', "/");
    let mut components = Vec::new();
    for part in replaced.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                return Err(status::Custom(
                    Status::BadRequest,
                    "ERROR Path traversal not allowed".to_string(),
                ));
            }
            _ => components.push(part),
        }
    }
    if components.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(format!("/{}", components.join("/")))
    }
}

fn create_file_impl(
    auth_key: String,
    source: String,
    path: String,
    metadata: Option<serde_json::Value>,
    mime_type: Option<String>,
    provided_type: Option<String>,
    permissions: Option<std::collections::HashMap<String, FilePermsInput>>,
    pool: &DbPool,
) -> Result<String, status::Custom<String>> {
    if source.is_empty() {
        return Err(status::Custom(
            Status::BadRequest,
            "ERROR Source is required".to_string(),
        ));
    }
    if path.is_empty() {
        return Err(status::Custom(
            Status::BadRequest,
            "ERROR Path is required".to_string(),
        ));
    }

    let normalized_path = normalize_file_path(&path)?;
    let link_type = if let Some(t) = provided_type {
        let t_lower = t.to_lowercase();
        if !["git", "ftp", "http", "base64_data_url", "local"].contains(&t_lower.as_str()) {
            return Err(status::Custom(
                Status::BadRequest,
                "ERROR Invalid file type".to_string(),
            ));
        }
        t_lower
    } else {
        detect_link_type(&source).to_string()
    };

    let conn = pool.get().map_err(|_| {
        status::Custom(
            Status::InternalServerError,
            "ERROR Failed to get connection from pool".to_string(),
        )
    })?;

    let perms = if auth_key.is_empty() {
        load_engine_sync(&conn, "everyone").ok_or_else(|| {
            status::Custom(
                Status::InternalServerError,
                "ERROR Failed to load permissions".to_string(),
            )
        })?
    } else {
        let p = perms_from_key_sync(&conn, auth_key).ok_or_else(|| {
            status::Custom(Status::Unauthorized, "ERROR Invalid auth key".to_string())
        })?;
        PermissionEngine::new(p)
    };

    if link_type == "local" && !perms.get_permissions().is_root {
        return Err(status::Custom(
            Status::Forbidden,
            "ERROR Only root can create files with 'local' source type".to_string(),
        ));
    }

    let has_create = perms
        .get_file_perms_sync(&conn, &normalized_path)
        .map_err(|e| status::Custom(Status::InternalServerError, format!("ERROR {e}")))?
        .has(&FilePermission::new(
            normalized_path.clone(),
            FilePermType::CreateFile,
        ));

    if !has_create {
        return Err(status::Custom(
            Status::Forbidden,
            "ERROR You do not have permission to create files at this path".to_string(),
        ));
    }

    let detected_mime = detect_mime_type(&normalized_path, mime_type);
    let metadata_value = metadata.unwrap_or(serde_json::json!({}));
    let file_id = generate_file_id();

    let link_target = if link_type == "local" {
        normalized_path.trim_start_matches('/').to_string()
    } else {
        source.clone()
    };

    let result = conn.execute(
        "INSERT INTO files (id, path, metadata, type, mime_type, size, link, link_target, cache, cache_dur, created_at, updated_at) VALUES (?, ?, ?, 'file', ?, 0, ?, ?, FALSE, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        params![
            file_id,
            normalized_path,
            metadata_value.to_string(),
            detected_mime,
            link_type,
            link_target,
        ],
    ).map_err(|e| {
        let err_msg = e.to_string();
        if err_msg.contains("UNIQUE") || err_msg.contains("unique") {
            status::Custom(
                Status::Conflict,
                "ERROR A file already exists at this path".to_string(),
            )
        } else {
            status::Custom(
                Status::InternalServerError,
                "ERROR Failed to create file record".to_string(),
            )
        }
    })?;

    if result == 0 {
        return Err(status::Custom(
            Status::InternalServerError,
            "ERROR Failed to create file record".to_string(),
        ));
    }

    // Prepare permissions map with default "everyone" read permission
    let mut perms_map = permissions.unwrap_or_default();
    
    // Ensure "everyone" has read permission by default (unless explicitly set in request body)
    perms_map.entry("everyone".to_string())
        .or_insert_with(|| FilePermsInput {
            bypass_weight: None,
            recursive: None,
            read: Some(true),
            delete: None,
            write: None,
            create_file: None,
            create_folder: None,
            create_link: None,
            create_backup: None,
            create_with_weight: None,
            generate_link: None,
            encrypt: None,
        });

    let perm_insert_query = r#"
        INSERT INTO file_perms (
            id, permission_id, path, bypass_weight, recursive, read, delete, write,
            create_file, create_folder, create_link, create_backup, create_with_weight,
            generate_link, encrypt, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    "#;
    for (perm_id, p_input) in perms_map {
        let fp_id = generate_file_id();
        let _ = conn.execute(
            perm_insert_query,
            params![
                fp_id,
                perm_id,
                normalized_path.clone(),
                p_input.bypass_weight.unwrap_or(false),
                p_input.recursive.unwrap_or(false),
                p_input.read.unwrap_or(false),
                p_input.delete.unwrap_or(false),
                p_input.write.unwrap_or(false),
                p_input.create_file.unwrap_or(false),
                p_input.create_folder.unwrap_or(false),
                p_input.create_link.unwrap_or(false),
                p_input.create_backup.unwrap_or(false),
                p_input.create_with_weight.unwrap_or(false),
                p_input.generate_link.unwrap_or(false),
                p_input.encrypt.unwrap_or(false),
            ],
        );
    }

    let response = CreatedFileResponse {
        id: file_id,
        path: normalized_path,
        r#type: "file".to_string(),
        link: Some(link_type.to_string()),
        link_target,
        mime_type: detected_mime,
        metadata: metadata_value,
        size: 0,
    };

    Ok(serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string()))
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

#[post("/file/<path..>", format = "json", data = "<data>")]
pub async fn create_file(
    path: std::path::PathBuf,
    data: Json<CreateFileData>,
    auth_key: String,
    pool: &State<DbPool>,
) -> Result<String, status::Custom<String>> {
    let path_str = path.to_string_lossy().to_string();

    let pool = pool.inner().clone();
    rocket::tokio::task::spawn_blocking(move || {
        let inner_data = data.into_inner();
        create_file_impl(
            auth_key,
            inner_data.source,
            path_str,
            inner_data.metadata,
            inner_data.mime_type,
            inner_data.r#type,
            inner_data.permissions,
            &pool,
        )
    })
    .await
    .map_err(|_| status::Custom(Status::InternalServerError, "ERROR Task failed".to_string()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::{CONFIG, create_db_pool, db_integrity, create_path_recursive};
    use rocket::http::{ContentType, Status};
    use rocket::local::asynchronous::Client;

    struct TestServer {
        _temp: tempfile::TempDir,
        pool: Option<DbPool>,
        client: Client,
    }

    async fn test_server() -> TestServer {
        let temp = tempfile::tempdir().unwrap();
        let mount = temp.path().to_str().unwrap().to_string();
        create_path_recursive(Some(mount.clone()));

        {
            let mut config = Config::defaulted();
            config.mount = Some(mount.clone());
            config.remote_allow_local = Some(true);
            config.startup_sync = Some(false);
            config.auto_sync = Some(false);
            let mut guard = CONFIG.lock().unwrap();
            guard.replace(config);
        }

        let db_path = temp.path().join("s4.db");
        let pool = create_db_pool(db_path.to_str().unwrap());
        db_integrity(&pool).await;
        {
            let conn = pool.get().unwrap();
            conn.execute(
                "INSERT INTO permissions (id, weight, is_root) VALUES ('testuser', 10, TRUE)",
                [],
            )
            .unwrap();
            conn.execute("UPDATE permissions SET is_root = TRUE WHERE id = 'everyone'", []).unwrap();
            conn.execute(
                "INSERT INTO users (id, username, password_hash, is_everyone, permission_id) VALUES ('testuser', 'testuser', '', FALSE, 'testuser')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO keys (id, key, owner_id, permission_id) VALUES ('testkey1', 'test-key-123', 'testuser', 'testuser')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO file_perms (id, permission_id, path, recursive, read, create_file) VALUES ('everyone_allowed', 'everyone', '/allowed', TRUE, TRUE, TRUE)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO file_perms (id, permission_id, path, recursive, read, create_file) VALUES ('denied_perms', 'everyone', '/denied', TRUE, TRUE, FALSE)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO file_perms (id, permission_id, path, recursive, read, create_file) VALUES ('user_allowed', 'testuser', '/userpath', TRUE, TRUE, TRUE)",
                [],
            )
            .unwrap();
        }

        let rocket = rocket::build()
            .manage(pool.clone())
            .mount("/api", routes![create_file]);
        let client = Client::untracked(rocket).await.unwrap();

        TestServer {
            _temp: temp,
            pool: Some(pool),
            client,
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.pool.take();
        }
    }

    fn count_files(pool: &DbPool) -> i64 {
        let conn = pool.get().unwrap();
        conn.query_row("SELECT COUNT(*) FROM files WHERE type = 'file'", [], |row| row.get(0))
            .unwrap()
    }

    #[tokio::test]
    async fn create_file_requires_source_field() {
        let server = test_server().await;

        let response = server
            .client
            .post("/api/file/test.txt")
            .header(ContentType::JSON)
            .body(r#"{}"#)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::UnprocessableEntity);
    }

    #[tokio::test]
    async fn create_file_rejects_empty_source() {
        let server = test_server().await;

        let response = server
            .client
            .post("/api/file/test.txt")
            .header(ContentType::JSON)
            .body(r#"{"source": ""}"#)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);
    }

    #[tokio::test]
    async fn create_file_succeeds_with_valid_data() {
        let server = test_server().await;
        let initial_count = count_files(server.pool.as_ref().unwrap());

        let response = server
            .client
            .post("/api/file/allowed/new-file.txt")
            .header(ContentType::JSON)
            .body(r#"{"source": "local-file"}"#)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let body = response.into_string().await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["path"], "/allowed/new-file.txt");
        assert_eq!(json["type"], "file");
        assert_eq!(json["link"], "local");
        assert_eq!(json["link_target"], "allowed/new-file.txt");
        assert_eq!(json["size"], 0);
        assert!(json["id"].as_str().unwrap().starts_with("f."));

        assert_eq!(count_files(server.pool.as_ref().unwrap()), initial_count + 1);
    }

    #[tokio::test]
    async fn create_file_detects_http_link_type() {
        let server = test_server().await;

        let response = server
            .client
            .post("/api/file/allowed/remote.txt")
            .header(ContentType::JSON)
            .body(r#"{"source": "https://example.com/file.txt"}"#)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let body = response.into_string().await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["link"], "http");
        assert_eq!(json["link_target"], "https://example.com/file.txt");
    }

    #[tokio::test]
    async fn create_file_detects_ftp_link_type() {
        let server = test_server().await;

        let response = server
            .client
            .post("/api/file/allowed/ftp.txt")
            .header(ContentType::JSON)
            .body(r#"{"source": "ftp://ftp.example.com/file.txt"}"#)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let body = response.into_string().await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["link"], "ftp");
    }

    #[tokio::test]
    async fn create_file_detects_git_link_type() {
        let server = test_server().await;

        let response = server
            .client
            .post("/api/file/allowed/repo")
            .header(ContentType::JSON)
            .body(r#"{"source": "git@github.com:user/repo.git#path/to/file.txt"}"#)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let body = response.into_string().await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["link"], "git");
    }

    #[tokio::test]
    async fn create_file_detects_base64_data_url_type() {
        let server = test_server().await;

        let response = server
            .client
            .post("/api/file/allowed/data.txt")
            .header(ContentType::JSON)
            .body(r#"{"source": "data:text/plain;base64,SGVsbG8="}"#)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let body = response.into_string().await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["link"], "base64_data_url");
    }

    #[tokio::test]
    async fn create_file_stores_metadata() {
        let server = test_server().await;

        let response = server
            .client
            .post("/api/file/allowed/meta.txt")
            .header(ContentType::JSON)
            .body(r#"{"source": "local", "metadata": {"key": "value"}}"#)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let body = response.into_string().await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["metadata"]["key"], "value");
    }

    #[tokio::test]
    async fn create_file_defaults_metadata_to_empty_object() {
        let server = test_server().await;

        let response = server
            .client
            .post("/api/file/allowed/no-meta.txt")
            .header(ContentType::JSON)
            .body(r#"{"source": "local"}"#)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let body = response.into_string().await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["metadata"], serde_json::json!({}));
    }

    #[tokio::test]
    async fn create_file_detects_mime_type_from_extension() {
        let server = test_server().await;

        let response = server
            .client
            .post("/api/file/allowed/image.png")
            .header(ContentType::JSON)
            .body(r#"{"source": "local"}"#)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let body = response.into_string().await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["mime_type"], "image/png");
    }

    #[tokio::test]
    async fn create_file_accepts_provided_mime_type() {
        let server = test_server().await;

        let response = server
            .client
            .post("/api/file/allowed/custom.txt")
            .header(ContentType::JSON)
            .body(r#"{"source": "local", "mime_type": "application/custom"}"#)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let body = response.into_string().await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["mime_type"], "application/custom");
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "hangs on Windows due to Rocket test client cleanup"]
    async fn create_file_rejects_duplicate_path() {
        let server = test_server().await;

        let response1 = server
            .client
            .post("/api/file/allowed/duplicate.txt")
            .header(ContentType::JSON)
            .body(r#"{"source": "local"}"#)
            .dispatch()
            .await;
        assert_eq!(response1.status(), Status::Ok);
        drop(response1);

        let response2 = server
            .client
            .post("/api/file/allowed/duplicate.txt")
            .header(ContentType::JSON)
            .body(r#"{"source": "local"}"#)
            .dispatch()
            .await;
        assert_eq!(response2.status(), Status::Conflict);
        drop(response2);
        drop(server);
    }

    #[tokio::test]
    async fn create_file_requires_auth_for_non_root_paths() {
        let server = test_server().await;

        let response = server
            .client
            .post("/api/file/non-root/test.txt")
            .header(ContentType::JSON)
            .body(r#"{"source": "local"}"#)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
    }

    #[tokio::test]
    async fn create_file_with_auth_key_uses_user_permissions() {
        let server = test_server().await;

        let response = server
            .client
            .post("/api/file/userpath/test.txt?key=test-key-123")
            .header(ContentType::JSON)
            .body(r#"{"source": "local"}"#)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
    }

    #[tokio::test]
    async fn create_file_with_invalid_auth_key_is_rejected() {
        let server = test_server().await;

        let response = server
            .client
            .post("/api/file/allowed/test.txt?key=invalid-key")
            .header(ContentType::JSON)
            .body(r#"{"source": "local"}"#)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Unauthorized);
    }
}
