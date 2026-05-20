use std::path::PathBuf;

use duckdb::params;
use rocket::State;
use rocket::http::{Header, Status};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::{Responder, Response, status};
use rocket::tokio::task::spawn_blocking;
use s4_macros::get;

use crate::{
    CONFIG, DbPool,
    config::Config,
    logger::warn,
    utils::{
        dbstructs::File as DbFile,
        get_file::{
            ByteRange, CacheStatus, FileResolveError, FileResolveRequest, FileSourceType,
            ResolvedFile, effective_cache, parse_range_header, resolve_file_content,
        },
        permissions::{
            FilePermType, FilePermission, PermissionEngine, load_engine_sync, perms_from_key_sync,
        },
    },
};

#[derive(Debug, Clone)]
pub struct RangeHeader(pub Option<ByteRange>);

pub struct FileResponse(Response<'static>);

impl<'r> Responder<'r, 'static> for FileResponse {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'static> {
        Ok(self.0)
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RangeHeader {
    type Error = String;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one("Range") {
            Some(value) => match parse_range_header(value) {
                Ok(range) => Outcome::Success(RangeHeader(range)),
                Err(err) => Outcome::Error((Status::BadRequest, format!("{err:?}"))),
            },
            None => Outcome::Success(RangeHeader(None)),
        }
    }
}

#[get("/file/<path..>?<cache>")]
pub async fn get_file(
    path: PathBuf,
    cache: Option<bool>,
    range: RangeHeader,
    pool: &State<DbPool>,
    auth_key: String,
) -> Result<FileResponse, status::Custom<String>> {
    let normalized_path = normalize_route_path(&path)?;
    let authenticated = !auth_key.is_empty();
    let config = current_config();

    let db_file = load_file_row(pool.inner().clone(), normalized_path.clone()).await?;
    if db_file.r#type == "folder" {
        return Err(status::Custom(
            Status::BadRequest,
            "ERROR Folders cannot be downloaded as files".to_string(),
        ));
    }

    check_read_permission(pool.inner().clone(), auth_key, normalized_path.clone()).await?;

    let source_type = source_type_for_row(&db_file)?;
    let source_path = source_path_for_row(&db_file);
    let effective_cache = effective_cache(cache, Some(db_file.cache), &config);

    let request = FileResolveRequest {
        source_type,
        source_path,
        virtual_path: normalized_path.clone(),
        effective_cache,
        cache_duration_ms: db_file.cache_dur.max(0) as u64,
        authenticated,
        range: range.0,
        config: &config,
    };

    match resolve_file_content(request).await {
        Ok(mut resolved) => {
            if resolved.mime_type.is_none() {
                resolved.mime_type = db_file.mime_type.clone();
            }
            build_file_response(resolved, effective_cache)
        }
        Err(FileResolveError::NotFoundDefinite(message)) => {
            if config.remove_not_found_files() {
                cleanup_missing_file_row(pool.inner().clone(), db_file.id.clone()).await;
            }
            Err(status::Custom(
                Status::NotFound,
                format!("ERROR File not found: {message}"),
            ))
        }
        Err(FileResolveError::RangeNotSatisfiable(size)) => {
            let mut builder = Response::build();
            builder.status(Status::RangeNotSatisfiable);
            if let Some(size) = size {
                builder.header(Header::new("Content-Range", format!("bytes */{size}")));
            }
            Ok(FileResponse(builder.finalize()))
        }
        Err(FileResolveError::BadRequest(message)) => Err(status::Custom(
            Status::BadRequest,
            format!("ERROR {message}"),
        )),
        Err(FileResolveError::Forbidden(message)) => Err(status::Custom(
            Status::Forbidden,
            format!("ERROR {message}"),
        )),
        Err(FileResolveError::UpstreamFailure(message)) => Err(status::Custom(
            Status::BadGateway,
            format!("ERROR Upstream failure: {message}"),
        )),
        Err(FileResolveError::InternalFailure(message)) => Err(status::Custom(
            Status::InternalServerError,
            format!("ERROR {message}"),
        )),
    }
}

fn normalize_route_path(path: &PathBuf) -> Result<String, status::Custom<String>> {
    let path = path.to_string_lossy().replace('\\', "/");
    if path.contains('\0') || path.split('/').any(|part| part == "..") {
        return Err(status::Custom(
            Status::BadRequest,
            "ERROR Invalid file path".to_string(),
        ));
    }
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(format!("/{trimmed}"))
    }
}

fn current_config() -> Config {
    let guard = CONFIG.lock().unwrap();
    guard
        .as_ref()
        .map(CloneForRequest::cloned_for_request)
        .unwrap_or_else(Config::defaulted)
}

trait CloneForRequest {
    fn cloned_for_request(&self) -> Config;
}

impl CloneForRequest for Config {
    fn cloned_for_request(&self) -> Config {
        Config {
            host: Some(self.host().to_string()),
            port: Some(self.port()),
            mount: Some(self.mount().to_string()),
            can_unauthenticated_cache: Some(self.can_unauthenticated_cache()),
            max_cache_entry_size: Some(self.max_cache_entry_size()),
            total_max_cache: Some(self.total_max_cache()),
            default_use_cache: Some(self.default_use_cache()),
            remove_not_found_files: Some(self.remove_not_found_files()),
            allow_query_override_default: Some(self.allow_query_override_default()),
            allow_query_override_db: Some(self.allow_query_override_db()),
            remote_allow_local: Some(self.remote_allow_local()),
            startup_sync: Some(self.startup_sync()),
            auto_sync: Some(self.auto_sync()),
        }
    }
}

async fn load_file_row(
    pool: DbPool,
    normalized_path: String,
) -> Result<DbFile, status::Custom<String>> {
    spawn_blocking(move || {
        let conn = pool.get().map_err(|_| {
            status::Custom(
                Status::InternalServerError,
                "ERROR Failed to get connection from pool".to_string(),
            )
        })?;

        conn.query_row(
            "SELECT id, path, metadata, type, mime_type, size, link, link_target, cache, cache_dur, created_at, updated_at FROM files WHERE path = ?",
            params![normalized_path],
            |row| {
                let metadata: Option<String> = row.get(2)?;
                Ok(DbFile {
                    id: row.get(0)?,
                    path: row.get(1)?,
                    metadata: metadata
                        .as_deref()
                        .and_then(|value| serde_json::from_str(value).ok()),
                    r#type: row.get(3)?,
                    mime_type: row.get(4)?,
                    size: row.get(5)?,
                    link: row.get(6)?,
                    link_target: row.get(7)?,
                    cache: row.get(8)?,
                    cache_dur: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                })
            },
        )
        .map_err(|_| status::Custom(Status::NotFound, "ERROR File not found".to_string()))
    })
    .await
    .map_err(|_| {
        status::Custom(
            Status::InternalServerError,
            "ERROR Task join error".to_string(),
        )
    })?
}

async fn check_read_permission(
    pool: DbPool,
    auth_key: String,
    normalized_path: String,
) -> Result<(), status::Custom<String>> {
    let has_permission = spawn_blocking(move || {
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

        let has_read = perms
            .get_file_perms_sync(&conn, &normalized_path)
            .map_err(|e| status::Custom(Status::InternalServerError, format!("ERROR {e}")))?
            .has(&FilePermission::new(
                normalized_path.clone(),
                FilePermType::Read,
            ));

        Ok::<bool, status::Custom<String>>(has_read)
    })
    .await
    .map_err(|_| {
        status::Custom(
            Status::InternalServerError,
            "ERROR Task join error".to_string(),
        )
    })??;

    if has_permission {
        Ok(())
    } else {
        Err(status::Custom(
            Status::Forbidden,
            "ERROR You do not have permission to read this file".to_string(),
        ))
    }
}

fn source_type_for_row(file: &DbFile) -> Result<FileSourceType, status::Custom<String>> {
    if let Some(link) = &file.link {
        return match link.as_str() {
            "http" => Ok(FileSourceType::Http),
            "local" => Ok(FileSourceType::Local),
            "base64_data_url" => Ok(FileSourceType::Base64DataUrl),
            "ftp" => Ok(FileSourceType::Ftp),
            "git" => Ok(FileSourceType::Git),
            _ => Err(status::Custom(
                Status::BadRequest,
                "ERROR Unsupported file source".to_string(),
            )),
        };
    }

    if let Some(target) = &file.link_target {
        if target.starts_with("http://") || target.starts_with("https://") {
            return Ok(FileSourceType::Http);
        }
        if target.starts_with("ftp://") {
            return Ok(FileSourceType::Ftp);
        }
        if target.starts_with("data:") {
            return Ok(FileSourceType::Base64DataUrl);
        }
    }

    Ok(FileSourceType::Local)
}

fn source_path_for_row(file: &DbFile) -> String {
    file.link_target
        .clone()
        .unwrap_or_else(|| file.path.trim_start_matches('/').to_string())
}

fn build_file_response(
    resolved: ResolvedFile,
    effective_cache: bool,
) -> Result<FileResponse, status::Custom<String>> {
    let mut builder = Response::build();

    let status = if matches!(resolved.upstream_status, Some(206)) || resolved.served_range.is_some()
    {
        Status::PartialContent
    } else {
        Status::Ok
    };
    builder.status(status);

    builder.header(Header::new(
        "Content-Type",
        resolved
            .mime_type
            .unwrap_or_else(|| "application/octet-stream".to_string()),
    ));
    if let Some(length) = resolved.content_length {
        builder.header(Header::new("Content-Length", length.to_string()));
    }
    builder.header(Header::new("Accept-Ranges", "bytes"));

    if let Some(range) = resolved.served_range {
        builder.header(Header::new(
            "Content-Range",
            format!(
                "bytes {}-{}/{}",
                range.start, range.end, range.complete_size
            ),
        ));
    }
    if let Some(etag) = resolved.metadata_headers.get("etag") {
        builder.header(Header::new("ETag", etag.clone()));
    }
    if let Some(last_modified) = resolved.metadata_headers.get("last-modified") {
        builder.header(Header::new("Last-Modified", last_modified.clone()));
    }

    builder.header(Header::new(
        "Content-Disposition",
        format!(
            "inline; filename=\"{}\"",
            escape_filename(&resolved.filename)
        ),
    ));
    builder.header(Header::new(
        "Cache-Control",
        cache_control_header(effective_cache, resolved.cache_status),
    ));

    builder.streamed_body(resolved.reader);
    Ok(FileResponse(builder.finalize()))
}

fn cache_control_header(effective_cache: bool, status: CacheStatus) -> &'static str {
    match (effective_cache, status) {
        (true, CacheStatus::Hit | CacheStatus::Miss) => "private, max-age=0, must-revalidate",
        _ => "no-store",
    }
}

fn escape_filename(filename: &str) -> String {
    filename.replace(['"', '\\'], "_")
}

async fn cleanup_missing_file_row(pool: DbPool, file_id: String) {
    let result = spawn_blocking(move || -> Result<(), String> {
        let conn = pool.get().map_err(|e| e.to_string())?;
        conn.execute(
            "DELETE FROM links WHERE file_id = ?",
            params![file_id.clone()],
        )
        .map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM files WHERE id = ?", params![file_id])
            .map_err(|e| e.to_string())?;
        Ok(())
    })
    .await;

    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => warn(&format!(
            "Skipping not-found file cleanup because row deletion failed: {err}"
        )),
        Err(err) => warn(&format!(
            "Skipping not-found file cleanup because cleanup task failed: {err}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use duckdb::params;
    use rocket::http::{Header, Status};
    use rocket::local::asynchronous::Client;

    struct TestServer {
        _temp: tempfile::TempDir,
        pool: DbPool,
        client: Client,
    }

    async fn test_server() -> TestServer {
        let temp = tempfile::tempdir().unwrap();
        let mount = temp.path().to_str().unwrap().to_string();
        crate::create_path_recursive(Some(mount.clone()));

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
        let pool = crate::create_db_pool(db_path.to_str().unwrap());
        crate::db_integrity(&pool).await;
        {
            let conn = pool.get().unwrap();
            conn.execute(
                "INSERT OR IGNORE INTO permissions (id, weight, is_root) VALUES ('everyone', 0, FALSE)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT OR IGNORE INTO users (id, username, password_hash, is_everyone, permission_id) VALUES ('everyone', 'everyone', '', TRUE, 'everyone')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO file_perms (id, permission_id, path, recursive, read) VALUES ('everyone_allowed', 'everyone', '/allowed', TRUE, TRUE)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO files (id, path, type, mime_type, size, link, link_target, cache, cache_dur) VALUES (?, ?, 'file', ?, ?, 'local', ?, ?, 0)",
                params![
                    "served",
                    "/allowed/served.txt",
                    "text/plain",
                    11i64,
                    "allowed/served.txt",
                    true
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO files (id, path, type, mime_type, size, link, link_target, cache, cache_dur) VALUES (?, ?, 'file', 'text/plain', 0, 'local', ?, FALSE, 0)",
                params!["denied", "/denied.txt", "missing-denied.txt"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO files (id, path, type, mime_type, size, link, link_target, cache, cache_dur) VALUES (?, ?, 'file', 'text/plain', 0, 'local', ?, FALSE, 0)",
                params!["missing_keep", "/allowed/missing-keep.txt", "allowed/missing-keep.txt"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO files (id, path, type, mime_type, size, link, link_target, cache, cache_dur) VALUES (?, ?, 'file', 'text/plain', 0, 'local', ?, FALSE, 0)",
                params!["missing_delete", "/allowed/missing-delete.txt", "allowed/missing-delete.txt"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO files (id, path, type, mime_type, size, link, link_target, cache, cache_dur) VALUES (?, ?, 'file', 'text/plain', 11, 'base64_data_url', ?, TRUE, 0)",
                params![
                    "data_cache",
                    "/allowed/data-cache.txt",
                    "data:text/plain;base64,SGVsbG8gd29ybGQ="
                ],
            )
            .unwrap();
        }

        let file_path = temp.path().join("files").join("allowed").join("served.txt");
        tokio::fs::create_dir_all(file_path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&file_path, b"hello world").await.unwrap();

        let rocket = rocket::build()
            .manage(pool.clone())
            .mount("/api", routes![get_file]);
        let client = Client::untracked(rocket).await.unwrap();

        TestServer {
            _temp: temp,
            pool,
            client,
        }
    }

    fn row_exists(pool: &DbPool, path: &str) -> bool {
        let conn = pool.get().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM files WHERE path = ?",
                params![path],
                |row| row.get(0),
            )
            .unwrap();
        count > 0
    }

    fn set_cleanup(value: bool) {
        let mut guard = CONFIG.lock().unwrap();
        let mut config = guard.as_ref().unwrap().cloned_for_request();
        config.remove_not_found_files = Some(value);
        guard.replace(config);
    }

    #[tokio::test]
    async fn file_route_serves_local_ranges_permissions_and_cleanup() {
        let server = test_server().await;

        let response = server
            .client
            .get("/api/file/missing-row.txt")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        let response = server.client.get("/api/file/denied.txt").dispatch().await;
        assert_eq!(response.status(), Status::Forbidden);

        set_cleanup(false);
        let response = server
            .client
            .get("/api/file/allowed/missing-keep.txt")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);
        assert!(row_exists(&server.pool, "/allowed/missing-keep.txt"));

        set_cleanup(true);
        let response = server
            .client
            .get("/api/file/allowed/missing-delete.txt")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);
        assert!(!row_exists(&server.pool, "/allowed/missing-delete.txt"));
        set_cleanup(false);

        let response = server
            .client
            .get("/api/file/allowed/served.txt")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.headers().get_one("Content-Type"),
            Some("text/plain")
        );
        assert_eq!(response.headers().get_one("Content-Length"), Some("11"));
        assert_eq!(response.headers().get_one("Accept-Ranges"), Some("bytes"));
        assert_eq!(response.into_bytes().await.unwrap(), b"hello world");

        let response = server
            .client
            .get("/api/file/allowed/served.txt")
            .header(Header::new("Range", "bytes=6-10"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::PartialContent);
        assert_eq!(
            response.headers().get_one("Content-Range"),
            Some("bytes 6-10/11")
        );
        assert_eq!(response.into_bytes().await.unwrap(), b"world");

        let response = server
            .client
            .get("/api/file/allowed/served.txt")
            .header(Header::new("Range", "bytes=99-100"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::RangeNotSatisfiable);
        assert_eq!(
            response.headers().get_one("Content-Range"),
            Some("bytes */11")
        );

        let response = server
            .client
            .get("/api/file/allowed/data-cache.txt?cache=false")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.headers().get_one("Cache-Control"),
            Some("no-store")
        );
        assert_eq!(response.into_bytes().await.unwrap(), b"Hello world");
    }
}
