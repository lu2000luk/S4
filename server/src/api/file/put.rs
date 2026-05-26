use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use duckdb::params;
use flate2::read::{GzDecoder, ZlibDecoder};
use mime_type::MimeFormat;
use rocket::State;
use rocket::data::{Data, ToByteUnit};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::status;
use rocket::serde::Serialize;
use rocket::tokio::fs as tokio_fs;
use rocket::tokio::io::{AsyncReadExt, AsyncWriteExt};
use rocket::tokio::task::spawn_blocking;
use s4_macros::put;
use uuid::Uuid;

use crate::{
    CONFIG, DbPool,
    config::Config,
    logger::{log, warn},
    utils::{
        permissions::{
            FilePermType, FilePermission, PermissionEngine, load_engine_sync, load_permission_sync,
        },
        pstr::{
            JsonResponseWithWarning, ParsedPermissionString, PermissionStringHeaders,
            PermissionStringQuery, insert_default_read_permission, insert_permission_string_entries,
            parse_creation_permission_string,
        },
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompressionType {
    Gzip,
    Zlib,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OffsetMode {
    Append,
    Override,
}

#[derive(Debug, Clone, Default)]
pub struct UploadHeaders {
    x_byte_offset: Option<String>,
    upload_offset: Option<String>,
    content_range: Option<String>,
    x_compressed: Option<String>,
    content_encoding: Option<String>,
    content_length: Option<String>,
    x_permissions: Option<String>,
    x_perms: Option<String>,
    x_perm: Option<String>,
    x_permission: Option<String>,
}

#[derive(Debug, Clone)]
struct ExistingFile {
    id: String,
    size: i64,
    mime_type: Option<String>,
    link: Option<String>,
    link_target: Option<String>,
    created_by_id: Option<String>,
}

#[derive(Debug, Clone)]
struct Preflight {
    user_id: String,
    permission_id: String,
    is_root: bool,
    total_storage_size: Option<i64>,
    existing: Option<ExistingFile>,
}

#[derive(Debug, Serialize)]
struct PutFileResponse {
    id: String,
    path: String,
    r#type: String,
    size: i64,
    mime_type: Option<String>,
    link: String,
    link_target: String,
    created_by_id: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for UploadHeaders {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(UploadHeaders {
            x_byte_offset: request
                .headers()
                .get_one("X-Byte-Offset")
                .map(str::to_string),
            upload_offset: request
                .headers()
                .get_one("Upload-Offset")
                .map(str::to_string),
            content_range: request
                .headers()
                .get_one("Content-Range")
                .map(str::to_string),
            x_compressed: request
                .headers()
                .get_one("X-Compressed")
                .map(str::to_string),
            content_encoding: request
                .headers()
                .get_one("Content-Encoding")
                .map(str::to_string),
            content_length: request
                .headers()
                .get_one("Content-Length")
                .map(str::to_string),
            x_permissions: request
                .headers()
                .get_one("X-Permissions")
                .map(str::to_string),
            x_perms: request.headers().get_one("X-Perms").map(str::to_string),
            x_perm: request.headers().get_one("X-Perm").map(str::to_string),
            x_permission: request
                .headers()
                .get_one("X-Permission")
                .map(str::to_string),
        })
    }
}

impl UploadHeaders {
    fn permission_string_headers(&self) -> PermissionStringHeaders {
        PermissionStringHeaders::new(
            self.x_permissions.clone(),
            self.x_perms.clone(),
            self.x_perm.clone(),
            self.x_permission.clone(),
        )
    }
}

#[put(
    "/file/<path..>?<start>&<offsetmode>&<compressed>&<permissions>&<permission>&<perms>&<perm>",
    data = "<data>"
)]
pub async fn put_file(
    path: PathBuf,
    start: Option<String>,
    offsetmode: Option<String>,
    compressed: Option<String>,
    permissions: Option<String>,
    permission: Option<String>,
    perms: Option<String>,
    perm: Option<String>,
    headers: UploadHeaders,
    data: Data<'_>,
    auth_key: String,
    pool: &State<DbPool>,
) -> Result<JsonResponseWithWarning, status::Custom<String>> {
    let normalized_path = normalize_file_path(&path.to_string_lossy())?;
    if normalized_path == "/" {
        return Err(status::Custom(
            Status::BadRequest,
            "ERROR File path is required".to_string(),
        ));
    }

    let byte_offset = parse_byte_offset(start.as_deref(), &headers)?;
    let offset_mode = parse_offset_mode(offsetmode.as_deref())?;
    let compression = parse_compression(compressed.as_deref(), &headers)?;
    let config = current_config();
    let permission_query = PermissionStringQuery {
        permissions,
        permission,
        perms,
        perm,
    };
    let permission_string = parse_creation_permission_string(
        permission_query.selected_value(&headers.permission_string_headers()),
        config.ignore_errors(),
    )?;

    if compression.is_some() {
        if let Some(content_length) = parse_optional_u64(headers.content_length.as_deref())? {
            if content_length > config.max_compression_upload() {
                return Err(max_compression_error());
            }
        }
    }

    let pool_for_preflight = pool.inner().clone();
    let path_for_preflight = normalized_path.clone();
    let auth_for_preflight = auth_key.clone();
    let preflight = spawn_blocking(move || {
        preflight_upload(pool_for_preflight, auth_for_preflight, path_for_preflight)
    })
    .await
    .map_err(|_| task_error())??;

    log(&format!(
        "PUT upload attempt user={} path={}",
        preflight.user_id, normalized_path
    ));

    let processing_dir = Path::new(config.mount())
        .join(".s4")
        .join("processing")
        .join(generate_processing_id());
    tokio_fs::create_dir_all(&processing_dir)
        .await
        .map_err(|e| {
            status::Custom(
                Status::InternalServerError,
                format!("ERROR Failed to create processing directory: {e}"),
            )
        })?;

    let upload_path = processing_dir.join("upload.bin");
    let upload_size = match stream_body_to_processing_file(
        data,
        &upload_path,
        compression
            .is_some()
            .then_some(config.max_compression_upload()),
    )
    .await
    {
        Ok(size) => size,
        Err(err) => {
            cleanup_processing_dir(&processing_dir).await;
            return Err(err);
        }
    };

    if compression.is_some() && upload_size > config.max_compression_upload() {
        cleanup_processing_dir(&processing_dir).await;
        return Err(max_compression_error());
    }

    let job = UploadJob {
        pool: pool.inner().clone(),
        mount: config.mount().to_string(),
        normalized_path,
        upload_path,
        compression,
        byte_offset,
        offset_mode,
        preflight,
        permission_string,
    };

    let result = spawn_blocking(move || run_upload_job(job))
        .await
        .map_err(|_| task_error())?;

    cleanup_processing_dir(&processing_dir).await;
    result.and_then(|response| {
        let warning = response.permission_warning.clone();
        serde_json::to_string(&response.body)
            .map(|body| JsonResponseWithWarning { body, warning })
            .map_err(|e| {
                status::Custom(
                    Status::InternalServerError,
                    format!("ERROR Failed to serialize response: {e}"),
                )
            })
    })
}

struct UploadJob {
    pool: DbPool,
    mount: String,
    normalized_path: String,
    upload_path: PathBuf,
    compression: Option<CompressionType>,
    byte_offset: Option<u64>,
    offset_mode: OffsetMode,
    preflight: Preflight,
    permission_string: Option<ParsedPermissionString>,
}

struct PutFileJobResponse {
    body: PutFileResponse,
    permission_warning: Option<String>,
}

fn run_upload_job(job: UploadJob) -> Result<PutFileJobResponse, status::Custom<String>> {
    let destination = local_destination_path(&job.mount, &job.normalized_path);
    ensure_parent_dirs(&destination)?;

    let temp_path = temp_sibling_path(&destination, "tmp");
    let rollback_path = temp_sibling_path(&destination, "rollback");

    let conn = job.pool.get().map_err(|_| {
        status::Custom(
            Status::InternalServerError,
            "ERROR Failed to get connection from pool".to_string(),
        )
    })?;
    let max_final_size = quota_final_size_limit(&conn, &job.preflight)?;

    let write_result = assemble_destination_file(&job, &destination, &temp_path, max_final_size);
    let final_size = match write_result {
        Ok(size) => size,
        Err(err) => {
            remove_file_if_exists(&temp_path);
            return Err(err);
        }
    };

    replace_destination(&destination, &temp_path, &rollback_path)?;

    if !quota_allows(&conn, &job.preflight, final_size)? {
        warn(&format!(
            "PUT upload quota rejected user={} path={}",
            job.preflight.user_id, job.normalized_path
        ));
        rollback_destination(&destination, &rollback_path);
        return Err(max_compression_error());
    }

    let response = upsert_file_row(&conn, &job, final_size).map_err(|err| {
        rollback_destination(&destination, &rollback_path);
        err
    })?;

    remove_file_if_exists(&rollback_path);
    Ok(response)
}

fn preflight_upload(
    pool: DbPool,
    auth_key: String,
    normalized_path: String,
) -> Result<Preflight, status::Custom<String>> {
    let conn = pool.get().map_err(|_| {
        status::Custom(
            Status::InternalServerError,
            "ERROR Failed to get connection from pool".to_string(),
        )
    })?;

    let (user_id, permission_id, engine) = if auth_key.is_empty() {
        let engine = load_engine_sync(&conn, "everyone").ok_or_else(|| {
            status::Custom(
                Status::InternalServerError,
                "ERROR Failed to load permissions".to_string(),
            )
        })?;
        ("everyone".to_string(), "everyone".to_string(), engine)
    } else {
        let (user_id, permission_id): (String, String) = conn
            .query_row(
                "SELECT owner_id, permission_id FROM keys WHERE key = ?",
                params![auth_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| {
                status::Custom(Status::Unauthorized, "ERROR Invalid auth key".to_string())
            })?;
        let permissions = load_permission_sync(&conn, &permission_id).ok_or_else(|| {
            status::Custom(
                Status::InternalServerError,
                "ERROR Failed to load permissions".to_string(),
            )
        })?;
        (user_id, permission_id, PermissionEngine::new(permissions))
    };

    let existing = load_existing_file(&conn, &normalized_path)?;
    if let Some(file) = &existing {
        if file.link.as_deref() == Some("local") && file.link_target.as_deref().is_none() {
            return Err(status::Custom(
                Status::BadRequest,
                "ERROR Invalid local file record".to_string(),
            ));
        }
    }

    if !engine.get_permissions().is_root {
        let has_write = engine
            .get_file_perms_sync(&conn, &normalized_path)
            .map_err(|e| status::Custom(Status::InternalServerError, format!("ERROR {e}")))?
            .has(&FilePermission::new(
                normalized_path.clone(),
                FilePermType::Write,
            ));

        if !has_write {
            return Err(status::Custom(
                Status::Forbidden,
                "ERROR You do not have permission to write this file".to_string(),
            ));
        }
    }

    Ok(Preflight {
        user_id,
        permission_id,
        is_root: engine.get_permissions().is_root,
        total_storage_size: engine.get_permissions().total_storage_size,
        existing,
    })
}

fn load_existing_file(
    conn: &duckdb::Connection,
    normalized_path: &str,
) -> Result<Option<ExistingFile>, status::Custom<String>> {
    match conn.query_row(
        "SELECT id, size, mime_type, link, link_target, created_by_id, type FROM files WHERE path = ?",
        params![normalized_path],
        |row| {
            let file_type: String = row.get(6)?;
            Ok((
                ExistingFile {
                    id: row.get(0)?,
                    size: row.get(1)?,
                    mime_type: row.get(2)?,
                    link: row.get(3)?,
                    link_target: row.get(4)?,
                    created_by_id: row.get(5)?,
                },
                file_type,
            ))
        },
    ) {
        Ok((file, file_type)) if file_type == "file" => Ok(Some(file)),
        Ok(_) => Err(status::Custom(
            Status::BadRequest,
            "ERROR Target path is not a file".to_string(),
        )),
        Err(_) => Ok(None),
    }
}

async fn stream_body_to_processing_file(
    data: Data<'_>,
    upload_path: &Path,
    compressed_limit: Option<u64>,
) -> Result<u64, status::Custom<String>> {
    let limit = compressed_limit
        .and_then(|value| value.checked_add(1))
        .unwrap_or(u64::MAX);
    let mut stream = data.open(limit.bytes());
    let mut file = tokio_fs::File::create(upload_path).await.map_err(|e| {
        status::Custom(
            Status::InternalServerError,
            format!("ERROR Failed to create processing file: {e}"),
        )
    })?;

    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = stream.read(&mut buffer).await.map_err(|e| {
            status::Custom(
                Status::InternalServerError,
                format!("ERROR Failed to read upload body: {e}"),
            )
        })?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(|| {
            status::Custom(Status::BadRequest, "ERROR Upload is too large".to_string())
        })?;
        if compressed_limit.is_some_and(|max| total > max) {
            return Err(max_compression_error());
        }
        file.write_all(&buffer[..read]).await.map_err(|e| {
            status::Custom(
                Status::InternalServerError,
                format!("ERROR Failed to write processing file: {e}"),
            )
        })?;
    }
    file.flush().await.map_err(|e| {
        status::Custom(
            Status::InternalServerError,
            format!("ERROR Failed to flush processing file: {e}"),
        )
    })?;
    Ok(total)
}

fn assemble_destination_file(
    job: &UploadJob,
    destination: &Path,
    temp_path: &Path,
    max_final_size: Option<u64>,
) -> Result<i64, status::Custom<String>> {
    let source = File::open(&job.upload_path).map_err(|e| {
        status::Custom(
            Status::InternalServerError,
            format!("ERROR Failed to open processing file: {e}"),
        )
    })?;

    let mut reader: Box<dyn Read> = match job.compression {
        Some(CompressionType::Gzip) => Box::new(GzDecoder::new(source)),
        Some(CompressionType::Zlib) => Box::new(ZlibDecoder::new(source)),
        None => Box::new(source),
    };

    let mut temp = OpenOptions::new()
        .create_new(true)
        .write(true)
        .read(true)
        .open(temp_path)
        .map_err(|e| {
            status::Custom(
                Status::InternalServerError,
                format!("ERROR Failed to create temporary output file: {e}"),
            )
        })?;

    let existing_len = fs::metadata(destination).map(|m| m.len()).unwrap_or(0);
    let write_start = job.byte_offset.unwrap_or(0);

    if let Some(offset) = job.byte_offset {
        copy_existing_prefix(destination, &mut temp, offset)?;
        enforce_temp_size_limit(&mut temp, max_final_size)?;
        if offset > existing_len {
            temp.set_len(offset).map_err(|e| {
                status::Custom(
                    Status::InternalServerError,
                    format!("ERROR Failed to extend temporary output file: {e}"),
                )
            })?;
            enforce_temp_size_limit(&mut temp, max_final_size)?;
        }
        temp.seek(SeekFrom::Start(offset)).map_err(|e| {
            status::Custom(
                Status::InternalServerError,
                format!("ERROR Failed to seek temporary output file: {e}"),
            )
        })?;
    }

    let written = copy_reader_counted(&mut reader, &mut temp, max_final_size)?;

    if job.byte_offset.is_some() && job.offset_mode == OffsetMode::Append {
        let tail_start = write_start.saturating_add(written);
        if tail_start < existing_len {
            copy_existing_tail(destination, &mut temp, tail_start)?;
            enforce_temp_size_limit(&mut temp, max_final_size)?;
        }
    }

    temp.flush().map_err(|e| {
        status::Custom(
            Status::InternalServerError,
            format!("ERROR Failed to flush temporary output file: {e}"),
        )
    })?;
    let size = temp.metadata().map_err(|e| {
        status::Custom(
            Status::InternalServerError,
            format!("ERROR Failed to read temporary output size: {e}"),
        )
    })?;
    i64::try_from(size.len()).map_err(|_| {
        status::Custom(
            Status::BadRequest,
            "ERROR Uploaded file is too large".to_string(),
        )
    })
}

fn copy_existing_prefix(
    destination: &Path,
    temp: &mut File,
    offset: u64,
) -> Result<(), status::Custom<String>> {
    if offset == 0 || !destination.exists() {
        return Ok(());
    }

    let existing = File::open(destination).map_err(|e| {
        status::Custom(
            Status::InternalServerError,
            format!("ERROR Failed to open existing file: {e}"),
        )
    })?;
    let mut limited = existing.take(offset);
    std::io::copy(&mut limited, temp).map_err(|e| {
        status::Custom(
            Status::InternalServerError,
            format!("ERROR Failed to copy existing file prefix: {e}"),
        )
    })?;
    Ok(())
}

fn copy_existing_tail(
    destination: &Path,
    temp: &mut File,
    tail_start: u64,
) -> Result<(), status::Custom<String>> {
    let mut existing = File::open(destination).map_err(|e| {
        status::Custom(
            Status::InternalServerError,
            format!("ERROR Failed to open existing file: {e}"),
        )
    })?;
    existing.seek(SeekFrom::Start(tail_start)).map_err(|e| {
        status::Custom(
            Status::InternalServerError,
            format!("ERROR Failed to seek existing file: {e}"),
        )
    })?;
    std::io::copy(&mut existing, temp).map_err(|e| {
        status::Custom(
            Status::InternalServerError,
            format!("ERROR Failed to copy existing file tail: {e}"),
        )
    })?;
    Ok(())
}

fn copy_reader_counted(
    reader: &mut dyn Read,
    writer: &mut File,
    max_size: Option<u64>,
) -> Result<u64, status::Custom<String>> {
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|e| {
            status::Custom(
                Status::BadRequest,
                format!("ERROR Failed to process upload body: {e}"),
            )
        })?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read]).map_err(|e| {
            status::Custom(
                Status::InternalServerError,
                format!("ERROR Failed to write temporary output file: {e}"),
            )
        })?;
        total = total.checked_add(read as u64).ok_or_else(|| {
            status::Custom(Status::BadRequest, "ERROR Upload is too large".to_string())
        })?;
        enforce_temp_size_limit(writer, max_size)?;
    }
    Ok(total)
}

fn enforce_temp_size_limit(
    temp: &mut File,
    max_size: Option<u64>,
) -> Result<(), status::Custom<String>> {
    let Some(max_size) = max_size else {
        return Ok(());
    };
    let position = temp.stream_position().map_err(|e| {
        status::Custom(
            Status::InternalServerError,
            format!("ERROR Failed to inspect temporary output file: {e}"),
        )
    })?;
    if position > max_size {
        return Err(max_compression_error());
    }
    Ok(())
}

fn quota_final_size_limit(
    conn: &duckdb::Connection,
    preflight: &Preflight,
) -> Result<Option<u64>, status::Custom<String>> {
    if preflight.is_root {
        return Ok(None);
    }

    let Some(max_storage) = preflight.total_storage_size else {
        return Ok(None);
    };

    let current = calculate_user_storage(conn, &preflight.permission_id)?;
    let old_size = if let Some(existing) = &preflight.existing {
        if owner_belongs_to_permission(
            conn,
            existing.created_by_id.as_deref(),
            &preflight.permission_id,
        )? {
            existing.size.max(0)
        } else {
            0
        }
    } else {
        0
    };
    let occupied_without_current_file = current.checked_sub(old_size).ok_or_else(|| {
        status::Custom(
            Status::BadRequest,
            "ERROR Uploaded file is too large".to_string(),
        )
    })?;
    let available = max_storage
        .checked_sub(occupied_without_current_file)
        .unwrap_or(0);
    u64::try_from(available)
        .map(Some)
        .map_err(|_| max_compression_error())
}

fn quota_allows(
    conn: &duckdb::Connection,
    preflight: &Preflight,
    final_size: i64,
) -> Result<bool, status::Custom<String>> {
    if preflight.is_root {
        return Ok(true);
    }

    let Some(max_storage) = preflight.total_storage_size else {
        return Ok(true);
    };

    let current = calculate_user_storage(conn, &preflight.permission_id)?;
    let old_size = if let Some(existing) = &preflight.existing {
        if owner_belongs_to_permission(
            conn,
            existing.created_by_id.as_deref(),
            &preflight.permission_id,
        )? {
            existing.size.max(0)
        } else {
            0
        }
    } else {
        0
    };

    let adjusted = current
        .checked_sub(old_size)
        .and_then(|value| value.checked_add(final_size))
        .ok_or_else(|| {
            status::Custom(
                Status::BadRequest,
                "ERROR Uploaded file is too large".to_string(),
            )
        })?;
    Ok(adjusted <= max_storage)
}

fn calculate_user_storage(
    conn: &duckdb::Connection,
    permission_id: &str,
) -> Result<i64, status::Custom<String>> {
    conn.query_row(
        r#"
            SELECT COALESCE(SUM(files.size), 0)
            FROM files
            LEFT JOIN users ON files.created_by_id = users.id
            WHERE users.permission_id = ? OR files.created_by_id = ?
        "#,
        params![permission_id, permission_id],
        |row| row.get(0),
    )
    .map_err(|e| {
        status::Custom(
            Status::InternalServerError,
            format!("ERROR Failed to calculate storage usage: {e}"),
        )
    })
}

fn owner_belongs_to_permission(
    conn: &duckdb::Connection,
    owner_id: Option<&str>,
    permission_id: &str,
) -> Result<bool, status::Custom<String>> {
    let Some(owner_id) = owner_id else {
        return Ok(false);
    };
    if owner_id == permission_id {
        return Ok(true);
    }
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM users WHERE id = ? AND permission_id = ?",
            params![owner_id, permission_id],
            |row| row.get(0),
        )
        .map_err(|e| {
            status::Custom(
                Status::InternalServerError,
                format!("ERROR Failed to check storage owner: {e}"),
            )
        })?;
    Ok(count > 0)
}

fn upsert_file_row(
    conn: &duckdb::Connection,
    job: &UploadJob,
    final_size: i64,
) -> Result<PutFileJobResponse, status::Custom<String>> {
    let mime_type = detect_mime_type(&job.normalized_path).or_else(|| {
        job.preflight
            .existing
            .as_ref()
            .and_then(|f| f.mime_type.clone())
    });
    let link_target = job.normalized_path.trim_start_matches('/').to_string();
    let created_by_id = job.preflight.user_id.clone();

    let mut permission_warning = None;
    let file_id = if let Some(existing) = &job.preflight.existing {
        conn.execute(
            "UPDATE files SET size = ?, mime_type = ?, link = 'local', link_target = ?, created_by_id = COALESCE(created_by_id, ?), updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            params![
                final_size,
                mime_type.clone(),
                link_target.clone(),
                created_by_id.clone(),
                existing.id.clone(),
            ],
        )
        .map_err(|e| {
            status::Custom(
                Status::InternalServerError,
                format!("ERROR Failed to update file record: {e}"),
            )
        })?;
        existing.id.clone()
    } else {
        let file_id = generate_file_id();
        conn.execute(
            "INSERT INTO files (id, path, metadata, type, mime_type, size, link, link_target, cache, cache_dur, created_by_id, created_at, updated_at) VALUES (?, ?, '{}', 'file', ?, ?, 'local', ?, FALSE, 0, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            params![
                file_id.clone(),
                job.normalized_path.clone(),
                mime_type.clone(),
                final_size,
                link_target.clone(),
                created_by_id.clone(),
            ],
        )
        .map_err(|e| {
            status::Custom(
                Status::InternalServerError,
                format!("ERROR Failed to create file record: {e}"),
            )
        })?;
        if let Some(permission_string) = &job.permission_string {
            insert_permission_string_entries(conn, &job.normalized_path, &permission_string.entries)?;
            permission_warning = permission_string.warning.clone();
        } else {
            insert_default_read_permission(conn, &job.normalized_path)?;
        }
        file_id
    };

    Ok(PutFileJobResponse {
        body: PutFileResponse {
            id: file_id,
            path: job.normalized_path.clone(),
            r#type: "file".to_string(),
            size: final_size,
            mime_type,
            link: "local".to_string(),
            link_target,
            created_by_id,
        },
        permission_warning,
    })
}

fn replace_destination(
    destination: &Path,
    temp_path: &Path,
    rollback_path: &Path,
) -> Result<(), status::Custom<String>> {
    remove_file_if_exists(rollback_path);
    if destination.exists() {
        fs::rename(destination, rollback_path).map_err(|e| {
            status::Custom(
                Status::InternalServerError,
                format!("ERROR Failed to prepare existing file rollback: {e}"),
            )
        })?;
    }

    if let Err(err) = fs::rename(temp_path, destination) {
        rollback_destination(destination, rollback_path);
        return Err(status::Custom(
            Status::InternalServerError,
            format!("ERROR Failed to move uploaded file into place: {err}"),
        ));
    }

    Ok(())
}

fn rollback_destination(destination: &Path, rollback_path: &Path) {
    remove_file_if_exists(destination);
    if rollback_path.exists() {
        if let Err(err) = fs::rename(rollback_path, destination) {
            warn(&format!(
                "Failed to restore previous file during rollback: {err}"
            ));
        }
    }
}

fn local_destination_path(mount: &str, normalized_path: &str) -> PathBuf {
    Path::new(mount)
        .join("files")
        .join(normalized_path.trim_start_matches('/'))
}

fn ensure_parent_dirs(path: &Path) -> Result<(), status::Custom<String>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            status::Custom(
                Status::InternalServerError,
                format!("ERROR Failed to create parent directories: {e}"),
            )
        })?;
    }
    Ok(())
}

fn temp_sibling_path(destination: &Path, kind: &str) -> PathBuf {
    let filename = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("upload");
    destination.with_file_name(format!(".{filename}.{kind}.{}", Uuid::new_v4()))
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

fn parse_byte_offset(
    query_start: Option<&str>,
    headers: &UploadHeaders,
) -> Result<Option<u64>, status::Custom<String>> {
    if let Some(value) = query_start {
        return parse_u64(value, "start").map(Some);
    }
    if let Some(value) = headers.x_byte_offset.as_deref() {
        return parse_u64(value, "X-Byte-Offset").map(Some);
    }
    if let Some(value) = headers.upload_offset.as_deref() {
        return parse_u64(value, "Upload-Offset").map(Some);
    }
    if let Some(value) = headers.content_range.as_deref() {
        return parse_content_range_start(value).map(Some);
    }
    Ok(None)
}

fn parse_offset_mode(value: Option<&str>) -> Result<OffsetMode, status::Custom<String>> {
    match value.map(|v| v.trim().to_ascii_lowercase()) {
        None => Ok(OffsetMode::Append),
        Some(value) if value == "append" => Ok(OffsetMode::Append),
        Some(value) if value == "override" => Ok(OffsetMode::Override),
        Some(_) => Err(status::Custom(
            Status::BadRequest,
            "ERROR Invalid offsetmode".to_string(),
        )),
    }
}

fn parse_compression(
    query_compressed: Option<&str>,
    headers: &UploadHeaders,
) -> Result<Option<CompressionType>, status::Custom<String>> {
    if let Some(value) = query_compressed {
        return parse_compression_value(value);
    }
    if let Some(value) = headers.x_compressed.as_deref() {
        return parse_compression_value(value);
    }
    if let Some(value) = headers.content_encoding.as_deref() {
        return parse_compression_value(value);
    }
    Ok(None)
}

fn parse_compression_value(value: &str) -> Result<Option<CompressionType>, status::Custom<String>> {
    let lower = value.trim().to_ascii_lowercase();
    match lower.as_str() {
        "" | "identity" | "none" | "false" => Ok(None),
        "gzip" => Ok(Some(CompressionType::Gzip)),
        "zlib" | "deflate" => Ok(Some(CompressionType::Zlib)),
        _ => Err(status::Custom(
            Status::BadRequest,
            "ERROR Invalid compression type".to_string(),
        )),
    }
}

fn parse_content_range_start(value: &str) -> Result<u64, status::Custom<String>> {
    let trimmed = value.trim();
    let Some(range) = trimmed.strip_prefix("bytes ") else {
        return Err(status::Custom(
            Status::BadRequest,
            "ERROR Invalid Content-Range header".to_string(),
        ));
    };
    let Some((start, _rest)) = range.split_once('-') else {
        return Err(status::Custom(
            Status::BadRequest,
            "ERROR Invalid Content-Range header".to_string(),
        ));
    };
    parse_u64(start, "Content-Range")
}

fn parse_optional_u64(value: Option<&str>) -> Result<Option<u64>, status::Custom<String>> {
    value.map(|v| parse_u64(v, "Content-Length")).transpose()
}

fn parse_u64(value: &str, field: &str) -> Result<u64, status::Custom<String>> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|_| status::Custom(Status::BadRequest, format!("ERROR Invalid {field} value")))
}

fn detect_mime_type(path: &str) -> Option<String> {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .and_then(mime_type::MimeType::from_ext)
        .map(|mime| mime.to_string())
}

fn current_config() -> Config {
    let guard = CONFIG.lock().unwrap();
    guard
        .as_ref()
        .map(CloneForPutRequest::cloned_for_put_request)
        .unwrap_or_else(Config::defaulted)
}

trait CloneForPutRequest {
    fn cloned_for_put_request(&self) -> Config;
}

impl CloneForPutRequest for Config {
    fn cloned_for_put_request(&self) -> Config {
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
            max_compression_upload: Some(self.max_compression_upload()),
            ignore_errors: Some(self.ignore_errors()),
        }
    }
}

fn generate_processing_id() -> String {
    format!("processing-{}", Uuid::new_v4())
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

fn max_compression_error() -> status::Custom<String> {
    status::Custom(
        Status::PayloadTooLarge,
        "ERROR Max compressed upload size reached!".to_string(),
    )
}

fn task_error() -> status::Custom<String> {
    status::Custom(
        Status::InternalServerError,
        "ERROR Task join error".to_string(),
    )
}

fn remove_file_if_exists(path: &Path) {
    if path.exists() {
        if let Err(err) = fs::remove_file(path) {
            warn(&format!("Failed to remove file {}: {err}", path.display()));
        }
    }
}

async fn cleanup_processing_dir(path: &Path) {
    if let Err(err) = tokio_fs::remove_dir_all(path).await {
        warn(&format!(
            "Failed to cleanup processing directory {}: {err}",
            path.display()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use duckdb::params;
    use flate2::Compression;
    use flate2::write::{GzEncoder, ZlibEncoder};
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::asynchronous::Client;

    struct TestServer {
        _temp: tempfile::TempDir,
        mount: String,
        pool: DbPool,
        client: Client,
        _config_guard: std::sync::MutexGuard<'static, ()>,
    }

    async fn test_server() -> TestServer {
        let config_guard = crate::test_config_lock();
        let temp = tempfile::tempdir().unwrap();
        let mount = temp.path().to_str().unwrap().to_string();
        crate::create_path_recursive(Some(mount.clone()));

        {
            let mut config = Config::defaulted();
            config.mount = Some(mount.clone());
            config.remote_allow_local = Some(true);
            config.startup_sync = Some(false);
            config.auto_sync = Some(false);
            config.max_compression_upload = Some(1024);
            let mut guard = CONFIG.lock().unwrap();
            guard.replace(config);
        }

        let db_path = temp.path().join("s4.db");
        let pool = crate::create_db_pool(db_path.to_str().unwrap());
        crate::db_integrity(&pool).await;
        {
            let conn = pool.get().unwrap();
            conn.execute(
                "INSERT INTO permissions (id, weight, is_root, total_storage_size) VALUES ('writer', 10, FALSE, 100000)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO permissions (id, weight, is_root, total_storage_size) VALUES ('limited', 10, FALSE, 5)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO users (id, username, password_hash, is_everyone, permission_id) VALUES ('writer_user', 'writer_user', '', FALSE, 'writer')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO users (id, username, password_hash, is_everyone, permission_id) VALUES ('limited_user', 'limited_user', '', FALSE, 'limited')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO keys (id, key, owner_id, permission_id) VALUES ('writer_key', 'writer-key', 'writer_user', 'writer')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO keys (id, key, owner_id, permission_id) VALUES ('limited_key', 'limited-key', 'limited_user', 'limited')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO file_perms (id, permission_id, path, recursive, read, write, create_file) VALUES ('writer_allowed', 'writer', '/allowed', TRUE, TRUE, TRUE, TRUE)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO file_perms (id, permission_id, path, recursive, read, write, create_file) VALUES ('writer_denied', 'writer', '/denied', TRUE, TRUE, FALSE, TRUE)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO file_perms (id, permission_id, path, recursive, read, write, create_file) VALUES ('limited_allowed', 'limited', '/allowed', TRUE, TRUE, TRUE, TRUE)",
                [],
            )
            .unwrap();
        }

        let rocket = rocket::build()
            .manage(pool.clone())
            .mount("/api", routes![put_file]);
        let client = Client::untracked(rocket).await.unwrap();

        TestServer {
            _temp: temp,
            mount,
            pool,
            client,
            _config_guard: config_guard,
        }
    }

    fn read_local(mount: &str, rel: &str) -> Vec<u8> {
        fs::read(Path::new(mount).join("files").join(rel)).unwrap()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn zlib(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn put_file_creates_binary_file_and_row() {
        let server = test_server().await;
        let response = server
            .client
            .put("/api/file/allowed/blob.bin?key=writer-key")
            .header(ContentType::Binary)
            .body(vec![0, 1, 2, 3, 255])
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            read_local(&server.mount, "allowed/blob.bin"),
            vec![0, 1, 2, 3, 255]
        );

        let body = response.into_string().await.unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["path"], "/allowed/blob.bin");
        assert_eq!(json["size"], 5);
        assert_eq!(json["created_by_id"], "writer_user");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn put_file_supports_offset_append_and_override() {
        let server = test_server().await;

        let response = server
            .client
            .put("/api/file/allowed/text.txt?key=writer-key")
            .body("hello world")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let response = server
            .client
            .put("/api/file/allowed/text.txt?key=writer-key&start=6")
            .body("S4")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            read_local(&server.mount, "allowed/text.txt"),
            b"hello S4rld"
        );

        let response = server
            .client
            .put("/api/file/allowed/text.txt?key=writer-key&start=5&offsetmode=override")
            .body("!")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(read_local(&server.mount, "allowed/text.txt"), b"hello!");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn put_file_supports_offset_headers() {
        let server = test_server().await;

        let response = server
            .client
            .put("/api/file/allowed/header.txt?key=writer-key")
            .body("abcdef")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let response = server
            .client
            .put("/api/file/allowed/header.txt?key=writer-key")
            .header(Header::new("X-Byte-Offset", "2"))
            .body("ZZ")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(read_local(&server.mount, "allowed/header.txt"), b"abZZef");

        let response = server
            .client
            .put("/api/file/allowed/range.txt?key=writer-key")
            .header(Header::new("Content-Range", "bytes 3-5/6"))
            .body("xyz")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(read_local(&server.mount, "allowed/range.txt"), b"\0\0\0xyz");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn put_file_decompresses_gzip_and_zlib_uploads() {
        let server = test_server().await;

        let response = server
            .client
            .put("/api/file/allowed/gzip.txt?key=writer-key&compressed=gzip")
            .body(gzip(b"gzip text"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(read_local(&server.mount, "allowed/gzip.txt"), b"gzip text");

        let response = server
            .client
            .put("/api/file/allowed/zlib.txt?key=writer-key")
            .header(Header::new("X-Compressed", "zlib"))
            .body(zlib(b"zlib text"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(read_local(&server.mount, "allowed/zlib.txt"), b"zlib text");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn put_file_rejects_invalid_compression_and_denied_write() {
        let server = test_server().await;

        let response = server
            .client
            .put("/api/file/allowed/archive.txt?key=writer-key&compressed=zip")
            .body("nope")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);

        let response = server
            .client
            .put("/api/file/denied/file.txt?key=writer-key")
            .body("nope")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn put_file_rejects_quota_and_cleans_processing_dir() {
        let server = test_server().await;

        let response = server
            .client
            .put("/api/file/allowed/too-big.txt?key=limited-key")
            .body("too large")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::PayloadTooLarge);
        assert!(
            !Path::new(&server.mount)
                .join("files")
                .join("allowed/too-big.txt")
                .exists()
        );

        let processing = Path::new(&server.mount).join(".s4").join("processing");
        let count = fs::read_dir(processing)
            .map(|entries| entries.filter_map(Result::ok).count())
            .unwrap_or(0);
        assert_eq!(count, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn put_file_rejects_compressed_payload_over_limit() {
        let server = test_server().await;
        let response = server
            .client
            .put("/api/file/allowed/huge.gz?key=writer-key&compressed=gzip")
            .body(vec![0u8; 2048])
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::PayloadTooLarge);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn put_file_updates_existing_db_size() {
        let server = test_server().await;

        let response = server
            .client
            .put("/api/file/allowed/replace.txt?key=writer-key")
            .body("first")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let response = server
            .client
            .put("/api/file/allowed/replace.txt?key=writer-key")
            .body("second-value")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let conn = server.pool.get().unwrap();
        let size: i64 = conn
            .query_row(
                "SELECT size FROM files WHERE path = '/allowed/replace.txt'",
                params![],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(size, 12);
    }
}
