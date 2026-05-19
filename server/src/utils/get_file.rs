use std::{
    collections::HashMap,
    io::{self, Cursor, SeekFrom},
    path::{Component, Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use data_url::DataUrl;
use futures_util::TryStreamExt;
use mime_type::MimeFormat;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use tokio::{
    fs::{self, File},
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, ReadBuf},
};
use tokio_util::io::StreamReader;
use url::Url;

use crate::config::Config;

pub type BoxedAsyncRead = Pin<Box<dyn AsyncRead + Send + 'static>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSourceType {
    Ftp,
    Git,
    Http,
    Local,
    Base64DataUrl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheStatus {
    Disabled,
    BypassedUnauthenticated,
    Hit,
    Miss,
    NotCacheable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteRange {
    pub start: Option<u64>,
    pub end: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedRange {
    pub start: u64,
    pub end: u64,
    pub complete_size: u64,
}

#[derive(Debug, Clone)]
pub struct FileResolveRequest<'a> {
    pub source_type: FileSourceType,
    pub source_path: String,
    pub virtual_path: String,
    pub effective_cache: bool,
    pub cache_duration_ms: u64,
    pub authenticated: bool,
    pub range: Option<ByteRange>,
    pub config: &'a Config,
}

pub struct ResolvedFile {
    pub reader: BoxedAsyncRead,
    pub filename: String,
    pub mime_type: Option<String>,
    pub full_size: Option<u64>,
    pub content_length: Option<u64>,
    pub served_range: Option<ServedRange>,
    pub cache_status: CacheStatus,
    pub metadata_headers: HashMap<String, String>,
    pub upstream_status: Option<u16>,
}

#[derive(Debug)]
pub enum FileResolveError {
    BadRequest(String),
    Forbidden(String),
    NotFoundDefinite(String),
    RangeNotSatisfiable(Option<u64>),
    UpstreamFailure(String),
    InternalFailure(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CacheMetadata {
    pub source_path_hash: String,
    pub original_source_path: String,
    pub filename: String,
    pub size: u64,
    pub created_timestamp: i64,
    pub last_accessed_timestamp: i64,
    pub mime_type: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

pub fn parse_range_header(header: &str) -> Result<Option<ByteRange>, FileResolveError> {
    let Some(spec) = header.strip_prefix("bytes=") else {
        return Err(FileResolveError::BadRequest(
            "only bytes ranges are supported".to_string(),
        ));
    };

    if spec.contains(',') {
        return Err(FileResolveError::BadRequest(
            "multiple ranges are not supported".to_string(),
        ));
    }

    let Some((start, end)) = spec.split_once('-') else {
        return Err(FileResolveError::BadRequest(
            "invalid range syntax".to_string(),
        ));
    };

    if start.is_empty() && end.is_empty() {
        return Err(FileResolveError::BadRequest(
            "empty range is invalid".to_string(),
        ));
    }

    let parsed_start = if start.is_empty() {
        None
    } else {
        Some(
            start
                .parse::<u64>()
                .map_err(|_| FileResolveError::BadRequest("invalid range start".to_string()))?,
        )
    };

    let parsed_end = if end.is_empty() {
        None
    } else {
        Some(
            end.parse::<u64>()
                .map_err(|_| FileResolveError::BadRequest("invalid range end".to_string()))?,
        )
    };

    if let (Some(start), Some(end)) = (parsed_start, parsed_end) {
        if start > end {
            return Ok(Some(ByteRange {
                start: Some(start),
                end: Some(end),
            }));
        }
    }

    Ok(Some(ByteRange {
        start: parsed_start,
        end: parsed_end,
    }))
}

pub fn resolve_range(range: &ByteRange, size: u64) -> Result<ServedRange, FileResolveError> {
    if size == 0 {
        return Err(FileResolveError::RangeNotSatisfiable(Some(size)));
    }

    match (range.start, range.end) {
        (Some(start), Some(end)) if start <= end && start < size => Ok(ServedRange {
            start,
            end: end.min(size - 1),
            complete_size: size,
        }),
        (Some(start), None) if start < size => Ok(ServedRange {
            start,
            end: size - 1,
            complete_size: size,
        }),
        (None, Some(suffix)) if suffix > 0 => {
            let len = suffix.min(size);
            Ok(ServedRange {
                start: size - len,
                end: size - 1,
                complete_size: size,
            })
        }
        _ => Err(FileResolveError::RangeNotSatisfiable(Some(size))),
    }
}

pub fn effective_cache(query_cache: Option<bool>, db_cache: Option<bool>, config: &Config) -> bool {
    let row_value = db_cache.unwrap_or_else(|| config.default_use_cache());

    if let Some(query_value) = query_cache {
        let query_can_override_row = db_cache.is_none() || config.allow_query_override_db();
        if config.allow_query_override_default() && query_can_override_row {
            return query_value;
        }
    }

    row_value
}

pub fn cache_key(source_path: &str) -> String {
    format!("{:x}", Sha1::digest(source_path.as_bytes()))
}

pub fn sanitize_filename(filename: &str) -> String {
    let sanitized: String = filename
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => c,
            _ => '_',
        })
        .collect();

    let trimmed = sanitized.trim_matches('.');
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn filename_from_path(path: &str) -> String {
    path.rsplit(&['/', '\\', '#', '?'][..])
        .find(|part| !part.is_empty())
        .map(sanitize_filename)
        .unwrap_or_else(|| "file".to_string())
}

pub async fn resolve_file_content(
    request: FileResolveRequest<'_>,
) -> Result<ResolvedFile, FileResolveError> {
    match request.source_type {
        FileSourceType::Local => resolve_local(request).await,
        FileSourceType::Base64DataUrl => resolve_data_url(request).await,
        FileSourceType::Http | FileSourceType::Ftp | FileSourceType::Git => {
            resolve_cacheable_remote(request).await
        }
    }
}

async fn resolve_local(request: FileResolveRequest<'_>) -> Result<ResolvedFile, FileResolveError> {
    let path = resolve_local_path(request.config.mount(), &request.source_path)?;
    let mut file = File::open(&path).await.map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => FileResolveError::NotFoundDefinite(e.to_string()),
        io::ErrorKind::PermissionDenied => FileResolveError::Forbidden(e.to_string()),
        _ => FileResolveError::InternalFailure(e.to_string()),
    })?;
    let size = file
        .metadata()
        .await
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?
        .len();
    let filename = filename_from_path(&request.virtual_path);
    let mime_type = mime_from_filename(&filename);

    let (reader, served_range, content_length): (BoxedAsyncRead, Option<ServedRange>, Option<u64>) =
        if let Some(range) = &request.range {
            let served = resolve_range(range, size)?;
            file.seek(SeekFrom::Start(served.start))
                .await
                .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?;
            let len = served.end - served.start + 1;
            (Box::pin(file.take(len)), Some(served), Some(len))
        } else {
            (Box::pin(file), None, Some(size))
        };

    Ok(ResolvedFile {
        reader,
        filename,
        mime_type,
        full_size: Some(size),
        content_length,
        served_range,
        cache_status: CacheStatus::NotCacheable,
        metadata_headers: HashMap::new(),
        upstream_status: None,
    })
}

pub fn resolve_local_path(mount: &str, source_path: &str) -> Result<PathBuf, FileResolveError> {
    if source_path.contains('\0') {
        return Err(FileResolveError::BadRequest(
            "path contains a null byte".to_string(),
        ));
    }

    let relative = source_path.trim_start_matches(&['/', '\\'][..]);
    let relative_path = Path::new(relative);
    for component in relative_path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::Prefix(_) | Component::RootDir
        ) {
            return Err(FileResolveError::Forbidden(
                "path traversal is not allowed".to_string(),
            ));
        }
    }

    Ok(Path::new(mount).join("files").join(relative_path))
}

async fn resolve_data_url(
    request: FileResolveRequest<'_>,
) -> Result<ResolvedFile, FileResolveError> {
    let data_url = DataUrl::process(&request.source_path)
        .map_err(|e| FileResolveError::BadRequest(format!("invalid data URL: {:?}", e)))?;
    let mime_type = Some(data_url.mime_type().to_string());
    let (mut bytes, _) = data_url
        .decode_to_vec()
        .map_err(|e| FileResolveError::BadRequest(format!("invalid data URL body: {:?}", e)))?;
    let size = bytes.len() as u64;
    let filename = filename_from_path(&request.virtual_path);

    let (reader, served_range, content_length): (BoxedAsyncRead, Option<ServedRange>, Option<u64>) =
        if let Some(range) = &request.range {
            let served = resolve_range(range, size)?;
            bytes = bytes[served.start as usize..=served.end as usize].to_vec();
            let len = bytes.len() as u64;
            (Box::pin(Cursor::new(bytes)), Some(served), Some(len))
        } else {
            (Box::pin(Cursor::new(bytes)), None, Some(size))
        };

    Ok(ResolvedFile {
        reader,
        filename,
        mime_type,
        full_size: Some(size),
        content_length,
        served_range,
        cache_status: CacheStatus::NotCacheable,
        metadata_headers: HashMap::new(),
        upstream_status: None,
    })
}

async fn resolve_cacheable_remote(
    request: FileResolveRequest<'_>,
) -> Result<ResolvedFile, FileResolveError> {
    let can_use_cache = request.effective_cache
        && (request.authenticated || request.config.can_unauthenticated_cache());

    if !request.effective_cache {
        return fetch_uncached(request).await.map(|mut resolved| {
            resolved.cache_status = CacheStatus::Disabled;
            resolved
        });
    }

    if !can_use_cache {
        return fetch_uncached(request).await.map(|mut resolved| {
            resolved.cache_status = CacheStatus::BypassedUnauthenticated;
            resolved
        });
    }

    let entry = CacheEntry::new(request.config.mount(), &request.source_path);
    ensure_cache_dirs(&entry).await?;
    enforce_total_cache(request.config.mount(), request.config.total_max_cache()).await?;

    if let Some(cached) =
        open_cache_hit(&entry, request.range.clone(), request.cache_duration_ms).await?
    {
        return Ok(cached);
    }

    let mut uncached = fetch_uncached(FileResolveRequest {
        range: None,
        ..request
    })
    .await?;

    let Some(known_size) = uncached.full_size.or(uncached.content_length) else {
        return attach_cache_writer(uncached, entry, request.config.max_cache_entry_size()).await;
    };

    if known_size > request.config.max_cache_entry_size() {
        uncached.cache_status = CacheStatus::Miss;
        return Ok(uncached);
    }

    attach_cache_writer(uncached, entry, request.config.max_cache_entry_size()).await
}

async fn fetch_uncached(request: FileResolveRequest<'_>) -> Result<ResolvedFile, FileResolveError> {
    match request.source_type {
        FileSourceType::Http => fetch_http_uncached(request).await,
        FileSourceType::Ftp => fetch_ftp_uncached(request).await,
        FileSourceType::Git => fetch_git_uncached(request).await,
        FileSourceType::Local | FileSourceType::Base64DataUrl => Err(
            FileResolveError::InternalFailure("invalid remote fetch source".to_string()),
        ),
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    dir: PathBuf,
    file: PathBuf,
    meta: PathBuf,
    tmp: PathBuf,
    hash: String,
    original_source_path: String,
}

impl CacheEntry {
    fn new(mount: &str, source_path: &str) -> Self {
        let hash = cache_key(source_path);
        let filename = filename_from_path(source_path);
        let root = Path::new(mount).join(".s4");
        let dir = root.join(&hash);
        CacheEntry {
            file: dir.join(filename),
            meta: dir.join("meta.json"),
            tmp: root.join("tmp"),
            dir,
            hash,
            original_source_path: source_path.to_string(),
        }
    }
}

async fn ensure_cache_dirs(entry: &CacheEntry) -> Result<(), FileResolveError> {
    fs::create_dir_all(&entry.dir)
        .await
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?;
    fs::create_dir_all(&entry.tmp)
        .await
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))
}

async fn open_cache_hit(
    entry: &CacheEntry,
    range: Option<ByteRange>,
    cache_duration_ms: u64,
) -> Result<Option<ResolvedFile>, FileResolveError> {
    let Ok(meta_bytes) = fs::read(&entry.meta).await else {
        return Ok(None);
    };
    let Ok(mut meta) = serde_json::from_slice::<CacheMetadata>(&meta_bytes) else {
        let _ = fs::remove_dir_all(&entry.dir).await;
        return Ok(None);
    };

    if is_cache_expired(&meta, cache_duration_ms) {
        let _ = fs::remove_dir_all(&entry.dir).await;
        return Ok(None);
    }

    let mut file = match File::open(&entry.file).await {
        Ok(file) => file,
        Err(_) => {
            let _ = fs::remove_dir_all(&entry.dir).await;
            return Ok(None);
        }
    };
    let size = file
        .metadata()
        .await
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?
        .len();
    meta.last_accessed_timestamp = now_ms();
    meta.size = size;
    write_meta(&entry.meta, &meta).await?;

    let (reader, served_range, content_length): (BoxedAsyncRead, Option<ServedRange>, Option<u64>) =
        if let Some(range) = &range {
            let served = resolve_range(range, size)?;
            file.seek(SeekFrom::Start(served.start))
                .await
                .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?;
            let len = served.end - served.start + 1;
            (Box::pin(file.take(len)), Some(served), Some(len))
        } else {
            (Box::pin(file), None, Some(size))
        };

    let mut headers = HashMap::new();
    if let Some(etag) = &meta.etag {
        headers.insert("etag".to_string(), etag.clone());
    }
    if let Some(last_modified) = &meta.last_modified {
        headers.insert("last-modified".to_string(), last_modified.clone());
    }

    Ok(Some(ResolvedFile {
        reader,
        filename: meta.filename,
        mime_type: meta.mime_type,
        full_size: Some(size),
        content_length,
        served_range,
        cache_status: CacheStatus::Hit,
        metadata_headers: headers,
        upstream_status: None,
    }))
}

fn is_cache_expired(meta: &CacheMetadata, cache_duration_ms: u64) -> bool {
    cache_duration_ms > 0
        && now_ms().saturating_sub(meta.created_timestamp) > cache_duration_ms as i64
}

async fn attach_cache_writer(
    mut resolved: ResolvedFile,
    entry: CacheEntry,
    max_cache_entry_size: u64,
) -> Result<ResolvedFile, FileResolveError> {
    let part = entry.tmp.join(format!("{}.part", entry.hash));
    let part_file = fs::File::create(&part)
        .await
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?;
    let (mut tx, rx) = tokio::io::duplex(64 * 1024);
    let mut source = resolved.reader;
    let final_file = entry.file.clone();
    let meta_path = entry.meta.clone();
    let original_source_path = entry.original_source_path.clone();
    let source_path_hash = entry.hash.clone();
    let filename = resolved.filename.clone();
    let mime_type = resolved.mime_type.clone();
    let etag = resolved.metadata_headers.get("etag").cloned();
    let last_modified = resolved.metadata_headers.get("last-modified").cloned();

    tokio::spawn(async move {
        let mut part_file = part_file;
        let mut cached = true;
        let mut written = 0u64;
        let mut buf = vec![0u8; 64 * 1024];

        loop {
            let read = match source.read(&mut buf).await {
                Ok(0) => break,
                Ok(read) => read,
                Err(_) => {
                    cached = false;
                    break;
                }
            };

            if tx.write_all(&buf[..read]).await.is_err() {
                cached = false;
                break;
            }

            if cached {
                written += read as u64;
                if written > max_cache_entry_size {
                    cached = false;
                    let _ = fs::remove_file(&part).await;
                } else if part_file.write_all(&buf[..read]).await.is_err() {
                    cached = false;
                    let _ = fs::remove_file(&part).await;
                }
            }
        }

        let _ = tx.shutdown().await;

        if cached {
            let _ = part_file.flush().await;
            drop(part_file);
            if fs::rename(&part, &final_file).await.is_ok() {
                let now = now_ms();
                let meta = CacheMetadata {
                    source_path_hash,
                    original_source_path,
                    filename,
                    size: written,
                    created_timestamp: now,
                    last_accessed_timestamp: now,
                    mime_type,
                    etag,
                    last_modified,
                };
                let _ = write_meta(&meta_path, &meta).await;
            }
        } else {
            let _ = fs::remove_file(&part).await;
        }
    });

    resolved.reader = Box::pin(rx);
    resolved.cache_status = CacheStatus::Miss;
    Ok(resolved)
}

async fn fetch_http_uncached(
    request: FileResolveRequest<'_>,
) -> Result<ResolvedFile, FileResolveError> {
    let url = Url::parse(&request.source_path)
        .map_err(|e| FileResolveError::BadRequest(format!("invalid URL: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(FileResolveError::BadRequest(
            "HTTP source must use http or https".to_string(),
        ));
    }

    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?;
    let mut builder = client
        .get(url.clone())
        .header(reqwest::header::ACCEPT_ENCODING, "identity");
    if let Some(range) = &request.range {
        builder = builder.header(reqwest::header::RANGE, range_header_value(range));
    }
    let response = builder
        .send()
        .await
        .map_err(|e| FileResolveError::UpstreamFailure(e.to_string()))?;

    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
        return Err(FileResolveError::NotFoundDefinite(status.to_string()));
    }
    if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
        let size = parse_complete_size_from_content_range(response.headers());
        return Err(FileResolveError::RangeNotSatisfiable(size));
    }
    if !status.is_success() {
        return Err(FileResolveError::UpstreamFailure(status.to_string()));
    }

    let headers = response.headers().clone();
    let metadata_headers = safe_http_headers(&headers);
    let mime_type = metadata_headers
        .get("content-type")
        .cloned()
        .or_else(|| mime_from_filename(url.path()));
    let content_length = headers
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .or_else(|| response.content_length());
    let served_range = headers
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_content_range);
    let full_size = served_range
        .as_ref()
        .map(|range| range.complete_size)
        .or(content_length);
    let stream = response
        .bytes_stream()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e));
    let reader = StreamReader::new(stream);

    Ok(ResolvedFile {
        reader: Box::pin(reader),
        filename: filename_from_path(url.path()),
        mime_type,
        full_size,
        content_length,
        served_range,
        cache_status: CacheStatus::NotCacheable,
        metadata_headers,
        upstream_status: Some(status.as_u16()),
    })
}

async fn fetch_ftp_uncached(
    request: FileResolveRequest<'_>,
) -> Result<ResolvedFile, FileResolveError> {
    let url = Url::parse(&request.source_path)
        .map_err(|e| FileResolveError::BadRequest(format!("invalid FTP URL: {e}")))?;
    if url.scheme() != "ftp" {
        return Err(FileResolveError::BadRequest(
            "FTP source must use ftp".to_string(),
        ));
    }
    let filename = filename_from_path(url.path());
    let tmp = Path::new(request.config.mount())
        .join(".s4")
        .join("tmp")
        .join(format!(
            "ftp-{}-{}",
            cache_key(&request.source_path),
            filename
        ));
    fs::create_dir_all(tmp.parent().unwrap())
        .await
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?;
    let tmp_for_blocking = tmp.clone();
    let source_path = request.source_path.clone();

    tokio::task::spawn_blocking(move || download_ftp_to_file(&source_path, &tmp_for_blocking))
        .await
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))??;

    open_materialized_file(tmp, filename, None, None).await
}

fn download_ftp_to_file(source_path: &str, target: &Path) -> Result<(), FileResolveError> {
    use suppaftp::FtpStream;

    let url = Url::parse(source_path)
        .map_err(|e| FileResolveError::BadRequest(format!("invalid FTP URL: {e}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| FileResolveError::BadRequest("FTP URL missing host".to_string()))?;
    let port = url.port().unwrap_or(21);
    let user = if url.username().is_empty() {
        "anonymous"
    } else {
        url.username()
    };
    let pass = url.password().unwrap_or("anonymous");
    let mut ftp = FtpStream::connect(format!("{host}:{port}"))
        .map_err(|e| classify_ftp_error(e.to_string()))?;
    ftp.login(user, pass)
        .map_err(|e| FileResolveError::UpstreamFailure(e.to_string()))?;
    let mut output = std::fs::File::create(target)
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?;
    let remote_path = url.path().trim_start_matches('/');
    let result = ftp.retr(remote_path, |stream| {
        io::copy(stream, &mut output)
            .map(|_| ())
            .map_err(suppaftp::FtpError::ConnectionError)
    });
    let _ = ftp.quit();
    result.map_err(|e| classify_ftp_error(e.to_string()))
}

fn classify_ftp_error(error: String) -> FileResolveError {
    let lower = error.to_ascii_lowercase();
    if lower.contains("550") || lower.contains("not found") || lower.contains("no such") {
        FileResolveError::NotFoundDefinite(error)
    } else {
        FileResolveError::UpstreamFailure(error)
    }
}

async fn fetch_git_uncached(
    request: FileResolveRequest<'_>,
) -> Result<ResolvedFile, FileResolveError> {
    let (repo_url, file_path) = parse_git_source(&request.source_path)?;
    let filename = filename_from_path(&file_path);
    let tmp = Path::new(request.config.mount())
        .join(".s4")
        .join("tmp")
        .join(format!(
            "git-{}-{}",
            cache_key(&request.source_path),
            filename
        ));
    fs::create_dir_all(tmp.parent().unwrap())
        .await
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?;
    let tmp_for_blocking = tmp.clone();

    tokio::task::spawn_blocking(move || {
        materialize_git_file(&repo_url, &file_path, &tmp_for_blocking)
    })
    .await
    .map_err(|e| FileResolveError::InternalFailure(e.to_string()))??;

    open_materialized_file(tmp, filename, None, request.range).await
}

fn parse_git_source(source: &str) -> Result<(String, String), FileResolveError> {
    if let Some((repo, path)) = source.split_once('#') {
        return Ok((repo.to_string(), path.trim_start_matches('/').to_string()));
    }
    if let Some((repo, path)) = source.split_once("::") {
        return Ok((repo.to_string(), path.trim_start_matches('/').to_string()));
    }
    if let Some(index) = source.find(".git/") {
        let repo_end = index + ".git".len();
        return Ok((
            source[..repo_end].to_string(),
            source[repo_end + 1..].trim_start_matches('/').to_string(),
        ));
    }
    Err(FileResolveError::BadRequest(
        "git source must be repo#path, repo::path, or repo.git/path".to_string(),
    ))
}

fn materialize_git_file(
    repo_url: &str,
    file_path: &str,
    target: &Path,
) -> Result<(), FileResolveError> {
    let tmp_parent = target
        .parent()
        .ok_or_else(|| FileResolveError::InternalFailure("missing temp parent".to_string()))?;
    let repo_dir = tmp_parent.join(format!("repo-{}", cache_key(repo_url)));
    let _ = std::fs::remove_dir_all(&repo_dir);
    let repo = git2::Repository::clone(repo_url, &repo_dir)
        .map_err(|e| FileResolveError::UpstreamFailure(e.message().to_string()))?;
    let head = repo
        .head()
        .map_err(|e| FileResolveError::UpstreamFailure(e.message().to_string()))?;
    let tree = head
        .peel_to_tree()
        .map_err(|e| FileResolveError::UpstreamFailure(e.message().to_string()))?;
    let entry = tree
        .get_path(Path::new(file_path))
        .map_err(|e| FileResolveError::NotFoundDefinite(e.message().to_string()))?;
    let blob = repo
        .find_blob(entry.id())
        .map_err(|e| FileResolveError::NotFoundDefinite(e.message().to_string()))?;
    std::fs::write(target, blob.content())
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?;
    let _ = std::fs::remove_dir_all(&repo_dir);
    Ok(())
}

async fn open_materialized_file(
    path: PathBuf,
    filename: String,
    mime_type: Option<String>,
    range: Option<ByteRange>,
) -> Result<ResolvedFile, FileResolveError> {
    let mut file = File::open(&path)
        .await
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?;
    let size = file
        .metadata()
        .await
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?
        .len();
    let (reader, served_range, content_length): (BoxedAsyncRead, Option<ServedRange>, Option<u64>) =
        if let Some(range) = &range {
            let served = resolve_range(range, size)?;
            file.seek(SeekFrom::Start(served.start))
                .await
                .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?;
            let len = served.end - served.start + 1;
            (
                Box::pin(DeleteOnDropReader::new(file.take(len), path)),
                Some(served),
                Some(len),
            )
        } else {
            (
                Box::pin(DeleteOnDropReader::new(file, path)),
                None,
                Some(size),
            )
        };

    Ok(ResolvedFile {
        reader,
        filename: filename.clone(),
        mime_type: mime_type.or_else(|| mime_from_filename(&filename)),
        full_size: Some(size),
        content_length,
        served_range,
        cache_status: CacheStatus::NotCacheable,
        metadata_headers: HashMap::new(),
        upstream_status: None,
    })
}

struct DeleteOnDropReader<R> {
    inner: R,
    path: PathBuf,
}

impl<R> DeleteOnDropReader<R> {
    fn new(inner: R, path: PathBuf) -> Self {
        Self { inner, path }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for DeleteOnDropReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<R> Drop for DeleteOnDropReader<R> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn range_header_value(range: &ByteRange) -> String {
    match (range.start, range.end) {
        (Some(start), Some(end)) => format!("bytes={start}-{end}"),
        (Some(start), None) => format!("bytes={start}-"),
        (None, Some(end)) => format!("bytes=-{end}"),
        (None, None) => "bytes=0-".to_string(),
    }
}

fn parse_content_range(value: &str) -> Option<ServedRange> {
    let value = value.strip_prefix("bytes ")?;
    let (range, size) = value.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    Some(ServedRange {
        start: start.parse().ok()?,
        end: end.parse().ok()?,
        complete_size: size.parse().ok()?,
    })
}

fn parse_complete_size_from_content_range(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("bytes */"))
        .and_then(|size| size.parse().ok())
}

fn safe_http_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    let mut safe = HashMap::new();
    for header in [
        reqwest::header::CONTENT_TYPE,
        reqwest::header::CONTENT_LENGTH,
        reqwest::header::LAST_MODIFIED,
        reqwest::header::ETAG,
    ] {
        if let Some(value) = headers.get(&header) {
            if let Ok(value) = value.to_str() {
                safe.insert(header.as_str().to_ascii_lowercase(), value.to_string());
            }
        }
    }
    safe
}

fn mime_from_filename(path: &str) -> Option<String> {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .and_then(mime_type::MimeType::from_ext)
        .map(|mime| mime.to_string())
}

async fn write_meta(path: &Path, meta: &CacheMetadata) -> Result<(), FileResolveError> {
    let bytes = serde_json::to_vec_pretty(meta)
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?;
    fs::write(path, bytes)
        .await
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

pub async fn enforce_total_cache(
    mount: &str,
    total_max_cache: u64,
) -> Result<(), FileResolveError> {
    let root = Path::new(mount).join(".s4");
    let mut entries = Vec::new();
    let mut total = 0u64;
    let Ok(mut dirs) = fs::read_dir(&root).await else {
        return Ok(());
    };

    while let Some(dir) = dirs
        .next_entry()
        .await
        .map_err(|e| FileResolveError::InternalFailure(e.to_string()))?
    {
        if dir.file_name() == "tmp" {
            continue;
        }
        let meta_path = dir.path().join("meta.json");
        let Ok(meta_bytes) = fs::read(&meta_path).await else {
            continue;
        };
        let Ok(meta) = serde_json::from_slice::<CacheMetadata>(&meta_bytes) else {
            continue;
        };
        total = total.saturating_add(meta.size);
        entries.push((meta.last_accessed_timestamp, meta.size, dir.path()));
    }

    if total <= total_max_cache {
        return Ok(());
    }

    entries.sort_by_key(|(last_accessed, _, _)| *last_accessed);
    for (_, size, path) in entries {
        if total <= total_max_cache {
            break;
        }
        if fs::remove_dir_all(&path).await.is_ok() {
            total = total.saturating_sub(size);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config::defaulted()
    }

    #[test]
    fn effective_cache_uses_query_only_when_gates_allow_it() {
        let config = test_config();
        assert!(!effective_cache(Some(false), Some(true), &config));
        assert!(effective_cache(Some(true), Some(false), &config));
        assert!(effective_cache(None, None, &config));

        let mut config = test_config();
        config.allow_query_override_db = Some(false);
        assert!(effective_cache(Some(false), Some(true), &config));

        let mut config = test_config();
        config.allow_query_override_default = Some(false);
        assert!(effective_cache(Some(false), None, &config));
    }

    #[test]
    fn range_parser_accepts_single_valid_forms() {
        assert_eq!(
            parse_range_header("bytes=0-99").unwrap(),
            Some(ByteRange {
                start: Some(0),
                end: Some(99)
            })
        );
        assert_eq!(
            parse_range_header("bytes=50-").unwrap(),
            Some(ByteRange {
                start: Some(50),
                end: None
            })
        );
        assert_eq!(
            parse_range_header("bytes=-25").unwrap(),
            Some(ByteRange {
                start: None,
                end: Some(25)
            })
        );
    }

    #[test]
    fn range_parser_rejects_invalid_forms() {
        assert!(parse_range_header("items=0-1").is_err());
        assert!(parse_range_header("bytes=").is_err());
        assert!(parse_range_header("bytes=0-1,2-3").is_err());
        assert!(parse_range_header("bytes=a-1").is_err());
    }

    #[test]
    fn range_resolution_handles_suffix_and_unsatisfiable() {
        assert_eq!(
            resolve_range(
                &ByteRange {
                    start: None,
                    end: Some(4)
                },
                10
            )
            .unwrap(),
            ServedRange {
                start: 6,
                end: 9,
                complete_size: 10
            }
        );
        assert!(matches!(
            resolve_range(
                &ByteRange {
                    start: Some(10),
                    end: None
                },
                10
            ),
            Err(FileResolveError::RangeNotSatisfiable(Some(10)))
        ));
    }

    #[test]
    fn local_path_traversal_is_rejected() {
        assert!(resolve_local_path("./data", "../secret").is_err());
        assert!(resolve_local_path("./data", "/safe/../secret").is_err());
        assert!(resolve_local_path("./data", "safe\0file").is_err());
        assert!(resolve_local_path("./data", "safe/file.txt").is_ok());
    }

    #[tokio::test]
    async fn data_url_decoding_and_range_slicing_work() {
        let config = test_config();
        let resolved = resolve_file_content(FileResolveRequest {
            source_type: FileSourceType::Base64DataUrl,
            source_path: "data:text/plain;base64,SGVsbG8gd29ybGQ=".to_string(),
            virtual_path: "/hello.txt".to_string(),
            effective_cache: false,
            cache_duration_ms: 0,
            authenticated: true,
            range: Some(ByteRange {
                start: Some(6),
                end: Some(10),
            }),
            config: &config,
        })
        .await
        .unwrap();
        let mut bytes = Vec::new();
        let mut reader = resolved.reader;
        reader.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"world");
        assert_eq!(resolved.content_length, Some(5));
        assert_eq!(resolved.mime_type, Some("text/plain".to_string()));
    }

    #[test]
    fn cache_key_generation_and_filename_sanitization_are_stable() {
        assert_eq!(cache_key("abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(sanitize_filename("../bad name.txt"), "_bad_name.txt");
        assert_eq!(sanitize_filename("..."), "file");
    }

    #[tokio::test]
    async fn cache_ttl_expiration_removes_entry() {
        let temp = tempfile::tempdir().unwrap();
        let entry = CacheEntry::new(temp.path().to_str().unwrap(), "http://example/file.txt");
        ensure_cache_dirs(&entry).await.unwrap();
        fs::write(&entry.file, b"stale").await.unwrap();
        write_meta(
            &entry.meta,
            &CacheMetadata {
                source_path_hash: entry.hash.clone(),
                original_source_path: "http://example/file.txt".to_string(),
                filename: "file.txt".to_string(),
                size: 5,
                created_timestamp: 1,
                last_accessed_timestamp: 1,
                mime_type: None,
                etag: None,
                last_modified: None,
            },
        )
        .await
        .unwrap();
        assert!(
            open_cache_hit(&entry, None, 1).await.unwrap().is_none(),
            "expired cache entries are not used"
        );
        assert!(!entry.dir.exists());
    }

    #[tokio::test]
    async fn lru_eviction_removes_oldest_entries() {
        let temp = tempfile::tempdir().unwrap();
        for (name, accessed) in [("old", 1), ("new", 2)] {
            let entry = CacheEntry::new(temp.path().to_str().unwrap(), name);
            ensure_cache_dirs(&entry).await.unwrap();
            fs::write(&entry.file, vec![0u8; 10]).await.unwrap();
            write_meta(
                &entry.meta,
                &CacheMetadata {
                    source_path_hash: entry.hash.clone(),
                    original_source_path: name.to_string(),
                    filename: name.to_string(),
                    size: 10,
                    created_timestamp: accessed,
                    last_accessed_timestamp: accessed,
                    mime_type: None,
                    etag: None,
                    last_modified: None,
                },
            )
            .await
            .unwrap();
        }
        enforce_total_cache(temp.path().to_str().unwrap(), 10)
            .await
            .unwrap();
        assert!(
            !CacheEntry::new(temp.path().to_str().unwrap(), "old")
                .dir
                .exists()
        );
        assert!(
            CacheEntry::new(temp.path().to_str().unwrap(), "new")
                .dir
                .exists()
        );
    }

    #[tokio::test]
    async fn max_cache_entry_abort_keeps_response_streaming() {
        let temp = tempfile::tempdir().unwrap();
        let entry = CacheEntry::new(temp.path().to_str().unwrap(), "remote");
        ensure_cache_dirs(&entry).await.unwrap();
        let resolved = ResolvedFile {
            reader: Box::pin(Cursor::new(vec![1, 2, 3, 4])),
            filename: "remote".to_string(),
            mime_type: None,
            full_size: None,
            content_length: None,
            served_range: None,
            cache_status: CacheStatus::NotCacheable,
            metadata_headers: HashMap::new(),
            upstream_status: None,
        };
        let mut resolved = attach_cache_writer(resolved, entry.clone(), 2)
            .await
            .unwrap();
        let mut bytes = Vec::new();
        resolved.reader.read_to_end(&mut bytes).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(bytes, vec![1, 2, 3, 4]);
        assert!(!entry.file.exists());
    }

    #[test]
    fn unauthenticated_cache_disabled_is_detectable() {
        let mut config = test_config();
        config.can_unauthenticated_cache = Some(false);
        assert!(!config.can_unauthenticated_cache());
    }

    #[test]
    fn not_found_classification_is_distinct_from_transient_failure() {
        assert!(matches!(
            classify_ftp_error("550 missing".to_string()),
            FileResolveError::NotFoundDefinite(_)
        ));
        assert!(matches!(
            classify_ftp_error("connection timed out".to_string()),
            FileResolveError::UpstreamFailure(_)
        ));
    }
}
