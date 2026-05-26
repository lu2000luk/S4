use duckdb::params;
use rocket::http::{Header, Status};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::{Responder, Response, status};

use crate::utils::dbstructs::FilePerms;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionEntry {
    pub user_id: String,
    pub perms: FilePerms,
    pub has_explicit_path: bool,
}

pub fn parse_permission_string(value: &str) -> Result<Vec<PermissionEntry>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    trimmed
        .split('|')
        .map(|entry| parse_entry(entry.trim()))
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct PermissionStringHeaders {
    x_permissions: Option<String>,
    x_perms: Option<String>,
    x_perm: Option<String>,
    x_permission: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PermissionStringQuery {
    pub permissions: Option<String>,
    pub permission: Option<String>,
    pub perms: Option<String>,
    pub perm: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedPermissionString {
    pub entries: Vec<ParsedPermissionEntry>,
    pub warning: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedPermissionEntry {
    pub permission_id: String,
    pub perms: FilePerms,
}

pub struct JsonResponseWithWarning {
    pub body: String,
    pub warning: Option<String>,
}

impl<'r> Responder<'r, 'static> for JsonResponseWithWarning {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'static> {
        let mut builder = Response::build();
        builder.status(Status::Ok);
        builder.header(Header::new("Content-Type", "application/json"));
        if let Some(warning) = self.warning {
            builder.header(Header::new("X-Error", warning));
        }
        builder.sized_body(self.body.len(), std::io::Cursor::new(self.body));
        Ok(builder.finalize())
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for PermissionStringHeaders {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(PermissionStringHeaders {
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

impl PermissionStringHeaders {
    pub fn new(
        x_permissions: Option<String>,
        x_perms: Option<String>,
        x_perm: Option<String>,
        x_permission: Option<String>,
    ) -> Self {
        Self {
            x_permissions,
            x_perms,
            x_perm,
            x_permission,
        }
    }

    pub fn selected_value(&self) -> Option<String> {
        self.x_permissions
            .clone()
            .or_else(|| self.x_perms.clone())
            .or_else(|| self.x_perm.clone())
            .or_else(|| self.x_permission.clone())
    }
}

impl PermissionStringQuery {
    pub fn selected_value(&self, headers: &PermissionStringHeaders) -> Option<String> {
        self.permissions
            .clone()
            .or_else(|| self.permission.clone())
            .or_else(|| self.perms.clone())
            .or_else(|| self.perm.clone())
            .or_else(|| headers.selected_value())
    }
}

pub fn parse_creation_permission_string(
    value: Option<String>,
    ignore_errors: bool,
) -> Result<Option<ParsedPermissionString>, status::Custom<String>> {
    let Some(value) = value else {
        return Ok(None);
    };

    let parsed = parse_permission_string(&value).map_err(|e| {
        status::Custom(
            Status::BadRequest,
            format!("ERROR Invalid permission string: {e}"),
        )
    })?;

    let mut entries = Vec::new();
    let mut ignored = Vec::new();
    for entry in parsed {
        if entry.has_explicit_path {
            if ignore_errors {
                ignored.push(entry.user_id);
                continue;
            }
            return Err(status::Custom(
                Status::BadRequest,
                "ERROR Permission strings for file creation must not include paths".to_string(),
            ));
        }

        entries.push(ParsedPermissionEntry {
            permission_id: entry.user_id,
            perms: entry.perms,
        });
    }

    let warning = if ignored.is_empty() {
        None
    } else {
        Some(format!(
            "Ignored permission entries with explicit paths: {}",
            ignored.join(", ")
        ))
    };

    Ok(Some(ParsedPermissionString { entries, warning }))
}

pub fn insert_permission_string_entries(
    conn: &duckdb::Connection,
    normalized_path: &str,
    entries: &[ParsedPermissionEntry],
) -> Result<(), status::Custom<String>> {
    for entry in entries {
        insert_file_perm(conn, normalized_path, &entry.permission_id, &entry.perms)?;
    }

    if !entries
        .iter()
        .any(|entry| entry.permission_id.as_str() == "everyone")
    {
        insert_default_read_permission(conn, normalized_path)?;
    }

    Ok(())
}

pub fn insert_default_read_permission(
    conn: &duckdb::Connection,
    normalized_path: &str,
) -> Result<(), status::Custom<String>> {
    conn.execute(
        "INSERT INTO file_perms (id, permission_id, path, recursive, read, created_at) VALUES (?, 'everyone', ?, FALSE, TRUE, CURRENT_TIMESTAMP)",
        params![generate_perm_id(), normalized_path],
    )
    .map_err(|e| {
        status::Custom(
            Status::InternalServerError,
            format!("ERROR Failed to create default file permission: {e}"),
        )
    })?;
    Ok(())
}

fn insert_file_perm(
    conn: &duckdb::Connection,
    normalized_path: &str,
    permission_id: &str,
    perms: &FilePerms,
) -> Result<(), status::Custom<String>> {
    conn.execute(
        r#"
            INSERT INTO file_perms (
                id, permission_id, path, bypass_weight, recursive, read, delete, write,
                create_file, create_folder, create_link, create_backup, create_with_weight,
                generate_link, encrypt, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        "#,
        params![
            generate_perm_id(),
            permission_id,
            normalized_path,
            perms.bypass_weight,
            perms.recursive,
            perms.read,
            perms.delete,
            perms.write,
            perms.create_file,
            perms.create_folder,
            perms.create_link,
            perms.create_backup,
            perms.create_with_weight,
            perms.generate_link,
            perms.encrypt,
        ],
    )
    .map_err(|e| {
        status::Custom(
            Status::InternalServerError,
            format!("ERROR Failed to create file permission: {e}"),
        )
    })?;
    Ok(())
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

fn parse_entry(entry: &str) -> Result<PermissionEntry, String> {
    if entry.is_empty() {
        return Err("Permission entry is empty".to_string());
    }

    let parts: Vec<&str> = entry.splitn(3, ':').collect();
    if parts.len() < 2 {
        return Err(format!("Invalid permission entry: {entry}"));
    }

    let user_id = parts[0].trim();
    if user_id.is_empty() {
        return Err("Permission entry missing user id".to_string());
    }

    let perm_spec = parts[1].trim();
    if perm_spec.is_empty() {
        return Err("Permission entry missing permissions".to_string());
    }

    let raw_path = parts.get(2).map(|p| p.trim()).unwrap_or("");
    let path = normalize_path(raw_path);

    let mut perms = empty_file_perm(path);
    apply_perm_spec(&mut perms, perm_spec)?;

    Ok(PermissionEntry {
        user_id: user_id.to_string(),
        perms,
        has_explicit_path: parts.len() == 3,
    })
}

fn apply_perm_spec(perms: &mut FilePerms, spec: &str) -> Result<(), String> {
    let chars: Vec<char> = spec.chars().collect();
    let mut index = 0;

    while index < chars.len() {
        match chars[index] {
            '[' => {
                let close = chars[index + 1..]
                    .iter()
                    .position(|c| *c == ']')
                    .ok_or_else(|| format!("Unclosed permission bracket in: {spec}"))?;
                let token_start = index + 1;
                let token_end = index + 1 + close;
                let token: String = chars[token_start..token_end].iter().collect();
                apply_bracket_token(perms, token.trim(), spec)?;
                index = token_end + 1;
            }
            ch if ch.is_whitespace() => {
                index += 1;
            }
            ch => {
                apply_char_token(perms, ch, spec)?;
                index += 1;
            }
        }
    }

    Ok(())
}

fn apply_char_token(perms: &mut FilePerms, token: char, spec: &str) -> Result<(), String> {
    match token {
        'r' => perms.read = true,
        'w' => perms.write = true,
        'd' => perms.delete = true,
        'a' => perms.bypass_weight = true,
        'x' => perms.recursive = true,
        'l' => perms.generate_link = true,
        'e' => perms.encrypt = true,
        _ => {
            return Err(format!("Unknown permission token '{token}' in: {spec}"));
        }
    }

    Ok(())
}

fn apply_bracket_token(perms: &mut FilePerms, token: &str, spec: &str) -> Result<(), String> {
    match token {
        "f" => perms.create_file = true,
        "d" => perms.create_folder = true,
        "l" => perms.create_link = true,
        "b" => perms.create_backup = true,
        "w" => perms.create_with_weight = true,
        _ => {
            return Err(format!(
                "Unknown bracket permission token '{token}' in: {spec}"
            ));
        }
    }

    Ok(())
}

fn empty_file_perm(path: String) -> FilePerms {
    FilePerms {
        id: String::new(),
        permission_id: String::new(),
        path,
        bypass_weight: false,
        recursive: false,
        read: false,
        delete: false,
        write: false,
        create_file: false,
        create_folder: false,
        create_link: false,
        create_backup: false,
        create_with_weight: false,
        generate_link: false,
        encrypt: false,
        created_at: chrono::Utc::now().naive_utc(),
    }
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return "/".to_string();
    }

    let slash_path = trimmed.replace('\\', "/");
    let mut components = Vec::new();

    for component in slash_path.split('/') {
        match component {
            "" | "." => {}
            ".." => {}
            _ => components.push(component),
        }
    }

    if components.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", components.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_entry_without_path() {
        let result = parse_permission_string("user123:rw").unwrap();
        assert_eq!(result.len(), 1);
        let entry = &result[0];
        assert_eq!(entry.user_id, "user123");
        assert_eq!(entry.perms.path, "/");
        assert!(!entry.has_explicit_path);
        assert!(entry.perms.read);
        assert!(entry.perms.write);
        assert!(!entry.perms.delete);
    }

    #[test]
    fn parse_entry_with_path_and_flags() {
        let result = parse_permission_string("group456:rwdx:/docs").unwrap();
        let entry = &result[0];
        assert_eq!(entry.user_id, "group456");
        assert_eq!(entry.perms.path, "/docs");
        assert!(entry.has_explicit_path);
        assert!(entry.perms.read);
        assert!(entry.perms.write);
        assert!(entry.perms.delete);
        assert!(entry.perms.recursive);
    }

    #[test]
    fn parse_bracket_permissions() {
        let result = parse_permission_string("user123:r[f][d][l][b][w]").unwrap();
        let entry = &result[0];
        assert!(entry.perms.read);
        assert!(entry.perms.create_file);
        assert!(entry.perms.create_folder);
        assert!(entry.perms.create_link);
        assert!(entry.perms.create_backup);
        assert!(entry.perms.create_with_weight);
    }

    #[test]
    fn parse_multiple_entries() {
        let result = parse_permission_string("u1:r|u2:w:/bucket").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].user_id, "u1");
        assert!(!result[0].has_explicit_path);
        assert!(result[0].perms.read);
        assert_eq!(result[1].user_id, "u2");
        assert!(result[1].has_explicit_path);
        assert!(result[1].perms.write);
        assert_eq!(result[1].perms.path, "/bucket");
    }

    #[test]
    fn marks_explicit_path_presence() {
        let without_path = parse_permission_string("user:rw").unwrap();
        assert!(!without_path[0].has_explicit_path);

        let with_path = parse_permission_string("user:rw:/x").unwrap();
        assert!(with_path[0].has_explicit_path);
    }

    #[test]
    fn parse_empty_string_returns_empty_list() {
        let result = parse_permission_string("  ").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn rejects_unknown_char_token() {
        let err = parse_permission_string("user123:z").unwrap_err();
        assert!(err.contains("Unknown permission token"));
    }

    #[test]
    fn rejects_unknown_bracket_token() {
        let err = parse_permission_string("user123:r[q]").unwrap_err();
        assert!(err.contains("Unknown bracket permission token"));
    }

    #[test]
    fn rejects_unclosed_bracket() {
        let err = parse_permission_string("user123:r[f").unwrap_err();
        assert!(err.contains("Unclosed permission bracket"));
    }

    #[test]
    fn rejects_missing_user_or_perm() {
        assert!(parse_permission_string(":r").is_err());
        assert!(parse_permission_string("user:").is_err());
        assert!(parse_permission_string("user").is_err());
    }
}
