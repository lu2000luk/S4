use crate::DbPool;
use crate::utils::complex::AuthHeader;
use crate::utils::permissions::perms_from_key_sync;
use rocket::State;
use rocket::http::CookieJar;
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::{Deserialize, json::Json};

#[derive(Deserialize)]
pub struct CheckAuthData {
    key: String,
}

fn check_auth_internal(key: String, pool: &DbPool) -> Result<String, status::Custom<String>> {
    let conn = pool.get().map_err(|_| {
        status::Custom(
            Status::InternalServerError,
            r#"{"success": false, "error": "Cannot get DB connection"}"#.to_string(),
        )
    })?;

    let perms = perms_from_key_sync(&conn, key).ok_or_else(|| {
        status::Custom(
            Status::Unauthorized,
            r#"{"success": false, "error": "Unauthorized"}"#.to_string(),
        )
    })?;

    Ok(format!(
        r#"{{"success": true, "error": false, "permission": {} }}"#,
        serde_json::to_string(&perms.id).unwrap_or_default()
    ))
}

#[rocket::get("/check_auth?<key>")]
pub async fn check_auth(
    key: Option<String>,
    auth_header: AuthHeader,
    cookies: &CookieJar<'_>,
    pool: &State<DbPool>,
) -> Result<String, status::Custom<String>> {
    let resolved_key = key
        .or_else(|| {
            auth_header
                .0
                .map(|k| k.strip_prefix("Bearer ").unwrap_or(&k).to_string())
        })
        .or_else(|| cookies.get("key").map(|c| c.value().to_string()))
        .ok_or_else(|| {
            status::Custom(
                Status::Unauthorized,
                r#"{"success": false, "error": "No authentication key provided"}"#.to_string(),
            )
        })?;

    let pool = pool.inner().clone();
    rocket::tokio::task::spawn_blocking(move || check_auth_internal(resolved_key, &pool))
        .await
        .map_err(|_| {
            status::Custom(
                Status::InternalServerError,
                r#"{"success": false, "error": "Task failed"}"#.to_string(),
            )
        })?
}

#[rocket::post("/check_auth", format = "json", data = "<data>")]
pub async fn check_auth_post(
    data: Json<CheckAuthData>,
    pool: &State<DbPool>,
) -> Result<String, status::Custom<String>> {
    let key = data.key.clone();
    let pool = pool.inner().clone();
    rocket::tokio::task::spawn_blocking(move || check_auth_internal(key, &pool))
        .await
        .map_err(|_| {
            status::Custom(
                Status::InternalServerError,
                r#"{"success": false, "error": "Task failed"}"#.to_string(),
            )
        })?
}
