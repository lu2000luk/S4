use crate::DbPool;
use rocket::State;
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::{Deserialize, json::Json};

#[derive(Deserialize)]
pub struct Data {
    user_id: String,
    password: String,
}

#[rocket::post("/user_key", format = "json", data = "<data>")]
pub async fn generate_user_key(
    data: Json<Data>,
    pool: &State<DbPool>,
) -> Result<String, status::Custom<String>> {
    if data.user_id.is_empty() || data.password.is_empty() {
        return Err(status::Custom(
            Status::BadRequest,
            "ERROR Invalid data".to_string(),
        ));
    }

    if data.user_id == "everyone" {
        return Err(status::Custom(
            Status::BadRequest,
            "ERROR User cannot be everyone".to_string(),
        ));
    }

    let conn = pool.get().map_err(|_| {
        status::Custom(
            Status::InternalServerError,
            "ERROR Failed to get connection from pool".to_string(),
        )
    })?;

    let passwd = conn
        .query_row(
            "SELECT password_hash FROM users WHERE id = ?",
            duckdb::params![data.user_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .unwrap_or(None)
        .unwrap_or_default();

    if passwd.is_empty() {
        return Err(status::Custom(
            Status::Unauthorized,
            "ERROR Authentication failed [err: targetUserNoPasswordHash]".to_string(),
        ));
    }

    if !bcrypt::verify(&data.password, &passwd).unwrap_or(false) {
        return Err(status::Custom(
            Status::Unauthorized,
            "ERROR Authentication failed [err: passwordMismatch]".to_string(),
        ));
    }

    let user_key_id = format!("user_{}", data.user_id.clone());

    let existing_key = conn
        .query_row(
            "SELECT key FROM keys WHERE id = ?",
            duckdb::params![user_key_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .unwrap_or(None)
        .unwrap_or_default();

    if !existing_key.is_empty() {
        return Ok(existing_key);
    }

    let new_key = crate::utils::key::generate_key();

    let user_perms = conn
        .query_row(
            "SELECT permission_id FROM users WHERE id = ?",
            duckdb::params![data.user_id],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| {
            status::Custom(
                Status::InternalServerError,
                "ERROR Failed to get user permissions".to_string(),
            )
        })?;

    let new_res = conn
        .execute(
            "INSERT INTO keys (id, key, owner_id, permission_id) VALUES (?, ?, ?, ?)",
            duckdb::params![user_key_id, new_key.clone(), data.user_id, user_perms],
        )
        .map_err(|_| {
            status::Custom(
                Status::InternalServerError,
                "ERROR Failed to insert new key".to_string(),
            )
        })?;

    if new_res == 0 {
        return Err(status::Custom(
            Status::InternalServerError,
            "ERROR Failed to create new key".to_string(),
        ));
    }

    Ok(new_key)
}

#[rocket::get("/user_key?<user_id>&<password>")]
pub async fn user_key_get(
    user_id: String,
    password: String,
    pool: &State<DbPool>,
) -> Result<String, status::Custom<String>> {
    let data = Json(Data { user_id, password });
    generate_user_key(data, pool).await
}

async fn delete_user_key_impl(
    user_id: String,
    password: String,
    pool: &State<DbPool>,
) -> Result<String, status::Custom<String>> {
    if user_id.is_empty() || password.is_empty() {
        return Err(status::Custom(
            Status::BadRequest,
            "ERROR Invalid data".to_string(),
        ));
    }

    if user_id == "everyone" {
        return Err(status::Custom(
            Status::BadRequest,
            "ERROR User cannot be everyone".to_string(),
        ));
    }

    let conn = pool.get().map_err(|_| {
        status::Custom(
            Status::InternalServerError,
            "ERROR Failed to get connection from pool".to_string(),
        )
    })?;

    let passwd = conn
        .query_row(
            "SELECT password_hash FROM users WHERE id = ?",
            duckdb::params![user_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .unwrap_or(None)
        .unwrap_or_default();

    if passwd.is_empty() {
        return Err(status::Custom(
            Status::Unauthorized,
            "ERROR Authentication failed [err: targetUserNoPasswordHash]".to_string(),
        ));
    }

    if !bcrypt::verify(&password, &passwd).unwrap_or(false) {
        return Err(status::Custom(
            Status::Unauthorized,
            "ERROR Authentication failed [err: passwordMismatch]".to_string(),
        ));
    }

    let user_key_id = format!("user_{}", user_id);

    let existing_key = conn
        .query_row(
            "SELECT key FROM keys WHERE id = ?",
            duckdb::params![user_key_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .unwrap_or(None)
        .unwrap_or_default();

    if existing_key.is_empty() {
        return Err(status::Custom(
            Status::BadRequest,
            "ERROR No key to delete".to_string(),
        ));
    }

    let del_res = conn
        .execute(
            "DELETE FROM keys WHERE id = ?",
            duckdb::params![user_key_id],
        )
        .map_err(|_| {
            status::Custom(
                Status::InternalServerError,
                "ERROR Failed to delete key".to_string(),
            )
        })?;

    if del_res == 0 {
        return Err(status::Custom(
            Status::InternalServerError,
            "ERROR Failed to delete key".to_string(),
        ));
    }

    Ok("SUCCESS Key deleted".to_string())
}

#[rocket::delete("/user_key?<user_id>&<password>")]
pub async fn user_key_delete(
    user_id: String,
    password: String,
    pool: &State<DbPool>,
) -> Result<String, status::Custom<String>> {
    delete_user_key_impl(user_id, password, pool).await
}

#[rocket::delete("/user_key", format = "json", data = "<data>", rank = 2)]
pub async fn user_key_delete_body(
    data: Json<Data>,
    pool: &State<DbPool>,
) -> Result<String, status::Custom<String>> {
    delete_user_key_impl(data.user_id.clone(), data.password.clone(), pool).await
}
