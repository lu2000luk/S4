use std::path::PathBuf;

use rocket::State;
use rocket::tokio::task::spawn_blocking;
use s4_macros::get;

use rocket::http::Status;
use rocket::response::status;

use crate::{
    DbPool,
    utils::permissions::{
        FilePermType, FilePermission, PermissionEngine, load_engine_sync, perms_from_key_sync,
    },
};

#[get("/file/<path..>")]
pub async fn get_file(
    path: PathBuf,
    pool: &State<DbPool>,
    auth_key: String,
) -> Result<String, status::Custom<String>> {
    let pool = pool.inner().clone();
    let path_clone = path.clone();

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

        let path_str = path_clone.to_str().unwrap();
        let has_read = perms
            .get_file_perms_sync(&conn, path_str)
            .map_err(|e| status::Custom(Status::InternalServerError, format!("ERROR {}", e)))?
            .has(&FilePermission::new(
                String::from(path_str),
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

    if !has_permission {
        return Err(status::Custom(
            Status::Forbidden,
            "ERROR: You do not have permission to read this file".to_string(),
        ));
    }

    Ok("can read".to_string())
}
