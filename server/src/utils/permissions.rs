use crate::utils::{complex::DBConn, dbstructs::Permissions};

pub async fn perms_from_key(conn: DBConn, key: String) -> Option<Permissions> {
    let permission_id: Option<String> = conn
        .query_row(
            "SELECT permission_id FROM keys WHERE key = ?",
            duckdb::params![key],
            |row| row.get(0),
        )
        .ok();

    let permission_id = permission_id?;

    conn.query_row(
        "SELECT id, weight, is_root, create_api_key, create_user, delete_user, edit_user, view_user, bypass_weight, max_action_size, max_backup_size, total_storage_size, max_create_users, convert_file, created_at FROM permissions WHERE id = ?",
        duckdb::params![permission_id],
        |row| {
            Ok(Permissions {
                id: row.get(0)?,
                weight: row.get(1)?,
                is_root: row.get(2)?,
                create_api_key: row.get(3)?,
                create_user: row.get(4)?,
                delete_user: row.get(5)?,
                edit_user: row.get(6)?,
                view_user: row.get(7)?,
                bypass_weight: row.get(8)?,
                max_action_size: row.get(9)?,
                max_backup_size: row.get(10)?,
                total_storage_size: row.get(11)?,
                max_create_users: row.get(12)?,
                convert_file: row.get(13)?,
                created_at: row.get(14)?,
            })
        },
    )
    .ok()
}
