#[derive(Debug, Clone)]
pub struct Permissions {
    pub id: String,
    pub weight: i32,
    pub is_root: bool,
    pub create_api_key: bool,
    pub create_user: bool,
    pub delete_user: bool,
    pub edit_user: bool,
    pub view_user: bool,
    pub bypass_weight: bool,
    pub max_action_size: Option<i64>,
    pub max_backup_size: Option<i64>,
    pub total_storage_size: Option<i64>,
    pub max_create_users: Option<i64>,
    pub convert_file: bool,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct FilePerms {
    pub id: String,
    pub permission_id: String,
    pub path: String,
    pub bypass_weight: bool,
    pub recursive: bool,
    pub read: bool,
    pub delete: bool,
    pub write: bool,
    pub create_file: bool,
    pub create_folder: bool,
    pub create_link: bool,
    pub create_backup: bool,
    pub create_with_weight: bool,
    pub generate_link: bool,
    pub encrypt: bool,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub is_everyone: bool,
    pub permission_id: String,
    pub created_by_id: Option<String>,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct File {
    pub id: String,
    pub path: String,
    pub metadata: Option<serde_json::Value>,
    pub r#type: String,
    pub mime_type: Option<String>,
    pub size: i64,
    pub link: Option<String>,
    pub link_target: Option<String>,
    pub cache: bool,
    pub cache_dur: i64,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct Backup {
    pub id: String,
    pub path: String,
    pub size: i64,
    pub created_at: chrono::NaiveDateTime,
    pub created_by_id: String,
    pub file_id: String,
}

#[derive(Debug, Clone)]
pub struct Key {
    pub id: String,
    pub key: String,
    pub created_at: chrono::NaiveDateTime,
    pub owner_id: String,
    pub permission_id: String,
}

#[derive(Debug, Clone)]
pub struct Link {
    pub id: String,
    pub file_id: String,
    pub created_at: chrono::NaiveDateTime,
    pub expires_at: Option<chrono::NaiveDateTime>,
    pub access_count: i32,
    pub max_access_count: Option<i32>,
    pub created_by_id: String,
    pub password_hash: Option<String>,
}
