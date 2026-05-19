#![allow(dead_code)]

use crate::utils::{
    complex::DBConn,
    dbstructs::{FilePerms, Permissions},
};

use crate::logger::warn;

const PERMISSIONS_SELECT_BY_ID: &str = "SELECT id, weight, is_root, create_api_key, create_user, delete_user, edit_user, view_user, bypass_weight, max_action_size, max_backup_size, total_storage_size, max_create_users, convert_file, created_at FROM permissions WHERE id = ?";

const FILE_PERMS_SELECT: &str = r#"
    SELECT id, permission_id, path, bypass_weight, recursive, read, delete, write,
           create_file, create_folder, create_link, create_backup, create_with_weight,
           generate_link, encrypt, created_at
    FROM file_perms
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermType {
    IsRoot,
    CreateApiKey,
    CreateUser,
    DeleteUser,
    EditUser,
    ViewUser,
    BypassWeight,
    ConvertFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilePermType {
    Read,
    Delete,
    Write,
    CreateFile,
    CreateFolder,
    CreateLink,
    CreateBackup,
    CreateWithWeight,
    GenerateLink,
    Encrypt,
    BypassWeight,
    Recursive,
}

#[derive(Debug, Clone, Copy)]
pub struct Permission(pub PermType);

impl Permission {
    pub fn new(perm_type: PermType) -> Self {
        Permission(perm_type)
    }

    pub fn is_root() -> Self {
        Permission(PermType::IsRoot)
    }

    pub fn create_api_key() -> Self {
        Permission(PermType::CreateApiKey)
    }

    pub fn create_user() -> Self {
        Permission(PermType::CreateUser)
    }

    pub fn delete_user() -> Self {
        Permission(PermType::DeleteUser)
    }

    pub fn edit_user() -> Self {
        Permission(PermType::EditUser)
    }

    pub fn view_user() -> Self {
        Permission(PermType::ViewUser)
    }

    pub fn bypass_weight() -> Self {
        Permission(PermType::BypassWeight)
    }

    pub fn convert_file() -> Self {
        Permission(PermType::ConvertFile)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PermWeight(pub i32);

impl PermWeight {
    pub fn new(weight: i32) -> Self {
        PermWeight(weight)
    }
}

#[derive(Debug, Clone)]
pub struct FilePermission {
    pub path: String,
    pub perm_type: FilePermType,
}

impl FilePermission {
    pub fn new(path: impl Into<String>, perm_type: FilePermType) -> Self {
        FilePermission {
            path: path.into(),
            perm_type,
        }
    }

    pub fn read(path: impl Into<String>) -> Self {
        Self::new(path, FilePermType::Read)
    }

    pub fn write(path: impl Into<String>) -> Self {
        Self::new(path, FilePermType::Write)
    }

    pub fn delete(path: impl Into<String>) -> Self {
        Self::new(path, FilePermType::Delete)
    }

    pub fn create_file(path: impl Into<String>) -> Self {
        Self::new(path, FilePermType::CreateFile)
    }

    pub fn create_folder(path: impl Into<String>) -> Self {
        Self::new(path, FilePermType::CreateFolder)
    }

    pub fn create_link(path: impl Into<String>) -> Self {
        Self::new(path, FilePermType::CreateLink)
    }

    pub fn create_backup(path: impl Into<String>) -> Self {
        Self::new(path, FilePermType::CreateBackup)
    }

    pub fn generate_link(path: impl Into<String>) -> Self {
        Self::new(path, FilePermType::GenerateLink)
    }

    pub fn encrypt(path: impl Into<String>) -> Self {
        Self::new(path, FilePermType::Encrypt)
    }

    pub fn create_with_weight(path: impl Into<String>) -> Self {
        Self::new(path, FilePermType::CreateWithWeight)
    }

    pub fn bypass_weight(path: impl Into<String>) -> Self {
        Self::new(path, FilePermType::BypassWeight)
    }

    pub fn recursive(path: impl Into<String>) -> Self {
        Self::new(path, FilePermType::Recursive)
    }
}

/// Engine for checking file permissions
#[derive(Debug, Clone)]
pub struct FilePermissionEngine {
    file_perms: Vec<FilePerms>,
    path: String,
}

impl FilePermissionEngine {
    pub fn new(file_perms: Vec<FilePerms>, path: String) -> Self {
        FilePermissionEngine { file_perms, path }
    }

    pub fn has(&self, file_perm: &FilePermission) -> bool {
        let target_path = match try_normalize_path(&file_perm.path) {
            Ok(path) => path,
            Err(_) => return false,
        };

        self.file_perms.iter().any(|perm| {
            let Ok(perm_path) = try_normalize_path(&perm.path) else {
                return false;
            };

            permission_path_matches(&perm_path, &target_path, perm.recursive)
                && self.check_perm_type(perm, file_perm.perm_type)
        })
    }

    pub fn has_type(&self, path: impl Into<String>, perm_type: FilePermType) -> bool {
        self.has(&FilePermission::new(path, perm_type))
    }

    pub fn can_download(&self, path: impl Into<String>) -> bool {
        self.has_type(path, FilePermType::Read)
    }

    pub fn can_generate_direct_link(&self, path: impl Into<String>) -> bool {
        let path = path.into();
        self.has_type(path.as_str(), FilePermType::Read)
            && self.has_type(path, FilePermType::GenerateLink)
    }

    pub fn can_upload_file(&self, path: impl Into<String>) -> bool {
        let path = path.into();
        self.has_type(path.as_str(), FilePermType::Write)
            && self.has_type(path, FilePermType::CreateFile)
    }

    pub fn can_create_folder_path(&self, path: impl Into<String>) -> bool {
        let path = path.into();
        self.has_type(path.as_str(), FilePermType::Write)
            && self.has_type(path, FilePermType::CreateFolder)
    }

    pub fn can_create_link_path(&self, path: impl Into<String>) -> bool {
        let path = path.into();
        self.has_type(path.as_str(), FilePermType::Write)
            && self.has_type(path, FilePermType::CreateLink)
    }

    pub fn can_delete_path(&self, path: impl Into<String>) -> bool {
        self.has_type(path, FilePermType::Delete)
    }

    pub fn can_create_backup_path(&self, path: impl Into<String>) -> bool {
        let path = path.into();
        self.has_type(path.as_str(), FilePermType::Read)
            && self.has_type(path, FilePermType::CreateBackup)
    }

    pub fn can_restore_backup_path(&self, path: impl Into<String>) -> bool {
        let path = path.into();
        self.has_type(path.as_str(), FilePermType::Write)
            && self.has_type(path, FilePermType::CreateBackup)
    }

    pub fn can_encrypt_path(&self, path: impl Into<String>) -> bool {
        let path = path.into();
        self.has_type(path.as_str(), FilePermType::Read)
            && self.has_type(path.as_str(), FilePermType::Write)
            && self.has_type(path, FilePermType::Encrypt)
    }

    pub fn can_convert_path(&self, path: impl Into<String>) -> bool {
        let path = path.into();
        self.has_type(path.as_str(), FilePermType::Read) && self.has_type(path, FilePermType::Write)
    }

    pub fn can_create_weighted_child_path(&self, path: impl Into<String>) -> bool {
        self.has_type(path, FilePermType::CreateWithWeight)
    }

    fn check_perm_type(&self, perm: &FilePerms, perm_type: FilePermType) -> bool {
        match perm_type {
            FilePermType::Read => perm.read,
            FilePermType::Delete => perm.delete,
            FilePermType::Write => perm.write,
            FilePermType::CreateFile => perm.create_file,
            FilePermType::CreateFolder => perm.create_folder,
            FilePermType::CreateLink => perm.create_link,
            FilePermType::CreateBackup => perm.create_backup,
            FilePermType::CreateWithWeight => perm.create_with_weight,
            FilePermType::GenerateLink => perm.generate_link,
            FilePermType::Encrypt => perm.encrypt,
            FilePermType::BypassWeight => perm.bypass_weight,
            FilePermType::Recursive => perm.recursive,
        }
    }

    pub fn has_all(&self, file_perms: &[FilePermission]) -> bool {
        file_perms.iter().all(|fp| self.has(fp))
    }

    pub fn has_any(&self, file_perms: &[FilePermission]) -> bool {
        file_perms.iter().any(|fp| self.has(fp))
    }

    pub fn get_perms(&self) -> &Vec<FilePerms> {
        &self.file_perms
    }

    pub fn get_path(&self) -> &str {
        &self.path
    }
}

#[derive(Debug, Clone)]
pub struct PermissionEngine {
    permissions: Permissions,
    required_weight: Option<i32>,
    modified: bool,
}

impl PermissionEngine {
    pub fn new(permissions: Permissions) -> Self {
        PermissionEngine {
            permissions,
            required_weight: None,
            modified: false,
        }
    }

    pub fn require(mut self, weight: PermWeight) -> Self {
        self.required_weight = Some(weight.0);
        self
    }

    pub fn clear_requirement(mut self) -> Self {
        self.required_weight = None;
        self
    }

    fn meets_weight_requirement(&self) -> bool {
        match self.required_weight {
            Some(required) => self.permissions.weight >= required || self.permissions.bypass_weight,
            None => true,
        }
    }

    pub fn has(&self, perm: Permission) -> bool {
        // Root bypasses all permission checks
        if self.permissions.is_root {
            return true;
        }

        if !self.meets_weight_requirement() {
            return false;
        }

        match perm.0 {
            PermType::IsRoot => self.permissions.is_root,
            PermType::CreateApiKey => self.permissions.create_api_key,
            PermType::CreateUser => self.permissions.create_user,
            PermType::DeleteUser => self.permissions.delete_user,
            PermType::EditUser => self.permissions.edit_user,
            PermType::ViewUser => self.permissions.view_user,
            PermType::BypassWeight => self.permissions.bypass_weight,
            PermType::ConvertFile => self.permissions.convert_file,
        }
    }

    pub fn has_all(&self, perms: &[Permission]) -> bool {
        perms.iter().all(|p| self.has(*p))
    }

    pub fn has_any(&self, perms: &[Permission]) -> bool {
        perms.iter().any(|p| self.has(*p))
    }

    pub fn weight(&self) -> i32 {
        self.permissions.weight
    }

    pub fn has_weight(&self, min_weight: i32) -> bool {
        self.permissions.is_root
            || self.permissions.weight >= min_weight
            || self.permissions.bypass_weight
    }

    pub fn can_assign_weight(&self, requested_weight: i32) -> bool {
        requested_weight >= 0 && self.has_weight(requested_weight)
    }

    pub fn can_create_api_key_with_weight(&self, requested_weight: i32) -> bool {
        self.has(Permission::create_api_key()) && self.can_assign_weight(requested_weight)
    }

    pub fn can_view_users(&self) -> bool {
        self.has(Permission::view_user())
    }

    pub fn can_edit_user_with_weight(&self, target_weight: i32) -> bool {
        self.has(Permission::edit_user()) && self.can_assign_weight(target_weight)
    }

    pub fn can_delete_user_with_weight(&self, target_weight: i32) -> bool {
        self.has(Permission::delete_user()) && self.can_assign_weight(target_weight)
    }

    pub fn can_action_size(&self, size: i64) -> bool {
        if self.permissions.is_root {
            return true;
        }
        if size < 0 {
            return false;
        }
        match self.permissions.max_action_size {
            Some(max) => size <= max,
            None => true,
        }
    }

    pub fn can_backup_size(&self, size: i64) -> bool {
        if self.permissions.is_root {
            return true;
        }
        if size < 0 {
            return false;
        }
        match self.permissions.max_backup_size {
            Some(max) => size <= max,
            None => true,
        }
    }

    pub fn can_storage_size(&self, size: i64) -> bool {
        if self.permissions.is_root {
            return true;
        }
        if size < 0 {
            return false;
        }
        match self.permissions.total_storage_size {
            Some(max) => size <= max,
            None => true,
        }
    }

    pub fn can_storage_size_with_occupied(&self, additional_size: i64, occupied_size: i64) -> bool {
        if self.permissions.is_root {
            return true;
        }
        match self.permissions.total_storage_size {
            Some(max) => checked_total_within_limit(occupied_size, additional_size, max),
            None => occupied_size >= 0 && additional_size >= 0,
        }
    }

    pub fn remaining_storage(&self, occupied_size: i64) -> Option<i64> {
        if self.permissions.is_root {
            return None; // Unlimited
        }
        if occupied_size < 0 {
            return self.permissions.total_storage_size;
        }
        self.permissions
            .total_storage_size
            .map(|max| (max - occupied_size).max(0))
    }

    pub fn can_create_users(&self, count: i64) -> bool {
        if self.permissions.is_root {
            return true;
        }
        if count < 0 {
            return false;
        }
        match self.permissions.max_create_users {
            Some(max) => count < max,
            None => true,
        }
    }

    pub fn can_create_more_users(&self, current_count: i64, additional: i64) -> bool {
        if self.permissions.is_root {
            return true;
        }
        match self.permissions.max_create_users {
            Some(max) => checked_total_within_limit(current_count, additional, max),
            None => current_count >= 0 && additional >= 0,
        }
    }

    pub fn can_create_subusers(
        &self,
        current_count: i64,
        additional: i64,
        requested_weight: i32,
    ) -> bool {
        self.has(Permission::create_user())
            && self.can_create_more_users(current_count, additional)
            && self.can_assign_weight(requested_weight)
    }

    pub fn can_store_additional(&self, occupied_size: i64, additional_size: i64) -> bool {
        self.can_storage_size_with_occupied(additional_size, occupied_size)
    }

    pub fn can_run_file_conversion(&self, action_size: i64) -> bool {
        self.has(Permission::convert_file()) && self.can_action_size(action_size)
    }

    pub fn can_run_backup(&self, backup_size: i64) -> bool {
        self.can_backup_size(backup_size)
    }

    pub fn is_within_time_window(
        now: chrono::NaiveDateTime,
        valid_from: Option<chrono::NaiveDateTime>,
        valid_until: Option<chrono::NaiveDateTime>,
    ) -> bool {
        valid_from.map(|start| now >= start).unwrap_or(true)
            && valid_until.map(|end| now <= end).unwrap_or(true)
    }

    pub fn get_id(&self) -> &str {
        &self.permissions.id
    }

    pub fn get_permissions(&self) -> &Permissions {
        &self.permissions
    }

    pub fn get_permissions_mut(&mut self) -> &mut Permissions {
        self.modified = true;
        &mut self.permissions
    }

    pub async fn get_file_perms(
        &self,
        conn: &DBConn,
        path: &str,
    ) -> Result<FilePermissionEngine, String> {
        self.get_file_perms_sync(conn, path)
    }

    pub fn get_file_perms_sync(
        &self,
        conn: &DBConn,
        path: &str,
    ) -> Result<FilePermissionEngine, String> {
        let normalized_path = try_normalize_path(path)?;
        let file_perms = fetch_file_perms_recursive(conn, &self.permissions.id, &normalized_path)?;
        Ok(FilePermissionEngine::new(file_perms, normalized_path))
    }

    pub async fn has_file_perm(
        &self,
        conn: &DBConn,
        file_perm: &FilePermission,
    ) -> Result<bool, String> {
        if self.permissions.is_root {
            return Ok(true);
        }

        let file_engine = self.get_file_perms(conn, &file_perm.path).await?;
        Ok(file_engine.has(file_perm))
    }

    pub fn has_file_perm_sync(
        &self,
        conn: &DBConn,
        file_perm: &FilePermission,
    ) -> Result<bool, String> {
        if self.permissions.is_root {
            return Ok(true);
        }

        let file_engine = self.get_file_perms_sync(conn, &file_perm.path)?;
        Ok(file_engine.has(file_perm))
    }

    pub fn set_weight(&mut self, weight: i32) -> &mut Self {
        self.permissions.weight = weight;
        self.modified = true;
        self
    }

    pub fn set_is_root(&mut self, is_root: bool) -> &mut Self {
        warn("[Permission Engine] Setting is_root");
        self.permissions.is_root = is_root;
        self.modified = true;
        self
    }

    pub fn set_create_api_key(&mut self, value: bool) -> &mut Self {
        self.permissions.create_api_key = value;
        self.modified = true;
        self
    }

    pub fn set_create_user(&mut self, value: bool) -> &mut Self {
        self.permissions.create_user = value;
        self.modified = true;
        self
    }

    pub fn set_delete_user(&mut self, value: bool) -> &mut Self {
        self.permissions.delete_user = value;
        self.modified = true;
        self
    }

    pub fn set_edit_user(&mut self, value: bool) -> &mut Self {
        self.permissions.edit_user = value;
        self.modified = true;
        self
    }

    pub fn set_view_user(&mut self, value: bool) -> &mut Self {
        self.permissions.view_user = value;
        self.modified = true;
        self
    }

    pub fn set_bypass_weight(&mut self, value: bool) -> &mut Self {
        self.permissions.bypass_weight = value;
        self.modified = true;
        self
    }

    pub fn set_convert_file(&mut self, value: bool) -> &mut Self {
        self.permissions.convert_file = value;
        self.modified = true;
        self
    }

    pub fn set_max_action_size(&mut self, size: Option<i64>) -> &mut Self {
        self.permissions.max_action_size = size;
        self.modified = true;
        self
    }

    pub fn set_max_backup_size(&mut self, size: Option<i64>) -> &mut Self {
        self.permissions.max_backup_size = size;
        self.modified = true;
        self
    }

    pub fn set_total_storage_size(&mut self, size: Option<i64>) -> &mut Self {
        self.permissions.total_storage_size = size;
        self.modified = true;
        self
    }

    pub fn set_max_create_users(&mut self, count: Option<i64>) -> &mut Self {
        self.permissions.max_create_users = count;
        self.modified = true;
        self
    }

    pub fn set_permission(&mut self, perm: Permission, value: bool) -> &mut Self {
        match perm.0 {
            PermType::IsRoot => self.permissions.is_root = value,
            PermType::CreateApiKey => self.permissions.create_api_key = value,
            PermType::CreateUser => self.permissions.create_user = value,
            PermType::DeleteUser => self.permissions.delete_user = value,
            PermType::EditUser => self.permissions.edit_user = value,
            PermType::ViewUser => self.permissions.view_user = value,
            PermType::BypassWeight => self.permissions.bypass_weight = value,
            PermType::ConvertFile => self.permissions.convert_file = value,
        }
        self.modified = true;
        self
    }

    pub fn is_modified(&self) -> bool {
        self.modified
    }

    pub fn clear_modified(&mut self) {
        self.modified = false;
    }

    pub async fn commit(&mut self, conn: &DBConn) -> Result<(), String> {
        if !self.modified {
            return Ok(());
        }

        let query = r#"
            UPDATE permissions SET
                weight = ?,
                is_root = ?,
                create_api_key = ?,
                create_user = ?,
                delete_user = ?,
                edit_user = ?,
                view_user = ?,
                bypass_weight = ?,
                max_action_size = ?,
                max_backup_size = ?,
                total_storage_size = ?,
                max_create_users = ?,
                convert_file = ?
            WHERE id = ?
        "#;

        conn.execute(
            query,
            duckdb::params![
                self.permissions.weight,
                self.permissions.is_root,
                self.permissions.create_api_key,
                self.permissions.create_user,
                self.permissions.delete_user,
                self.permissions.edit_user,
                self.permissions.view_user,
                self.permissions.bypass_weight,
                self.permissions.max_action_size,
                self.permissions.max_backup_size,
                self.permissions.total_storage_size,
                self.permissions.max_create_users,
                self.permissions.convert_file,
                self.permissions.id,
            ],
        )
        .map_err(|e| format!("Failed to commit permissions: {}", e))?;

        self.modified = false;
        Ok(())
    }

    pub async fn create(&self, conn: &DBConn) -> Result<(), String> {
        let query = r#"
            INSERT INTO permissions (
                id, weight, is_root, create_api_key, create_user, delete_user,
                edit_user, view_user, bypass_weight, max_action_size, max_backup_size,
                total_storage_size, max_create_users, convert_file, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#;

        conn.execute(
            query,
            duckdb::params![
                self.permissions.id,
                self.permissions.weight,
                self.permissions.is_root,
                self.permissions.create_api_key,
                self.permissions.create_user,
                self.permissions.delete_user,
                self.permissions.edit_user,
                self.permissions.view_user,
                self.permissions.bypass_weight,
                self.permissions.max_action_size,
                self.permissions.max_backup_size,
                self.permissions.total_storage_size,
                self.permissions.max_create_users,
                self.permissions.convert_file,
                self.permissions.created_at,
            ],
        )
        .map_err(|e| format!("Failed to create permissions: {}", e))?;

        Ok(())
    }

    pub async fn delete(&self, conn: &DBConn) -> Result<(), String> {
        conn.execute(
            "DELETE FROM file_perms WHERE permission_id = ?",
            duckdb::params![self.permissions.id],
        )
        .map_err(|e| format!("Failed to delete file permissions: {}", e))?;

        conn.execute(
            "DELETE FROM permissions WHERE id = ?",
            duckdb::params![self.permissions.id],
        )
        .map_err(|e| format!("Failed to delete permissions: {}", e))?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct FilePermBuilder {
    file_perm: FilePerms,
    is_new: bool,
}

impl FilePermBuilder {
    pub fn new(permission_id: String, path: String) -> Self {
        let normalized_path = try_normalize_path(&path).unwrap_or_else(|_| path.clone());

        FilePermBuilder {
            file_perm: FilePerms {
                id: generate_id(),
                permission_id,
                path: normalized_path,
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
            },
            is_new: true,
        }
    }

    pub fn from_existing(file_perm: FilePerms) -> Self {
        FilePermBuilder {
            file_perm,
            is_new: false,
        }
    }

    pub fn recursive(mut self, value: bool) -> Self {
        self.file_perm.recursive = value;
        self
    }

    pub fn bypass_weight(mut self, value: bool) -> Self {
        self.file_perm.bypass_weight = value;
        self
    }

    pub fn read(mut self, value: bool) -> Self {
        self.file_perm.read = value;
        self
    }

    pub fn write(mut self, value: bool) -> Self {
        self.file_perm.write = value;
        self
    }

    pub fn delete(mut self, value: bool) -> Self {
        self.file_perm.delete = value;
        self
    }

    pub fn create_file(mut self, value: bool) -> Self {
        self.file_perm.create_file = value;
        self
    }

    pub fn create_folder(mut self, value: bool) -> Self {
        self.file_perm.create_folder = value;
        self
    }

    pub fn create_link(mut self, value: bool) -> Self {
        self.file_perm.create_link = value;
        self
    }

    pub fn create_backup(mut self, value: bool) -> Self {
        self.file_perm.create_backup = value;
        self
    }

    pub fn create_with_weight(mut self, value: bool) -> Self {
        self.file_perm.create_with_weight = value;
        self
    }

    pub fn generate_link(mut self, value: bool) -> Self {
        self.file_perm.generate_link = value;
        self
    }

    pub fn encrypt(mut self, value: bool) -> Self {
        self.file_perm.encrypt = value;
        self
    }

    pub fn set_permission(mut self, perm_type: FilePermType, value: bool) -> Self {
        match perm_type {
            FilePermType::Read => self.file_perm.read = value,
            FilePermType::Delete => self.file_perm.delete = value,
            FilePermType::Write => self.file_perm.write = value,
            FilePermType::CreateFile => self.file_perm.create_file = value,
            FilePermType::CreateFolder => self.file_perm.create_folder = value,
            FilePermType::CreateLink => self.file_perm.create_link = value,
            FilePermType::CreateBackup => self.file_perm.create_backup = value,
            FilePermType::CreateWithWeight => self.file_perm.create_with_weight = value,
            FilePermType::GenerateLink => self.file_perm.generate_link = value,
            FilePermType::Encrypt => self.file_perm.encrypt = value,
            FilePermType::BypassWeight => self.file_perm.bypass_weight = value,
            FilePermType::Recursive => self.file_perm.recursive = value,
        }
        self
    }

    pub fn allow_read_all(mut self) -> Self {
        self.file_perm.read = true;
        self.file_perm.generate_link = true;
        self
    }

    pub fn allow_write_all(mut self) -> Self {
        self.file_perm.write = true;
        self.file_perm.create_file = true;
        self.file_perm.create_folder = true;
        self.file_perm.create_link = true;
        self.file_perm.create_backup = true;
        self
    }

    pub fn allow_all(mut self) -> Self {
        self.file_perm.read = true;
        self.file_perm.delete = true;
        self.file_perm.write = true;
        self.file_perm.create_file = true;
        self.file_perm.create_folder = true;
        self.file_perm.create_link = true;
        self.file_perm.create_backup = true;
        self.file_perm.create_with_weight = true;
        self.file_perm.generate_link = true;
        self.file_perm.encrypt = true;
        self
    }

    pub fn build(self) -> FilePerms {
        self.file_perm
    }

    pub async fn commit(self, conn: &DBConn) -> Result<FilePerms, String> {
        let mut file_perm = self.file_perm;
        file_perm.path = try_normalize_path(&file_perm.path)?;

        if self.is_new {
            let query = r#"
                INSERT INTO file_perms (
                    id, permission_id, path, bypass_weight, recursive, read, delete, write,
                    create_file, create_folder, create_link, create_backup, create_with_weight,
                    generate_link, encrypt, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#;

            conn.execute(
                query,
                duckdb::params![
                    file_perm.id,
                    file_perm.permission_id,
                    file_perm.path,
                    file_perm.bypass_weight,
                    file_perm.recursive,
                    file_perm.read,
                    file_perm.delete,
                    file_perm.write,
                    file_perm.create_file,
                    file_perm.create_folder,
                    file_perm.create_link,
                    file_perm.create_backup,
                    file_perm.create_with_weight,
                    file_perm.generate_link,
                    file_perm.encrypt,
                    file_perm.created_at,
                ],
            )
            .map_err(|e| format!("Failed to create file permission: {}", e))?;
        } else {
            let query = r#"
                UPDATE file_perms SET
                    path = ?,
                    bypass_weight = ?,
                    recursive = ?,
                    read = ?,
                    delete = ?,
                    write = ?,
                    create_file = ?,
                    create_folder = ?,
                    create_link = ?,
                    create_backup = ?,
                    create_with_weight = ?,
                    generate_link = ?,
                    encrypt = ?
                WHERE id = ?
            "#;

            conn.execute(
                query,
                duckdb::params![
                    file_perm.path,
                    file_perm.bypass_weight,
                    file_perm.recursive,
                    file_perm.read,
                    file_perm.delete,
                    file_perm.write,
                    file_perm.create_file,
                    file_perm.create_folder,
                    file_perm.create_link,
                    file_perm.create_backup,
                    file_perm.create_with_weight,
                    file_perm.generate_link,
                    file_perm.encrypt,
                    file_perm.id,
                ],
            )
            .map_err(|e| format!("Failed to update file permission: {}", e))?;
        }

        Ok(file_perm)
    }
}

pub async fn delete_file_perm(conn: &DBConn, id: &str) -> Result<(), String> {
    conn.execute("DELETE FROM file_perms WHERE id = ?", duckdb::params![id])
        .map_err(|e| format!("Failed to delete file permission: {}", e))?;
    Ok(())
}

pub async fn delete_file_perms_for_path(
    conn: &DBConn,
    permission_id: &str,
    path: &str,
) -> Result<(), String> {
    let normalized = try_normalize_path(path)?;
    conn.execute(
        "DELETE FROM file_perms WHERE permission_id = ? AND path = ?",
        duckdb::params![permission_id, normalized],
    )
    .map_err(|e| format!("Failed to delete file permissions: {}", e))?;
    Ok(())
}

fn normalize_path(path: &str) -> String {
    try_normalize_path(path).unwrap_or_else(|_| "/__invalid_permission_path__".to_string())
}

fn try_normalize_path(path: &str) -> Result<String, String> {
    let trimmed = path.trim();

    if trimmed.contains('\0') {
        return Err("Permission path contains a null byte".to_string());
    }

    let slash_path = trimmed.replace('\\', "/");
    let mut components = Vec::new();

    for component in slash_path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                return Err(format!(
                    "Permission path cannot contain parent traversal: {}",
                    path
                ));
            }
            _ => components.push(component),
        }
    }

    if components.is_empty() {
        Ok("/".to_string())
    } else {
        Ok(format!("/{}", components.join("/")))
    }
}

fn permission_path_matches(perm_path: &str, target_path: &str, recursive: bool) -> bool {
    perm_path == target_path || (recursive && is_same_or_descendant(target_path, perm_path))
}

fn is_same_or_descendant(target_path: &str, parent_path: &str) -> bool {
    parent_path == "/"
        || target_path == parent_path
        || target_path
            .strip_prefix(parent_path)
            .map(|remaining| remaining.starts_with('/'))
            .unwrap_or(false)
}

fn checked_total_within_limit(current: i64, additional: i64, max: i64) -> bool {
    current >= 0
        && additional >= 0
        && max >= 0
        && current
            .checked_add(additional)
            .map(|total| total <= max)
            .unwrap_or(false)
}

/// Get path hierarchy from most specific to root
/// e.g., "/a/b/c" -> ["/a/b/c", "/a/b", "/a", "/"]
fn get_path_hierarchy(path: &str) -> Vec<String> {
    let normalized = normalize_path(path);
    let mut paths = Vec::new();

    let mut current = normalized.as_str();
    paths.push(current.to_string());

    while current != "/" {
        if let Some(last_slash) = current.rfind('/') {
            if last_slash == 0 {
                current = "/";
            } else {
                current = &current[..last_slash];
            }
            paths.push(current.to_string());
        } else {
            break;
        }
    }

    paths
}

fn fetch_file_perms_recursive(
    conn: &DBConn,
    permission_id: &str,
    path: &str,
) -> Result<Vec<FilePerms>, String> {
    let query = format!(
        r#"{}
        WHERE permission_id = ?
        ORDER BY length(path) DESC
    "#,
        FILE_PERMS_SELECT
    );

    let mut stmt = conn
        .prepare(&query)
        .map_err(|e| format!("Failed to prepare file permissions query: {}", e))?;

    let rows = stmt
        .query_map(duckdb::params![permission_id], row_to_file_perms)
        .map_err(|e| format!("Failed to query file permissions: {}", e))?;

    let normalized_path = try_normalize_path(path)?;
    rows.map(|row| row.map_err(|e| format!("Failed to read file permission row: {}", e)))
        .filter_map(|row| match row {
            Ok(fp) => match try_normalize_path(&fp.path) {
                Ok(fp_path)
                    if permission_path_matches(&fp_path, &normalized_path, fp.recursive) =>
                {
                    Some(Ok(fp))
                }
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            },
            Err(e) => Some(Err(e)),
        })
        .collect()
}

fn row_to_file_perms(row: &duckdb::Row<'_>) -> duckdb::Result<FilePerms> {
    Ok(FilePerms {
        id: row.get(0)?,
        permission_id: row.get(1)?,
        path: row.get(2)?,
        bypass_weight: row.get(3)?,
        recursive: row.get(4)?,
        read: row.get(5)?,
        delete: row.get(6)?,
        write: row.get(7)?,
        create_file: row.get(8)?,
        create_folder: row.get(9)?,
        create_link: row.get(10)?,
        create_backup: row.get(11)?,
        create_with_weight: row.get(12)?,
        generate_link: row.get(13)?,
        encrypt: row.get(14)?,
        created_at: row.get(15)?,
    })
}

fn row_to_permissions(row: &duckdb::Row<'_>) -> duckdb::Result<Permissions> {
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
}

fn generate_id() -> String {
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

    format!("p.{}.{}", random_part, ts_b64)
}

pub fn to_engine(permissions: Permissions) -> PermissionEngine {
    PermissionEngine::new(permissions)
}

pub fn new_engine(id: String, weight: i32) -> PermissionEngine {
    PermissionEngine::new(Permissions {
        id,
        weight,
        is_root: false,
        create_api_key: false,
        create_user: false,
        delete_user: false,
        edit_user: false,
        view_user: false,
        bypass_weight: false,
        max_action_size: None,
        max_backup_size: None,
        total_storage_size: None,
        max_create_users: None,
        convert_file: false,
        created_at: chrono::Utc::now().naive_utc(),
    })
}

pub fn perms_from_key_sync(conn: &DBConn, key: String) -> Option<Permissions> {
    let permission_id: Option<String> = conn
        .query_row(
            "SELECT permission_id FROM keys WHERE key = ?",
            duckdb::params![key],
            |row| row.get(0),
        )
        .ok();

    let permission_id = permission_id?;

    conn.query_row(
        PERMISSIONS_SELECT_BY_ID,
        duckdb::params![permission_id],
        row_to_permissions,
    )
    .ok()
}

pub async fn perms_from_key(conn: &DBConn, key: String) -> Option<Permissions> {
    perms_from_key_sync(conn, key)
}

pub fn engine_from_key_sync(conn: &DBConn, key: String) -> Option<PermissionEngine> {
    perms_from_key_sync(&conn, key).map(PermissionEngine::new)
}

pub async fn engine_from_key(conn: &DBConn, key: String) -> Option<PermissionEngine> {
    perms_from_key_sync(&conn, key).map(PermissionEngine::new)
}

pub async fn load_permission(conn: &DBConn, permission_id: &str) -> Option<Permissions> {
    load_permission_sync(conn, permission_id)
}

pub async fn load_engine(conn: &DBConn, permission_id: &str) -> Option<PermissionEngine> {
    load_permission(conn, permission_id)
        .await
        .map(PermissionEngine::new)
}

pub fn load_permission_sync(conn: &DBConn, permission_id: &str) -> Option<Permissions> {
    conn.query_row(
        PERMISSIONS_SELECT_BY_ID,
        duckdb::params![permission_id],
        row_to_permissions,
    )
    .ok()
}

pub fn load_engine_sync(conn: &DBConn, permission_id: &str) -> Option<PermissionEngine> {
    load_permission_sync(conn, permission_id).map(PermissionEngine::new)
}

pub async fn engine_from_id(conn: &DBConn, permission_id: &str) -> Option<PermissionEngine> {
    load_engine(conn, permission_id).await
}

pub async fn load_file_perm(conn: &DBConn, id: &str) -> Option<FilePerms> {
    let query = format!("{} WHERE id = ?", FILE_PERMS_SELECT);

    conn.query_row(&query, duckdb::params![id], row_to_file_perms)
        .ok()
}

pub async fn load_all_file_perms(conn: &DBConn, permission_id: &str) -> Vec<FilePerms> {
    warn("Loading all file permissions.");

    let query = format!(
        r#"{}
        WHERE permission_id = ?
        ORDER BY path
    "#,
        FILE_PERMS_SELECT
    );

    let mut stmt = match conn.prepare(&query) {
        Ok(stmt) => stmt,
        Err(_) => return Vec::new(),
    };

    let rows = stmt.query_map(duckdb::params![permission_id], row_to_file_perms);

    match rows {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => Vec::new(),
    }
}

// TESTS - AI generated

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_permissions(is_root: bool, weight: i32) -> Permissions {
        Permissions {
            id: "test_id".to_string(),
            weight,
            is_root,
            create_api_key: true,
            create_user: false,
            delete_user: false,
            edit_user: true,
            view_user: true,
            bypass_weight: false,
            max_action_size: Some(1024),
            max_backup_size: Some(2048),
            total_storage_size: Some(10240),
            max_create_users: Some(5),
            convert_file: true,
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap().naive_utc(),
        }
    }

    fn mock_file_perms() -> Vec<FilePerms> {
        vec![
            FilePerms {
                id: "fp1".to_string(),
                permission_id: "test_id".to_string(),
                path: "/".to_string(),
                bypass_weight: false,
                recursive: true,
                read: true,
                delete: false,
                write: false,
                create_file: false,
                create_folder: false,
                create_link: false,
                create_backup: false,
                create_with_weight: false,
                generate_link: false,
                encrypt: false,
                created_at: chrono::DateTime::from_timestamp(0, 0).unwrap().naive_utc(),
            },
            FilePerms {
                id: "fp2".to_string(),
                permission_id: "test_id".to_string(),
                path: "/home".to_string(),
                bypass_weight: false,
                recursive: true,
                read: true,
                delete: false,
                write: true,
                create_file: true,
                create_folder: true,
                create_link: false,
                create_backup: false,
                create_with_weight: false,
                generate_link: false,
                encrypt: false,
                created_at: chrono::DateTime::from_timestamp(0, 0).unwrap().naive_utc(),
            },
            FilePerms {
                id: "fp3".to_string(),
                permission_id: "test_id".to_string(),
                path: "/home/user/secret".to_string(),
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
                encrypt: true,
                created_at: chrono::DateTime::from_timestamp(0, 0).unwrap().naive_utc(),
            },
        ]
    }

    #[test]
    fn test_permission_has() {
        let perms = mock_permissions(false, 50);
        let engine = to_engine(perms);

        assert!(engine.has(Permission::create_api_key()));
        assert!(engine.has(Permission::edit_user()));
        assert!(engine.has(Permission::view_user()));
        assert!(engine.has(Permission::convert_file()));
        assert!(!engine.has(Permission::create_user()));
        assert!(!engine.has(Permission::delete_user()));
        assert!(!engine.has(Permission::is_root()));
    }

    #[test]
    fn test_root_has_all() {
        let perms = mock_permissions(true, 100);
        let engine = to_engine(perms);

        assert!(engine.has(Permission::create_api_key()));
        assert!(engine.has(Permission::create_user()));
        assert!(engine.has(Permission::delete_user()));
        assert!(engine.has(Permission::is_root()));
    }

    #[test]
    fn test_root_bypasses_required_weight() {
        let perms = mock_permissions(true, 0);
        let engine = to_engine(perms).require(PermWeight::new(100_000));

        assert!(engine.has(Permission::delete_user()));
        assert!(engine.has_weight(100_000));
    }

    #[test]
    fn test_weight_requirement() {
        let perms = mock_permissions(false, 50);
        let engine = to_engine(perms);

        assert!(engine.clone().has(Permission::create_api_key()));

        assert!(
            engine
                .clone()
                .require(PermWeight::new(50))
                .has(Permission::create_api_key())
        );
        assert!(
            engine
                .clone()
                .require(PermWeight::new(30))
                .has(Permission::create_api_key())
        );

        assert!(
            !engine
                .clone()
                .require(PermWeight::new(100))
                .has(Permission::create_api_key())
        );
    }

    #[test]
    fn test_has_weight() {
        let perms = mock_permissions(false, 50);
        let engine = to_engine(perms);

        assert!(engine.has_weight(50));
        assert!(engine.has_weight(30));
        assert!(!engine.has_weight(100));
        assert!(engine.can_assign_weight(50));
        assert!(!engine.can_assign_weight(51));
        assert!(!engine.can_assign_weight(-1));
    }

    #[test]
    fn test_api_key_and_subuser_weight_guards() {
        let perms = mock_permissions(false, 50);
        let mut engine = to_engine(perms);

        assert!(engine.can_create_api_key_with_weight(50));
        assert!(!engine.can_create_api_key_with_weight(51));
        assert!(!engine.can_create_api_key_with_weight(-1));

        assert!(!engine.can_create_subusers(0, 1, 10));
        engine.set_create_user(true);
        assert!(engine.can_create_subusers(4, 1, 50));
        assert!(!engine.can_create_subusers(4, 2, 50));
        assert!(!engine.can_create_subusers(0, 1, 51));
        assert!(!engine.can_create_subusers(0, -1, 10));

        engine.set_bypass_weight(true);
        assert!(engine.can_create_api_key_with_weight(10_000));
        assert!(engine.can_create_subusers(0, 1, 10_000));
    }

    #[test]
    fn test_user_management_weight_guards() {
        let perms = mock_permissions(false, 50);
        let mut engine = to_engine(perms);

        assert!(engine.can_view_users());
        assert!(engine.can_edit_user_with_weight(50));
        assert!(!engine.can_edit_user_with_weight(51));
        assert!(!engine.can_delete_user_with_weight(50));

        engine.set_delete_user(true);
        assert!(engine.can_delete_user_with_weight(50));
        assert!(!engine.can_delete_user_with_weight(51));

        let root = to_engine(mock_permissions(true, 0));
        assert!(root.can_edit_user_with_weight(1_000_000));
        assert!(root.can_delete_user_with_weight(1_000_000));
    }

    #[test]
    fn test_size_limits() {
        let perms = mock_permissions(false, 50);
        let engine = to_engine(perms);

        assert!(engine.can_action_size(500));
        assert!(engine.can_action_size(1024));
        assert!(!engine.can_action_size(2000));
        assert!(!engine.can_action_size(-1));

        assert!(engine.can_backup_size(1000));
        assert!(engine.can_backup_size(2048));
        assert!(!engine.can_backup_size(3000));
        assert!(!engine.can_backup_size(-1));
    }

    #[test]
    fn test_storage_with_occupied() {
        let perms = mock_permissions(false, 50);
        let engine = to_engine(perms);

        assert!(engine.can_storage_size_with_occupied(1000, 5000));
        assert!(engine.can_storage_size_with_occupied(5000, 5000));
        assert!(!engine.can_storage_size_with_occupied(6000, 5000));
        assert!(!engine.can_storage_size_with_occupied(-1, 5000));
        assert!(!engine.can_storage_size_with_occupied(1, i64::MAX));

        assert_eq!(engine.remaining_storage(5000), Some(5240));
        assert_eq!(engine.remaining_storage(10240), Some(0));
        assert_eq!(engine.remaining_storage(15000), Some(0));
    }

    #[test]
    fn test_future_workflow_global_limits() {
        let perms = mock_permissions(false, 50);
        let engine = to_engine(perms);

        assert!(engine.can_store_additional(5000, 5000));
        assert!(!engine.can_store_additional(5000, 6000));
        assert!(engine.can_run_file_conversion(1024));
        assert!(!engine.can_run_file_conversion(1025));
        assert!(engine.can_run_backup(2048));
        assert!(!engine.can_run_backup(2049));
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("test"), "/test");
        assert_eq!(normalize_path("/test"), "/test");
        assert_eq!(normalize_path("/test/"), "/test");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(try_normalize_path(r"\test\\child").unwrap(), "/test/child");
        assert_eq!(try_normalize_path("/test//./child").unwrap(), "/test/child");
        assert!(try_normalize_path("/test/../child").is_err());
    }

    #[test]
    fn test_path_hierarchy() {
        let paths = get_path_hierarchy("/a/b/c");
        assert_eq!(paths, vec!["/a/b/c", "/a/b", "/a", "/"]);

        let paths = get_path_hierarchy("/");
        assert_eq!(paths, vec!["/"]);

        let paths = get_path_hierarchy("/single");
        assert_eq!(paths, vec!["/single", "/"]);
    }

    #[test]
    fn test_file_permission_recursive() {
        let file_perms = mock_file_perms();
        let engine = FilePermissionEngine::new(file_perms, "/home/user/docs".to_string());

        assert!(engine.has(&FilePermission::read("/home/user/docs")));
        assert!(engine.has(&FilePermission::write("/home/user/docs")));
        assert!(engine.has(&FilePermission::create_file("/home/user/docs")));
        assert!(!engine.has(&FilePermission::delete("/home/user/docs")));
        let engine2 = FilePermissionEngine::new(mock_file_perms(), "/home/user/secret".to_string());
        assert!(engine2.has(&FilePermission::encrypt("/home/user/secret")));
        let engine3 =
            FilePermissionEngine::new(mock_file_perms(), "/home/user/secret/child".to_string());
        assert!(!engine3.has(&FilePermission::encrypt("/home/user/secret/child")));
    }

    #[test]
    fn test_recursive_path_boundaries() {
        let file_perms = vec![FilePerms {
            id: "fp".to_string(),
            permission_id: "test_id".to_string(),
            path: "/home/user".to_string(),
            bypass_weight: false,
            recursive: true,
            read: true,
            delete: false,
            write: false,
            create_file: false,
            create_folder: false,
            create_link: false,
            create_backup: false,
            create_with_weight: false,
            generate_link: false,
            encrypt: false,
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap().naive_utc(),
        }];
        let engine = FilePermissionEngine::new(file_perms, "/home/user".to_string());

        assert!(engine.has(&FilePermission::read("/home/user/docs")));
        assert!(!engine.has(&FilePermission::read("/home/userland")));
    }

    #[test]
    fn test_file_workflow_helpers_for_planned_features() {
        let file_perm = FilePermBuilder::new("test_id".to_string(), "/bucket".to_string())
            .recursive(true)
            .allow_all()
            .build();
        let engine =
            FilePermissionEngine::new(vec![file_perm], "/bucket/docs/file.txt".to_string());

        assert!(engine.can_download("/bucket/docs/file.txt"));
        assert!(engine.can_generate_direct_link("/bucket/docs/file.txt"));
        assert!(engine.can_upload_file("/bucket/docs/file.txt"));
        assert!(engine.can_create_folder_path("/bucket/docs/new"));
        assert!(engine.can_create_link_path("/bucket/docs/link"));
        assert!(engine.can_create_backup_path("/bucket/docs/file.txt"));
        assert!(engine.can_restore_backup_path("/bucket/docs/file.txt"));
        assert!(engine.can_encrypt_path("/bucket/docs/file.txt"));
        assert!(engine.can_convert_path("/bucket/docs/file.txt"));
        assert!(engine.can_create_weighted_child_path("/bucket/docs/file.txt"));
        assert!(engine.can_delete_path("/bucket/docs/file.txt"));
        assert!(!engine.can_download("/bucket-neighbor/file.txt"));
    }

    #[test]
    fn test_file_workflow_helpers_require_composite_permissions() {
        let link_only = FilePermBuilder::new("test_id".to_string(), "/links".to_string())
            .recursive(true)
            .generate_link(true)
            .build();
        let encrypt_without_write =
            FilePermBuilder::new("test_id".to_string(), "/encrypted".to_string())
                .recursive(true)
                .read(true)
                .encrypt(true)
                .build();
        let backup_without_read =
            FilePermBuilder::new("test_id".to_string(), "/backups".to_string())
                .recursive(true)
                .create_backup(true)
                .build();
        let engine = FilePermissionEngine::new(
            vec![link_only, encrypt_without_write, backup_without_read],
            "/".to_string(),
        );

        assert!(!engine.can_generate_direct_link("/links/file.txt"));
        assert!(!engine.can_encrypt_path("/encrypted/file.txt"));
        assert!(!engine.can_create_backup_path("/backups/file.txt"));
    }

    #[test]
    fn test_has_all_and_has_any_for_multi_step_file_actions() {
        let file_perm = FilePermBuilder::new("test_id".to_string(), "/bucket".to_string())
            .recursive(true)
            .read(true)
            .write(true)
            .create_file(true)
            .build();
        let engine = FilePermissionEngine::new(vec![file_perm], "/bucket/file.txt".to_string());

        assert!(engine.has_all(&[
            FilePermission::read("/bucket/file.txt"),
            FilePermission::write("/bucket/file.txt"),
            FilePermission::create_file("/bucket/file.txt"),
        ]));
        assert!(engine.has_any(&[
            FilePermission::delete("/bucket/file.txt"),
            FilePermission::read("/bucket/file.txt"),
        ]));
        assert!(!engine.has_all(&[
            FilePermission::read("/bucket/file.txt"),
            FilePermission::delete("/bucket/file.txt"),
        ]));
    }

    #[test]
    fn test_invalid_permission_paths_are_denied() {
        let file_perm = FilePermBuilder::new("test_id".to_string(), "/bucket".to_string())
            .recursive(true)
            .allow_all()
            .build();
        let engine = FilePermissionEngine::new(vec![file_perm], "/bucket".to_string());

        assert!(!engine.can_download("/bucket/../secret"));
        assert!(!engine.can_upload_file("/bucket/\0/file.txt"));
    }

    #[test]
    fn test_file_perm_builder_normalizes_paths() {
        let file_perm =
            FilePermBuilder::new("test_id".to_string(), r"home\\user//docs/".to_string()).build();

        assert_eq!(file_perm.path, "/home/user/docs");
    }

    #[test]
    fn test_file_perm_builder_presets_are_consistent() {
        let read_all = FilePermBuilder::new("test_id".to_string(), "/read".to_string())
            .allow_read_all()
            .build();
        assert!(read_all.read);
        assert!(read_all.generate_link);
        assert!(!read_all.write);

        let write_all = FilePermBuilder::new("test_id".to_string(), "/write".to_string())
            .allow_write_all()
            .build();
        assert!(write_all.write);
        assert!(write_all.create_file);
        assert!(write_all.create_folder);
        assert!(write_all.create_link);
        assert!(write_all.create_backup);
        assert!(!write_all.read);
    }

    #[test]
    fn test_time_window_helper_for_future_time_limits() {
        let now = chrono::DateTime::from_timestamp(100, 0)
            .unwrap()
            .naive_utc();
        let before = chrono::DateTime::from_timestamp(50, 0).unwrap().naive_utc();
        let after = chrono::DateTime::from_timestamp(150, 0)
            .unwrap()
            .naive_utc();

        assert!(PermissionEngine::is_within_time_window(now, None, None));
        assert!(PermissionEngine::is_within_time_window(
            now,
            Some(before),
            Some(after)
        ));
        assert!(!PermissionEngine::is_within_time_window(
            now,
            Some(after),
            None
        ));
        assert!(!PermissionEngine::is_within_time_window(
            now,
            None,
            Some(before)
        ));
    }

    #[test]
    fn test_modification() {
        let perms = mock_permissions(false, 50);
        let mut engine = to_engine(perms);

        assert!(!engine.is_modified());

        engine.set_weight(100);
        assert!(engine.is_modified());
        assert_eq!(engine.weight(), 100);

        engine.set_create_user(true);
        assert!(engine.has(Permission::create_user()));

        engine.clear_modified();
        assert!(!engine.is_modified());
    }

    #[test]
    fn test_get_id() {
        let perms = mock_permissions(false, 50);
        let engine = to_engine(perms);

        assert_eq!(engine.get_id(), "test_id");
    }
}
