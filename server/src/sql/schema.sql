BEGIN;

-- PERMISSIONS
CREATE TABLE IF NOT EXISTS permissions (
    id VARCHAR PRIMARY KEY,
    weight INTEGER NOT NULL,
    is_root BOOLEAN NOT NULL DEFAULT FALSE,
    create_api_key BOOLEAN NOT NULL DEFAULT FALSE,
    create_user BOOLEAN NOT NULL DEFAULT FALSE,
    delete_user BOOLEAN NOT NULL DEFAULT FALSE,
    edit_user BOOLEAN NOT NULL DEFAULT FALSE,
    view_user BOOLEAN NOT NULL DEFAULT FALSE,
    bypass_weight BOOLEAN NOT NULL DEFAULT FALSE,
    max_action_size INT8,
    max_backup_size INT8,
    total_storage_size INT8,
    max_create_users INT8,
    convert_file BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- FILE_PERMS
CREATE TABLE IF NOT EXISTS file_perms (
    id VARCHAR PRIMARY KEY,
    permission_id VARCHAR NOT NULL,
    path VARCHAR NOT NULL,
    bypass_weight BOOLEAN NOT NULL DEFAULT FALSE,
    recursive BOOLEAN NOT NULL DEFAULT FALSE,
    read BOOLEAN NOT NULL DEFAULT FALSE,
    delete BOOLEAN NOT NULL DEFAULT FALSE,
    write BOOLEAN NOT NULL DEFAULT FALSE,
    create_file BOOLEAN NOT NULL DEFAULT FALSE,
    create_folder BOOLEAN NOT NULL DEFAULT FALSE,
    create_link BOOLEAN NOT NULL DEFAULT FALSE,
    create_backup BOOLEAN NOT NULL DEFAULT FALSE,
    create_with_weight BOOLEAN NOT NULL DEFAULT FALSE,
    generate_link BOOLEAN NOT NULL DEFAULT FALSE,
    encrypt BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
);

-- USERS
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR PRIMARY KEY,
    username VARCHAR NOT NULL UNIQUE,
    password_hash VARCHAR NOT NULL,
    is_everyone BOOLEAN NOT NULL DEFAULT FALSE,
    permission_id VARCHAR NOT NULL,
    created_by_id VARCHAR,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (permission_id) REFERENCES permissions(id),
    FOREIGN KEY (created_by_id) REFERENCES users(id)
);

-- FILES
CREATE TABLE IF NOT EXISTS files (
    id VARCHAR PRIMARY KEY,
    path VARCHAR NOT NULL UNIQUE,
    metadata JSON DEFAULT '{}',
    type VARCHAR NOT NULL CHECK (type IN ('file', 'folder', 'link')),
    mime_type VARCHAR,
    size BIGINT NOT NULL DEFAULT 0,
    link VARCHAR CHECK (link IN ('http', 'local', 'base64_data_url', 'ftp', 'git')),
    link_target VARCHAR,
    sync_on VARCHAR NOT NULL CHECK (sync_on IN ('view', 'manual', 'interval')) DEFAULT 'manual',
    sync_interval INTEGER,
    last_synced TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- BACKUPS
CREATE TABLE IF NOT EXISTS backups (
    id VARCHAR PRIMARY KEY,
    path VARCHAR NOT NULL,
    size BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    created_by_id VARCHAR NOT NULL,
    file_id VARCHAR NOT NULL,
    FOREIGN KEY (created_by_id) REFERENCES users(id),
    FOREIGN KEY (file_id) REFERENCES files(id)
);

-- KEYS
CREATE TABLE IF NOT EXISTS keys (
    id VARCHAR PRIMARY KEY,
    key VARCHAR NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    owner_id VARCHAR NOT NULL,
    permission_id VARCHAR NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
);

-- LINKS
CREATE TABLE IF NOT EXISTS links (
    id VARCHAR PRIMARY KEY,
    file_id VARCHAR NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    access_count INTEGER NOT NULL DEFAULT 0,
    max_access_count INTEGER,
    created_by_id VARCHAR NOT NULL,
    password_hash VARCHAR,
    FOREIGN KEY (file_id) REFERENCES files(id),
    FOREIGN KEY (created_by_id) REFERENCES users(id)
);

-- INDEXES
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_permission_id ON users(permission_id);
CREATE INDEX IF NOT EXISTS idx_users_created_by_id ON users(created_by_id);
CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
CREATE INDEX IF NOT EXISTS idx_backups_created_by_id ON backups(created_by_id);
CREATE INDEX IF NOT EXISTS idx_backups_file_id ON backups(file_id);
CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key);
CREATE INDEX IF NOT EXISTS idx_file_perms_permission_id ON file_perms(permission_id);
CREATE INDEX IF NOT EXISTS idx_file_perms_path ON file_perms(path);
CREATE INDEX IF NOT EXISTS idx_links_file_id ON links(file_id);
CREATE INDEX IF NOT EXISTS idx_links_created_by_id ON links(created_by_id);

COMMIT;
