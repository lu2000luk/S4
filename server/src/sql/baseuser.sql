BEGIN;
INSERT INTO permissions (
    id,
    weight,
    is_root,
    create_api_key,
    create_user,
    delete_user,
    edit_user,
    view_user,
    bypass_weight,
    max_action_size,
    max_backup_size,
    total_storage_size,
    max_create_users,
    convert_file
)
SELECT
    'admin',
    100000,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    9223372036854775807,
    9223372036854775807,
    9223372036854775807,
    9223372036854775807,
    TRUE
WHERE NOT EXISTS (
    SELECT 1 FROM permissions WHERE id = 'admin'
);

-- Insert admin file permissions for root path
INSERT INTO file_perms (
    id,
    permission_id,
    path,
    bypass_weight,
    recursive,
    read,
    delete,
    write,
    create_file,
    create_folder,
    create_link,
    create_backup,
    create_with_weight,
    generate_link,
    encrypt
)
SELECT
    'admin_root',
    'admin',
    '/',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE
WHERE NOT EXISTS (
    SELECT 1 FROM file_perms WHERE id = 'admin_root'
);

-- Insert base admin user
INSERT INTO users (
    id,
    username,
    password_hash,
    is_everyone,
    permission_id,
    created_by_id
)
SELECT
    'admin',
    'admin',
    '$2a$12$rsxkLXyNumuq0Ayexyu6LOVEOgrtAb1R98ptNCj9055JWEJ2SGdGy', -- Bcrypt 12 for "admin"
    FALSE,
    'admin',
    NULL
WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE id = 'admin'
);

-- Insert everyone permission
INSERT INTO permissions (
    id,
    weight,
    is_root,
    create_api_key,
    create_user,
    delete_user,
    edit_user,
    view_user,
    bypass_weight,
    max_action_size,
    max_backup_size,
    total_storage_size,
    max_create_users,
    convert_file
)
SELECT
    'everyone',
    0,
    FALSE,
    FALSE,
    FALSE,
    FALSE,
    FALSE,
    FALSE,
    FALSE,
    0,
    0,
    0,
    0,
    FALSE
WHERE NOT EXISTS (
    SELECT 1 FROM permissions WHERE id = 'everyone'
);

-- Insert everyone user
INSERT INTO users (
    id,
    username,
    password_hash,
    is_everyone,
    permission_id,
    created_by_id
)
SELECT
    'everyone',
    'everyone',
    '',
    TRUE,
    'everyone',
    'admin'
WHERE NOT EXISTS (
    SELECT 1 FROM users WHERE id = 'everyone'
);

COMMIT;
