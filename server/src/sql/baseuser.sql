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
    convert_file,
    file_perms
) VALUES (
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
    TRUE,
    '{"/": {"bypass_weight": true, "recursive": true, "read": true, "delete": true, "write": true, "create": {"file": true, "folder": true, "link": true, "backup": true, "with_weight": true}, "generate_link": true, "encrypt": true}}'
);

-- Insert base admin user
INSERT INTO users (
    id,
    username,
    password_hash,
    is_everyone,
    permission_id,
    created_by_id
) VALUES (
    'admin',
    'admin',
    '%hash%',
    FALSE,
    'admin',
    NULL
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
    convert_file,
    file_perms
) VALUES (
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
    FALSE,
    '{}'
);

-- Insert everyone user
INSERT INTO users (
    id,
    username,
    password_hash,
    is_everyone,
    permission_id,
    created_by_id
) VALUES (
    'everyone',
    'everyone',
    '',
    TRUE,
    'everyone',
    'admin'
);
