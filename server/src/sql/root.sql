INSERT INTO files (
    id,
    path,
    metadata,
    type,
    mime_type,
    size,
    link,
    link_target,
    created_at,
    updated_at
) VALUES (
    'root',
    '/',
    '{}',
    'folder',
    NULL,
    0,
    'local',
    '/',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);
