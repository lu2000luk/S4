# Permission String

Permission strings are an easy way to describe permissions in things like headers, query parameters or configs. They are a compact way to represent permissions and can be easily parsed by the server.

Format:

File permission (No path):
```
<user_id>:<perm>|<user_id_2>:<perm>...
```

File permission (With path):
```
<user_id>:<perm>:<path>|<user_id_2>:<perm>:<path>...
```

Where:
- `<user_id>`: The ID of the user or group (e.g., `user123`, `group456`).
- `<perm>`: The permission itself: 
  - `r` for read
  - `w` for write
  - `d` for delete
  - `a` for bypass weight (admin)
  - `x` for recursive (applies to all subdirectories/files)
  - `[f]` for create files
  - `[d]` for create directories
  - `[l]` for create links
  - `[b]` for create backup
  - `[w]` for create with weight
  - `l` for generating links
  - `e` for encryption
  - Example: `rwd` for read, write and delete permissions or `r[f][d][l]` for read permission and the ability to create files, directories and links.
- `<path>`: Optional path to specify the file or directory the permission applies to
