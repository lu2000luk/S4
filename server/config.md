# S4 Server Configuration

The server reads `config.toml` from the current working directory. Every entry is optional; omitted values use the defaults below.

| Field | Type | Default | Behavior |
| --- | --- | --- | --- |
| `host` | string | `"127.0.0.1"` | Address Rocket binds to. |
| `port` | integer (`u16`) | `8080` | TCP port Rocket listens on. |
| `mount` | string | `"./data/"` | Root data directory. S4 stores the database at `<mount>/s4.db`, local file bytes under `<mount>/files`, backups under `<mount>/backups`, and resolver cache entries under `<mount>/.s4`. |
| `can_unauthenticated_cache` | boolean | `true` | Allows unauthenticated requests to read from and write to the S4 remote cache. When `false`, unauthenticated responses bypass cache even if the file row and query request caching. |
| `max_cache_entry_size` | integer (`u64`) | `104857600` | Maximum bytes for one cached remote object. Known larger responses are not cached. If a streamed cache miss grows past this limit, S4 deletes the partial cache file and continues serving the response. |
| `total_max_cache` | integer (`u64`) | `1073741824` | Maximum total bytes for `<mount>/.s4` cache entries. S4 enforces this when checking or writing cache entries and evicts least-recently-used entries by `last_accessed_timestamp`. |
| `default_use_cache` | boolean | `true` | Default cache decision for file rows that do not have an explicit cache value during migration/defaulting. Cache only applies to `http`, `ftp`, and `git` sources. |
| `remove_not_found_files` | boolean | `false` | When `true`, `/api/file/<path..>` deletes a DB file row after permission checks if the resolver proves the backing source is definitely missing. Dependent `links` rows are deleted first; `backups` rows are kept, and if they block the file delete S4 logs and leaves the row. |
| `allow_query_override_default` | boolean | `true` | Allows `?cache=` to override `default_use_cache` when no explicit DB cache value applies. |
| `allow_query_override_db` | boolean | `true` | Allows `?cache=` to override `files.cache`. When `false`, query cache values cannot override the DB row value. |

## Cache Decision

`/api/file/<path..>` accepts `?cache=true` or `?cache=false`.

1. If `?cache=` is present and both override gates allow the relevant override, S4 uses the query value.
2. If `?cache=` is present and `allow_query_override_db = false`, the query cannot override `files.cache`.
3. If no query override applies, S4 uses `files.cache`.
4. If a row has no explicit cache value during migration/defaulting, S4 uses `default_use_cache`.
5. Cache reads and writes are only attempted for `http`, `ftp`, and `git` sources.

## Cache Files

Cache entries are stored at:

```text
<mount>/.s4/<sha1(source path)>/<sanitized filename>
<mount>/.s4/<sha1(source path)>/meta.json
```

Temporary cache writes use `<mount>/.s4/tmp/*.part` and are atomically renamed into the final entry after a successful EOF.
