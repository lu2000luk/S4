![S4 Banner](https://raw.githubusercontent.com/lu2000luk/S4/refs/heads/master/assets/banner.png)

A new, permission based, way to host your files on home servers / vps.

## !! Not developed yet !!

Planned features:
- Web UI
  - File explorer
  - User Management
  - Analytics/Dashboard
- Permissions
  - Subusers
  - API Permissions
  - Time based limits
  - Folders-as-buckets
- Versioning
  - Git compatibility
  - One-click backups/snapshots
- Fast Downloading
  - Parallel downloads client
  - Direct download link
- CDN-mode (Cache for external content)
- File Encryption
- APIs
  - REST API
  - Websockets/Webhooks/GraphQL for realtime
- Integrations
  - Github sync
  - Drive sync
  - Dropbox sync

## Structure

- `/server` - The server code (Rust) (API)

## Technical stuff

- Database: DuckDB
- Password hashing: Bcrypt 12 rounds
