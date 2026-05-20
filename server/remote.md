# Remote URLs

S4 supports mapping remote and local data sources directly into the virtual filesystem. When creating files via the `/api/file/<path..>` endpoint, you can set the `source` property to one of the supported URL formats and optionally override `type`.

Supported formats include:

- **HTTP/HTTPS** (`http`)
  - Standard web URLs.
  - Examples: `http://example.com/data.json`, `https://example.com/image.png`
- **FTP** (`ftp`)
  - Standard FTP URLs.
  - Examples: `ftp://user:pass@ftp.example.com/file.txt`, `ftp://ftp.example.com/public.zip`
- **Base64 Data URLs** (`base64_data_url`)
  - Inline base64-encoded data.
  - Example: `data:text/plain;base64,SGVsbG8gV29ybGQh`
- **Git** (`git`)
  - Git repository URLs or specific file paths inside a repo.
  - Automatically detected for URLs containing `.git/`, `#`, or `::`.
  - Example: `git@github.com:user/repo.git#path/to/file.txt`
- **Local** (`local`)
  - Standard paths pointing to local files on the S4 mount/files folder.
  - *Note: Creating local files on the file endpoint (aka without uploading) is restricted to users with root permissions.*
  - Example: `/...`