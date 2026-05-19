use std::pin::Pin;
use tokio::io::AsyncRead;

pub type BoxedAsyncRead = Pin<Box<dyn AsyncRead + Send + Sync>>;

pub enum FileContentSource {
    LocalFile(tokio::fs::File),
    RemoteStream(BoxedAsyncRead),
    InMemory(std::io::Cursor<Vec<u8>>),
}

pub async fn resolve_file_content(source: FileContentSource) -> BoxedAsyncRead {
    match source {
        FileContentSource::LocalFile(file) => Box::pin(file),
        FileContentSource::RemoteStream(stream) => stream,
        FileContentSource::InMemory(cursor) => Box::pin(cursor),
    }
}

pub async fn get_file_content(type: ) -> FileContentSource {}
