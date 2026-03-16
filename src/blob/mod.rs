//! Blob storage for large objects
//!
//! Provides filesystem and S3 blob storage backends.

pub mod s3;

use crate::{BeemFlowError, Result, constants};
use async_trait::async_trait;

pub use s3::S3BlobStore;

/// Blob storage trait
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Store a blob with optional MIME type and filename
    /// Returns a URL to the stored blob
    async fn put(
        &self,
        data: Vec<u8>,
        mime: Option<&str>,
        filename: Option<&str>,
    ) -> Result<String>;

    /// Retrieve a blob from a URL
    async fn get(&self, url: &str) -> Result<Vec<u8>>;
}

/// Filesystem blob storage
///
/// Stores blobs as files in a directory, matching Go's FilesystemBlobStore behavior:
/// - Atomic writes (write to .tmp, then rename)
/// - Returns file:// URLs
/// - Auto-generates filenames when not provided
pub struct FilesystemBlobStore {
    dir: String,
}

impl FilesystemBlobStore {
    /// Create a new filesystem blob store
    ///
    /// The directory will be created if it does not exist.
    pub async fn new(dir: String) -> Result<Self> {
        tokio::fs::create_dir_all(&dir).await?;
        Ok(Self { dir })
    }

    /// Create a new filesystem blob store (sync version for compatibility)
    pub fn new_sync(dir: String) -> Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }
}

#[async_trait]
impl BlobStore for FilesystemBlobStore {
    /// Store a blob as a file in the directory
    ///
    /// Uses atomic writes (write to .tmp, then rename) for safety.
    /// Returns a file:// URL.
    async fn put(
        &self,
        data: Vec<u8>,
        _mime: Option<&str>,
        filename: Option<&str>,
    ) -> Result<String> {
        use std::path::Path;

        // Generate filename if not provided (matches Go's behavior)
        let filename = match filename {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| {
                        BeemFlowError::storage(format!(
                            "System time error (clock set before 1970?): {}",
                            e
                        ))
                    })?
                    .as_nanos();
                format!("blob-{}", timestamp)
            }
        };

        let path = Path::new(&self.dir).join(&filename);

        // Atomic write: write to .tmp then rename
        let tmp_path = path.with_extension("tmp");
        tokio::fs::write(&tmp_path, data).await?;
        tokio::fs::rename(&tmp_path, &path).await?;

        // Return file:// URL
        Ok(format!("file://{}", path.to_string_lossy()))
    }

    /// Retrieve a blob from a file:// URL
    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        const PREFIX: &str = "file://";
        if !url.starts_with(PREFIX) {
            return Err(crate::BeemFlowError::validation(format!(
                "invalid file URL: {}",
                url
            )));
        }

        let path = &url[PREFIX.len()..];
        let data = tokio::fs::read(path).await?;
        Ok(data)
    }
}

// ============================================================================
// Blob Configuration & Factory
// ============================================================================

/// Blob storage configuration
#[derive(Debug, Clone)]
pub struct BlobConfig {
    /// Storage driver: "filesystem" or "s3"
    pub driver: Option<String>,
    /// Directory for filesystem storage
    pub directory: Option<String>,
    /// S3 bucket name
    pub bucket: Option<String>,
    /// S3 region
    pub region: Option<String>,
}

impl Default for BlobConfig {
    fn default() -> Self {
        Self {
            driver: Some("filesystem".to_string()),
            directory: Some(constants::default_blob_dir().to_string()),
            bucket: None,
            region: None,
        }
    }
}

/// Create a default blob store based on configuration
///
/// Matches Go's NewDefaultBlobStore behavior:
/// - Returns FilesystemBlobStore if config is None, empty, or driver is "filesystem"
/// - Returns S3BlobStore if driver is "s3"
/// - Uses default directory (~/.beemflow/files) if not specified
pub async fn new_default_blob_store(config: Option<&BlobConfig>) -> Result<Box<dyn BlobStore>> {
    // Determine driver and extract config values
    let driver = config
        .and_then(|c| c.driver.as_ref())
        .map(|s| s.as_str())
        .unwrap_or("filesystem");

    match driver {
        "" | "filesystem" => {
            // Use filesystem blob store
            let dir = config
                .and_then(|c| c.directory.as_ref())
                .cloned()
                .unwrap_or_else(|| constants::default_blob_dir().to_string());

            let store = FilesystemBlobStore::new(dir).await?;
            Ok(Box::new(store))
        }
        "s3" => {
            // Use S3 blob store
            let bucket = config.and_then(|c| c.bucket.as_ref()).ok_or_else(|| {
                crate::BeemFlowError::validation("s3 driver requires bucket and region".to_string())
            })?;

            let region = config.and_then(|c| c.region.as_ref()).ok_or_else(|| {
                crate::BeemFlowError::validation("s3 driver requires bucket and region".to_string())
            })?;

            if bucket.is_empty() || region.is_empty() {
                return Err(crate::BeemFlowError::validation(
                    "s3 driver requires non-empty bucket and region".to_string(),
                ));
            }

            let store = S3BlobStore::new(bucket.clone(), region.clone()).await?;
            Ok(Box::new(store))
        }
        other => Err(crate::BeemFlowError::validation(format!(
            "unsupported blob driver: {}",
            other
        ))),
    }
}

#[cfg(test)]
mod blob_test;
