//! S3 blob storage backend
//!
//! Provides S3-compatible blob storage (AWS S3, MinIO, LocalStack, etc.)

use super::BlobStore;
use crate::{BeemFlowError, Result};
use async_trait::async_trait;
use std::sync::Arc;

/// S3 blob storage
pub struct S3BlobStore {
    client: Arc<aws_sdk_s3::Client>,
    bucket: String,
}

impl S3BlobStore {
    /// Create a new S3 blob store
    ///
    /// # Arguments
    /// * `bucket` - S3 bucket name
    /// * `region` - AWS region (e.g., "us-east-1")
    pub async fn new(bucket: String, region: String) -> Result<Self> {
        // Load AWS config
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .load()
            .await;

        let client = aws_sdk_s3::Client::new(&config);

        Ok(Self {
            client: Arc::new(client),
            bucket,
        })
    }

    /// Create a new S3 blob store with custom endpoint (for MinIO, LocalStack, etc.)
    ///
    /// # Arguments
    /// * `bucket` - S3 bucket name
    /// * `region` - AWS region
    /// * `endpoint` - Custom S3-compatible endpoint URL
    pub async fn with_endpoint(bucket: String, region: String, endpoint: String) -> Result<Self> {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .endpoint_url(endpoint)
            .load()
            .await;

        let client = aws_sdk_s3::Client::new(&config);

        Ok(Self {
            client: Arc::new(client),
            bucket,
        })
    }
}

#[async_trait]
impl BlobStore for S3BlobStore {
    /// Upload data to S3 and return its URL
    ///
    /// Matches Go's S3BlobStore.Put behavior:
    /// - Uses filename as the S3 key
    /// - Uses mime as ContentType
    /// - Returns s3://bucket/key URL
    async fn put(
        &self,
        data: Vec<u8>,
        mime: Option<&str>,
        filename: Option<&str>,
    ) -> Result<String> {
        // Generate filename if not provided
        let key = match filename {
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

        let mut request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(data.into());

        // Set content type if provided
        if let Some(content_type) = mime {
            request = request.content_type(content_type);
        }

        request
            .send()
            .await
            .map_err(|e| BeemFlowError::storage(format!("Failed to put S3 object: {}", e)))?;

        // Return S3 URL in s3://bucket/key format
        Ok(format!("s3://{}/{}", self.bucket, key))
    }

    /// Retrieve data from S3 by URL
    ///
    /// Expects url format: s3://bucket/key
    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        // Parse s3://bucket/key URL
        if !url.starts_with("s3://") {
            return Err(BeemFlowError::validation(format!(
                "invalid S3 URL: {}",
                url
            )));
        }

        let url_parts = &url[5..]; // Remove "s3://"
        let parts: Vec<&str> = url_parts.splitn(2, '/').collect();

        // Use pattern matching instead of length check + indexing
        let (bucket, key) = match parts.as_slice() {
            [b, k] => (*b, *k),
            _ => {
                return Err(BeemFlowError::validation(format!(
                    "invalid S3 URL format: {}",
                    url
                )));
            }
        };

        // Verify bucket matches configured bucket
        if bucket != self.bucket {
            return Err(BeemFlowError::validation(format!(
                "requested bucket {} does not match configured bucket {}",
                bucket, self.bucket
            )));
        }

        let response = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| BeemFlowError::storage(format!("Failed to get S3 object: {}", e)))?;

        let data =
            response.body.collect().await.map_err(|e| {
                BeemFlowError::storage(format!("Failed to read S3 object body: {}", e))
            })?;

        Ok(data.to_vec())
    }
}
