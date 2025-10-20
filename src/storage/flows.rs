//! Filesystem-based draft flow operations
//!
//! Pure functions for working with .flow.yaml files on disk.
//! These handle the "working copy" of flows before deployment.

use crate::{BeemFlowError, Result};
use std::path::{Path, PathBuf};
use tokio::fs;

const FLOW_EXTENSION: &str = ".flow.yaml";

/// Save a flow to the filesystem (atomic write)
///
/// # Arguments
/// * `flows_dir` - Base directory for flows (e.g., ~/.beemflow/flows)
/// * `name` - Flow name (alphanumeric, hyphens, underscores only)
/// * `content` - YAML content (validated before writing)
///
/// # Returns
/// `Ok(true)` if file was updated, `Ok(false)` if created new
pub async fn save_flow(flows_dir: impl AsRef<Path>, name: &str, content: &str) -> Result<bool> {
    validate_flow_name(name)?;

    let path = build_flow_path(flows_dir, name);
    let existed = path.exists();

    // Validate YAML before writing (fail fast)
    crate::dsl::parse_string(content, None)?;

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }

    // Atomic write: temp file + rename
    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, content).await?;
    fs::rename(&temp_path, &path).await?;

    Ok(existed)
}

/// Get a flow from the filesystem
///
/// # Returns
/// `Ok(Some(content))` if found, `Ok(None)` if not found
pub async fn get_flow(flows_dir: impl AsRef<Path>, name: &str) -> Result<Option<String>> {
    validate_flow_name(name)?;

    let path = build_flow_path(&flows_dir, name);

    match fs::read_to_string(&path).await {
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// List all flows in the filesystem
///
/// # Returns
/// Sorted list of flow names (without .flow.yaml extension)
pub async fn list_flows(flows_dir: impl AsRef<Path>) -> Result<Vec<String>> {
    let flows_dir = flows_dir.as_ref();

    // Return empty list if directory doesn't exist yet
    if !flows_dir.exists() {
        return Ok(Vec::new());
    }

    let mut flows = Vec::new();
    let mut entries = fs::read_dir(flows_dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();

        // Check if it matches *.flow.yaml
        if let Some(file_name) = path.file_name().and_then(|s| s.to_str())
            && file_name.ends_with(FLOW_EXTENSION)
        {
            let name = file_name.trim_end_matches(FLOW_EXTENSION);
            flows.push(name.to_string());
        }
    }

    flows.sort();
    Ok(flows)
}

/// Delete a flow from the filesystem
pub async fn delete_flow(flows_dir: impl AsRef<Path>, name: &str) -> Result<()> {
    validate_flow_name(name)?;

    let path = build_flow_path(&flows_dir, name);

    if !path.exists() {
        return Err(BeemFlowError::not_found("Flow", name));
    }

    fs::remove_file(&path).await?;
    Ok(())
}

/// Check if a flow exists on the filesystem
pub async fn flow_exists(flows_dir: impl AsRef<Path>, name: &str) -> Result<bool> {
    validate_flow_name(name)?;
    let path = build_flow_path(&flows_dir, name);
    Ok(path.exists())
}

// Private helpers

fn validate_flow_name(name: &str) -> Result<()> {
    // Prevent path traversal and invalid characters
    if name.is_empty() {
        return Err(BeemFlowError::validation("Flow name cannot be empty"));
    }

    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(BeemFlowError::validation(
            "Invalid flow name: path separators and '..' not allowed",
        ));
    }

    // Only allow alphanumeric, hyphens, and underscores
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(BeemFlowError::validation(
            "Flow name must contain only alphanumeric characters, hyphens, and underscores",
        ));
    }

    Ok(())
}

fn build_flow_path(flows_dir: impl AsRef<Path>, name: &str) -> PathBuf {
    flows_dir
        .as_ref()
        .join(format!("{}{}", name, FLOW_EXTENSION))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_save_and_get_flow() {
        let temp = TempDir::new().unwrap();
        let content = "name: test\non: cli.manual\nsteps: []";

        // Save new flow
        let created = save_flow(temp.path(), "test_flow", content).await.unwrap();
        assert!(!created); // First time = created

        // Get flow back
        let retrieved = get_flow(temp.path(), "test_flow").await.unwrap();
        assert_eq!(retrieved, Some(content.to_string()));

        // Update existing flow
        let updated = save_flow(temp.path(), "test_flow", content).await.unwrap();
        assert!(updated); // Second time = updated
    }

    #[tokio::test]
    async fn test_list_flows() {
        let temp = TempDir::new().unwrap();

        // Empty directory
        let flows = list_flows(temp.path()).await.unwrap();
        assert_eq!(flows, Vec::<String>::new());

        // Add flows
        save_flow(
            temp.path(),
            "flow1",
            "name: flow1\non: cli.manual\nsteps: []",
        )
        .await
        .unwrap();
        save_flow(
            temp.path(),
            "flow2",
            "name: flow2\non: cli.manual\nsteps: []",
        )
        .await
        .unwrap();

        let flows = list_flows(temp.path()).await.unwrap();
        assert_eq!(flows, vec!["flow1", "flow2"]);
    }

    #[tokio::test]
    async fn test_delete_flow() {
        let temp = TempDir::new().unwrap();
        save_flow(temp.path(), "test", "name: test\non: cli.manual\nsteps: []")
            .await
            .unwrap();

        delete_flow(temp.path(), "test").await.unwrap();

        let exists = flow_exists(temp.path(), "test").await.unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn test_path_traversal_prevention() {
        let temp = TempDir::new().unwrap();

        let result = save_flow(temp.path(), "../evil", "name: evil").await;
        assert!(result.is_err());

        let result = save_flow(temp.path(), "foo/../bar", "name: bar").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_yaml_rejected() {
        let temp = TempDir::new().unwrap();

        let result = save_flow(temp.path(), "bad", "invalid: [yaml").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_nonexistent_flow() {
        let temp = TempDir::new().unwrap();

        let result = get_flow(temp.path(), "nonexistent").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_delete_nonexistent_flow() {
        let temp = TempDir::new().unwrap();

        let result = delete_flow(temp.path(), "nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_flow_names() {
        let temp = TempDir::new().unwrap();

        // Empty name
        let result = save_flow(temp.path(), "", "name: test").await;
        assert!(result.is_err());

        // Special characters
        let result = save_flow(temp.path(), "foo/bar", "name: test").await;
        assert!(result.is_err());

        let result = save_flow(temp.path(), "foo\\bar", "name: test").await;
        assert!(result.is_err());

        // Valid names
        assert!(
            save_flow(
                temp.path(),
                "valid-name",
                "name: test\non: cli.manual\nsteps: []"
            )
            .await
            .is_ok()
        );
        assert!(
            save_flow(
                temp.path(),
                "valid_name",
                "name: test\non: cli.manual\nsteps: []"
            )
            .await
            .is_ok()
        );
        assert!(
            save_flow(
                temp.path(),
                "validName123",
                "name: test\non: cli.manual\nsteps: []"
            )
            .await
            .is_ok()
        );
    }
}
