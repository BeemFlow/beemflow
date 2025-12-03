//! Filesystem-based draft flow operations
//!
//! Pure functions for working with .flow.yaml files on disk.
//! These handle the "working copy" of flows before deployment.
//!
//! # Multi-tenant isolation
//! All functions require an `organization_id` parameter. Flows are stored in
//! organization-specific subdirectories:
//! ```text
//! ~/.beemflow/flows/{organization_id}/{flow_name}.flow.yaml
//! ```
//! This ensures complete isolation between organizations' draft flows.

use crate::{BeemFlowError, Result};
use std::path::{Path, PathBuf};
use tokio::fs;

const FLOW_EXTENSION: &str = ".flow.yaml";

/// Save a flow to the filesystem (atomic write)
///
/// # Arguments
/// * `flows_dir` - Base directory for flows (e.g., ~/.beemflow/flows)
/// * `organization_id` - Organization identifier for isolation
/// * `name` - Flow name (alphanumeric, hyphens, underscores only)
/// * `content` - YAML content (validated before writing)
///
/// # Returns
/// `Ok(true)` if file was updated, `Ok(false)` if created new
pub async fn save_flow(
    flows_dir: impl AsRef<Path>,
    organization_id: &str,
    name: &str,
    content: &str,
) -> Result<bool> {
    validate_path_component(organization_id, "organization_id")?;
    validate_flow_name(name)?;

    let path = build_flow_path(&flows_dir, organization_id, name);
    let existed = path.exists();

    // Validate YAML before writing (fail fast)
    crate::dsl::parse_string(content, None)?;

    // Create parent directory if needed (includes organization subdirectory)
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
/// # Arguments
/// * `flows_dir` - Base directory for flows
/// * `organization_id` - Organization identifier for isolation
/// * `name` - Flow name
///
/// # Returns
/// `Ok(Some(content))` if found, `Ok(None)` if not found
pub async fn get_flow(
    flows_dir: impl AsRef<Path>,
    organization_id: &str,
    name: &str,
) -> Result<Option<String>> {
    validate_path_component(organization_id, "organization_id")?;
    validate_flow_name(name)?;

    let path = build_flow_path(&flows_dir, organization_id, name);

    match fs::read_to_string(&path).await {
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// List all flows in the filesystem for an organization
///
/// # Arguments
/// * `flows_dir` - Base directory for flows
/// * `organization_id` - Organization identifier for isolation
///
/// # Returns
/// Sorted list of flow names (without .flow.yaml extension)
pub async fn list_flows(flows_dir: impl AsRef<Path>, organization_id: &str) -> Result<Vec<String>> {
    validate_path_component(organization_id, "organization_id")?;

    let org_dir = flows_dir.as_ref().join(organization_id);

    // Return empty list if organization directory doesn't exist yet
    if !org_dir.exists() {
        return Ok(Vec::new());
    }

    let mut flows = Vec::new();
    let mut entries = fs::read_dir(&org_dir).await?;

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
///
/// # Arguments
/// * `flows_dir` - Base directory for flows
/// * `organization_id` - Organization identifier for isolation
/// * `name` - Flow name
pub async fn delete_flow(
    flows_dir: impl AsRef<Path>,
    organization_id: &str,
    name: &str,
) -> Result<()> {
    validate_path_component(organization_id, "organization_id")?;
    validate_flow_name(name)?;

    let path = build_flow_path(&flows_dir, organization_id, name);

    if !path.exists() {
        return Err(BeemFlowError::not_found("Flow", name));
    }

    fs::remove_file(&path).await?;
    Ok(())
}

/// Check if a flow exists on the filesystem
///
/// # Arguments
/// * `flows_dir` - Base directory for flows
/// * `organization_id` - Organization identifier for isolation
/// * `name` - Flow name
pub async fn flow_exists(
    flows_dir: impl AsRef<Path>,
    organization_id: &str,
    name: &str,
) -> Result<bool> {
    validate_path_component(organization_id, "organization_id")?;
    validate_flow_name(name)?;
    let path = build_flow_path(&flows_dir, organization_id, name);
    Ok(path.exists())
}

// Private helpers

/// Validate a path component to prevent path traversal attacks
///
/// This is used for both organization_id and flow names to ensure
/// they don't contain path separators or parent directory references.
fn validate_path_component(value: &str, field_name: &str) -> Result<()> {
    if value.is_empty() {
        return Err(BeemFlowError::validation(format!(
            "{} cannot be empty",
            field_name
        )));
    }

    if value.contains("..") || value.contains('/') || value.contains('\\') || value == "." {
        return Err(BeemFlowError::validation(format!(
            "Invalid {}: path separators and '..' not allowed",
            field_name
        )));
    }

    // Only allow alphanumeric, hyphens, and underscores
    if !value
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(BeemFlowError::validation(format!(
            "{} must contain only alphanumeric characters, hyphens, and underscores",
            field_name
        )));
    }

    Ok(())
}

fn validate_flow_name(name: &str) -> Result<()> {
    validate_path_component(name, "Flow name")
}

fn build_flow_path(flows_dir: impl AsRef<Path>, organization_id: &str, name: &str) -> PathBuf {
    flows_dir
        .as_ref()
        .join(organization_id)
        .join(format!("{}{}", name, FLOW_EXTENSION))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const TEST_ORG: &str = "test_org";

    #[tokio::test]
    async fn test_save_and_get_flow() {
        let temp = TempDir::new().unwrap();
        let content = "name: test\non: cli.manual\nsteps: []";

        // Save new flow
        let created = save_flow(temp.path(), TEST_ORG, "test_flow", content)
            .await
            .unwrap();
        assert!(!created); // First time = created

        // Get flow back
        let retrieved = get_flow(temp.path(), TEST_ORG, "test_flow").await.unwrap();
        assert_eq!(retrieved, Some(content.to_string()));

        // Update existing flow
        let updated = save_flow(temp.path(), TEST_ORG, "test_flow", content)
            .await
            .unwrap();
        assert!(updated); // Second time = updated
    }

    #[tokio::test]
    async fn test_list_flows() {
        let temp = TempDir::new().unwrap();

        // Empty directory
        let flows = list_flows(temp.path(), TEST_ORG).await.unwrap();
        assert_eq!(flows, Vec::<String>::new());

        // Add flows
        save_flow(
            temp.path(),
            TEST_ORG,
            "flow1",
            "name: flow1\non: cli.manual\nsteps: []",
        )
        .await
        .unwrap();
        save_flow(
            temp.path(),
            TEST_ORG,
            "flow2",
            "name: flow2\non: cli.manual\nsteps: []",
        )
        .await
        .unwrap();

        let flows = list_flows(temp.path(), TEST_ORG).await.unwrap();
        assert_eq!(flows, vec!["flow1", "flow2"]);
    }

    #[tokio::test]
    async fn test_delete_flow() {
        let temp = TempDir::new().unwrap();
        save_flow(
            temp.path(),
            TEST_ORG,
            "test",
            "name: test\non: cli.manual\nsteps: []",
        )
        .await
        .unwrap();

        delete_flow(temp.path(), TEST_ORG, "test").await.unwrap();

        let exists = flow_exists(temp.path(), TEST_ORG, "test").await.unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn test_path_traversal_prevention() {
        let temp = TempDir::new().unwrap();

        // Invalid flow names
        let result = save_flow(temp.path(), TEST_ORG, "../evil", "name: evil").await;
        assert!(result.is_err());

        let result = save_flow(temp.path(), TEST_ORG, "foo/../bar", "name: bar").await;
        assert!(result.is_err());

        // Invalid organization_id
        let result = save_flow(temp.path(), "../evil_org", "test", "name: test").await;
        assert!(result.is_err());

        let result = save_flow(temp.path(), "org/../other", "test", "name: test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_yaml_rejected() {
        let temp = TempDir::new().unwrap();

        let result = save_flow(temp.path(), TEST_ORG, "bad", "invalid: [yaml").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_nonexistent_flow() {
        let temp = TempDir::new().unwrap();

        let result = get_flow(temp.path(), TEST_ORG, "nonexistent")
            .await
            .unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_delete_nonexistent_flow() {
        let temp = TempDir::new().unwrap();

        let result = delete_flow(temp.path(), TEST_ORG, "nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_flow_names() {
        let temp = TempDir::new().unwrap();

        // Empty name
        let result = save_flow(temp.path(), TEST_ORG, "", "name: test").await;
        assert!(result.is_err());

        // Special characters
        let result = save_flow(temp.path(), TEST_ORG, "foo/bar", "name: test").await;
        assert!(result.is_err());

        let result = save_flow(temp.path(), TEST_ORG, "foo\\bar", "name: test").await;
        assert!(result.is_err());

        // Valid names
        assert!(
            save_flow(
                temp.path(),
                TEST_ORG,
                "valid-name",
                "name: test\non: cli.manual\nsteps: []"
            )
            .await
            .is_ok()
        );
        assert!(
            save_flow(
                temp.path(),
                TEST_ORG,
                "valid_name",
                "name: test\non: cli.manual\nsteps: []"
            )
            .await
            .is_ok()
        );
        assert!(
            save_flow(
                temp.path(),
                TEST_ORG,
                "validName123",
                "name: test\non: cli.manual\nsteps: []"
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn test_organization_isolation() {
        let temp = TempDir::new().unwrap();
        let content = "name: test\non: cli.manual\nsteps: []";

        // Save same-named flow to different organizations
        save_flow(temp.path(), "org_a", "shared_flow", content)
            .await
            .unwrap();
        save_flow(temp.path(), "org_b", "shared_flow", content)
            .await
            .unwrap();

        // Each org should only see their own flows
        let flows_a = list_flows(temp.path(), "org_a").await.unwrap();
        let flows_b = list_flows(temp.path(), "org_b").await.unwrap();

        assert_eq!(flows_a, vec!["shared_flow"]);
        assert_eq!(flows_b, vec!["shared_flow"]);

        // Deleting from one org shouldn't affect the other
        delete_flow(temp.path(), "org_a", "shared_flow")
            .await
            .unwrap();

        assert!(
            !flow_exists(temp.path(), "org_a", "shared_flow")
                .await
                .unwrap()
        );
        assert!(
            flow_exists(temp.path(), "org_b", "shared_flow")
                .await
                .unwrap()
        );
    }
}
