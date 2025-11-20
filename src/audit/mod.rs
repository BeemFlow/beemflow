//! Audit logging system
//!
//! Provides immutable audit trail of all user actions for compliance and security.

use crate::Result;
use crate::auth::RequestContext;
use crate::storage::Storage;
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

/// Audit logger for recording user actions
pub struct AuditLogger {
    storage: Arc<dyn Storage>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    /// Log an audit event
    ///
    /// This is async and non-blocking - errors are logged but don't fail the request
    pub async fn log(&self, event: AuditEvent) -> Result<()> {
        let log = AuditLog {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().timestamp_millis(),
            request_id: event.request_id.clone(),
            organization_id: event.organization_id.clone(),
            user_id: event.user_id.clone(),
            client_ip: event.client_ip.clone(),
            user_agent: event.user_agent.clone(),
            action: event.action.clone(),
            resource_type: event.resource_type.clone(),
            resource_id: event.resource_id.clone(),
            resource_name: event.resource_name.clone(),
            http_method: event.http_method.clone(),
            http_path: event.http_path.clone(),
            http_status_code: event.http_status_code,
            success: event.success,
            error_message: event.error_message.clone(),
            metadata: event.metadata.clone(),
            created_at: Utc::now().timestamp_millis(),
        };

        // Emit structured tracing log based on event severity
        let level = event.severity();
        match level {
            tracing::Level::ERROR => tracing::error!(
                action = %event.action,
                user_id = ?event.user_id,
                organization_id = %event.organization_id,
                success = event.success,
                http_status = ?event.http_status_code,
                error = ?event.error_message,
                "Audit: {}",
                event.action
            ),
            tracing::Level::WARN => tracing::warn!(
                action = %event.action,
                user_id = ?event.user_id,
                organization_id = %event.organization_id,
                success = event.success,
                http_status = ?event.http_status_code,
                error = ?event.error_message,
                "Audit: {}",
                event.action
            ),
            tracing::Level::INFO => tracing::info!(
                action = %event.action,
                user_id = ?event.user_id,
                organization_id = %event.organization_id,
                success = event.success,
                resource_type = ?event.resource_type,
                resource_id = ?event.resource_id,
                "Audit: {}",
                event.action
            ),
            _ => tracing::debug!(
                action = %event.action,
                user_id = ?event.user_id,
                organization_id = %event.organization_id,
                success = event.success,
                http_method = ?event.http_method,
                http_path = ?event.http_path,
                "Audit: {}",
                event.action
            ),
        }

        // Store in database
        self.storage.create_audit_log(&log).await
    }

    /// Log from request context (convenience method)
    pub async fn log_from_context(
        &self,
        ctx: &RequestContext,
        action: impl Into<String>,
        success: bool,
    ) -> Result<()> {
        self.log(AuditEvent {
            request_id: ctx.request_id.clone(),
            organization_id: ctx.organization_id.clone(),
            user_id: Some(ctx.user_id.clone()),
            client_ip: ctx.client_ip.clone(),
            user_agent: ctx.user_agent.clone(),
            action: action.into(),
            resource_type: None,
            resource_id: None,
            resource_name: None,
            http_method: None,
            http_path: None,
            http_status_code: None,
            success,
            error_message: None,
            metadata: None,
        })
        .await
    }
}

/// Audit event to be logged
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub request_id: String,
    pub organization_id: String,
    pub user_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub resource_name: Option<String>,
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub http_status_code: Option<i32>,
    pub success: bool,
    pub error_message: Option<String>,
    pub metadata: Option<String>,
}

impl AuditEvent {
    /// Create audit event from request context
    pub fn from_context(ctx: &RequestContext, action: impl Into<String>, success: bool) -> Self {
        Self {
            request_id: ctx.request_id.clone(),
            organization_id: ctx.organization_id.clone(),
            user_id: Some(ctx.user_id.clone()),
            client_ip: ctx.client_ip.clone(),
            user_agent: ctx.user_agent.clone(),
            action: action.into(),
            resource_type: None,
            resource_id: None,
            resource_name: None,
            http_method: None,
            http_path: None,
            http_status_code: None,
            success,
            error_message: None,
            metadata: None,
        }
    }

    /// Determine log level based on action and success
    pub fn severity(&self) -> tracing::Level {
        if !self.success {
            // Failed actions - severity based on HTTP status
            if let Some(status) = self.http_status_code {
                if status >= 500 {
                    return tracing::Level::ERROR;
                }
                if status == 403 || status == 401 {
                    return tracing::Level::WARN;
                }
            }
            return tracing::Level::WARN;
        }

        // Successful security-sensitive actions
        if self.action.contains("login")
            || self.action.contains("register")
            || self.action.contains("logout")
            || self.action.contains("delete")
            || self.action.contains("disconnect")
            || self.action.contains("deploy")
            || self.action.contains("revoke")
        {
            return tracing::Level::INFO;
        }

        // Normal operations
        tracing::Level::DEBUG
    }

    /// Add resource information
    pub fn with_resource(
        mut self,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        self.resource_type = Some(resource_type.into());
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Add HTTP information
    pub fn with_http(
        mut self,
        method: impl Into<String>,
        path: impl Into<String>,
        status_code: i32,
    ) -> Self {
        self.http_method = Some(method.into());
        self.http_path = Some(path.into());
        self.http_status_code = Some(status_code);
        self
    }

    /// Add error message
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error_message = Some(error.into());
        self.success = false;
        self
    }

    /// Add metadata (JSON string)
    pub fn with_metadata(mut self, metadata: impl Into<String>) -> Self {
        self.metadata = Some(metadata.into());
        self
    }
}

/// Stored audit log entry
#[derive(Debug, Clone)]
pub struct AuditLog {
    pub id: String,
    pub timestamp: i64,
    pub request_id: String,
    pub organization_id: String,
    pub user_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub resource_name: Option<String>,
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub http_status_code: Option<i32>,
    pub success: bool,
    pub error_message: Option<String>,
    pub metadata: Option<String>,
    pub created_at: i64,
}

/// Common audit actions
pub mod actions {
    // Authentication
    pub const USER_LOGIN: &str = "user.login";
    pub const USER_LOGOUT: &str = "user.logout";
    pub const USER_REGISTER: &str = "user.register";
    pub const TOKEN_REFRESH: &str = "token.refresh";
    pub const TOKEN_REVOKE: &str = "token.revoke";

    // Flows
    pub const FLOW_CREATE: &str = "flow.create";
    pub const FLOW_UPDATE: &str = "flow.update";
    pub const FLOW_DELETE: &str = "flow.delete";
    pub const FLOW_DEPLOY: &str = "flow.deploy";
    pub const FLOW_READ: &str = "flow.read";

    // Runs
    pub const RUN_TRIGGER: &str = "run.trigger";
    pub const RUN_CANCEL: &str = "run.cancel";
    pub const RUN_DELETE: &str = "run.delete";
    pub const RUN_READ: &str = "run.read";

    // OAuth
    pub const OAUTH_CONNECT: &str = "oauth.connect";
    pub const OAUTH_DISCONNECT: &str = "oauth.disconnect";

    // Secrets
    pub const SECRET_CREATE: &str = "secret.create";
    pub const SECRET_UPDATE: &str = "secret.update";
    pub const SECRET_DELETE: &str = "secret.delete";
    pub const SECRET_READ: &str = "secret.read";

    // Organization
    pub const ORG_UPDATE: &str = "org.update";
    pub const ORG_DELETE: &str = "org.delete";

    // Members
    pub const MEMBER_INVITE: &str = "member.invite";
    pub const MEMBER_REMOVE: &str = "member.remove";
    pub const MEMBER_ROLE_UPDATE: &str = "member.role_update";

    // Tools
    pub const TOOL_INSTALL: &str = "tool.install";
    pub const TOOL_UNINSTALL: &str = "tool.uninstall";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Role;

    fn create_test_context() -> RequestContext {
        RequestContext {
            user_id: "user123".to_string(),
            organization_id: "org456".to_string(),
            organization_name: "Test Org".to_string(),
            role: Role::Admin,
            client_ip: Some("192.168.1.1".to_string()),
            user_agent: Some("TestAgent/1.0".to_string()),
            request_id: "req123".to_string(),
        }
    }

    #[test]
    fn test_audit_event_from_context() {
        let ctx = create_test_context();
        let event = AuditEvent::from_context(&ctx, actions::FLOW_CREATE, true);

        assert_eq!(event.organization_id, "org456");
        assert_eq!(event.user_id, Some("user123".to_string()));
        assert_eq!(event.action, actions::FLOW_CREATE);
        assert!(event.success);
        assert_eq!(event.client_ip, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_audit_event_with_resource() {
        let ctx = create_test_context();
        let event = AuditEvent::from_context(&ctx, actions::FLOW_UPDATE, true)
            .with_resource("flow", "my-flow-123");

        assert_eq!(event.resource_type, Some("flow".to_string()));
        assert_eq!(event.resource_id, Some("my-flow-123".to_string()));
    }

    #[test]
    fn test_audit_event_with_http() {
        let ctx = create_test_context();
        let event = AuditEvent::from_context(&ctx, actions::RUN_TRIGGER, true).with_http(
            "POST",
            "/api/runs",
            200,
        );

        assert_eq!(event.http_method, Some("POST".to_string()));
        assert_eq!(event.http_path, Some("/api/runs".to_string()));
        assert_eq!(event.http_status_code, Some(200));
    }

    #[test]
    fn test_audit_event_with_error() {
        let ctx = create_test_context();
        let event = AuditEvent::from_context(&ctx, actions::FLOW_DELETE, true)
            .with_error("Permission denied");

        assert_eq!(event.error_message, Some("Permission denied".to_string()));
        assert!(!event.success); // with_error sets success to false
    }

    #[test]
    fn test_severity_failed_operations() {
        let ctx = create_test_context();

        // 500+ errors should be ERROR level
        let event_500 =
            AuditEvent::from_context(&ctx, "api.error", false).with_http("GET", "/api/test", 500);
        assert_eq!(event_500.severity(), tracing::Level::ERROR);

        let event_503 =
            AuditEvent::from_context(&ctx, "api.error", false).with_http("GET", "/api/test", 503);
        assert_eq!(event_503.severity(), tracing::Level::ERROR);

        // 401/403 should be WARN level
        let event_401 = AuditEvent::from_context(&ctx, "api.unauthorized", false).with_http(
            "GET",
            "/api/test",
            401,
        );
        assert_eq!(event_401.severity(), tracing::Level::WARN);

        let event_403 = AuditEvent::from_context(&ctx, "api.forbidden", false).with_http(
            "GET",
            "/api/test",
            403,
        );
        assert_eq!(event_403.severity(), tracing::Level::WARN);

        // Other errors should be WARN level
        let event_400 = AuditEvent::from_context(&ctx, "api.bad_request", false).with_http(
            "GET",
            "/api/test",
            400,
        );
        assert_eq!(event_400.severity(), tracing::Level::WARN);

        // Failed operation without status should be WARN
        let event_no_status = AuditEvent::from_context(&ctx, "api.failed", false);
        assert_eq!(event_no_status.severity(), tracing::Level::WARN);
    }

    #[test]
    fn test_severity_successful_operations() {
        let ctx = create_test_context();

        // Security-sensitive operations should be INFO
        let login_event = AuditEvent::from_context(&ctx, actions::USER_LOGIN, true);
        assert_eq!(login_event.severity(), tracing::Level::INFO);

        let register_event = AuditEvent::from_context(&ctx, actions::USER_REGISTER, true);
        assert_eq!(register_event.severity(), tracing::Level::INFO);

        let logout_event = AuditEvent::from_context(&ctx, actions::USER_LOGOUT, true);
        assert_eq!(logout_event.severity(), tracing::Level::INFO);

        let delete_event = AuditEvent::from_context(&ctx, actions::FLOW_DELETE, true);
        assert_eq!(delete_event.severity(), tracing::Level::INFO);

        let deploy_event = AuditEvent::from_context(&ctx, actions::FLOW_DEPLOY, true);
        assert_eq!(deploy_event.severity(), tracing::Level::INFO);

        let disconnect_event = AuditEvent::from_context(&ctx, actions::OAUTH_DISCONNECT, true);
        assert_eq!(disconnect_event.severity(), tracing::Level::INFO);

        let revoke_event = AuditEvent::from_context(&ctx, actions::TOKEN_REVOKE, true);
        assert_eq!(revoke_event.severity(), tracing::Level::INFO);

        // Normal operations should be DEBUG
        let read_event = AuditEvent::from_context(&ctx, actions::FLOW_READ, true);
        assert_eq!(read_event.severity(), tracing::Level::DEBUG);

        let update_event = AuditEvent::from_context(&ctx, actions::FLOW_UPDATE, true);
        assert_eq!(update_event.severity(), tracing::Level::DEBUG);

        let create_event = AuditEvent::from_context(&ctx, actions::FLOW_CREATE, true);
        assert_eq!(create_event.severity(), tracing::Level::DEBUG);
    }
}
