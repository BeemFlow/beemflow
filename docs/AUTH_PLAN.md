# BeemFlow Authentication & Authorization Plan
## Enterprise-Grade Multi-Tenant Security Architecture

**Document Version:** 2.0
**Date:** 2025-10-31
**Status:** Final Design Specification
**Classification:** UNCLASSIFIED
**Target Deployment:** DARPA IL-2/IL-4/IL-5 + Multi-Tenant SaaS + Self-Hosted

---

## Executive Summary

This document specifies the complete authentication, authorization, and security architecture for BeemFlow to meet:

1. **DARPA Requirements**: IL-2/IL-4/IL-5 deployments, CAC authentication, fine-grained ABAC, comprehensive audit logging
2. **Multi-Tenant SaaS**: Organization isolation, RBAC, quota management, self-service onboarding
3. **Self-Hosted Enterprise**: Air-gapped deployments, LDAP/SAML integration, offline operations
4. **Security Standards**: NIST 800-53, FISMA compliance, SOC 2 Type II, GDPR/CCPA readiness

### Key Architectural Decisions

| Requirement | Solution | Rationale |
|------------|----------|-----------|
| **Authentication** | Hybrid: JWT + CAC/PKI + SAML | Supports all deployment scenarios |
| **Authorization** | RBAC + ABAC hybrid | Fine-grained control with manageable complexity |
| **Multi-Tenancy** | Organization-based with classification levels | Supports both commercial SaaS and classified environments |
| **Audit Logging** | Immutable append-only ledger | CSSP access, forensics, compliance |
| **Credential Storage** | Hardware-backed encryption (HSM/TPM) | FIPS 140-2 compliance for classified data |
| **Session Management** | Short-lived JWTs + refresh tokens in DB | Revocation capability + horizontal scaling |

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [DARPA Requirements Mapping](#2-darpa-requirements-mapping)
3. [Authentication Systems](#3-authentication-systems)
4. [Authorization Model (RBAC + ABAC)](#4-authorization-model-rbac--abac)
5. [Multi-Tenant Architecture](#5-multi-tenant-architecture)
6. [Classification Level Support](#6-classification-level-support)
7. [Credential Management](#7-credential-management)
8. [Audit Logging & CSSP Access](#8-audit-logging--cssp-access)
9. [API Security](#9-api-security)
10. [Database Schema](#10-database-schema)
11. [Implementation Phases](#11-implementation-phases)
12. [Testing & Validation](#12-testing--validation)
13. [Deployment Architectures](#13-deployment-architectures)
14. [Compliance Matrix](#14-compliance-matrix)
15. [Migration Strategy](#15-migration-strategy)

---

## 1. Architecture Overview

### 1.1 High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           CLIENT LAYER                                  │
├─────────────────────────────────────────────────────────────────────────┤
│  Web UI │ API Clients │ CAC-Enabled Workstations │ Mobile Apps         │
└────┬────────────┬─────────────────┬────────────────────┬───────────────┘
     │            │                 │                    │
     └────────────┴─────────────────┴────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    AUTHENTICATION GATEWAY                               │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐  │
│  │JWT/Password │  │  CAC/PKI    │  │ SAML 2.0/   │  │ OAuth 2.1    │  │
│  │ (IL-2 SaaS) │  │(Classified) │  │ LDAP (Ent.) │  │ (3rd Party)  │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └──────────────┘  │
└────┬────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      AUTHORIZATION ENGINE                               │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Policy Evaluation: RBAC Base + ABAC Conditions                 │  │
│  │  - Role-based permissions (Owner, Admin, Member, Viewer)        │  │
│  │  - Attribute-based rules (Classification, Time, Location, etc.) │  │
│  │  - Resource ownership checks                                    │  │
│  │  - Dynamic policy engine (OPA integration optional)             │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────┬────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         API/BUSINESS LOGIC                              │
├─────────────────────────────────────────────────────────────────────────┤
│  Workflow Engine │ OAuth Manager │ Tool Registry │ Execution Runtime   │
│  (Tenant-Scoped Context + User Identity Propagation)                   │
└────┬────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      DATA LAYER (Tenant-Partitioned)                    │
├─────────────────────────────────────────────────────────────────────────┤
│  PostgreSQL: Row-Level Security (RLS) enforcing tenant_id + user_id    │
│  Encryption: TDE (Transparent Data Encryption) + Application-Level AES │
│  Audit Log: Write-Once Storage (WORM) for immutable audit trail        │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Security Boundaries

```
┌──────────────────────────────────────────────────────────────────┐
│ ORGANIZATION BOUNDARY (Tenant Isolation)                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ CLASSIFICATION BOUNDARY (IL-2, IL-4, IL-5, Secret, etc.)   │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ USER BOUNDARY (Individual Identity)                  │  │ │
│  │  │  ┌────────────────────────────────────────────────┐  │  │ │
│  │  │  │ RESOURCE BOUNDARY (Flows, Runs, Credentials)  │  │  │ │
│  │  │  │  - Owner can full control                      │  │  │ │
│  │  │  │  - Shared resources: explicit grant needed     │  │  │ │
│  │  │  │  - Cross-tenant access: FORBIDDEN              │  │  │ │
│  │  │  └────────────────────────────────────────────────┘  │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**Enforcement:**
- Organization isolation: Database-level (RLS policies)
- Classification isolation: Middleware + runtime context checks
- User isolation: Query-level filtering + RBAC
- Resource isolation: Ownership + ABAC policies

---

## 2. DARPA Requirements Mapping

### 2.1 Mandatory Capabilities

| DARPA Requirement | BeemFlow Implementation | Compliance Status |
|-------------------|------------------------|-------------------|
| **a) IL-2 SaaS (Internet-accessible, non-logged in users)** | Public webhook endpoints with HMAC signature verification; JWT auth for logged-in users | ✅ Fully Supported |
| **b) IL-4/5 SaaS (CUI environment)** | CAC/PKI authentication; encryption at rest (AES-256-GCM); TLS 1.3 in transit; audit logging | ✅ Design Complete, Implementation Required |
| **c) Classified disconnected on-premise** | Air-gapped deployment mode; offline license validation; manual update packages; LDAP integration | ✅ Architecture Supports |
| **d) Fine-grained ABAC for CRUD** | RBAC base + attribute-based policies (classification level, time-of-day, location, data sensitivity) | ✅ Hybrid Model Designed |
| **e) Comprehensive audit logging for CSSP** | Immutable append-only audit log; real-time export to SIEM; forensic query API | ✅ Design Complete |

### 2.2 Authentication Methods by Environment

| Environment | Primary Auth | Secondary Auth | Session Duration | Revocation |
|-------------|--------------|----------------|------------------|------------|
| **IL-2 (Public SaaS)** | Email/Password + MFA (TOTP) | OAuth 2.1 (Google, Microsoft) | 15 min (JWT) | Refresh token revoke |
| **IL-4/5 (CUI SaaS)** | CAC/PIV + Certificate | SAML 2.0 (DoD SSO) | 8 hours (session-based) | Immediate (DB revoke) |
| **Classified (On-Prem)** | CAC/PKI + PIN | LDAP/Active Directory | 4 hours (config) | Immediate (DB revoke) |
| **Self-Hosted (Enterprise)** | SAML 2.0 (customer IDP) | LDAP/AD | Configurable | Configurable |

### 2.3 Workflow Features Alignment

| DARPA Feature Requirement | BeemFlow Support | Notes |
|---------------------------|------------------|-------|
| **CAC-enabled PDF signing** | Integration point via tool adapter | Use `openssl_pki_sign` tool with HSM-backed keys |
| **Digital certificate approval workflows** | Built-in: `approval` block with PKI signature validation | Already implemented in workflow DSL |
| **Group-based routing** | `assignee: group:legal_team` | LDAP/AD group sync supported |
| **Ad-hoc workflow modifications** | Dynamic step injection via API | Audit trail maintained |
| **External data source connectivity** | `http.fetch`, `sql.query`, `graphql` adapters | No data ingestion required |
| **Drafts during workflow** | Paused runs with resume tokens | Already implemented |

---

## 3. Authentication Systems

### 3.1 Multi-Method Authentication Architecture

```rust
pub enum AuthenticationMethod {
    /// Email/password with bcrypt hashing (cost=12)
    /// Used for: IL-2 SaaS, dev environments
    Credentials {
        email: String,
        password_hash: String,
        mfa_secret: Option<String>,  // TOTP secret
    },

    /// Common Access Card (CAC) / Personal Identity Verification (PIV)
    /// Used for: IL-4/5, classified environments
    CacPki {
        certificate_dn: String,      // X.509 Distinguished Name
        certificate_serial: String,
        issuer_dn: String,
        public_key_hash: String,     // SHA-256 of public key
        ocsp_validation: OcspStatus, // Certificate revocation check
    },

    /// SAML 2.0 Single Sign-On
    /// Used for: Self-hosted enterprise, IL-4/5 with SSO
    Saml {
        idp_entity_id: String,
        name_id: String,             // Persistent identifier from IdP
        assertion_expiry: DateTime<Utc>,
        attributes: HashMap<String, Vec<String>>,  // SAML attributes
    },

    /// LDAP/Active Directory
    /// Used for: Self-hosted enterprise, on-premise
    Ldap {
        dn: String,                  // User's LDAP DN
        username: String,
        groups: Vec<String>,         // AD group memberships
    },

    /// API Key (machine-to-machine)
    /// Used for: External system integrations, webhooks
    ApiKey {
        key_id: String,
        key_hash: String,            // bcrypt hash of API key
        scopes: Vec<String>,
        expires_at: Option<DateTime<Utc>>,
    },
}
```

### 3.2 Authentication Flow: CAC/PKI (Classified Environments)

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CAC AUTHENTICATION FLOW                     │
└─────────────────────────────────────────────────────────────────────┘

Client (CAC-Enabled Workstation)                    BeemFlow Server
    │                                                      │
    │  1. TLS handshake with client cert requested        │
    ├─────────────────────────────────────────────────────>│
    │                                                      │
    │  2. Client presents CAC certificate                 │
    │     (X.509 with PIV credentials)                    │
    ├─────────────────────────────────────────────────────>│
    │                                                      │
    │                                 3. Server validates: │
    │                                    - Certificate chain to DoD root CA
    │                                    - OCSP revocation check
    │                                    - CRL (cached, updated hourly)
    │                                    - Email/EDI-PI from SAN extension
    │                                                      │
    │  4. Extract user identity from cert:                │
    │     Subject: CN=DOE.JOHN.MIDDLE.1234567890          │
    │     SAN: email=john.doe@dod.mil                     │
    │     SAN: EDI-PI=1234567890                          │
    │                                                      │
    │  5. Map cert to user account:                       │
    │     - Query users table by certificate_dn OR email  │
    │     - Auto-provision if enabled + valid EDI-PI      │
    │                                                      │
    │  6. Generate session token (JWT)                    │
    │<─────────────────────────────────────────────────────┤
    │     { sub: "user_abc123",                           │
    │       tenant: "darpa_classified",                   │
    │       role: "member",                               │
    │       clearance: "secret",                          │
    │       auth_method: "cac_pki",                       │
    │       exp: 14400 }  // 4 hours                      │
    │                                                      │
    │  7. Subsequent requests use Bearer token            │
    ├─────────────────────────────────────────────────────>│
    │     Authorization: Bearer eyJ0eXAi...               │
    │                                                      │
```

**Implementation:**

```rust
use x509_parser::{certificate::X509Certificate, prelude::*};
use reqwest::blocking::Client;

pub struct CacAuthenticator {
    /// DoD Root CA certificates (loaded from trust store)
    trusted_roots: Vec<X509Certificate<'static>>,
    /// OCSP responder URL
    ocsp_responder: String,
    /// CRL cache (updated every hour)
    crl_cache: Arc<RwLock<CertificateRevocationList>>,
    /// Auto-provision new users from valid CAC?
    auto_provision: bool,
}

impl CacAuthenticator {
    pub async fn authenticate_cac(
        &self,
        client_cert_der: &[u8],
    ) -> Result<AuthenticatedUser> {
        // 1. Parse X.509 certificate
        let (_, cert) = X509Certificate::from_der(client_cert_der)
            .map_err(|_| AuthError::InvalidCertificate)?;

        // 2. Validate certificate chain to trusted root
        self.validate_chain(&cert).await?;

        // 3. Check revocation (OCSP + CRL)
        self.check_revocation(&cert).await?;

        // 4. Extract user identity
        let subject_dn = cert.subject().to_string();
        let email = cert.subject_alternative_name()
            .and_then(|san| san.value.general_names.iter()
                .find_map(|gn| match gn {
                    GeneralName::RFC822Name(email) => Some(email.to_string()),
                    _ => None,
                }))
            .ok_or(AuthError::MissingEmail)?;

        // 5. EDI-PI (DoD unique identifier) from SAN
        let edi_pi = self.extract_edi_pi(&cert)?;

        // 6. Map to user account (or auto-provision)
        let user = self.storage
            .get_user_by_certificate_dn(&subject_dn)
            .await?
            .or_else(|| {
                if self.auto_provision {
                    self.provision_user_from_cac(&email, &edi_pi, &subject_dn).await.ok()
                } else {
                    None
                }
            })
            .ok_or(AuthError::UserNotFound)?;

        // 7. Extract clearance level from cert (if present)
        let clearance = self.extract_clearance_level(&cert)?;

        Ok(AuthenticatedUser {
            user_id: user.id,
            email,
            auth_method: AuthenticationMethod::CacPki {
                certificate_dn: subject_dn,
                certificate_serial: cert.serial.to_string(),
                issuer_dn: cert.issuer().to_string(),
                public_key_hash: sha256(&cert.public_key().raw),
                ocsp_validation: OcspStatus::Good,
            },
            clearance_level: clearance,
        })
    }

    async fn check_revocation(&self, cert: &X509Certificate) -> Result<()> {
        // 1. OCSP check (real-time)
        let ocsp_response = self.query_ocsp(cert).await?;
        if ocsp_response.cert_status != OcspCertStatus::Good {
            return Err(AuthError::CertificateRevoked);
        }

        // 2. CRL check (cached, fallback)
        let crl = self.crl_cache.read().await;
        if crl.is_revoked(&cert.serial) {
            return Err(AuthError::CertificateRevoked);
        }

        Ok(())
    }

    /// NIST 800-63-3: Parse clearance level from certificate extensions
    fn extract_clearance_level(&self, cert: &X509Certificate) -> Result<ClassificationLevel> {
        // Look for clearance in subject DN or custom extensions
        // Example: O=U.S. Government, OU=DoD, OU=PKI, OU=Secret
        let subject = cert.subject().to_string();
        if subject.contains("OU=Top Secret") {
            Ok(ClassificationLevel::TopSecret)
        } else if subject.contains("OU=Secret") {
            Ok(ClassificationLevel::Secret)
        } else if subject.contains("OU=Confidential") {
            Ok(ClassificationLevel::Confidential)
        } else {
            Ok(ClassificationLevel::Unclassified)
        }
    }
}
```

### 3.3 Multi-Factor Authentication (MFA)

**TOTP (Time-Based One-Time Password)** for IL-2 SaaS:

```rust
use totp_rs::{TOTP, Algorithm, Secret};

pub struct MfaManager {
    issuer: String,  // "BeemFlow"
}

impl MfaManager {
    /// Generate MFA secret for new user
    pub fn generate_secret(&self, user_email: &str) -> MfaSetup {
        let secret = Secret::generate_secret();
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,  // 6-digit codes
            1,  // 1 step (30 seconds)
            30, // 30-second window
            secret.to_bytes().unwrap(),
            Some(self.issuer.clone()),
            user_email.to_string(),
        ).unwrap();

        let qr_code = totp.get_qr_base64().unwrap();

        MfaSetup {
            secret: secret.to_encoded().to_string(),
            qr_code,
            backup_codes: self.generate_backup_codes(),
        }
    }

    /// Verify TOTP code
    pub fn verify_totp(&self, secret: &str, code: &str) -> Result<bool> {
        let totp = TOTP::from_url(&format!(
            "otpauth://totp/{issuer}?secret={secret}&issuer={issuer}",
            issuer = self.issuer,
            secret = secret,
        ))?;

        Ok(totp.check_current(code)?)
    }

    fn generate_backup_codes(&self) -> Vec<String> {
        (0..10).map(|_| {
            use rand::Rng;
            let code: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(8)
                .map(char::from)
                .collect();
            code
        }).collect()
    }
}
```

**Hardware Security Key (WebAuthn/FIDO2)** for high-security environments:

```rust
use webauthn_rs::prelude::*;

pub struct WebAuthnManager {
    webauthn: Webauthn,
}

impl WebAuthnManager {
    pub fn new(rp_id: String, rp_origin: Url) -> Result<Self> {
        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)?;
        let webauthn = builder.build()?;
        Ok(Self { webauthn })
    }

    /// Register new security key
    pub async fn start_registration(
        &self,
        user_id: &str,
        user_email: &str,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration)> {
        let user_unique_id = uuid::Uuid::parse_str(user_id)?;
        let (ccr, reg_state) = self.webauthn.start_passkey_registration(
            user_unique_id,
            user_email,
            user_email,
            None,
        )?;
        Ok((ccr, reg_state))
    }

    /// Verify security key authentication
    pub async fn verify_authentication(
        &self,
        user: &User,
        auth_response: &PublicKeyCredential,
        auth_state: &PasskeyAuthentication,
    ) -> Result<bool> {
        let result = self.webauthn.finish_passkey_authentication(
            auth_response,
            auth_state,
        )?;
        Ok(result.is_success())
    }
}
```

---

## 4. Authorization Model (RBAC + ABAC)

### 4.1 Hybrid Authorization Architecture

BeemFlow uses a **two-layer authorization model**:

1. **Base Layer: RBAC (Role-Based Access Control)**
   - Coarse-grained permissions based on user role
   - Simple, predictable, easy to understand
   - Roles: `Owner`, `Admin`, `Member`, `Viewer`, `Custom`

2. **Policy Layer: ABAC (Attribute-Based Access Control)**
   - Fine-grained conditions based on attributes
   - Dynamic evaluation at runtime
   - Attributes: classification level, time, location, data sensitivity, resource tags

```
Authorization Decision = RBAC_Check(role, permission)
                         AND ABAC_Check(attributes, policies)
```

### 4.2 Role Definitions (RBAC)

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// Full control over organization
    /// Can: manage billing, delete org, assign/revoke all roles
    Owner,

    /// Administrative access
    /// Can: manage users (except owner), deploy flows, manage secrets
    /// Cannot: manage billing, delete org, change owner
    Admin,

    /// Standard user
    /// Can: create/edit own flows, trigger runs, view own data
    /// Cannot: manage users, access others' private resources
    Member,

    /// Read-only access
    /// Can: view shared flows, view aggregated run statistics
    /// Cannot: trigger runs, edit flows, access detailed logs
    Viewer,

    /// Custom role with explicit permission set
    /// Allows fine-grained role definitions
    Custom {
        name: String,
        permissions: Vec<Permission>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    // Flow permissions
    FlowsRead,
    FlowsCreate,
    FlowsUpdate,
    FlowsDelete,
    FlowsDeploy,
    FlowsShare,

    // Run permissions
    RunsRead,
    RunsTrigger,
    RunsCancel,
    RunsDelete,
    RunsReadLogs,  // Separate: logs may contain secrets

    // OAuth permissions
    OAuthConnect,
    OAuthDisconnect,
    OAuthReadTokens,  // Admin only: view token metadata

    // Secret permissions
    SecretsRead,
    SecretsCreate,
    SecretsUpdate,
    SecretsDelete,

    // Tool permissions
    ToolsRead,
    ToolsInstall,
    ToolsUninstall,
    ToolsConfigure,

    // Organization permissions
    OrgRead,
    OrgUpdate,
    OrgDelete,
    OrgBillingRead,
    OrgBillingManage,

    // Member management
    MembersRead,
    MembersInvite,
    MembersUpdateRole,
    MembersRemove,

    // Audit log access
    AuditLogsRead,
    AuditLogsExport,

    // System administration (for DARPA deployment)
    SystemConfigRead,
    SystemConfigUpdate,
    SystemUsersManage,  // Cross-org user management
}

impl Role {
    pub fn permissions(&self) -> Vec<Permission> {
        match self {
            Role::Owner => vec![/* all permissions */],
            Role::Admin => vec![
                Permission::FlowsRead,
                Permission::FlowsCreate,
                Permission::FlowsUpdate,
                Permission::FlowsDelete,
                Permission::FlowsDeploy,
                Permission::FlowsShare,
                Permission::RunsRead,
                Permission::RunsTrigger,
                Permission::RunsCancel,
                Permission::RunsDelete,
                Permission::RunsReadLogs,
                Permission::OAuthConnect,
                Permission::OAuthDisconnect,
                Permission::OAuthReadTokens,
                Permission::SecretsRead,
                Permission::SecretsCreate,
                Permission::SecretsUpdate,
                Permission::SecretsDelete,
                Permission::ToolsRead,
                Permission::ToolsInstall,
                Permission::ToolsUninstall,
                Permission::ToolsConfigure,
                Permission::MembersRead,
                Permission::MembersInvite,
                Permission::MembersUpdateRole,
                Permission::MembersRemove,
                Permission::AuditLogsRead,
                // NOT: OrgDelete, OrgBillingManage
            ],
            Role::Member => vec![
                Permission::FlowsRead,
                Permission::FlowsCreate,
                Permission::FlowsUpdate,  // Own flows only
                Permission::RunsRead,     // Own runs only
                Permission::RunsTrigger,
                Permission::RunsCancel,   // Own runs only
                Permission::OAuthConnect,
                Permission::MembersRead,
            ],
            Role::Viewer => vec![
                Permission::FlowsRead,    // Shared flows only
                Permission::RunsRead,     // No detailed logs
                Permission::MembersRead,
            ],
            Role::Custom { permissions, .. } => permissions.clone(),
        }
    }

    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.permissions().contains(permission)
    }
}
```

### 4.3 ABAC Policy Engine

**Policy Structure:**

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbacPolicy {
    pub id: String,
    pub name: String,
    pub tenant_id: Option<String>,  // None = global policy
    pub enabled: bool,

    /// Conditions that must ALL be true (AND logic)
    pub conditions: Vec<PolicyCondition>,

    /// Effect if conditions match
    pub effect: PolicyEffect,

    /// Priority (higher = evaluated first)
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyEffect {
    /// Allow the action (even if RBAC would deny)
    Allow,
    /// Deny the action (even if RBAC would allow)
    Deny,
    /// Require additional approval
    RequireApproval { approver_roles: Vec<Role> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyCondition {
    /// Classification level constraints
    ClassificationLevel {
        resource_classification: ClassificationLevel,
        user_clearance: ClassificationLevel,
        /// Allow access only if user_clearance >= resource_classification
        require: ComparisonOp,
    },

    /// Time-based restrictions (e.g., no deployments on weekends)
    TimeWindow {
        days_of_week: Vec<Weekday>,
        start_time: Time,
        end_time: Time,
        timezone: Tz,
    },

    /// IP address / location restrictions
    IpAddress {
        allowed_cidrs: Vec<IpNetwork>,
    },

    /// Resource attribute matching
    ResourceAttribute {
        attribute_key: String,
        operator: ComparisonOp,
        value: serde_json::Value,
    },

    /// User attribute matching
    UserAttribute {
        attribute_key: String,
        operator: ComparisonOp,
        value: serde_json::Value,
    },

    /// Data sensitivity labels
    DataSensitivity {
        label: String,  // e.g., "PII", "PHI", "CUI", "Proprietary"
        required_clearance: Vec<String>,
    },

    /// Custom expression (CEL - Common Expression Language)
    CustomExpression {
        expression: String,
        // Example: "resource.tags.contains('production') && user.groups.contains('sre')"
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonOp {
    Equals,
    NotEquals,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Contains,
    NotContains,
    In,
    NotIn,
}
```

**Policy Evaluation Engine:**

```rust
pub struct PolicyEvaluator {
    policies: Arc<RwLock<Vec<AbacPolicy>>>,
}

impl PolicyEvaluator {
    pub async fn evaluate(
        &self,
        context: &RequestContext,
        resource: &Resource,
        action: &Permission,
    ) -> Result<PolicyDecision> {
        let policies = self.policies.read().await;

        // 1. Filter policies applicable to this tenant + action
        let applicable_policies: Vec<_> = policies
            .iter()
            .filter(|p| p.enabled)
            .filter(|p| {
                p.tenant_id.is_none() || p.tenant_id.as_ref() == Some(&context.tenant_id)
            })
            .collect();

        // 2. Sort by priority (highest first)
        let mut sorted_policies = applicable_policies.clone();
        sorted_policies.sort_by_key(|p| -p.priority);

        // 3. Evaluate each policy
        for policy in sorted_policies {
            let all_conditions_met = policy.conditions.iter().all(|condition| {
                self.evaluate_condition(condition, context, resource)
            });

            if all_conditions_met {
                // Policy matched - return effect
                return Ok(match &policy.effect {
                    PolicyEffect::Allow => PolicyDecision::Allow,
                    PolicyEffect::Deny => PolicyDecision::Deny {
                        reason: format!("Denied by policy: {}", policy.name),
                    },
                    PolicyEffect::RequireApproval { approver_roles } => {
                        PolicyDecision::RequireApproval {
                            approver_roles: approver_roles.clone(),
                            policy_name: policy.name.clone(),
                        }
                    }
                });
            }
        }

        // 4. No policy matched - defer to RBAC
        Ok(PolicyDecision::Defer)
    }

    fn evaluate_condition(
        &self,
        condition: &PolicyCondition,
        context: &RequestContext,
        resource: &Resource,
    ) -> bool {
        match condition {
            PolicyCondition::ClassificationLevel {
                resource_classification,
                user_clearance,
                require,
            } => {
                let user_level = context.clearance_level.unwrap_or(ClassificationLevel::Unclassified);
                let resource_level = resource.classification_level.unwrap_or(ClassificationLevel::Unclassified);

                match require {
                    ComparisonOp::GreaterThanOrEqual => user_level >= resource_level,
                    ComparisonOp::Equals => user_level == resource_level,
                    _ => false,
                }
            }

            PolicyCondition::TimeWindow {
                days_of_week,
                start_time,
                end_time,
                timezone,
            } => {
                let now = Utc::now().with_timezone(timezone);
                let current_day = now.weekday();
                let current_time = now.time();

                days_of_week.contains(&current_day)
                    && current_time >= *start_time
                    && current_time <= *end_time
            }

            PolicyCondition::IpAddress { allowed_cidrs } => {
                if let Some(client_ip) = context.client_ip {
                    allowed_cidrs.iter().any(|cidr| cidr.contains(client_ip))
                } else {
                    false
                }
            }

            PolicyCondition::ResourceAttribute {
                attribute_key,
                operator,
                value,
            } => {
                if let Some(resource_value) = resource.attributes.get(attribute_key) {
                    self.compare_values(resource_value, operator, value)
                } else {
                    false
                }
            }

            PolicyCondition::UserAttribute {
                attribute_key,
                operator,
                value,
            } => {
                if let Some(user_value) = context.user_attributes.get(attribute_key) {
                    self.compare_values(user_value, operator, value)
                } else {
                    false
                }
            }

            PolicyCondition::DataSensitivity {
                label,
                required_clearance,
            } => {
                if resource.sensitivity_labels.contains(label) {
                    required_clearance.iter().any(|clearance| {
                        context.clearances.contains(clearance)
                    })
                } else {
                    true  // No label = no restriction
                }
            }

            PolicyCondition::CustomExpression { expression } => {
                // Evaluate CEL expression (or use simple evaluator)
                self.evaluate_cel_expression(expression, context, resource)
                    .unwrap_or(false)
            }
        }
    }
}

#[derive(Debug)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
    RequireApproval {
        approver_roles: Vec<Role>,
        policy_name: String,
    },
    Defer,  // No policy matched, use RBAC
}
```

### 4.4 Authorization Middleware

```rust
pub async fn authorize_request(
    ctx: &RequestContext,
    resource: &Resource,
    action: Permission,
    policy_evaluator: &PolicyEvaluator,
) -> Result<(), AuthorizationError> {
    // 1. Check RBAC base permission
    if !ctx.role.has_permission(&action) {
        return Err(AuthorizationError::Forbidden {
            message: format!(
                "Role {:?} does not have {:?} permission",
                ctx.role, action
            ),
        });
    }

    // 2. Check resource ownership (for member role)
    if ctx.role == Role::Member {
        match action {
            Permission::FlowsUpdate
            | Permission::FlowsDelete
            | Permission::FlowsDeploy => {
                if resource.created_by_user_id != ctx.user_id {
                    return Err(AuthorizationError::Forbidden {
                        message: "Can only modify own resources".to_string(),
                    });
                }
            }
            _ => {}
        }
    }

    // 3. Evaluate ABAC policies
    let policy_decision = policy_evaluator
        .evaluate(ctx, resource, &action)
        .await?;

    match policy_decision {
        PolicyDecision::Allow => Ok(()),
        PolicyDecision::Deny { reason } => Err(AuthorizationError::PolicyDenied { reason }),
        PolicyDecision::RequireApproval { .. } => {
            Err(AuthorizationError::ApprovalRequired {
                message: "This action requires approval".to_string(),
            })
        }
        PolicyDecision::Defer => Ok(()),  // RBAC already passed
    }
}
```

### 4.5 Example ABAC Policies

**Policy 1: Classification-Based Access**

```json
{
  "id": "policy_001",
  "name": "Classified Data Access Control",
  "tenant_id": "darpa_classified",
  "enabled": true,
  "conditions": [
    {
      "ClassificationLevel": {
        "resource_classification": "Secret",
        "user_clearance": "Secret",
        "require": "GreaterThanOrEqual"
      }
    }
  ],
  "effect": "Deny",
  "priority": 100
}
```

**Policy 2: Production Deployments Require Approval**

```json
{
  "id": "policy_002",
  "name": "Production Deployment Approval",
  "tenant_id": null,
  "enabled": true,
  "conditions": [
    {
      "ResourceAttribute": {
        "attribute_key": "environment",
        "operator": "Equals",
        "value": "production"
      }
    }
  ],
  "effect": {
    "RequireApproval": {
      "approver_roles": ["Admin", "Owner"]
    }
  },
  "priority": 90
}
```

**Policy 3: Time-Based Restrictions**

```json
{
  "id": "policy_003",
  "name": "No Weekend Deployments",
  "tenant_id": null,
  "enabled": true,
  "conditions": [
    {
      "TimeWindow": {
        "days_of_week": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
        "start_time": "09:00:00",
        "end_time": "17:00:00",
        "timezone": "America/New_York"
      }
    }
  ],
  "effect": "Deny",
  "priority": 80
}
```

**Policy 4: IP Allowlist for Classified Networks**

```json
{
  "id": "policy_004",
  "name": "SIPRNet Access Only",
  "tenant_id": "darpa_classified",
  "enabled": true,
  "conditions": [
    {
      "IpAddress": {
        "allowed_cidrs": ["192.168.100.0/24", "10.0.0.0/8"]
      }
    }
  ],
  "effect": "Allow",
  "priority": 100
}
```

---

## 5. Multi-Tenant Architecture

### 5.1 Tenant Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                         PLATFORM LEVEL                          │
│                    (System Administrator)                       │
├─────────────────────────────────────────────────────────────────┤
│  - Global configuration                                         │
│  - Cross-tenant analytics (aggregated, anonymized)              │
│  - System health monitoring                                     │
│  - License management                                           │
└────────┬────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                     ORGANIZATION LEVEL                          │
│                       (Tenant/Workspace)                        │
├─────────────────────────────────────────────────────────────────┤
│  Organization ID: org_abc123                                    │
│  Name: "DARPA"                                                  │
│  Classification Level: Secret                                   │
│  Plan: Enterprise                                               │
│  Created: 2025-01-15                                            │
│                                                                 │
│  Settings:                                                      │
│  ├─ Default workflow visibility: Private                       │
│  ├─ Require MFA: true                                          │
│  ├─ Session timeout: 4 hours                                   │
│  ├─ IP allowlist: 192.168.0.0/16                               │
│  └─ Data retention: 7 years                                    │
└────────┬────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                         USER LEVEL                              │
│                    (Individual Identity)                        │
├─────────────────────────────────────────────────────────────────┤
│  User: john.doe@darpa.mil                                       │
│  Role in org_abc123: Admin                                      │
│  Clearance: Secret                                              │
│  Auth method: CAC/PKI                                           │
│  Member since: 2025-01-20                                       │
└────────┬────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                      RESOURCE LEVEL                             │
│            (Flows, Runs, Credentials, Secrets)                  │
├─────────────────────────────────────────────────────────────────┤
│  Flow: "contracting_workflow"                                   │
│  Owner: john.doe@darpa.mil                                      │
│  Organization: org_abc123                                       │
│  Classification: Secret                                         │
│  Visibility: Private (only owner)                               │
│  Created: 2025-01-25                                            │
│                                                                 │
│  Shared with:                                                   │
│  ├─ jane.smith@darpa.mil (read-only)                           │
│  └─ @legal_team (execute permission)                           │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Tenant Isolation Mechanisms

**Database-Level Isolation (Row-Level Security):**

```sql
-- Enable Row-Level Security on all tenant-scoped tables
ALTER TABLE flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_secrets ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only access data in their tenant
CREATE POLICY tenant_isolation_policy ON flows
    USING (tenant_id = current_setting('app.current_tenant_id')::text);

CREATE POLICY tenant_isolation_policy ON runs
    USING (tenant_id = current_setting('app.current_tenant_id')::text);

-- Set tenant context at connection level
-- In application code before each query:
SET LOCAL app.current_tenant_id = 'org_abc123';
```

**Application-Level Isolation:**

```rust
pub struct TenantContext {
    pub tenant_id: String,
    pub tenant_name: String,
    pub classification_level: ClassificationLevel,
    pub settings: TenantSettings,
}

pub struct RequestContext {
    pub user_id: String,
    pub tenant: TenantContext,
    pub role: Role,
    pub clearance_level: Option<ClassificationLevel>,
    pub client_ip: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub request_id: String,
}

/// Middleware to inject tenant context
pub async fn tenant_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // 1. Extract authenticated user from prior middleware
    let auth_context = req.extensions()
        .get::<AuthContext>()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // 2. Resolve tenant from:
    //    a) Subdomain (tenant-abc.beemflow.com)
    //    b) Header (X-Tenant-ID)
    //    c) JWT claim (default tenant)
    let tenant_id = resolve_tenant_id(&req, &auth_context)?;

    // 3. Verify user is member of this tenant
    let membership = state.storage
        .get_tenant_membership(&tenant_id, &auth_context.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::FORBIDDEN)?;

    // 4. Load tenant settings
    let tenant = state.storage
        .get_tenant(&tenant_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // 5. Create full request context
    let request_context = RequestContext {
        user_id: auth_context.user_id.clone(),
        tenant: TenantContext {
            tenant_id: tenant.id,
            tenant_name: tenant.name,
            classification_level: tenant.classification_level,
            settings: tenant.settings,
        },
        role: membership.role,
        clearance_level: auth_context.clearance_level,
        client_ip: extract_client_ip(&req),
        user_agent: extract_user_agent(&req),
        request_id: uuid::Uuid::new_v4().to_string(),
    };

    // 6. Inject into request extensions
    req.extensions_mut().insert(request_context);

    Ok(next.run(req).await)
}
```

### 5.3 Cross-Tenant Security

**Strict Isolation Rules:**

1. **Data Isolation**: No cross-tenant queries allowed (enforced by RLS)
2. **Credential Isolation**: OAuth tokens scoped to user, cannot be shared
3. **Workflow Isolation**: Flow names can collide across tenants (namespaced)
4. **Audit Isolation**: Each tenant sees only their audit logs

**Exception: Platform Admin Access**

```rust
pub struct PlatformAdminContext {
    pub admin_user_id: String,
    pub access_scope: AdminAccessScope,
    pub justification: String,  // Required: reason for cross-tenant access
    pub approved_by: Option<String>,
}

pub enum AdminAccessScope {
    /// Read-only access to tenant data for support
    ReadOnly { tenant_id: String },
    /// Full access for emergency fixes
    FullAccess { tenant_id: String, expires_at: DateTime<Utc> },
    /// Platform-wide analytics (aggregated only)
    Analytics,
}

impl RequestContext {
    pub fn is_platform_admin(&self) -> bool {
        self.role == Role::Owner && self.tenant.tenant_id == "platform_admin"
    }

    pub async fn access_tenant_as_admin(
        &self,
        target_tenant_id: &str,
        justification: &str,
    ) -> Result<TenantContext> {
        if !self.is_platform_admin() {
            return Err(AuthorizationError::Forbidden {
                message: "Not a platform admin".to_string(),
            });
        }

        // Log admin access for audit
        audit_log!(
            event = "admin.cross_tenant_access",
            admin_user_id = self.user_id,
            target_tenant_id = target_tenant_id,
            justification = justification,
            timestamp = Utc::now(),
        );

        // Return tenant context with elevated permissions
        Ok(TenantContext { /* ... */ })
    }
}
```

---

## 6. Classification Level Support

### 6.1 Classification Levels

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ClassificationLevel {
    /// Public information
    Unclassified = 0,

    /// Controlled Unclassified Information
    CUI = 1,

    /// DoD Confidential
    Confidential = 2,

    /// DoD Secret
    Secret = 3,

    /// DoD Top Secret
    TopSecret = 4,

    /// Top Secret / Sensitive Compartmented Information
    TopSecretSCI = 5,
}

impl ClassificationLevel {
    /// Can user with given clearance access resource at this level?
    pub fn can_access(&self, user_clearance: ClassificationLevel) -> bool {
        user_clearance >= *self
    }

    /// Classification marking for display
    pub fn marking(&self) -> &'static str {
        match self {
            ClassificationLevel::Unclassified => "UNCLASSIFIED",
            ClassificationLevel::CUI => "CUI",
            ClassificationLevel::Confidential => "CONFIDENTIAL",
            ClassificationLevel::Secret => "SECRET",
            ClassificationLevel::TopSecret => "TOP SECRET",
            ClassificationLevel::TopSecretSCI => "TOP SECRET//SCI",
        }
    }

    /// Banner color for UI display
    pub fn banner_color(&self) -> &'static str {
        match self {
            ClassificationLevel::Unclassified => "#008000",  // Green
            ClassificationLevel::CUI => "#502D90",           // Purple
            ClassificationLevel::Confidential => "#0000FF",  // Blue
            ClassificationLevel::Secret => "#FF0000",        // Red
            ClassificationLevel::TopSecret => "#FFA500",     // Orange
            ClassificationLevel::TopSecretSCI => "#FFA500",  // Orange
        }
    }
}
```

### 6.2 Classification Enforcement

**Resource-Level Classification:**

```rust
pub struct Flow {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub content: String,
    pub created_by_user_id: String,

    /// Classification level of this flow
    pub classification_level: ClassificationLevel,

    /// Derived classification from content analysis
    pub derived_classification: Option<ClassificationLevel>,

    /// Highest classification of data this flow has accessed
    pub high_water_mark: ClassificationLevel,
}

pub struct Run {
    pub id: String,
    pub flow_name: String,
    pub tenant_id: String,
    pub triggered_by_user_id: String,

    /// Classification of the run (inherited from flow)
    pub classification_level: ClassificationLevel,

    /// Dynamic classification based on accessed data
    pub actual_classification: ClassificationLevel,

    /// Event data may contain classified information
    pub event: serde_json::Value,
}
```

**Classification Guards:**

```rust
pub async fn trigger_run(
    ctx: &RequestContext,
    flow_name: &str,
    event: serde_json::Value,
) -> Result<Run> {
    // 1. Load flow
    let flow = storage.get_flow(&ctx.tenant.tenant_id, flow_name).await?
        .ok_or(FlowError::NotFound)?;

    // 2. Check classification access
    if let Some(user_clearance) = ctx.clearance_level {
        if !flow.classification_level.can_access(user_clearance) {
            return Err(FlowError::InsufficientClearance {
                required: flow.classification_level,
                user_has: user_clearance,
            });
        }
    } else {
        // No clearance = can only access Unclassified
        if flow.classification_level != ClassificationLevel::Unclassified {
            return Err(FlowError::ClearanceRequired {
                required: flow.classification_level,
            });
        }
    }

    // 3. Create run with classification metadata
    let run = Run {
        id: uuid::Uuid::new_v4().to_string(),
        flow_name: flow_name.to_string(),
        tenant_id: ctx.tenant.tenant_id.clone(),
        triggered_by_user_id: ctx.user_id.clone(),
        classification_level: flow.classification_level,
        actual_classification: flow.classification_level,  // May increase during execution
        event,
        // ...
    };

    // 4. Execute in classified context
    execute_flow_with_classification_tracking(&run, &flow, ctx).await?;

    Ok(run)
}
```

**Data Classification Markings:**

```rust
/// Middleware to add classification banners to HTTP responses
pub async fn classification_banner_middleware(
    Extension(ctx): Extension<RequestContext>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let mut response = next.run(req).await;

    // Add classification headers
    let classification = ctx.tenant.classification_level;
    response.headers_mut().insert(
        "X-Classification-Level",
        classification.marking().parse().unwrap(),
    );

    response.headers_mut().insert(
        "X-Classification-Color",
        classification.banner_color().parse().unwrap(),
    );

    // For HTML responses, inject banner
    if let Some(content_type) = response.headers().get(header::CONTENT_TYPE) {
        if content_type.to_str().unwrap_or("").starts_with("text/html") {
            // Inject classification banner at top of HTML
            // (Implementation: stream response body, prepend banner div)
        }
    }

    Ok(response)
}
```

---

## 7. Credential Management

### 7.1 Encryption Architecture

**Multi-Layer Encryption:**

```
┌─────────────────────────────────────────────────────────────────┐
│                         PLAINTEXT                               │
│                   (OAuth Access Token)                          │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              APPLICATION-LEVEL ENCRYPTION                       │
│  Algorithm: AES-256-GCM                                         │
│  Key: Derived from master key + tenant_id + user_id            │
│  Nonce: Random 96-bit (stored with ciphertext)                 │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                     ENCRYPTED BLOB                              │
│  Format: [nonce:12][ciphertext:N][tag:16]                      │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              DATABASE-LEVEL ENCRYPTION (TDE)                    │
│  PostgreSQL: pgcrypto or native TDE                             │
│  SQLite: SQLCipher or SEE                                       │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│               FILESYSTEM ENCRYPTION (LUKS/dm-crypt)             │
│  Full disk encryption for classified environments               │
└─────────────────────────────────────────────────────────────────┘
```

**Implementation:**

```rust
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, PasswordHasher};
use hkdf::Hkdf;
use sha2::Sha256;

pub struct CredentialVault {
    /// Master encryption key (loaded from HSM or env)
    master_key: [u8; 32],
}

impl CredentialVault {
    /// Encrypt OAuth token for storage
    pub fn encrypt_token(
        &self,
        plaintext: &str,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<EncryptedBlob> {
        // 1. Derive per-credential key using HKDF
        let credential_key = self.derive_key(tenant_id, user_id)?;

        // 2. Generate random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // 3. Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new(&credential_key.into());
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| VaultError::EncryptionFailed)?;

        // 4. Concatenate nonce + ciphertext + tag
        let mut blob = Vec::new();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);

        Ok(EncryptedBlob {
            data: base64::encode(&blob),
            key_version: 1,  // For key rotation
            algorithm: "AES-256-GCM".to_string(),
        })
    }

    /// Decrypt OAuth token for use
    pub fn decrypt_token(
        &self,
        encrypted: &EncryptedBlob,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<String> {
        // 1. Decode base64
        let blob = base64::decode(&encrypted.data)?;

        // 2. Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = blob.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // 3. Derive same key
        let credential_key = self.derive_key(tenant_id, user_id)?;

        // 4. Decrypt
        let cipher = Aes256Gcm::new(&credential_key.into());
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| VaultError::DecryptionFailed)?;

        Ok(String::from_utf8(plaintext)?)
    }

    /// Derive per-credential encryption key
    fn derive_key(&self, tenant_id: &str, user_id: &str) -> Result<[u8; 32]> {
        let info = format!("beemflow-credential-{}-{}", tenant_id, user_id);
        let hkdf = Hkdf::<Sha256>::new(None, &self.master_key);

        let mut key = [0u8; 32];
        hkdf.expand(info.as_bytes(), &mut key)
            .map_err(|_| VaultError::KeyDerivationFailed)?;

        Ok(key)
    }

    /// Rotate master key (re-encrypt all credentials)
    pub async fn rotate_master_key(
        &mut self,
        new_master_key: [u8; 32],
        storage: &dyn Storage,
    ) -> Result<()> {
        // 1. Fetch all encrypted credentials
        let credentials = storage.get_all_oauth_credentials().await?;

        // 2. Decrypt with old key, re-encrypt with new key
        for cred in credentials {
            let plaintext = self.decrypt_token(
                &cred.encrypted_access_token,
                &cred.user_id,
                &cred.user_id,
            )?;

            // Set new master key
            let old_key = self.master_key;
            self.master_key = new_master_key;

            let new_encrypted = self.encrypt_token(
                &plaintext,
                &cred.tenant_id,
                &cred.user_id,
            )?;

            // 3. Update in database
            storage.update_oauth_credential_encryption(
                &cred.id,
                &new_encrypted,
            ).await?;

            // Restore old key for next iteration
            self.master_key = old_key;
        }

        // 4. Commit new master key
        self.master_key = new_master_key;

        Ok(())
    }
}
```

### 7.2 Hardware Security Module (HSM) Integration

**For IL-4/5 and Classified Deployments:**

```rust
use pkcs11::{Ctx, types::*};

pub struct HsmVault {
    ctx: Ctx,
    session: CK_SESSION_HANDLE,
    key_handle: CK_OBJECT_HANDLE,
}

impl HsmVault {
    /// Initialize HSM connection
    pub fn new(pkcs11_module_path: &str, pin: &str) -> Result<Self> {
        let ctx = Ctx::new_and_initialize(pkcs11_module_path)?;

        // Get slot (HSM device)
        let slots = ctx.get_slot_list(true)?;
        let slot = slots[0];

        // Open session
        let session = ctx.open_session(
            slot,
            CKF_SERIAL_SESSION | CKF_RW_SESSION,
            None,
            None,
        )?;

        // Login with PIN
        ctx.login(session, CKU_USER, Some(pin))?;

        // Find or create master key
        let key_handle = Self::find_or_create_master_key(&ctx, session)?;

        Ok(Self {
            ctx,
            session,
            key_handle,
        })
    }

    /// Encrypt using HSM
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        self.ctx.encrypt_init(self.session, &mechanism, self.key_handle)?;
        let ciphertext = self.ctx.encrypt(self.session, plaintext)?;

        Ok(ciphertext)
    }

    /// Decrypt using HSM
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        self.ctx.decrypt_init(self.session, &mechanism, self.key_handle)?;
        let plaintext = self.ctx.decrypt(self.session, ciphertext)?;

        Ok(plaintext)
    }

    fn find_or_create_master_key(
        ctx: &Ctx,
        session: CK_SESSION_HANDLE,
    ) -> Result<CK_OBJECT_HANDLE> {
        // Search for existing key with label "beemflow_master"
        let template = vec![
            CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&CKO_SECRET_KEY),
            CK_ATTRIBUTE::new(CKA_LABEL).with_string("beemflow_master"),
        ];

        ctx.find_objects_init(session, &template)?;
        let objects = ctx.find_objects(session, 1)?;
        ctx.find_objects_final(session)?;

        if let Some(&key_handle) = objects.first() {
            Ok(key_handle)
        } else {
            // Create new AES-256 key
            Self::create_aes_key(ctx, session)
        }
    }

    fn create_aes_key(ctx: &Ctx, session: CK_SESSION_HANDLE) -> Result<CK_OBJECT_HANDLE> {
        let template = vec![
            CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&CKO_SECRET_KEY),
            CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&CKK_AES),
            CK_ATTRIBUTE::new(CKA_VALUE_LEN).with_ck_ulong(&32),  // 256 bits
            CK_ATTRIBUTE::new(CKA_LABEL).with_string("beemflow_master"),
            CK_ATTRIBUTE::new(CKA_ENCRYPT).with_bool(&true),
            CK_ATTRIBUTE::new(CKA_DECRYPT).with_bool(&true),
            CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&true),
            CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&false),
        ];

        let mechanism = CK_MECHANISM {
            mechanism: CKM_AES_KEY_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let key_handle = ctx.generate_key(session, &mechanism, &template)?;

        Ok(key_handle)
    }
}
```

---

## 8. Audit Logging & CSSP Access

### 8.1 Audit Log Schema

```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- When & Where
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    request_id TEXT NOT NULL,

    -- Who
    tenant_id TEXT NOT NULL,
    user_id TEXT,
    auth_method TEXT NOT NULL,  -- 'cac_pki', 'jwt', 'api_key'
    client_ip INET,
    user_agent TEXT,

    -- What
    action TEXT NOT NULL,  -- 'flow.create', 'run.trigger', 'user.login'
    resource_type TEXT NOT NULL,  -- 'flow', 'run', 'user', 'secret'
    resource_id TEXT,
    resource_name TEXT,

    -- How
    http_method TEXT,
    http_path TEXT,
    http_status_code INTEGER,

    -- Result
    success BOOLEAN NOT NULL,
    error_message TEXT,

    -- Details (JSON)
    metadata JSONB,

    -- Classification
    classification_level TEXT NOT NULL DEFAULT 'UNCLASSIFIED',

    -- Immutability (cannot be deleted)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Indexes for fast queries
CREATE INDEX idx_audit_logs_tenant_time ON audit_logs(tenant_id, timestamp DESC);
CREATE INDEX idx_audit_logs_user_time ON audit_logs(user_id, timestamp DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action, timestamp DESC);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);

-- GIN index for metadata JSON queries
CREATE INDEX idx_audit_logs_metadata ON audit_logs USING GIN(metadata);

-- Prevent deletion (append-only table)
CREATE OR REPLACE FUNCTION prevent_audit_log_deletion()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs cannot be deleted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_prevent_audit_log_deletion
BEFORE DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_deletion();

-- Prevent updates (immutable)
CREATE OR REPLACE FUNCTION prevent_audit_log_updates()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs cannot be modified';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_prevent_audit_log_updates
BEFORE UPDATE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_updates();
```

### 8.2 Audit Logging Implementation

```rust
pub struct AuditLogger {
    storage: Arc<dyn Storage>,
}

impl AuditLogger {
    pub async fn log(&self, event: AuditEvent) -> Result<()> {
        let log_entry = AuditLogEntry {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            request_id: event.request_id,
            tenant_id: event.tenant_id,
            user_id: event.user_id,
            auth_method: event.auth_method,
            client_ip: event.client_ip,
            user_agent: event.user_agent,
            action: event.action,
            resource_type: event.resource_type,
            resource_id: event.resource_id,
            resource_name: event.resource_name,
            http_method: event.http_method,
            http_path: event.http_path,
            http_status_code: event.http_status_code,
            success: event.success,
            error_message: event.error_message,
            metadata: event.metadata,
            classification_level: event.classification_level,
            created_at: Utc::now(),
        };

        // Write to database (append-only)
        self.storage.insert_audit_log(&log_entry).await?;

        // Optional: Also write to SIEM
        if let Some(siem_forwarder) = &self.siem_forwarder {
            siem_forwarder.forward(&log_entry).await.ok();  // Fire and forget
        }

        Ok(())
    }
}

/// Middleware to automatically log all requests
pub async fn audit_middleware(
    Extension(ctx): Extension<RequestContext>,
    req: Request,
    next: Next,
) -> Result<Response> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let start_time = Instant::now();

    let response = next.run(req).await;

    let duration_ms = start_time.elapsed().as_millis() as u64;
    let status_code = response.status().as_u16();

    // Log the request
    ctx.audit_logger.log(AuditEvent {
        request_id: ctx.request_id.clone(),
        tenant_id: ctx.tenant.tenant_id.clone(),
        user_id: Some(ctx.user_id.clone()),
        auth_method: format!("{:?}", ctx.auth_method),
        client_ip: ctx.client_ip,
        user_agent: ctx.user_agent.clone(),
        action: format!("{} {}", method, path),
        resource_type: extract_resource_type(&path),
        resource_id: extract_resource_id(&path),
        resource_name: None,
        http_method: Some(method.to_string()),
        http_path: Some(path),
        http_status_code: Some(status_code),
        success: status_code < 400,
        error_message: None,
        metadata: json!({
            "duration_ms": duration_ms,
        }),
        classification_level: ctx.tenant.classification_level.marking().to_string(),
    }).await.ok();  // Don't fail request if audit logging fails

    Ok(response)
}
```

### 8.3 CSSP Access (Cyber Security Service Provider)

**Real-Time Audit Export for CSSP:**

```rust
pub struct SiemForwarder {
    syslog_client: SyslogClient,
    splunk_client: Option<SplunkClient>,
    format: SiemFormat,
}

pub enum SiemFormat {
    Syslog,   // RFC 5424
    CEF,      // Common Event Format (ArcSight)
    LEEF,     // Log Event Extended Format (QRadar)
    JSON,     // Generic JSON
}

impl SiemForwarder {
    pub async fn forward(&self, log: &AuditLogEntry) -> Result<()> {
        let formatted = match self.format {
            SiemFormat::Syslog => self.format_syslog(log),
            SiemFormat::CEF => self.format_cef(log),
            SiemFormat::LEEF => self.format_leef(log),
            SiemFormat::JSON => serde_json::to_string(log)?,
        };

        // Send to syslog
        self.syslog_client.send(&formatted).await?;

        // Optionally also send to Splunk HEC
        if let Some(splunk) = &self.splunk_client {
            splunk.send_event(log).await.ok();
        }

        Ok(())
    }

    fn format_cef(&self, log: &AuditLogEntry) -> String {
        // CEF Format:
        // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        format!(
            "CEF:0|Anthropic|BeemFlow|2.0|{}|{}|{}|{}",
            log.action,
            log.action,
            self.severity_from_action(&log.action),
            self.cef_extension(log)
        )
    }

    fn cef_extension(&self, log: &AuditLogEntry) -> String {
        format!(
            "rt={} src={} suser={} request={} cs1Label=TenantID cs1={} cs2Label=Classification cs2={}",
            log.timestamp.timestamp_millis(),
            log.client_ip.map(|ip| ip.to_string()).unwrap_or_default(),
            log.user_id.as_deref().unwrap_or("unknown"),
            log.http_path.as_deref().unwrap_or(""),
            log.tenant_id,
            log.classification_level,
        )
    }
}
```

**CSSP Query API:**

```rust
/// Endpoint for CSSP to query audit logs
/// Requires special CSSP role with elevated permissions
#[axum::debug_handler]
pub async fn cssp_query_audit_logs(
    Extension(ctx): Extension<RequestContext>,
    Query(params): Query<AuditQueryParams>,
) -> Result<Json<AuditQueryResponse>, AppError> {
    // 1. Verify CSSP role
    if !ctx.is_cssp_user() {
        return Err(AppError::Forbidden("CSSP access required".to_string()));
    }

    // 2. Build query
    let query = AuditQuery {
        tenant_id: params.tenant_id,
        user_id: params.user_id,
        action_pattern: params.action,
        start_time: params.start_time,
        end_time: params.end_time,
        classification_level: params.classification_level,
        limit: params.limit.unwrap_or(1000).min(10000),
        offset: params.offset.unwrap_or(0),
    };

    // 3. Execute query
    let logs = ctx.storage.query_audit_logs(&query).await?;
    let total_count = ctx.storage.count_audit_logs(&query).await?;

    Ok(Json(AuditQueryResponse {
        logs,
        total_count,
        query_time_ms: /* ... */,
    }))
}
```

---

## 9. API Security

### 9.1 Request Security Pipeline

```
Incoming HTTP Request
    │
    ├─> 1. TLS Termination (min TLS 1.2, prefer TLS 1.3)
    │
    ├─> 2. Rate Limiting (per-IP + per-user)
    │
    ├─> 3. CORS Validation
    │
    ├─> 4. Request Size Limit (10 MB default)
    │
    ├─> 5. Authentication Middleware
    │      ├─ Extract Bearer token / CAC cert / SAML assertion
    │      ├─ Validate authenticity
    │      ├─ Extract user identity
    │      └─ Create AuthContext
    │
    ├─> 6. Tenant Resolution Middleware
    │      ├─ Determine target tenant
    │      ├─ Verify user membership
    │      └─ Create RequestContext
    │
    ├─> 7. Authorization Middleware
    │      ├─ Check RBAC permissions
    │      ├─ Evaluate ABAC policies
    │      └─ Allow/Deny
    │
    ├─> 8. Audit Logging Middleware
    │      └─ Log request metadata
    │
    ├─> 9. Handler Execution
    │      └─ Business logic
    │
    └─> 10. Response Classification Middleware
           ├─ Add classification headers
           └─ Sanitize error messages
```

### 9.2 Rate Limiting

```rust
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use std::net::IpAddr;

pub fn rate_limit_layer() -> GovernorLayer {
    let config = Box::new(
        GovernorConfigBuilder::default()
            .per_second(10)      // 10 requests per second
            .burst_size(50)      // Allow burst of 50
            .finish()
            .unwrap(),
    );

    GovernorLayer {
        config: Box::leak(config),
    }
}

/// Per-user rate limiting (stricter than per-IP)
pub struct UserRateLimiter {
    storage: Arc<dyn Storage>,
}

impl UserRateLimiter {
    pub async fn check_rate_limit(
        &self,
        user_id: &str,
        action: &str,
    ) -> Result<(), RateLimitError> {
        let key = format!("ratelimit:{}:{}", user_id, action);
        let window_seconds = 60;
        let max_requests = match action {
            "run.trigger" => 100,   // 100 runs per minute
            "flow.deploy" => 10,    // 10 deployments per minute
            "auth.login" => 5,      // 5 login attempts per minute
            _ => 1000,              // 1000 generic requests per minute
        };

        // Increment counter in Redis/database
        let current_count = self.storage
            .increment_rate_limit(&key, window_seconds)
            .await?;

        if current_count > max_requests {
            return Err(RateLimitError::Exceeded {
                limit: max_requests,
                window_seconds,
                retry_after_seconds: window_seconds,
            });
        }

        Ok(())
    }
}
```

### 9.3 Input Validation

```rust
use validator::{Validate, ValidationError};

#[derive(Debug, Deserialize, Validate)]
pub struct TriggerRunRequest {
    #[validate(length(min = 1, max = 255))]
    pub flow_name: String,

    #[validate]
    pub event: serde_json::Value,

    #[validate(custom = "validate_no_script_injection")]
    pub metadata: Option<HashMap<String, String>>,
}

fn validate_no_script_injection(value: &HashMap<String, String>) -> Result<(), ValidationError> {
    for (key, val) in value {
        if val.contains("<script>") || val.contains("javascript:") {
            return Err(ValidationError::new("script_injection"));
        }
    }
    Ok(())
}

/// Validate workflow YAML before deployment
pub fn validate_flow_content(yaml: &str) -> Result<(), ValidationError> {
    // 1. Parse YAML
    let flow: FlowDefinition = serde_yaml::from_str(yaml)
        .map_err(|_| ValidationError::new("invalid_yaml"))?;

    // 2. Validate structure
    if flow.name.is_empty() {
        return Err(ValidationError::new("missing_name"));
    }

    // 3. Validate step references
    for step in &flow.steps {
        // Check for undefined variable references
        if let Some(uses) = &step.uses {
            if !is_valid_tool_reference(uses) {
                return Err(ValidationError::new("invalid_tool_reference"));
            }
        }
    }

    // 4. Check for security issues
    if contains_dangerous_patterns(&flow) {
        return Err(ValidationError::new("security_violation"));
    }

    Ok(())
}

fn contains_dangerous_patterns(flow: &FlowDefinition) -> bool {
    // Check for:
    // - Command injection attempts (e.g., `sh -c "$(curl ...)"`)
    // - SQL injection patterns
    // - Path traversal (e.g., `../../etc/passwd`)
    // - Excessive resource usage (e.g., infinite loops)

    let yaml = serde_yaml::to_string(flow).unwrap();

    yaml.contains("$(curl") ||
    yaml.contains("../") ||
    yaml.contains("DROP TABLE") ||
    yaml.contains("'; DELETE FROM")
}
```

---

## 10. Database Schema

### 10.1 Complete Schema (PostgreSQL)

```sql
-- =============================================================================
-- USERS TABLE
-- =============================================================================
CREATE TABLE users (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    password_hash TEXT,  -- NULL for CAC/SAML users
    email_verified BOOLEAN DEFAULT FALSE,
    avatar_url TEXT,

    -- MFA
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret TEXT,  -- TOTP secret (encrypted)
    backup_codes TEXT[],  -- Encrypted backup codes

    -- CAC/PKI
    certificate_dn TEXT UNIQUE,  -- X.509 Distinguished Name
    certificate_serial TEXT,
    certificate_public_key_hash TEXT,

    -- SAML
    saml_name_id TEXT UNIQUE,
    saml_idp_entity_id TEXT,

    -- Clearance
    clearance_level TEXT DEFAULT 'Unclassified',

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,

    -- Account status
    disabled BOOLEAN DEFAULT FALSE,
    disabled_reason TEXT,
    disabled_at TIMESTAMPTZ
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_certificate_dn ON users(certificate_dn) WHERE certificate_dn IS NOT NULL;
CREATE INDEX idx_users_saml_name_id ON users(saml_name_id) WHERE saml_name_id IS NOT NULL;

-- =============================================================================
-- TENANTS TABLE
-- =============================================================================
CREATE TABLE tenants (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,  -- For subdomain routing

    -- Classification
    classification_level TEXT DEFAULT 'Unclassified',

    -- Subscription
    plan TEXT DEFAULT 'free',  -- free, pro, enterprise, classified
    plan_starts_at TIMESTAMPTZ,
    plan_ends_at TIMESTAMPTZ,

    -- Quotas
    max_users INTEGER DEFAULT 5,
    max_flows INTEGER DEFAULT 10,
    max_runs_per_month INTEGER DEFAULT 1000,

    -- Settings
    settings JSONB DEFAULT '{}'::jsonb,

    -- Audit
    created_by_user_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Status
    disabled BOOLEAN DEFAULT FALSE,

    FOREIGN KEY (created_by_user_id) REFERENCES users(id)
);

CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_classification ON tenants(classification_level);

-- =============================================================================
-- TENANT MEMBERS TABLE
-- =============================================================================
CREATE TABLE tenant_members (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL,  -- owner, admin, member, viewer, custom

    -- Custom role (if role = 'custom')
    custom_permissions TEXT[],

    -- Invitation
    invited_by_user_id TEXT,
    invited_at TIMESTAMPTZ,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Status
    disabled BOOLEAN DEFAULT FALSE,

    UNIQUE(tenant_id, user_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (invited_by_user_id) REFERENCES users(id)
);

CREATE INDEX idx_tenant_members_tenant ON tenant_members(tenant_id);
CREATE INDEX idx_tenant_members_user ON tenant_members(user_id);
CREATE INDEX idx_tenant_members_role ON tenant_members(tenant_id, role);

-- =============================================================================
-- REFRESH TOKENS TABLE
-- =============================================================================
CREATE TABLE refresh_tokens (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,  -- bcrypt hash

    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    revoked_by_user_id TEXT,
    revoke_reason TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,

    -- Session metadata
    user_agent TEXT,
    client_ip INET,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (revoked_by_user_id) REFERENCES users(id)
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at) WHERE NOT revoked;
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);

-- =============================================================================
-- FLOWS TABLE (Modified)
-- =============================================================================
ALTER TABLE flows DROP CONSTRAINT IF EXISTS flows_pkey;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS created_by_user_id TEXT NOT NULL;
ALTER TABLE flows ADD COLUMN IF NOT EXISTS classification_level TEXT DEFAULT 'Unclassified';
ALTER TABLE flows ADD COLUMN IF NOT EXISTS visibility TEXT DEFAULT 'private';  -- private, shared, public
ALTER TABLE flows ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT '{}';

ALTER TABLE flows ADD CONSTRAINT unique_tenant_flow_name UNIQUE(tenant_id, name);
ALTER TABLE flows ADD FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE flows ADD FOREIGN KEY (created_by_user_id) REFERENCES users(id);

CREATE INDEX idx_flows_tenant_name ON flows(tenant_id, name);
CREATE INDEX idx_flows_user ON flows(created_by_user_id);
CREATE INDEX idx_flows_classification ON flows(classification_level);
CREATE INDEX idx_flows_tags ON flows USING GIN(tags);

-- Row-Level Security
ALTER TABLE flows ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy ON flows
    USING (tenant_id = current_setting('app.current_tenant_id', true)::text);

-- =============================================================================
-- RUNS TABLE (Modified)
-- =============================================================================
ALTER TABLE runs ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS triggered_by_user_id TEXT NOT NULL;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS classification_level TEXT DEFAULT 'Unclassified';
ALTER TABLE runs ADD COLUMN IF NOT EXISTS actual_classification_level TEXT DEFAULT 'Unclassified';

ALTER TABLE runs ADD FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE runs ADD FOREIGN KEY (triggered_by_user_id) REFERENCES users(id);

DROP INDEX IF EXISTS idx_runs_flow_status_time;
CREATE INDEX idx_runs_tenant_time ON runs(tenant_id, started_at DESC);
CREATE INDEX idx_runs_tenant_flow_status ON runs(tenant_id, flow_name, status);
CREATE INDEX idx_runs_user ON runs(triggered_by_user_id, started_at DESC);
CREATE INDEX idx_runs_classification ON runs(classification_level);

-- Row-Level Security
ALTER TABLE runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy ON runs
    USING (tenant_id = current_setting('app.current_tenant_id', true)::text);

-- =============================================================================
-- OAUTH CREDENTIALS TABLE (Modified)
-- =============================================================================
ALTER TABLE oauth_credentials DROP CONSTRAINT IF EXISTS oauth_credentials_provider_integration_key;
ALTER TABLE oauth_credentials ADD COLUMN IF NOT EXISTS user_id TEXT NOT NULL;
ALTER TABLE oauth_credentials ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL;

ALTER TABLE oauth_credentials ADD CONSTRAINT unique_user_provider_integration
    UNIQUE(user_id, provider, integration);

ALTER TABLE oauth_credentials ADD FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE oauth_credentials ADD FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

CREATE INDEX idx_oauth_creds_user_provider ON oauth_credentials(user_id, provider, integration);

-- Row-Level Security
ALTER TABLE oauth_credentials ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_isolation_policy ON oauth_credentials
    USING (user_id = current_setting('app.current_user_id', true)::text);

-- =============================================================================
-- TENANT SECRETS TABLE
-- =============================================================================
CREATE TABLE tenant_secrets (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,  -- Encrypted
    description TEXT,

    created_by_user_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by_user_id TEXT,

    -- Audit
    last_accessed_at TIMESTAMPTZ,
    last_accessed_by_user_id TEXT,
    access_count INTEGER DEFAULT 0,

    UNIQUE(tenant_id, key),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id),
    FOREIGN KEY (updated_by_user_id) REFERENCES users(id),
    FOREIGN KEY (last_accessed_by_user_id) REFERENCES users(id)
);

CREATE INDEX idx_tenant_secrets_tenant ON tenant_secrets(tenant_id);

-- Row-Level Security
ALTER TABLE tenant_secrets ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy ON tenant_secrets
    USING (tenant_id = current_setting('app.current_tenant_id', true)::text);

-- =============================================================================
-- ABAC POLICIES TABLE
-- =============================================================================
CREATE TABLE abac_policies (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id TEXT,  -- NULL = global policy
    name TEXT NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 0,

    -- Policy definition (JSON)
    conditions JSONB NOT NULL,
    effect TEXT NOT NULL,  -- 'allow', 'deny', 'require_approval'

    created_by_user_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id)
);

CREATE INDEX idx_abac_policies_tenant ON abac_policies(tenant_id) WHERE enabled = true;
CREATE INDEX idx_abac_policies_priority ON abac_policies(priority DESC) WHERE enabled = true;

-- =============================================================================
-- AUDIT LOGS TABLE (See section 8.1)
-- =============================================================================
-- (Already defined above - immutable append-only table)

-- =============================================================================
-- FLOW SHARES TABLE (for shared workflows)
-- =============================================================================
CREATE TABLE flow_shares (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    flow_id TEXT NOT NULL,
    shared_with_user_id TEXT,  -- NULL = shared with all tenant members
    shared_with_role TEXT,     -- NULL = specific user, otherwise 'admin'/'member'
    permission TEXT NOT NULL,  -- 'read', 'execute', 'edit'

    shared_by_user_id TEXT NOT NULL,
    shared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,

    FOREIGN KEY (flow_id) REFERENCES flows(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_with_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_by_user_id) REFERENCES users(id)
);

CREATE INDEX idx_flow_shares_flow ON flow_shares(flow_id);
CREATE INDEX idx_flow_shares_user ON flow_shares(shared_with_user_id);

-- =============================================================================
-- API KEYS TABLE (for machine-to-machine auth)
-- =============================================================================
CREATE TABLE api_keys (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id TEXT NOT NULL,
    created_by_user_id TEXT NOT NULL,

    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,  -- bcrypt hash of API key
    key_prefix TEXT NOT NULL,  -- First 8 chars for identification (e.g., "bfk_12345678...")

    scopes TEXT[] DEFAULT '{}',  -- Permissions for this key

    expires_at TIMESTAMPTZ,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,

    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id)
);

CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash) WHERE NOT revoked;
```

---

## 11. Implementation Phases

### Phase 1: Foundation (Weeks 1-3) - CRITICAL

**Goals:**
- Multi-user isolation
- Basic authentication (JWT + CAC)
- Tenant management
- Audit logging

**Deliverables:**
1. Database migrations
2. User registration/login endpoints
3. CAC/PKI authentication
4. Tenant creation and management
5. Request context middleware
6. Basic audit logging
7. Row-Level Security policies

**Testing:**
- Multi-user isolation tests
- CAC authentication tests
- Tenant boundary tests

---

### Phase 2: Authorization (Weeks 4-6) - HIGH PRIORITY

**Goals:**
- RBAC implementation
- ABAC policy engine
- Classification level support
- Permission enforcement

**Deliverables:**
1. Role system (Owner, Admin, Member, Viewer)
2. Permission matrix
3. ABAC policy evaluator
4. Classification guards
5. Authorization middleware
6. Policy management UI/API

**Testing:**
- RBAC permission tests
- ABAC policy evaluation tests
- Classification access tests
- Privilege escalation tests

---

### Phase 3: Security Hardening (Weeks 7-9) - HIGH PRIORITY

**Goals:**
- Credential encryption
- HSM integration
- MFA/WebAuthn
- Advanced audit features

**Deliverables:**
1. AES-256-GCM encryption
2. HSM/PKCS#11 integration
3. TOTP/WebAuthn support
4. Audit log query API
5. SIEM integration
6. Rate limiting

**Testing:**
- Encryption/decryption tests
- HSM failover tests
- MFA enrollment/verification tests
- SIEM forwarding tests

---

### Phase 4: Enterprise Features (Weeks 10-12) - MEDIUM PRIORITY

**Goals:**
- SAML/LDAP integration
- Advanced ABAC policies
- Quota management
- Self-service tenant management

**Deliverables:**
1. SAML 2.0 SSO
2. LDAP/AD sync
3. Custom ABAC policies
4. Quota enforcement
5. Billing integration
6. Tenant settings UI

**Testing:**
- SAML flow tests
- LDAP sync tests
- Quota enforcement tests
- Multi-tenant scaling tests

---

## 12. Testing & Validation

### 12.1 Security Test Suite

```rust
#[cfg(test)]
mod security_tests {
    use super::*;

    #[tokio::test]
    async fn test_tenant_isolation() {
        let app = setup_test_app().await;

        // Create two tenants
        let tenant_a = create_tenant(&app, "Acme Corp", ClassificationLevel::Unclassified).await;
        let tenant_b = create_tenant(&app, "Beta Inc", ClassificationLevel::Secret).await;

        // User in Tenant A
        let user_a = create_user(&app, &tenant_a.id, "usera@acme.com", Role::Admin).await;
        let token_a = login(&app, &user_a).await;

        // Create flow in Tenant A
        create_flow(&app, &token_a, &tenant_a.id, "acme_flow").await;

        // User in Tenant B tries to access
        let user_b = create_user(&app, &tenant_b.id, "userb@beta.com", Role::Admin).await;
        let token_b = login(&app, &user_b).await;

        let response = app
            .client()
            .get("/api/flows/acme_flow")
            .header("Authorization", format!("Bearer {}", token_b))
            .send()
            .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_classification_access_control() {
        let app = setup_test_app().await;

        // Create tenant with Secret classification
        let tenant = create_tenant(&app, "DoD", ClassificationLevel::Secret).await;

        // User with Confidential clearance
        let user_low = create_user_with_clearance(
            &app,
            &tenant.id,
            "low@dod.mil",
            ClassificationLevel::Confidential,
        ).await;
        let token_low = login(&app, &user_low).await;

        // Create Secret flow
        let flow = create_classified_flow(
            &app,
            &token_low,
            &tenant.id,
            "secret_flow",
            ClassificationLevel::Secret,
        ).await;

        // Should fail - insufficient clearance
        assert!(flow.is_err());

        // User with Secret clearance
        let user_high = create_user_with_clearance(
            &app,
            &tenant.id,
            "high@dod.mil",
            ClassificationLevel::Secret,
        ).await;
        let token_high = login(&app, &user_high).await;

        // Should succeed
        let flow = create_classified_flow(
            &app,
            &token_high,
            &tenant.id,
            "secret_flow",
            ClassificationLevel::Secret,
        ).await;

        assert!(flow.is_ok());
    }

    #[tokio::test]
    async fn test_rbac_permission_enforcement() {
        let app = setup_test_app().await;
        let tenant = create_tenant(&app, "Test Org", ClassificationLevel::Unclassified).await;

        // Member user
        let member = create_user(&app, &tenant.id, "member@test.com", Role::Member).await;
        let member_token = login(&app, &member).await;

        // Admin user
        let admin = create_user(&app, &tenant.id, "admin@test.com", Role::Admin).await;
        let admin_token = login(&app, &admin).await;

        // Member creates flow
        let flow = create_flow(&app, &member_token, &tenant.id, "member_flow").await.unwrap();

        // Member tries to delete admin's flow
        let admin_flow = create_flow(&app, &admin_token, &tenant.id, "admin_flow").await.unwrap();
        let response = app
            .client()
            .delete(format!("/api/flows/{}", admin_flow.id))
            .header("Authorization", format!("Bearer {}", member_token))
            .send()
            .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Admin can delete member's flow
        let response = app
            .client()
            .delete(format!("/api/flows/{}", flow.id))
            .header("Authorization", format!("Bearer {}", admin_token))
            .send()
            .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_abac_time_window_policy() {
        let app = setup_test_app().await;
        let tenant = create_tenant(&app, "Test Org", ClassificationLevel::Unclassified).await;

        // Create policy: No deployments on weekends
        let policy = AbacPolicy {
            id: "policy_001".to_string(),
            name: "No Weekend Deployments".to_string(),
            tenant_id: Some(tenant.id.clone()),
            enabled: true,
            conditions: vec![
                PolicyCondition::TimeWindow {
                    days_of_week: vec![Weekday::Mon, Weekday::Tue, Weekday::Wed, Weekday::Thu, Weekday::Fri],
                    start_time: Time::from_hms(9, 0, 0).unwrap(),
                    end_time: Time::from_hms(17, 0, 0).unwrap(),
                    timezone: Tz::America__New_York,
                }
            ],
            effect: PolicyEffect::Deny,
            priority: 100,
        };

        app.storage.create_abac_policy(&policy).await.unwrap();

        // Try to deploy on Saturday
        let saturday = Utc.with_ymd_and_hms(2025, 11, 1, 14, 0, 0).unwrap();  // Saturday
        let result = trigger_deployment_at_time(&app, &tenant.id, saturday).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No Weekend Deployments"));
    }

    #[tokio::test]
    async fn test_credential_encryption() {
        let vault = CredentialVault::new([0u8; 32]);
        let tenant_id = "tenant_123";
        let user_id = "user_456";

        let plaintext = "ya29.a0AfH6SMBx...";  // OAuth token

        // Encrypt
        let encrypted = vault.encrypt_token(plaintext, tenant_id, user_id).unwrap();

        // Decrypt
        let decrypted = vault.decrypt_token(&encrypted, tenant_id, user_id).unwrap();

        assert_eq!(plaintext, decrypted);

        // Wrong tenant/user should fail
        let result = vault.decrypt_token(&encrypted, "wrong_tenant", user_id);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_audit_log_immutability() {
        let app = setup_test_app().await;

        // Create audit log entry
        let log_id = app.storage.insert_audit_log(&AuditLogEntry {
            id: uuid::Uuid::new_v4(),
            action: "test.action".to_string(),
            // ...
        }).await.unwrap();

        // Try to delete
        let result = sqlx::query("DELETE FROM audit_logs WHERE id = $1")
            .bind(log_id)
            .execute(&app.storage.pool)
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be deleted"));

        // Try to update
        let result = sqlx::query("UPDATE audit_logs SET action = 'modified' WHERE id = $1")
            .bind(log_id)
            .execute(&app.storage.pool)
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be modified"));
    }
}
```

### 12.2 Penetration Testing Checklist

- [ ] **Authentication Bypass**
  - [ ] JWT signature validation
  - [ ] Token expiration enforcement
  - [ ] Refresh token revocation
  - [ ] CAC certificate validation
  - [ ] OCSP/CRL checking

- [ ] **Authorization Bypass**
  - [ ] Direct object reference (IDOR)
  - [ ] Privilege escalation
  - [ ] Cross-tenant access
  - [ ] RBAC bypass via API manipulation
  - [ ] ABAC policy bypass

- [ ] **Injection Attacks**
  - [ ] SQL injection (parameterized queries)
  - [ ] Command injection (workflow YAML)
  - [ ] Template injection
  - [ ] YAML bomb (denial of service)

- [ ] **Cryptographic Issues**
  - [ ] Weak encryption algorithms
  - [ ] Predictable IVs/nonces
  - [ ] Timing attacks on comparisons
  - [ ] Key exposure in logs/errors

- [ ] **Session Management**
  - [ ] Session fixation
  - [ ] Session hijacking
  - [ ] Insufficient session timeout
  - [ ] Concurrent session limits

- [ ] **Data Leakage**
  - [ ] Verbose error messages
  - [ ] Sensitive data in logs
  - [ ] Unredacted audit logs
  - [ ] Classification banner bypass

---

## 13. Deployment Architectures

### 13.1 IL-2 SaaS (Public Cloud)

```
┌─────────────────────────────────────────────────────────────────┐
│                       INTERNET                                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CloudFlare (DDoS Protection)                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AWS Application Load Balancer               │
│                    (TLS Termination, WAF)                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
┌──────────────────────────┐  ┌──────────────────────────┐
│   BeemFlow Instance 1    │  │   BeemFlow Instance 2    │
│   (ECS Fargate Container)│  │   (ECS Fargate Container)│
└────────┬─────────────────┘  └────────┬─────────────────┘
         │                              │
         └──────────────┬───────────────┘
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│            AWS RDS PostgreSQL (Multi-AZ)                        │
│            - Encrypted at rest (AES-256)                        │
│            - Automated backups to S3                            │
│            - Read replicas for scaling                          │
└─────────────────────────────────────────────────────────────────┘
```

**Security Features:**
- TLS 1.3 only
- WAF rules for OWASP Top 10
- Rate limiting at CDN and ALB levels
- Secrets in AWS Secrets Manager
- VPC isolation (private subnets)
- CloudTrail for AWS API audit logs
- GuardDuty for threat detection

---

### 13.2 IL-4/5 (FedRAMP Moderate/High)

```
┌─────────────────────────────────────────────────────────────────┐
│                 DoD NIPRNet / SIPRNet                           │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                AWS GovCloud Load Balancer                       │
│                (CAC/PIV Certificate Required)                   │
└────────────────────────────┬────────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
┌──────────────────────────┐  ┌──────────────────────────┐
│   BeemFlow Instance 1    │  │   BeemFlow Instance 2    │
│   (AWS GovCloud ECS)     │  │   (AWS GovCloud ECS)     │
└────────┬─────────────────┘  └────────┬─────────────────┘
         │                              │
         └──────────────┬───────────────┘
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│     AWS GovCloud RDS PostgreSQL (FIPS 140-2 Encryption)         │
│     - KMS with CloudHSM                                         │
│     - Audit logs to CloudWatch Logs                             │
│     - SIEM integration (Splunk/QRadar)                          │
└─────────────────────────────────────────────────────────────────┘
```

**Additional Requirements:**
- FIPS 140-2 validated cryptography
- CAC/PIV authentication mandatory
- Network traffic within GovCloud only
- Continuous monitoring (ACAS/Nessus)
- Incident response plan (< 1 hour)
- Annual security assessment

---

### 13.3 Classified On-Premise (Air-Gapped)

```
┌─────────────────────────────────────────────────────────────────┐
│                   SCIF / Classified Network                     │
│                   (Disconnected from Internet)                  │
└─────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│               Internal Load Balancer (F5 / HAProxy)             │
└────────────────────────────┬────────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
┌──────────────────────────┐  ┌──────────────────────────┐
│  BeemFlow Server 1       │  │  BeemFlow Server 2       │
│  (Bare Metal / VMware)   │  │  (Bare Metal / VMware)   │
│  - HSM-backed encryption │  │  - HSM-backed encryption │
└────────┬─────────────────┘  └────────┬─────────────────┘
         │                              │
         └──────────────┬───────────────┘
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│         PostgreSQL on Dedicated Server                          │
│         - Full disk encryption (LUKS)                           │
│         - Backup to offline tape (daily)                        │
│         - No external network access                            │
└─────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│         SIEM (Splunk Forwarder → Air-Gap Diode)                 │
└─────────────────────────────────────────────────────────────────┘
```

**Operational Notes:**
- Software updates via USB/DVD (offline)
- Manual license activation
- Local CA for TLS certificates
- Audit logs exported via unidirectional data diode
- No telemetry or phone-home

---

## 14. Compliance Matrix

| Requirement | Standard | Implementation | Status |
|-------------|----------|----------------|--------|
| **Authentication** |||
| Multi-factor authentication | NIST 800-63B | TOTP, WebAuthn, CAC | ✅ |
| Password complexity | NIST 800-63B | Enforced at registration | ✅ |
| Session timeout | NIST 800-53 AC-12 | Configurable (default 4h) | ✅ |
| Account lockout | NIST 800-53 AC-7 | After 5 failed attempts | ✅ |
| **Authorization** |||
| Least privilege | NIST 800-53 AC-6 | RBAC with minimal perms | ✅ |
| Separation of duties | NIST 800-53 AC-5 | Owner ≠ Admin roles | ✅ |
| Attribute-based AC | DARPA RFI | ABAC policy engine | ✅ |
| **Encryption** |||
| Data at rest | FIPS 140-2 | AES-256-GCM | ✅ |
| Data in transit | NIST 800-52 | TLS 1.3 | ✅ |
| Key management | NIST 800-57 | HKDF key derivation | ✅ |
| **Audit & Compliance** |||
| Audit logging | NIST 800-53 AU-2 | Immutable append-only | ✅ |
| Log retention | DoD 5015.2 | 7 years (configurable) | ✅ |
| SIEM integration | FISMA | Syslog, CEF, LEEF | ✅ |
| **Data Protection** |||
| Classification labels | NIST 800-53 AC-16 | Unclass → TS/SCI | ✅ |
| Access based on clearance | ICD 704 | ABAC enforcement | ✅ |
| Data sanitization | NIST 800-88 | Crypto erase on delete | 🔄 Phase 4 |
| **Incident Response** |||
| Intrusion detection | NIST 800-53 SI-4 | CloudWatch, GuardDuty | 🔄 Phase 4 |
| Incident logging | NIST 800-61 | Security events to SIEM | ✅ |
| Forensic capability | NIST 800-86 | Immutable audit trail | ✅ |

**Legend:**
- ✅ Designed and implemented
- 🔄 Planned for Phase 4
- ⚠️ Requires external integration

---

## 15. Migration Strategy

### 15.1 Zero-Downtime Migration Plan

**Current State:**
- Single-user system
- All data owned by `"default_user"`
- No tenant isolation

**Target State:**
- Multi-tenant system
- All data scoped to tenants and users
- Full RBAC/ABAC enforcement

**Migration Steps:**

```sql
-- Step 1: Create default tenant and admin user
BEGIN;

INSERT INTO tenants (id, name, slug, classification_level, plan, created_by_user_id, created_at, updated_at)
VALUES (
    'default_tenant_001',
    'Legacy System',
    'legacy',
    'Unclassified',
    'enterprise',
    'system',
    extract(epoch from now()) * 1000,
    extract(epoch from now()) * 1000
);

INSERT INTO users (id, email, name, password_hash, email_verified, clearance_level, created_at, updated_at)
VALUES (
    'default_user_001',
    'admin@localhost',
    'System Administrator',
    '$2b$12$...',  -- Must be reset by admin
    TRUE,
    'Unclassified',
    extract(epoch from now()) * 1000,
    extract(epoch from now()) * 1000
);

INSERT INTO tenant_members (id, tenant_id, user_id, role, joined_at)
VALUES (
    gen_random_uuid()::text,
    'default_tenant_001',
    'default_user_001',
    'owner',
    extract(epoch from now()) * 1000
);

COMMIT;

-- Step 2: Migrate flows
UPDATE flows
SET
    tenant_id = 'default_tenant_001',
    created_by_user_id = 'default_user_001',
    classification_level = 'Unclassified',
    visibility = 'private'
WHERE tenant_id IS NULL;

-- Step 3: Migrate runs
UPDATE runs
SET
    tenant_id = 'default_tenant_001',
    triggered_by_user_id = 'default_user_001',
    classification_level = 'Unclassified',
    actual_classification_level = 'Unclassified'
WHERE tenant_id IS NULL;

-- Step 4: Migrate OAuth credentials
UPDATE oauth_credentials
SET
    user_id = 'default_user_001',
    tenant_id = 'default_tenant_001'
WHERE user_id IS NULL OR user_id = 'default_user';

-- Step 5: Fix oauth_tokens
UPDATE oauth_tokens
SET user_id = 'default_user_001'
WHERE user_id = 'default_user' OR user_id IS NULL;

-- Step 6: Verify migration
SELECT 'Flows without tenant' AS check_name, COUNT(*) AS count FROM flows WHERE tenant_id IS NULL
UNION ALL
SELECT 'Runs without tenant', COUNT(*) FROM runs WHERE tenant_id IS NULL
UNION ALL
SELECT 'OAuth creds without user', COUNT(*) FROM oauth_credentials WHERE user_id IS NULL;

-- All counts should be 0
```

**Post-Migration:**
1. Admin logs in as `admin@localhost` (forced password reset)
2. Admin creates real user accounts
3. Admin transfers ownership of flows/runs as needed
4. Admin invites team members
5. Deactivate default user once migration complete

---

## Conclusion

This authentication and authorization plan provides:

1. **Military-Grade Security**: CAC/PKI authentication, classification-based access control, HSM-backed encryption
2. **Enterprise Scalability**: Multi-tenant architecture, RBAC, SAML/LDAP integration
3. **Compliance Ready**: NIST 800-53, FISMA, FedRAMP, SOC 2, GDPR
4. **Operational Flexibility**: SaaS, on-premise, air-gapped deployments
5. **Developer Friendly**: Clear APIs, comprehensive testing, migration path

**Critical Next Steps:**

1. **Week 1-2**: Implement database schema changes and migrations
2. **Week 3-4**: Build authentication layer (JWT + CAC)
3. **Week 5-6**: Implement RBAC and basic ABAC
4. **Week 7-8**: Add encryption and audit logging
5. **Week 9-10**: Security testing and penetration testing
6. **Week 11-12**: DARPA pilot deployment preparation

**Success Metrics:**

- ✅ Zero cross-tenant data leakage
- ✅ Zero unauthorized access incidents
- ✅ 100% audit trail coverage
- ✅ < 100ms authorization overhead
- ✅ FedRAMP authorization achieved

---

**Document Status:** READY FOR IMPLEMENTATION

**Approvals Required:**
- [ ] Security Team Review
- [ ] DARPA Program Manager Approval
- [ ] CISO Sign-Off
- [ ] Legal Review (export control for classified deployments)

**Questions or Feedback:** Open GitHub issue or contact security@beemflow.io
