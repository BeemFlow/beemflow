# BeemFlow DARPA Phase: Government-Grade Security & Classification

**Status:** Ready for Implementation
**Prerequisites:** [AUTH_SAAS_PHASE.md](AUTH_SAAS_PHASE.md) must be completed first
**Target:** DARPA IL-2/IL-4/IL-5, Classified On-Premise, FedRAMP Authorization
**Timeline:** 4-5 weeks

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [DARPA Requirements Mapping](#darpa-requirements-mapping)
3. [Architecture Overview](#architecture-overview)
4. [Implementation Roadmap](#implementation-roadmap)
5. [Step 1: Classification Levels](#step-1-classification-levels)
6. [Step 2: CAC/PKI Authentication](#step-2-cacpki-authentication)
7. [Step 3: ABAC Policy Engine](#step-3-abac-policy-engine)
8. [Step 4: SAML/LDAP Integration](#step-4-samlldap-integration)
9. [Step 5: HSM Integration](#step-5-hsm-integration)
10. [Step 6: SIEM Integration](#step-6-siem-integration)
11. [Step 7: WebAuthn/FIDO2](#step-7-webauthfido2)
12. [Step 8: Air-Gapped Deployment](#step-8-air-gapped-deployment)
13. [Step 9: Advanced Audit](#step-9-advanced-audit)
14. [Step 10: Compliance & Testing](#step-10-compliance--testing)
15. [Deployment Architectures](#deployment-architectures)
16. [Security Validation](#security-validation)

---

## Executive Summary

### Prerequisites

✅ **SaaS Phase Complete** - Must have:
- Multi-tenant architecture with organizations
- JWT authentication and RBAC
- User-scoped OAuth credentials
- Audit logging infrastructure
- PostgreSQL with Row-Level Security

### DARPA Requirements

This phase implements the following DARPA RFI requirements:

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| **a) IL-2 SaaS (Internet)** | ✅ Completed in SaaS phase | Complete |
| **b) IL-4/5 SaaS (CUI)** | CAC/PKI auth, FIPS 140-2 encryption, TLS 1.3 | This Phase |
| **c) Classified On-Premise** | Air-gapped, offline validation, LDAP | This Phase |
| **d) Fine-grained ABAC** | Classification-based, time-based, attribute policies | This Phase |
| **e) CSSP Audit Logging** | Real-time SIEM export, immutable logs | This Phase |
| CAC-enabled PDF signing | PKI signature via HSM | This Phase |
| Digital certificate workflows | X.509 signature validation | This Phase |
| External data connectivity | Already supported (http.fetch, sql.query) | Complete |

### Implementation Timeline

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| **Classification** | 3 days | Classification levels, banners, guards |
| **CAC/PKI** | 5 days | Certificate auth, OCSP validation |
| **ABAC** | 4 days | Policy engine, evaluation |
| **SAML/LDAP** | 3 days | Enterprise SSO integration |
| **HSM** | 5 days | PKCS#11, hardware-backed keys |
| **SIEM** | 3 days | Real-time CEF/LEEF export |
| **WebAuthn** | 2 days | Hardware security keys |
| **Air-Gap** | 3 days | Offline deployment, manual updates |
| **Testing** | 5 days | Security audit, penetration testing |
| **Total** | **4-5 weeks** | FedRAMP-ready deployment |

### New Capabilities

After this phase, BeemFlow will support:

✅ **Classification-Based Access Control** - Unclassified → TS/SCI
✅ **CAC/PIV Authentication** - DoD Common Access Card
✅ **FIPS 140-2 Encryption** - HSM-backed key storage
✅ **Air-Gapped Deployment** - No internet connectivity required
✅ **SIEM Integration** - Real-time security event export
✅ **FedRAMP Authorization** - IL-4/5 compliance
✅ **Offline Operations** - Manual update packages

---

## DARPA Requirements Mapping

### Minimum Capabilities (From RFI)

**a) IL-2 SaaS (Public Internet)**
- ✅ Already implemented in SaaS phase
- JWT authentication with refresh tokens
- Public webhook endpoints with HMAC verification
- TLS 1.3 encryption in transit

**b) IL-4/5 SaaS (CUI Environment)**
- ⚙️ CAC/PKI authentication (this phase)
- ⚙️ FIPS 140-2 validated cryptography (HSM)
- ⚙️ AES-256-GCM encryption at rest
- ✅ Existing provisional authorization path (FedRAMP)
- ⚙️ Bi-directional communication with IL-2 (API gateways)

**c) Classified Disconnected On-Premise**
- ⚙️ Air-gapped deployment support
- ⚙️ Offline license validation
- ⚙️ Manual update packages
- ⚙️ LDAP/Active Directory integration

**d) Fine-Grained ABAC**
- ⚙️ User clearance level checks
- ⚙️ Resource classification enforcement
- ⚙️ Time-based access policies
- ⚙️ IP address/location restrictions
- ✅ CRUD permission framework (RBAC base)

**e) CSSP Audit Logging**
- ✅ Immutable audit logs (SaaS phase)
- ⚙️ Real-time SIEM export (this phase)
- ⚙️ CEF/LEEF format support
- ⚙️ Forensic query API for CSSP

### Mandatory Requirements

**✅ CAC-enabled PDF signing** - Via `openssl_pki.sign` tool with HSM
**✅ Digital certificate approvals** - `approval` block with X.509 validation
**✅ Group-based routing** - `assignee: group:legal_team` with LDAP sync
**✅ Ad-hoc workflow modifications** - Dynamic step injection API
**✅ External data sources** - HTTP, SQL, GraphQL adapters
**✅ Drafts during workflow** - Paused runs with resume tokens

---

## Architecture Overview

### Classification Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                    CLASSIFICATION LEVELS                        │
└─────────────────────────────────────────────────────────────────┘

Level 0: UNCLASSIFIED
    ↓ (Accessible to all users)
Level 1: CUI (Controlled Unclassified Information)
    ↓ (Requires CUI clearance)
Level 2: CONFIDENTIAL (DoD)
    ↓ (Requires Confidential clearance)
Level 3: SECRET (DoD)
    ↓ (Requires Secret clearance)
Level 4: TOP SECRET (DoD)
    ↓ (Requires Top Secret clearance)
Level 5: TOP SECRET//SCI (Sensitive Compartmented Information)
    ↓ (Requires TS/SCI clearance + need-to-know)

Authorization Rule: user.clearance >= resource.classification
```

### CAC Authentication Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    CAC AUTHENTICATION FLOW                      │
└─────────────────────────────────────────────────────────────────┘

1. TLS Handshake
   Client → Server: ClientHello
   Server → Client: Certificate Request (X.509 client cert required)
   Client → Server: CAC Certificate (PIV credentials)

2. Certificate Validation
   ├─ Parse X.509 certificate
   ├─ Validate chain to DoD Root CA
   ├─ Check OCSP (Online Certificate Status Protocol)
   ├─ Check CRL (Certificate Revocation List)
   └─ Extract user identity (Subject DN, EDI-PI)

3. User Mapping
   ├─ Query: SELECT * FROM users WHERE certificate_dn = ?
   ├─ OR: Auto-provision from certificate attributes
   └─ Extract clearance level from certificate OU field

4. Session Creation
   ├─ Generate session token (database-backed, not JWT)
   ├─ Store: user_id, clearance_level, cert_serial
   └─ Return secure cookie (HttpOnly, Secure, SameSite)

5. Subsequent Requests
   ├─ Validate session from database
   ├─ Re-verify certificate serial (not revoked)
   └─ Inject RequestContext with clearance level
```

### ABAC Policy Evaluation

```
┌─────────────────────────────────────────────────────────────────┐
│              AUTHORIZATION DECISION PROCESS                     │
└─────────────────────────────────────────────────────────────────┘

Request: User A wants to deploy flow "classified_workflow"

Step 1: RBAC Check (Base Permission)
    ├─ User role: Member
    ├─ Required permission: FlowsDeploy
    └─ ✅ Member has FlowsDeploy permission

Step 2: Ownership Check
    ├─ Flow created_by: User A
    ├─ User ID: User A
    └─ ✅ User owns the resource

Step 3: ABAC Policy Evaluation (Priority Order)
    ┌────────────────────────────────────────────────────────┐
    │ Policy 1: Classification Access Control (Priority 100) │
    ├────────────────────────────────────────────────────────┤
    │ Condition: resource.classification <= user.clearance   │
    │ Resource classification: SECRET                        │
    │ User clearance: CONFIDENTIAL                           │
    │ Result: ❌ DENY - Insufficient clearance              │
    └────────────────────────────────────────────────────────┘

Final Decision: ❌ DENIED
Reason: "User clearance (CONFIDENTIAL) insufficient for SECRET resource"
```

---

## Implementation Roadmap

### Step-by-Step Checklist

- [ ] **Step 1:** Classification levels (3 days)
  - [ ] Classification enum and types
  - [ ] Database schema updates
  - [ ] Classification guards
  - [ ] UI banners

- [ ] **Step 2:** CAC/PKI authentication (5 days)
  - [ ] X.509 certificate parsing
  - [ ] OCSP/CRL validation
  - [ ] User provisioning from certs
  - [ ] Session management

- [ ] **Step 3:** ABAC policy engine (4 days)
  - [ ] Policy data model
  - [ ] Policy evaluator
  - [ ] Condition types
  - [ ] Management API

- [ ] **Step 4:** SAML/LDAP integration (3 days)
  - [ ] SAML 2.0 SP implementation
  - [ ] LDAP client
  - [ ] Group sync
  - [ ] SSO endpoints

- [ ] **Step 5:** HSM integration (5 days)
  - [ ] PKCS#11 interface
  - [ ] Key generation
  - [ ] Encryption/decryption
  - [ ] Signature operations

- [ ] **Step 6:** SIEM integration (3 days)
  - [ ] CEF formatter
  - [ ] LEEF formatter
  - [ ] Syslog client
  - [ ] Real-time export

- [ ] **Step 7:** WebAuthn/FIDO2 (2 days)
  - [ ] Registration flow
  - [ ] Authentication flow
  - [ ] Credential management

- [ ] **Step 8:** Air-gapped deployment (3 days)
  - [ ] Offline license validation
  - [ ] Manual update packages
  - [ ] No-internet mode

- [ ] **Step 9:** Advanced audit (2 days)
  - [ ] CSSP query API
  - [ ] Export formats
  - [ ] Forensic tools

- [ ] **Step 10:** Compliance & testing (5 days)
  - [ ] Security audit
  - [ ] Penetration testing
  - [ ] FedRAMP documentation

---

## Step 1: Classification Levels

### Classification Types

**File: `src/auth/classification.rs` (NEW)**

```rust
//! Classification level support for government/defense deployments

use serde::{Deserialize, Serialize};
use std::fmt;

/// Classification levels following DoD/IC standards
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ClassificationLevel {
    /// Public information (Level 0)
    Unclassified = 0,

    /// Controlled Unclassified Information (Level 1)
    /// Federal: CUI Basic, CUI Specified
    /// DoD: FOUO (For Official Use Only)
    #[serde(rename = "CUI")]
    CUI = 1,

    /// DoD Confidential (Level 2)
    /// Could cause damage to national security
    Confidential = 2,

    /// DoD Secret (Level 3)
    /// Could cause serious damage to national security
    Secret = 3,

    /// DoD Top Secret (Level 4)
    /// Could cause exceptionally grave damage
    #[serde(rename = "TOP SECRET")]
    TopSecret = 4,

    /// Top Secret / Sensitive Compartmented Information (Level 5)
    /// Requires TS clearance + specific compartment access
    #[serde(rename = "TOP SECRET//SCI")]
    TopSecretSCI = 5,
}

impl ClassificationLevel {
    /// Check if user can access resource at this classification
    pub fn can_access(&self, user_clearance: ClassificationLevel) -> bool {
        user_clearance >= *self
    }

    /// Classification marking for display/banners
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

    /// Banner color for UI (NIST/DoD standard colors)
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

    /// Portion marking for inline classification
    pub fn portion_marking(&self) -> &'static str {
        match self {
            ClassificationLevel::Unclassified => "(U)",
            ClassificationLevel::CUI => "(CUI)",
            ClassificationLevel::Confidential => "(C)",
            ClassificationLevel::Secret => "(S)",
            ClassificationLevel::TopSecret => "(TS)",
            ClassificationLevel::TopSecretSCI => "(TS//SCI)",
        }
    }

    /// Parse from string (case-insensitive)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "UNCLASSIFIED" | "U" => Some(Self::Unclassified),
            "CUI" => Some(Self::CUI),
            "CONFIDENTIAL" | "C" => Some(Self::Confidential),
            "SECRET" | "S" => Some(Self::Secret),
            "TOP SECRET" | "TS" => Some(Self::TopSecret),
            "TOP SECRET//SCI" | "TS//SCI" => Some(Self::TopSecretSCI),
            _ => None,
        }
    }
}

impl fmt::Display for ClassificationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.marking())
    }
}

impl Default for ClassificationLevel {
    fn default() -> Self {
        Self::Unclassified
    }
}
```

### Update Data Models

**File: `src/auth/types.rs` (MODIFY)**

Add classification to User and resource types:

```rust
// Add to User struct (after line 20):
pub clearance_level: ClassificationLevel,

// Add to Tenant struct:
pub classification_level: ClassificationLevel,

// Add to RequestContext:
pub clearance_level: ClassificationLevel,
```

**File: `src/model.rs` (MODIFY)**

Add classification to Run and Flow:

```rust
// Add to Run struct (around line 200):
pub classification_level: ClassificationLevel,
/// Actual classification may increase during execution (high-water mark)
pub actual_classification: ClassificationLevel,

// Add to Flow (if using database-backed flows):
pub classification_level: ClassificationLevel,
```

### Database Schema

**File: `migrations/postgres/20250101000004_classification.sql` (NEW)**

```sql
-- Add classification support

-- Users table: Add clearance level
ALTER TABLE users ADD COLUMN clearance_level TEXT DEFAULT 'Unclassified';
CREATE INDEX idx_users_clearance ON users(clearance_level);

-- Tenants table: Add classification level
ALTER TABLE tenants ADD COLUMN classification_level TEXT DEFAULT 'Unclassified';
CREATE INDEX idx_tenants_classification ON tenants(classification_level);

-- Runs table: Add classification tracking
ALTER TABLE runs ADD COLUMN classification_level TEXT DEFAULT 'Unclassified';
ALTER TABLE runs ADD COLUMN actual_classification TEXT DEFAULT 'Unclassified';
CREATE INDEX idx_runs_classification ON runs(classification_level);

-- Flows table: Add classification
ALTER TABLE flows ADD COLUMN classification_level TEXT DEFAULT 'Unclassified';
CREATE INDEX idx_flows_classification ON flows(classification_level);

-- OAuth credentials: Inherit user's clearance
ALTER TABLE oauth_credentials ADD COLUMN max_classification TEXT DEFAULT 'Unclassified';
```

### Classification Guards

**File: `src/auth/classification.rs` (continued)**

```rust
/// Check if user can access classified resource
pub fn check_classification_access(
    user_clearance: ClassificationLevel,
    resource_classification: ClassificationLevel,
) -> Result<(), crate::BeemFlowError> {
    if user_clearance < resource_classification {
        return Err(crate::BeemFlowError::OAuth(format!(
            "Insufficient clearance: user has {}, resource requires {}",
            user_clearance.marking(),
            resource_classification.marking()
        )));
    }
    Ok(())
}

/// High-water mark tracking for workflow execution
pub struct ClassificationTracker {
    initial: ClassificationLevel,
    current: ClassificationLevel,
}

impl ClassificationTracker {
    pub fn new(initial: ClassificationLevel) -> Self {
        Self {
            initial,
            current: initial,
        }
    }

    /// Update to highest classification seen
    pub fn observe(&mut self, level: ClassificationLevel) {
        if level > self.current {
            tracing::warn!(
                "Classification escalation: {} → {}",
                self.current.marking(),
                level.marking()
            );
            self.current = level;
        }
    }

    /// Get current highest classification
    pub fn current(&self) -> ClassificationLevel {
        self.current
    }

    /// Check if classification increased during execution
    pub fn escalated(&self) -> bool {
        self.current > self.initial
    }
}
```

### HTTP Classification Banner Middleware

**File: `src/http/middleware.rs` (ADD)**

```rust
/// Add classification banners to HTTP responses
pub async fn classification_banner_middleware(
    Extension(ctx): Extension<RequestContext>,
    req: Request,
    next: Next,
) -> Response {
    let mut response = next.run(req).await;

    let classification = ctx.clearance_level;

    // Add headers
    response.headers_mut().insert(
        "X-Classification-Level",
        classification.marking().parse().unwrap(),
    );

    response.headers_mut().insert(
        "X-Classification-Color",
        classification.banner_color().parse().unwrap(),
    );

    response.headers_mut().insert(
        "X-Classification-Marking",
        classification.portion_marking().parse().unwrap(),
    );

    // For HTML responses, inject banner div
    // (Implementation would stream and modify HTML)

    response
}
```

---

## Step 2: CAC/PKI Authentication

### Dependencies

**File: `Cargo.toml` (ADD)**

```toml
[dependencies]
# X.509 certificate parsing
x509-parser = "0.15"
rustls = { version = "0.21", features = ["dangerous_configuration"] }
rustls-pemfile = "1.0"

# OCSP validation
reqwest = { version = "0.11", features = ["rustls-tls"] }

# Certificate operations
openssl = "0.10"
```

### CAC Authenticator

**File: `src/auth/cac.rs` (NEW)**

```rust
//! Common Access Card (CAC) / Personal Identity Verification (PIV) authentication

use crate::auth::classification::ClassificationLevel;
use crate::auth::types::User;
use crate::storage::AuthStorage;
use crate::{BeemFlowError, Result};
use std::sync::Arc;
use x509_parser::prelude::*;

pub struct CacAuthenticator {
    /// DoD Root CA certificates (loaded from trust store)
    trusted_roots: Vec<Vec<u8>>,
    /// OCSP responder URL
    ocsp_responder: String,
    /// CRL cache (updated periodically)
    crl_cache: Arc<parking_lot::RwLock<CertificateRevocationList>>,
    /// Auto-provision new users from valid CAC?
    auto_provision: bool,
    /// Storage for user lookup/creation
    storage: Arc<dyn AuthStorage>,
}

#[derive(Debug)]
pub struct AuthenticatedCacUser {
    pub user_id: String,
    pub email: String,
    pub name: String,
    pub clearance_level: ClassificationLevel,
    pub certificate_dn: String,
    pub certificate_serial: String,
}

impl CacAuthenticator {
    pub fn new(
        ocsp_responder: String,
        auto_provision: bool,
        storage: Arc<dyn AuthStorage>,
    ) -> Self {
        Self {
            trusted_roots: load_dod_root_cas(),
            ocsp_responder,
            crl_cache: Arc::new(parking_lot::RwLock::new(CertificateRevocationList::new())),
            auto_provision,
            storage,
        }
    }

    /// Authenticate user from CAC certificate
    pub async fn authenticate(&self, cert_der: &[u8]) -> Result<AuthenticatedCacUser> {
        // 1. Parse certificate
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|_| BeemFlowError::OAuth("Invalid certificate".into()))?;

        // 2. Validate chain to DoD root CA
        self.validate_chain(&cert)?;

        // 3. Check revocation (OCSP + CRL)
        self.check_revocation(&cert).await?;

        // 4. Extract identity
        let subject_dn = cert.subject().to_string();
        let email = self.extract_email(&cert)?;
        let name = self.extract_name(&cert)?;
        let edi_pi = self.extract_edi_pi(&cert)?;

        // 5. Extract clearance level
        let clearance = self.extract_clearance(&cert)?;

        // 6. Map to user account
        let user = self.storage
            .get_user_by_certificate_dn(&subject_dn)
            .await?
            .or_else(|| {
                if self.auto_provision {
                    Some(self.provision_user(
                        &email,
                        &name,
                        &subject_dn,
                        &cert.serial.to_string(),
                        clearance,
                    ).await.ok()?)
                } else {
                    None
                }
            })
            .ok_or_else(|| BeemFlowError::OAuth("User not found and auto-provision disabled".into()))?;

        Ok(AuthenticatedCacUser {
            user_id: user.id,
            email,
            name,
            clearance_level: clearance,
            certificate_dn: subject_dn,
            certificate_serial: cert.serial.to_string(),
        })
    }

    fn validate_chain(&self, cert: &X509Certificate) -> Result<()> {
        // Verify certificate chain to DoD root CA
        // (Simplified - full implementation would use openssl or rustls)

        let issuer = cert.issuer().to_string();

        // Check if issued by known DoD CA
        let known_issuers = [
            "CN=DOD ID CA-",
            "CN=DoD Root CA",
            "CN=DOD SW CA-",
        ];

        if !known_issuers.iter().any(|ca| issuer.contains(ca)) {
            return Err(BeemFlowError::OAuth(format!(
                "Certificate not issued by DoD CA: {}",
                issuer
            )));
        }

        // Verify signature (simplified)
        // Full implementation would validate entire chain

        Ok(())
    }

    async fn check_revocation(&self, cert: &X509Certificate) -> Result<()> {
        // 1. OCSP check (real-time)
        let ocsp_response = self.query_ocsp(cert).await?;
        if ocsp_response.status != OcspStatus::Good {
            return Err(BeemFlowError::OAuth("Certificate revoked (OCSP)".into()));
        }

        // 2. CRL check (cached, fallback)
        let crl = self.crl_cache.read();
        if crl.is_revoked(&cert.serial.to_string()) {
            return Err(BeemFlowError::OAuth("Certificate revoked (CRL)".into()));
        }

        Ok(())
    }

    async fn query_ocsp(&self, cert: &X509Certificate) -> Result<OcspResponse> {
        // Query OCSP responder
        // Simplified - full implementation would use proper OCSP protocol

        let client = reqwest::Client::new();
        let response = client
            .post(&self.ocsp_responder)
            .body(create_ocsp_request(cert))
            .send()
            .await
            .map_err(|e| BeemFlowError::Network(e))?;

        if response.status().is_success() {
            Ok(OcspResponse {
                status: OcspStatus::Good,
            })
        } else {
            Ok(OcspResponse {
                status: OcspStatus::Unknown,
            })
        }
    }

    fn extract_email(&self, cert: &X509Certificate) -> Result<String> {
        // Extract email from SAN extension
        if let Some(san) = cert.subject_alternative_name() {
            for name in &san.value.general_names {
                if let x509_parser::extensions::GeneralName::RFC822Name(email) = name {
                    return Ok(email.to_string());
                }
            }
        }

        Err(BeemFlowError::OAuth("No email in certificate".into()))
    }

    fn extract_name(&self, cert: &X509Certificate) -> Result<String> {
        // Extract CN from subject
        let subject = cert.subject();
        for attr in subject.iter_common_name() {
            if let Ok(cn) = attr.as_str() {
                // CAC format: "LAST.FIRST.MIDDLE.ID"
                let parts: Vec<&str> = cn.split('.').collect();
                if parts.len() >= 2 {
                    return Ok(format!("{} {}", parts[1], parts[0]));
                }
                return Ok(cn.to_string());
            }
        }

        Err(BeemFlowError::OAuth("No CN in certificate".into()))
    }

    fn extract_edi_pi(&self, cert: &X509Certificate) -> Result<String> {
        // EDI-PI (DoD unique identifier) from SAN or CN
        // Format: 10-digit number

        let subject = cert.subject().to_string();

        // Extract from CN (last component)
        if let Some(cn) = subject.split("CN=").nth(1) {
            let parts: Vec<&str> = cn.split('.').collect();
            if let Some(last) = parts.last() {
                if last.len() == 10 && last.chars().all(|c| c.is_numeric()) {
                    return Ok(last.to_string());
                }
            }
        }

        Err(BeemFlowError::OAuth("No EDI-PI in certificate".into()))
    }

    fn extract_clearance(&self, cert: &X509Certificate) -> Result<ClassificationLevel> {
        // Extract from OU field in subject
        // Example: "O=U.S. Government, OU=DoD, OU=PKI, OU=Secret"

        let subject = cert.subject().to_string();

        if subject.contains("OU=Top Secret") || subject.contains("OU=TS") {
            Ok(ClassificationLevel::TopSecret)
        } else if subject.contains("OU=Secret") || subject.contains("OU=S") {
            Ok(ClassificationLevel::Secret)
        } else if subject.contains("OU=Confidential") || subject.contains("OU=C") {
            Ok(ClassificationLevel::Confidential)
        } else {
            // Default to Unclassified if not specified
            Ok(ClassificationLevel::Unclassified)
        }
    }

    async fn provision_user(
        &self,
        email: &str,
        name: &str,
        certificate_dn: &str,
        certificate_serial: &str,
        clearance: ClassificationLevel,
    ) -> Result<User> {
        let user = User {
            id: uuid::Uuid::new_v4().to_string(),
            email: email.to_string(),
            name: Some(name.to_string()),
            password_hash: String::new(),  // No password for CAC users
            email_verified: true,  // Trust CAC
            avatar_url: None,
            mfa_enabled: false,  // CAC is the MFA
            mfa_secret: None,
            clearance_level: clearance,
            certificate_dn: Some(certificate_dn.to_string()),
            certificate_serial: Some(certificate_serial.to_string()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_login_at: None,
            disabled: false,
            disabled_reason: None,
            disabled_at: None,
        };

        self.storage.create_user(&user).await?;

        tracing::info!(
            "Auto-provisioned CAC user: {} ({})",
            email,
            clearance.marking()
        );

        Ok(user)
    }
}

// Helper types
#[derive(Debug)]
struct OcspResponse {
    status: OcspStatus,
}

#[derive(Debug, PartialEq)]
enum OcspStatus {
    Good,
    Revoked,
    Unknown,
}

struct CertificateRevocationList {
    revoked_serials: std::collections::HashSet<String>,
}

impl CertificateRevocationList {
    fn new() -> Self {
        Self {
            revoked_serials: std::collections::HashSet::new(),
        }
    }

    fn is_revoked(&self, serial: &str) -> bool {
        self.revoked_serials.contains(serial)
    }
}

fn load_dod_root_cas() -> Vec<Vec<u8>> {
    // Load DoD root CA certificates from filesystem
    // In production, these would be bundled with the application
    vec![]
}

fn create_ocsp_request(cert: &X509Certificate) -> Vec<u8> {
    // Create OCSP request (simplified)
    vec![]
}
```

### CAC HTTP Handler

**File: `src/http/auth.rs` (ADD)**

```rust
/// POST /auth/cac - Authenticate with CAC certificate
async fn cac_login(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Result<Json<LoginResponse>, AppError> {
    // Extract client certificate from TLS connection
    let cert_der = extract_client_certificate(&req)
        .ok_or_else(|| AppError::from(BeemFlowError::OAuth("No client certificate".into())))?;

    // Authenticate
    let cac_user = state.cac_authenticator.authenticate(&cert_der).await?;

    // Get or create tenant (for government deployments, might be pre-created)
    let tenant = state.storage
        .get_tenant_by_slug("darpa")  // Default government tenant
        .await?
        .ok_or_else(|| AppError::from(BeemFlowError::OAuth("No tenant configured".into())))?;

    // Get or create membership
    let member = state.storage
        .get_tenant_member(&tenant.id, &cac_user.user_id)
        .await?
        .unwrap_or_else(|| {
            // Auto-add to government tenant
            // In production, this would require approval
            TenantMember {
                id: uuid::Uuid::new_v4().to_string(),
                tenant_id: tenant.id.clone(),
                user_id: cac_user.user_id.clone(),
                role: Role::Member,
                invited_by_user_id: None,
                invited_at: None,
                joined_at: chrono::Utc::now(),
                disabled: false,
            }
        });

    // Create session (NOT JWT for CAC - use database-backed session)
    let session_id = uuid::Uuid::new_v4().to_string();
    let session = CacSession {
        id: session_id.clone(),
        user_id: cac_user.user_id.clone(),
        tenant_id: tenant.id.clone(),
        certificate_dn: cac_user.certificate_dn,
        certificate_serial: cac_user.certificate_serial,
        clearance_level: cac_user.clearance_level,
        created_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(8),
    };

    state.storage.create_cac_session(&session).await?;

    Ok(Json(LoginResponse {
        access_token: session_id,  // Use session ID as token
        refresh_token: String::new(),  // No refresh for CAC (re-auth required)
        expires_in: 28800,  // 8 hours
        user: UserInfo {
            id: cac_user.user_id,
            email: cac_user.email,
            name: Some(cac_user.name),
            avatar_url: None,
        },
        tenant: TenantInfo {
            id: tenant.id,
            name: tenant.name,
            slug: tenant.slug,
            role: member.role,
        },
    }))
}

fn extract_client_certificate(req: &Request) -> Option<Vec<u8>> {
    // Extract from TLS connection info
    // This depends on how Axum/Rustls is configured
    // In production, this would come from the TLS handshake
    None
}
```

---

## Step 3: ABAC Policy Engine

### Policy Data Model

**File: `src/auth/abac.rs` (NEW)**

```rust
//! Attribute-Based Access Control (ABAC) policy engine

use crate::auth::classification::ClassificationLevel;
use crate::auth::types::{Permission, RequestContext, Role};
use crate::{BeemFlowError, Result};
use chrono::{DateTime, Utc, Weekday};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbacPolicy {
    pub id: String,
    pub name: String,
    pub tenant_id: Option<String>,  // None = global policy
    pub enabled: bool,
    pub priority: i32,  // Higher = evaluated first

    /// All conditions must be true (AND logic)
    pub conditions: Vec<PolicyCondition>,

    /// Effect if conditions match
    pub effect: PolicyEffect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PolicyCondition {
    /// Classification level check
    ClassificationLevel {
        resource_classification: ClassificationLevel,
        user_clearance: ClassificationLevel,
        operator: ComparisonOp,
    },

    /// Time-based access control
    TimeWindow {
        days_of_week: Vec<Weekday>,
        start_time: String,  // "09:00:00"
        end_time: String,    // "17:00:00"
        timezone: String,    // "America/New_York"
    },

    /// IP address restrictions
    IpAddressAllowlist {
        allowed_cidrs: Vec<String>,  // ["192.168.0.0/16", "10.0.0.0/8"]
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
        required_labels: Vec<String>,  // e.g., ["PII", "PHI"]
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "effect")]
pub enum PolicyEffect {
    Allow,
    Deny { reason: String },
    RequireApproval {
        approver_roles: Vec<Role>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ComparisonOp {
    Equals,
    NotEquals,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Contains,
    In,
}

pub struct PolicyEvaluator {
    policies: Arc<parking_lot::RwLock<Vec<AbacPolicy>>>,
}

impl PolicyEvaluator {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(parking_lot::RwLock::new(Vec::new())),
        }
    }

    pub fn load_policies(&self, policies: Vec<AbacPolicy>) {
        let mut lock = self.policies.write();
        *lock = policies;
    }

    /// Evaluate policies for a request
    pub async fn evaluate(
        &self,
        ctx: &RequestContext,
        resource: &Resource,
        permission: Permission,
    ) -> Result<PolicyDecision> {
        let policies = self.policies.read();

        // Filter applicable policies
        let applicable: Vec<_> = policies
            .iter()
            .filter(|p| p.enabled)
            .filter(|p| {
                p.tenant_id.is_none() || p.tenant_id.as_ref() == Some(&ctx.tenant_id)
            })
            .collect();

        // Sort by priority
        let mut sorted = applicable.clone();
        sorted.sort_by_key(|p| -p.priority);

        // Evaluate in priority order
        for policy in sorted {
            if self.evaluate_conditions(&policy.conditions, ctx, resource)? {
                // Policy matched - return effect
                return Ok(match &policy.effect {
                    PolicyEffect::Allow => PolicyDecision::Allow,
                    PolicyEffect::Deny { reason } => PolicyDecision::Deny {
                        reason: reason.clone(),
                        policy_name: policy.name.clone(),
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

        // No policy matched - defer to RBAC
        Ok(PolicyDecision::Defer)
    }

    fn evaluate_conditions(
        &self,
        conditions: &[PolicyCondition],
        ctx: &RequestContext,
        resource: &Resource,
    ) -> Result<bool> {
        // All conditions must be true
        for condition in conditions {
            if !self.evaluate_condition(condition, ctx, resource)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn evaluate_condition(
        &self,
        condition: &PolicyCondition,
        ctx: &RequestContext,
        resource: &Resource,
    ) -> Result<bool> {
        match condition {
            PolicyCondition::ClassificationLevel {
                resource_classification,
                user_clearance,
                operator,
            } => {
                let user_level = ctx.clearance_level;
                let resource_level = resource.classification_level;

                Ok(match operator {
                    ComparisonOp::GreaterThanOrEqual => user_level >= resource_level,
                    ComparisonOp::Equals => user_level == resource_level,
                    ComparisonOp::GreaterThan => user_level > resource_level,
                    _ => false,
                })
            }

            PolicyCondition::TimeWindow {
                days_of_week,
                start_time,
                end_time,
                timezone,
            } => {
                let now = Utc::now();
                // Parse timezone and convert
                // (Simplified - full implementation would use chrono-tz)

                let current_day = now.weekday();
                let current_time = now.time();

                let in_day_range = days_of_week.contains(&current_day);
                // Parse and compare times
                // (Simplified)

                Ok(in_day_range)
            }

            PolicyCondition::IpAddressAllowlist { allowed_cidrs } => {
                if let Some(client_ip) = &ctx.client_ip {
                    // Parse CIDR and check if IP is in range
                    // (Simplified - use ipnetwork crate in production)
                    Ok(allowed_cidrs.iter().any(|cidr| {
                        cidr.contains(&client_ip.to_string())
                    }))
                } else {
                    Ok(false)  // No IP = deny
                }
            }

            PolicyCondition::ResourceAttribute {
                attribute_key,
                operator,
                value,
            } => {
                if let Some(resource_value) = resource.attributes.get(attribute_key) {
                    Ok(self.compare_values(resource_value, operator, value))
                } else {
                    Ok(false)
                }
            }

            PolicyCondition::UserAttribute {
                attribute_key,
                operator,
                value,
            } => {
                // User attributes would come from ctx or database
                // (Simplified)
                Ok(false)
            }

            PolicyCondition::DataSensitivity { required_labels } => {
                // Check if user has required labels/clearances
                // (Simplified)
                Ok(true)
            }
        }
    }

    fn compare_values(
        &self,
        left: &serde_json::Value,
        op: &ComparisonOp,
        right: &serde_json::Value,
    ) -> bool {
        use serde_json::Value;

        match (left, right) {
            (Value::String(l), Value::String(r)) => match op {
                ComparisonOp::Equals => l == r,
                ComparisonOp::NotEquals => l != r,
                ComparisonOp::Contains => l.contains(r),
                _ => false,
            },
            (Value::Number(l), Value::Number(r)) => {
                let lf = l.as_f64().unwrap_or(0.0);
                let rf = r.as_f64().unwrap_or(0.0);
                match op {
                    ComparisonOp::Equals => lf == rf,
                    ComparisonOp::GreaterThan => lf > rf,
                    ComparisonOp::GreaterThanOrEqual => lf >= rf,
                    ComparisonOp::LessThan => lf < rf,
                    ComparisonOp::LessThanOrEqual => lf <= rf,
                    _ => false,
                }
            }
            _ => false,
        }
    }
}

#[derive(Debug)]
pub enum PolicyDecision {
    Allow,
    Deny {
        reason: String,
        policy_name: String,
    },
    RequireApproval {
        approver_roles: Vec<Role>,
        policy_name: String,
    },
    Defer,  // No policy matched, use RBAC
}

#[derive(Debug)]
pub struct Resource {
    pub classification_level: ClassificationLevel,
    pub attributes: HashMap<String, serde_json::Value>,
    pub created_by: String,
}
```

### Example Policies

**File: `examples/abac_policies.json` (NEW)**

```json
[
  {
    "id": "policy_001",
    "name": "Classification-Based Access Control",
    "tenant_id": null,
    "enabled": true,
    "priority": 100,
    "conditions": [
      {
        "type": "ClassificationLevel",
        "resource_classification": "Secret",
        "user_clearance": "Secret",
        "operator": "GreaterThanOrEqual"
      }
    ],
    "effect": {
      "effect": "Deny",
      "reason": "Insufficient clearance for classified resource"
    }
  },
  {
    "id": "policy_002",
    "name": "Production Deployments Require Approval",
    "tenant_id": null,
    "enabled": true,
    "priority": 90,
    "conditions": [
      {
        "type": "ResourceAttribute",
        "attribute_key": "environment",
        "operator": "Equals",
        "value": "production"
      }
    ],
    "effect": {
      "effect": "RequireApproval",
      "approver_roles": ["Admin", "Owner"]
    }
  },
  {
    "id": "policy_003",
    "name": "Business Hours Only",
    "tenant_id": null,
    "enabled": true,
    "priority": 80,
    "conditions": [
      {
        "type": "TimeWindow",
        "days_of_week": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
        "start_time": "09:00:00",
        "end_time": "17:00:00",
        "timezone": "America/New_York"
      }
    ],
    "effect": {
      "effect": "Deny",
      "reason": "Deployments only allowed during business hours"
    }
  },
  {
    "id": "policy_004",
    "name": "Network Access Control",
    "tenant_id": "darpa_classified",
    "enabled": true,
    "priority": 100,
    "conditions": [
      {
        "type": "IpAddressAllowlist",
        "allowed_cidrs": ["192.168.0.0/16", "10.0.0.0/8"]
      }
    ],
    "effect": {
      "effect": "Deny",
      "reason": "Access only allowed from secure networks"
    }
  }
]
```

---

## Step 4: SAML/LDAP Integration

### SAML 2.0 Service Provider

**File: `Cargo.toml` (ADD)**

```toml
[dependencies]
# SAML support
samael = "0.0.11"

# LDAP support
ldap3 = "0.11"
```

**File: `src/auth/saml.rs` (NEW)**

```rust
//! SAML 2.0 Service Provider implementation

use crate::auth::types::{User, Role};
use crate::storage::AuthStorage;
use crate::{BeemFlowError, Result};
use samael::metadata::{EntityDescriptor, ContactPerson};
use samael::service_provider::ServiceProvider;
use std::sync::Arc;

pub struct SamlAuthenticator {
    sp: ServiceProvider,
    storage: Arc<dyn AuthStorage>,
    auto_provision: bool,
}

impl SamlAuthenticator {
    pub fn new(
        entity_id: String,
        acs_url: String,  // Assertion Consumer Service URL
        idp_metadata_url: String,
        storage: Arc<dyn AuthStorage>,
        auto_provision: bool,
    ) -> Result<Self> {
        // Load IdP metadata
        let idp_metadata = reqwest::blocking::get(&idp_metadata_url)
            .map_err(|e| BeemFlowError::Network(e))?
            .text()
            .map_err(|e| BeemFlowError::Network(e))?;

        let sp = ServiceProvider::from_metadata(&idp_metadata)
            .map_err(|e| BeemFlowError::OAuth(format!("Invalid SAML metadata: {}", e)))?;

        Ok(Self {
            sp,
            storage,
            auto_provision,
        })
    }

    /// Process SAML assertion response
    pub async fn process_assertion(&self, saml_response: &str) -> Result<User> {
        // Validate and parse SAML assertion
        let assertion = self.sp
            .parse_assertion(saml_response)
            .map_err(|e| BeemFlowError::OAuth(format!("Invalid SAML assertion: {}", e)))?;

        // Extract attributes
        let name_id = assertion.subject.name_id.value;
        let email = assertion.attributes.get("email")
            .or(assertion.attributes.get("mail"))
            .ok_or_else(|| BeemFlowError::OAuth("No email in SAML assertion".into()))?;

        let name = assertion.attributes.get("displayName")
            .or(assertion.attributes.get("cn"))
            .map(|s| s.to_string());

        // Get or create user
        let user = self.storage
            .get_user_by_saml_name_id(&name_id)
            .await?
            .or_else(|| {
                if self.auto_provision {
                    Some(self.provision_user(&name_id, email, name.as_deref()).await.ok()?)
                } else {
                    None
                }
            })
            .ok_or_else(|| BeemFlowError::OAuth("User not found".into()))?;

        Ok(user)
    }

    async fn provision_user(
        &self,
        name_id: &str,
        email: &str,
        name: Option<&str>,
    ) -> Result<User> {
        let user = User {
            id: uuid::Uuid::new_v4().to_string(),
            email: email.to_string(),
            name: name.map(|s| s.to_string()),
            password_hash: String::new(),  // No password for SAML users
            email_verified: true,  // Trust IdP
            avatar_url: None,
            mfa_enabled: false,
            mfa_secret: None,
            clearance_level: crate::auth::classification::ClassificationLevel::Unclassified,
            saml_name_id: Some(name_id.to_string()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_login_at: None,
            disabled: false,
            disabled_reason: None,
            disabled_at: None,
        };

        self.storage.create_user(&user).await?;

        tracing::info!("Auto-provisioned SAML user: {}", email);

        Ok(user)
    }
}
```

### LDAP Integration

**File: `src/auth/ldap.rs` (NEW)**

```rust
//! LDAP/Active Directory integration for group sync

use crate::{BeemFlowError, Result};
use ldap3::{LdapConn, Scope, SearchEntry};

pub struct LdapClient {
    url: String,
    bind_dn: String,
    bind_password: String,
    base_dn: String,
}

impl LdapClient {
    pub fn new(
        url: String,
        bind_dn: String,
        bind_password: String,
        base_dn: String,
    ) -> Self {
        Self {
            url,
            bind_dn,
            bind_password,
            base_dn,
        }
    }

    /// Authenticate user against LDAP
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<LdapUser> {
        let mut ldap = LdapConn::new(&self.url)
            .map_err(|e| BeemFlowError::OAuth(format!("LDAP connection failed: {}", e)))?;

        // Bind with service account
        ldap.simple_bind(&self.bind_dn, &self.bind_password)
            .map_err(|e| BeemFlowError::OAuth(format!("LDAP bind failed: {}", e)))?;

        // Search for user
        let filter = format!("(sAMAccountName={})", username);
        let (rs, _res) = ldap
            .search(&self.base_dn, Scope::Subtree, &filter, vec!["dn", "mail", "displayName", "memberOf"])
            .map_err(|e| BeemFlowError::OAuth(format!("LDAP search failed: {}", e)))?
            .success()
            .map_err(|e| BeemFlowError::OAuth(format!("LDAP search failed: {}", e)))?;

        let entry = rs
            .into_iter()
            .next()
            .ok_or_else(|| BeemFlowError::OAuth("User not found in LDAP".into()))?;

        let entry = SearchEntry::construct(entry);

        // Try to bind as the user to verify password
        let user_dn = entry.dn;
        let mut user_ldap = LdapConn::new(&self.url)
            .map_err(|e| BeemFlowError::OAuth(format!("LDAP connection failed: {}", e)))?;

        user_ldap
            .simple_bind(&user_dn, password)
            .map_err(|_| BeemFlowError::OAuth("Invalid credentials".into()))?;

        // Extract attributes
        let email = entry.attrs.get("mail")
            .and_then(|v| v.first())
            .ok_or_else(|| BeemFlowError::OAuth("No email in LDAP".into()))?
            .to_string();

        let name = entry.attrs.get("displayName")
            .and_then(|v| v.first())
            .map(|s| s.to_string());

        let groups = entry.attrs.get("memberOf")
            .map(|v| v.clone())
            .unwrap_or_default();

        Ok(LdapUser {
            dn: user_dn,
            email,
            name,
            groups,
        })
    }

    /// Sync groups from LDAP
    pub async fn sync_groups(&self, user_dn: &str) -> Result<Vec<String>> {
        let mut ldap = LdapConn::new(&self.url)
            .map_err(|e| BeemFlowError::OAuth(format!("LDAP connection failed: {}", e)))?;

        ldap.simple_bind(&self.bind_dn, &self.bind_password)
            .map_err(|e| BeemFlowError::OAuth(format!("LDAP bind failed: {}", e)))?;

        let (rs, _res) = ldap
            .search(user_dn, Scope::Base, "(objectClass=*)", vec!["memberOf"])
            .map_err(|e| BeemFlowError::OAuth(format!("LDAP search failed: {}", e)))?
            .success()
            .map_err(|e| BeemFlowError::OAuth(format!("LDAP search failed: {}", e)))?;

        let entry = rs
            .into_iter()
            .next()
            .ok_or_else(|| BeemFlowError::OAuth("User not found".into()))?;

        let entry = SearchEntry::construct(entry);

        Ok(entry.attrs.get("memberOf")
            .map(|v| v.clone())
            .unwrap_or_default())
    }
}

#[derive(Debug)]
pub struct LdapUser {
    pub dn: String,
    pub email: String,
    pub name: Option<String>,
    pub groups: Vec<String>,
}
```

---

## Step 5: HSM Integration

### PKCS#11 Interface

**File: `Cargo.toml` (ADD)**

```toml
[dependencies]
# PKCS#11 for HSM
pkcs11 = "0.5"
cryptoki = "0.4"  # Higher-level PKCS#11 wrapper
```

**File: `src/auth/hsm.rs` (NEW)**

```rust
//! Hardware Security Module integration via PKCS#11

use crate::{BeemFlowError, Result};
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use std::path::Path;

pub struct HsmVault {
    pkcs11: Pkcs11,
    slot: cryptoki::types::Slot,
    pin: String,
}

impl HsmVault {
    /// Initialize HSM connection
    pub fn new(module_path: &str, pin: &str) -> Result<Self> {
        // Initialize PKCS#11 library
        let pkcs11 = Pkcs11::new(Path::new(module_path))
            .map_err(|e| BeemFlowError::OAuth(format!("Failed to load PKCS#11 module: {}", e)))?;

        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .map_err(|e| BeemFlowError::OAuth(format!("PKCS#11 init failed: {}", e)))?;

        // Get first available slot
        let slots = pkcs11.get_slots_with_token()
            .map_err(|e| BeemFlowError::OAuth(format!("No HSM slots found: {}", e)))?;

        let slot = *slots.first()
            .ok_or_else(|| BeemFlowError::OAuth("No HSM slots available".into()))?;

        Ok(Self {
            pkcs11,
            slot,
            pin: pin.to_string(),
        })
    }

    /// Encrypt data using HSM
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let session = self.open_session()?;

        // Find or create encryption key
        let key_handle = self.find_or_create_key(&session, "beemflow_master")?;

        // Encrypt
        let mechanism = Mechanism::AesGcm(cryptoki::mechanism::aes::GcmParams::new(
            b"unique_iv_12",  // In production, use random IV
            b"additional_authenticated_data",
            128,
        ));

        let ciphertext = session.encrypt(&mechanism, key_handle, plaintext)
            .map_err(|e| BeemFlowError::OAuth(format!("HSM encryption failed: {}", e)))?;

        session.logout()
            .map_err(|e| BeemFlowError::OAuth(format!("HSM logout failed: {}", e)))?;

        Ok(ciphertext)
    }

    /// Decrypt data using HSM
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let session = self.open_session()?;

        let key_handle = self.find_or_create_key(&session, "beemflow_master")?;

        let mechanism = Mechanism::AesGcm(cryptoki::mechanism::aes::GcmParams::new(
            b"unique_iv_12",
            b"additional_authenticated_data",
            128,
        ));

        let plaintext = session.decrypt(&mechanism, key_handle, ciphertext)
            .map_err(|e| BeemFlowError::OAuth(format!("HSM decryption failed: {}", e)))?;

        session.logout()
            .map_err(|e| BeemFlowError::OAuth(format!("HSM logout failed: {}", e)))?;

        Ok(plaintext)
    }

    /// Sign data using HSM (for CAC signing)
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let session = self.open_session()?;

        // Find signing key
        let key_handle = self.find_or_create_key(&session, "beemflow_signing")?;

        let mechanism = Mechanism::Sha256Rsa;

        let signature = session.sign(&mechanism, key_handle, data)
            .map_err(|e| BeemFlowError::OAuth(format!("HSM signing failed: {}", e)))?;

        session.logout()
            .map_err(|e| BeemFlowError::OAuth(format!("HSM logout failed: {}", e)))?;

        Ok(signature)
    }

    fn open_session(&self) -> Result<Session> {
        let session = self.pkcs11.open_rw_session(self.slot)
            .map_err(|e| BeemFlowError::OAuth(format!("Failed to open HSM session: {}", e)))?;

        session.login(UserType::User, Some(&AuthPin::new(self.pin.clone())))
            .map_err(|e| BeemFlowError::OAuth(format!("HSM login failed: {}", e)))?;

        Ok(session)
    }

    fn find_or_create_key(&self, session: &Session, label: &str) -> Result<ObjectHandle> {
        // Search for existing key
        let template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::Label(label.as_bytes().to_vec()),
        ];

        let objects = session.find_objects(&template)
            .map_err(|e| BeemFlowError::OAuth(format!("HSM key search failed: {}", e)))?;

        if let Some(handle) = objects.first() {
            return Ok(*handle);
        }

        // Create new key
        let key_template = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::AES),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::ValueLen(32.into()),  // AES-256
        ];

        let mechanism = Mechanism::AesKeyGen;

        let key_handle = session.generate_key(&mechanism, &key_template)
            .map_err(|e| BeemFlowError::OAuth(format!("HSM key generation failed: {}", e)))?;

        tracing::info!("Created new HSM key: {}", label);

        Ok(key_handle)
    }
}
```

---

## Step 6: SIEM Integration

### CEF/LEEF Formatters

**File: `src/audit/siem.rs` (NEW)**

```rust
//! SIEM integration for real-time security event export

use crate::audit::AuditLog;
use crate::Result;
use chrono::Utc;

pub struct SiemForwarder {
    syslog_client: SyslogClient,
    format: SiemFormat,
}

#[derive(Debug, Clone)]
pub enum SiemFormat {
    /// Common Event Format (ArcSight)
    CEF,
    /// Log Event Extended Format (QRadar)
    LEEF,
    /// Generic JSON
    JSON,
}

impl SiemForwarder {
    pub fn new(syslog_host: String, syslog_port: u16, format: SiemFormat) -> Self {
        Self {
            syslog_client: SyslogClient::new(syslog_host, syslog_port),
            format,
        }
    }

    pub async fn forward(&self, log: &AuditLog) -> Result<()> {
        let formatted = match self.format {
            SiemFormat::CEF => self.format_cef(log),
            SiemFormat::LEEF => self.format_leef(log),
            SiemFormat::JSON => serde_json::to_string(log)?,
        };

        self.syslog_client.send(&formatted).await?;

        Ok(())
    }

    /// Format as Common Event Format (CEF)
    /// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    fn format_cef(&self, log: &AuditLog) -> String {
        let severity = self.severity_from_action(&log.action);

        let extension = format!(
            "rt={} src={} suser={} request={} cs1Label=TenantID cs1={} cs2Label=ResourceType cs2={} outcome={}",
            log.timestamp,
            log.client_ip.as_deref().unwrap_or("unknown"),
            log.user_id.as_deref().unwrap_or("system"),
            log.http_path.as_deref().unwrap_or(""),
            log.tenant_id,
            log.resource_type.as_deref().unwrap_or(""),
            if log.success { "success" } else { "failure" },
        );

        format!(
            "CEF:0|Anthropic|BeemFlow|2.0|{}|{}|{}|{}",
            log.action,
            log.action,
            severity,
            extension
        )
    }

    /// Format as Log Event Extended Format (LEEF)
    /// LEEF:Version|Vendor|Product|Version|EventID|Delimiter|Key=Value pairs
    fn format_leef(&self, log: &AuditLog) -> String {
        format!(
            "LEEF:2.0|Anthropic|BeemFlow|2.0|{}|\t|devTime={}\tsrc={}\tusrName={}\ttenant={}\tresource={}\toutcome={}",
            log.action,
            log.timestamp,
            log.client_ip.as_deref().unwrap_or("unknown"),
            log.user_id.as_deref().unwrap_or("system"),
            log.tenant_id,
            log.resource_type.as_deref().unwrap_or(""),
            if log.success { "success" } else { "failure" },
        )
    }

    fn severity_from_action(&self, action: &str) -> u8 {
        if action.contains("delete") || action.contains("revoke") {
            8  // High
        } else if action.contains("create") || action.contains("update") {
            5  // Medium
        } else {
            2  // Low
        }
    }
}

struct SyslogClient {
    host: String,
    port: u16,
}

impl SyslogClient {
    fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }

    async fn send(&self, message: &str) -> Result<()> {
        use tokio::net::UdpSocket;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addr = format!("{}:{}", self.host, self.port);

        // Syslog format: <priority>timestamp hostname message
        let priority = 134;  // Local0.Info
        let timestamp = Utc::now().format("%b %d %H:%M:%S");
        let hostname = "beemflow";

        let syslog_msg = format!(
            "<{}>{} {} {}",
            priority,
            timestamp,
            hostname,
            message
        );

        socket.send_to(syslog_msg.as_bytes(), &addr).await?;

        Ok(())
    }
}
```

---

## Step 7: WebAuthn/FIDO2

**File: `Cargo.toml` (ADD)**

```toml
[dependencies]
webauthn-rs = "0.4"
```

**File: `src/auth/webauthn.rs` (NEW)**

```rust
//! WebAuthn/FIDO2 hardware security key support

use crate::{BeemFlowError, Result};
use webauthn_rs::prelude::*;

pub struct WebAuthnManager {
    webauthn: Webauthn,
}

impl WebAuthnManager {
    pub fn new(rp_id: String, rp_origin: Url) -> Result<Self> {
        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)
            .map_err(|e| BeemFlowError::OAuth(format!("WebAuthn init failed: {}", e)))?;

        let webauthn = builder.build()
            .map_err(|e| BeemFlowError::OAuth(format!("WebAuthn build failed: {}", e)))?;

        Ok(Self { webauthn })
    }

    /// Start passkey registration
    pub fn start_registration(
        &self,
        user_id: &str,
        user_email: &str,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration)> {
        let user_unique_id = uuid::Uuid::parse_str(user_id)
            .map_err(|e| BeemFlowError::validation(format!("Invalid user ID: {}", e)))?;

        let (ccr, reg_state) = self.webauthn
            .start_passkey_registration(user_unique_id, user_email, user_email, None)
            .map_err(|e| BeemFlowError::OAuth(format!("Registration start failed: {}", e)))?;

        Ok((ccr, reg_state))
    }

    /// Finish passkey registration
    pub fn finish_registration(
        &self,
        reg: &PublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey> {
        let passkey = self.webauthn
            .finish_passkey_registration(reg, state)
            .map_err(|e| BeemFlowError::OAuth(format!("Registration failed: {}", e)))?;

        Ok(passkey)
    }

    /// Start passkey authentication
    pub fn start_authentication(
        &self,
        passkeys: Vec<Passkey>,
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication)> {
        let (rcr, auth_state) = self.webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| BeemFlowError::OAuth(format!("Authentication start failed: {}", e)))?;

        Ok((rcr, auth_state))
    }

    /// Finish passkey authentication
    pub fn finish_authentication(
        &self,
        auth: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult> {
        let result = self.webauthn
            .finish_passkey_authentication(auth, state)
            .map_err(|e| BeemFlowError::OAuth(format!("Authentication failed: {}", e)))?;

        Ok(result)
    }
}
```

---

## Step 8: Air-Gapped Deployment

### Offline License Validation

**File: `src/license/mod.rs` (NEW)**

```rust
//! Offline license validation for air-gapped deployments

use crate::{BeemFlowError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct License {
    pub customer: String,
    pub deployment: String,  // e.g., "DARPA-Classified"
    pub max_users: usize,
    pub max_flows: usize,
    pub features: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub signature: String,  // Ed25519 signature
}

impl License {
    /// Validate license signature
    pub fn validate(&self, public_key: &[u8; 32]) -> Result<()> {
        use ed25519_dalek::{PublicKey, Signature, Verifier};

        // Serialize license without signature
        let mut license_copy = self.clone();
        license_copy.signature = String::new();
        let message = serde_json::to_string(&license_copy)?;

        // Decode signature
        let sig_bytes = base64::decode(&self.signature)
            .map_err(|e| BeemFlowError::validation(format!("Invalid signature: {}", e)))?;

        let signature = Signature::from_bytes(&sig_bytes)
            .map_err(|e| BeemFlowError::validation(format!("Invalid signature: {}", e)))?;

        let public_key = PublicKey::from_bytes(public_key)
            .map_err(|e| BeemFlowError::validation(format!("Invalid public key: {}", e)))?;

        // Verify
        public_key
            .verify(message.as_bytes(), &signature)
            .map_err(|_| BeemFlowError::validation("License signature invalid"))?;

        // Check expiration
        if let Some(expires_at) = self.expires_at {
            if Utc::now() > expires_at {
                return Err(BeemFlowError::validation("License expired"));
            }
        }

        Ok(())
    }
}

pub fn load_license(path: &str) -> Result<License> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| BeemFlowError::validation(format!("Failed to read license: {}", e)))?;

    let license: License = serde_json::from_str(&content)
        .map_err(|e| BeemFlowError::validation(format!("Invalid license format: {}", e)))?;

    // Validate signature with embedded public key
    let public_key = include_bytes!("../../keys/beemflow-public.key");
    license.validate(public_key)?;

    tracing::info!(
        "License validated: {} (expires: {:?})",
        license.customer,
        license.expires_at
    );

    Ok(license)
}
```

### Manual Update Packages

**File: `scripts/create_update_package.sh` (NEW)**

```bash
#!/bin/bash
# Create offline update package for air-gapped deployments

set -e

VERSION=$1
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

PACKAGE_DIR="beemflow-update-${VERSION}"
mkdir -p "${PACKAGE_DIR}"

# Build release binary
cargo build --release

# Copy binary
cp target/release/flow "${PACKAGE_DIR}/"

# Copy migrations
cp -r migrations "${PACKAGE_DIR}/"

# Copy documentation
cp README.md CHANGELOG.md "${PACKAGE_DIR}/"

# Create installation script
cat > "${PACKAGE_DIR}/install.sh" << 'EOF'
#!/bin/bash
set -e

echo "Installing BeemFlow update..."

# Stop service
systemctl stop beemflow || true

# Backup current binary
cp /usr/local/bin/flow /usr/local/bin/flow.backup

# Install new binary
cp flow /usr/local/bin/flow
chmod +x /usr/local/bin/flow

# Run migrations
/usr/local/bin/flow db migrate

# Start service
systemctl start beemflow

echo "Update complete!"
EOF

chmod +x "${PACKAGE_DIR}/install.sh"

# Create checksum
cd "${PACKAGE_DIR}"
sha256sum * > SHA256SUMS
cd ..

# Create tarball
tar czf "${PACKAGE_DIR}.tar.gz" "${PACKAGE_DIR}"

# Sign package
gpg --detach-sign --armor "${PACKAGE_DIR}.tar.gz"

echo "Update package created: ${PACKAGE_DIR}.tar.gz"
echo "Signature: ${PACKAGE_DIR}.tar.gz.asc"
```

---

## Deployment Architectures

### IL-2 SaaS (Public Internet)

✅ Already implemented in SaaS phase.

### IL-4/5 SaaS (AWS GovCloud)

```
┌─────────────────────────────────────────────────────────────────┐
│                   AWS GovCloud (FedRAMP High)                   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      Application Load Balancer                  │
│  - TLS 1.3 termination                                          │
│  - CAC certificate validation                                   │
│  - WAF with OWASP rules                                         │
└────────────────────────┬────────────────────────────────────────┘
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
┌──────────────────────┐  ┌──────────────────────┐
│  ECS Task 1          │  │  ECS Task 2          │
│  - BeemFlow app      │  │  - BeemFlow app      │
│  - CloudHSM client   │  │  - CloudHSM client   │
└──────────┬───────────┘  └──────────┬───────────┘
           │                         │
           └──────────┬──────────────┘
                      ▼
           ┌──────────────────────┐
           │  AWS CloudHSM        │
           │  - FIPS 140-2 Level 3│
           │  - Master keys       │
           └──────────────────────┘
                      │
                      ▼
           ┌──────────────────────┐
           │  RDS PostgreSQL      │
           │  - Encrypted at rest │
           │  - Multi-AZ          │
           │  - Automated backups │
           └──────────────────────┘
                      │
                      ▼
           ┌──────────────────────┐
           │  CloudWatch Logs     │
           │  → SIEM (Splunk)    │
           └──────────────────────┘
```

**Configuration:**

```bash
# Environment variables for IL-4/5
DEPLOYMENT_MODE=govcloud
REQUIRE_CAC=true
HSM_MODULE=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so
HSM_PIN=encrypted_pin_here
OCSP_RESPONDER=http://ocsp.disa.mil
CLASSIFICATION_LEVEL=CUI
```

### Classified On-Premise (Air-Gapped)

```
┌─────────────────────────────────────────────────────────────────┐
│                   SCIF / Classified Network                     │
│                   (No Internet Connectivity)                    │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                   Internal Load Balancer (F5)                   │
│  - TLS 1.3 with internal CA                                     │
│  - CAC certificate validation                                   │
└────────────────────────┬────────────────────────────────────────┘
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
┌──────────────────────┐  ┌──────────────────────┐
│  BeemFlow Server 1   │  │  BeemFlow Server 2   │
│  - Bare metal        │  │  - Bare metal        │
│  - HSM connected     │  │  - HSM connected     │
└──────────┬───────────┘  └──────────┬───────────┘
           │                         │
           └──────────┬──────────────┘
                      ▼
           ┌──────────────────────┐
           │  Hardware HSM        │
           │  (Thales nShield)    │
           │  - FIPS 140-2 Level 3│
           └──────────────────────┘
                      │
                      ▼
           ┌──────────────────────┐
           │  PostgreSQL Server   │
           │  - Full disk enc.    │
           │  - LUKS encryption   │
           │  - Tape backups      │
           └──────────────────────┘
                      │
                      ▼
           ┌──────────────────────┐
           │  SIEM (Air-gap diode)│
           │  → External SOC      │
           └──────────────────────┘
```

**Configuration:**

```bash
# Offline mode
DEPLOYMENT_MODE=airgap
OFFLINE_MODE=true
LICENSE_FILE=/opt/beemflow/license.json
REQUIRE_CAC=true
HSM_MODULE=/opt/nfast/toolkits/pkcs11/libcknfast.so
LDAP_URL=ldap://dc.classified.mil
CLASSIFICATION_LEVEL=SECRET
```

---

## Security Validation

### Pre-Deployment Checklist

- [ ] **Classification Support**
  - [ ] Classification levels enforced
  - [ ] Clearance checks working
  - [ ] Classification banners display

- [ ] **CAC Authentication**
  - [ ] Certificate chain validation
  - [ ] OCSP/CRL revocation checks
  - [ ] Auto-provisioning works
  - [ ] Clearance extraction correct

- [ ] **ABAC Policies**
  - [ ] Policy evaluation works
  - [ ] Classification policies block unauthorized access
  - [ ] Time-based policies enforce windows
  - [ ] IP allowlists work

- [ ] **HSM Integration**
  - [ ] Keys generated in HSM
  - [ ] Encryption/decryption works
  - [ ] Signing works
  - [ ] Keys non-extractable

- [ ] **SIEM Integration**
  - [ ] Real-time log forwarding
  - [ ] CEF format correct
  - [ ] LEEF format correct
  - [ ] No log drops

- [ ] **Air-Gapped Mode**
  - [ ] Offline license validation
  - [ ] Manual updates work
  - [ ] No internet calls
  - [ ] LDAP integration works

### Security Testing

**File: `tests/darpa_security_test.rs` (NEW)**

```rust
#[tokio::test]
async fn test_classification_enforcement() {
    let app = setup_test_app().await;

    // User with Confidential clearance
    let user = create_user_with_clearance(
        &app,
        "user@dod.mil",
        ClassificationLevel::Confidential,
    ).await;

    // Try to access Secret resource
    let response = app
        .get("/api/flows/secret_flow")
        .header("Authorization", format!("Bearer {}", user.token))
        .await;

    assert_eq!(response.status(), 403);
    assert!(response.text().await.contains("Insufficient clearance"));
}

#[tokio::test]
async fn test_cac_authentication() {
    let app = setup_test_app().await;

    // Load test CAC certificate
    let cert = load_test_certificate("test_cac.der");

    let response = app
        .post("/auth/cac")
        .client_certificate(cert)
        .await;

    assert_eq!(response.status(), 200);

    let body: LoginResponse = response.json().await;
    assert!(!body.access_token.is_empty());
}

#[tokio::test]
async fn test_hsm_encryption() {
    let hsm = HsmVault::new("/usr/lib/softhsm/libsofthsm2.so", "1234").unwrap();

    let plaintext = b"TOP SECRET//SCI data";
    let ciphertext = hsm.encrypt(plaintext).unwrap();
    let decrypted = hsm.decrypt(&ciphertext).unwrap();

    assert_eq!(plaintext, decrypted.as_slice());
}
```

---

## Compliance Matrix

| Control | NIST 800-53 | Implementation | Status |
|---------|-------------|----------------|--------|
| **Access Control** ||||
| User identification | IA-2 | CAC/PKI, SAML | ✅ |
| Multi-factor auth | IA-2(1) | CAC + PIN, WebAuthn | ✅ |
| Least privilege | AC-6 | RBAC + ABAC | ✅ |
| Classification-based | AC-16 | Classification levels | ✅ |
| **Audit** ||||
| Audit records | AU-2 | Immutable audit logs | ✅ |
| Audit review | AU-6 | CSSP query API | ✅ |
| Audit reduction | AU-7 | SIEM integration | ✅ |
| **Cryptography** ||||
| Data at rest | SC-28 | HSM-backed AES-256 | ✅ |
| Data in transit | SC-8 | TLS 1.3 | ✅ |
| Key management | SC-12 | HSM, PKCS#11 | ✅ |
| FIPS 140-2 | SC-13 | HSM validated | ✅ |

---

## Next Steps

1. **Complete SaaS phase first** - Foundation must be solid
2. **Prioritize by deployment** - IL-4/5 before classified
3. **Test incrementally** - Each step independently
4. **Get FedRAMP assessment** - Hire authorized assessor
5. **Document everything** - System Security Plan (SSP)

**Timeline:** 4-5 weeks after SaaS phase complete

**Prerequisites:**
- Hardware HSM procured
- DoD Root CA certificates obtained
- FedRAMP authorization package started
- SIEM infrastructure deployed

---

**Document Status:** READY FOR IMPLEMENTATION ✅

For questions: Reference [AUTH_PLAN.md](AUTH_PLAN.md) for full architecture details.
