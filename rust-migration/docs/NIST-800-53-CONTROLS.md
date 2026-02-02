# NIST SP 800-53 Rev 5 Control Mapping

This document maps NIST SP 800-53 Revision 5 security controls to their implementations in the Keycloak Rust codebase.

---

## Overview

Keycloak-RS implements security controls from NIST SP 800-53 Rev 5, focusing on control families relevant to identity and access management systems.

### Priority Control Families

| Family | Name                                | Relevance |
| ------ | ----------------------------------- | --------- |
| AC     | Access Control                      | Critical  |
| AU     | Audit and Accountability            | Critical  |
| IA     | Identification and Authentication   | Critical  |
| SC     | System and Communications Protection| Critical  |
| SI     | System and Information Integrity    | High      |
| CM     | Configuration Management            | High      |
| CP     | Contingency Planning                | Medium    |
| IR     | Incident Response                   | Medium    |

---

## AC - Access Control

### AC-2: Account Management

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| AC-2(1) | Automated Account Management | `kc-admin-api` user lifecycle | Planned |
| AC-2(2) | Automated Temporary Account Removal | Session expiration in `kc-session` | Planned |
| AC-2(3) | Disable Accounts | User enabled/disabled flag | Planned |
| AC-2(4) | Automated Audit Actions | Event logging in `kc-core` | Planned |

### AC-3: Access Enforcement

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| AC-3 | Access Enforcement | RBAC in `kc-auth` | Planned |
| AC-3(7) | Role-Based Access Control | Role mappings in `kc-model` | Planned |

### AC-6: Least Privilege

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| AC-6(1) | Authorize Access to Security Functions | Admin role restrictions | Planned |
| AC-6(2) | Non-Privileged Access for Non-Security Functions | Default user roles | Planned |
| AC-6(5) | Privileged Accounts | Realm admin separation | Planned |

### AC-7: Unsuccessful Logon Attempts

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| AC-7 | Unsuccessful Logon Attempts | Brute force protection in `kc-auth` | Planned |
| AC-7(2) | Purge/Wipe Mobile Device | N/A | N/A |

### AC-8: System Use Notification

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| AC-8 | System Use Notification | Login page terms display | Planned |

### AC-11: Device Lock

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| AC-11 | Device Lock | Session timeout | Planned |
| AC-11(1) | Pattern-Hiding Displays | N/A (server-side) | N/A |

### AC-12: Session Termination

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| AC-12 | Session Termination | `kc-session` logout handling | Planned |
| AC-12(1) | User-Initiated Logouts | Logout endpoint | Planned |

---

## AU - Audit and Accountability

### AU-2: Event Logging

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| AU-2 | Event Logging | Event system in `kc-core` | Planned |

**Events to Log:**

- Authentication attempts (success/failure)
- Account creation/modification/deletion
- Privilege escalation
- Token issuance/revocation
- Administrative actions

### AU-3: Content of Audit Records

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| AU-3 | Content of Audit Records | Structured event format | Planned |

**Required Fields:**

- Timestamp (ISO 8601)
- Event type
- User identity
- Source IP
- Outcome (success/failure)
- Affected resources

### AU-6: Audit Record Review, Analysis, and Reporting

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| AU-6 | Audit Review | Admin console event viewer | Planned |
| AU-6(1) | Automated Process Integration | Event export APIs | Planned |

### AU-9: Protection of Audit Information

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| AU-9 | Protection of Audit Information | Read-only audit tables | Planned |
| AU-9(4) | Access by Subset of Privileged Users | Audit viewer role | Planned |

### AU-12: Audit Record Generation

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| AU-12 | Audit Record Generation | Automatic event emission | Planned |
| AU-12(1) | System-Wide Audit Trail | Centralized event store | Planned |

---

## IA - Identification and Authentication

### IA-2: Identification and Authentication (Organizational Users)

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| IA-2 | Identification and Authentication | Core auth flow in `kc-auth` | Planned |
| IA-2(1) | Multi-Factor Authentication | OTP, WebAuthn authenticators | Planned |
| IA-2(2) | Multi-Factor to Privileged Accounts | MFA policy enforcement | Planned |
| IA-2(6) | Access to Accounts—Separate Device | Authenticator app support | Planned |
| IA-2(8) | Access to Accounts—Replay Resistant | TOTP time window validation | Planned |

### IA-4: Identifier Management

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| IA-4 | Identifier Management | User ID in `kc-model` | Planned |
| IA-4(4) | Identify User Status | Enabled/disabled flag | Planned |

### IA-5: Authenticator Management

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| IA-5 | Authenticator Management | `kc-auth/credential.rs` | Planned |
| IA-5(1) | Password-Based Authentication | Password policy enforcement | Planned |
| IA-5(2) | PKI-Based Authentication | Client certificate auth | Planned |
| IA-5(6) | Protection of Authenticators | Argon2id password hashing | Planned |

**Password Policy Controls (IA-5(1)):**

- Minimum length: 12 characters
- Complexity: uppercase, lowercase, digit, special
- History: prevent reuse of last N passwords
- Age: maximum password age
- Failed attempts: lockout after threshold

### IA-6: Authentication Feedback

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| IA-6 | Authentication Feedback | Generic error messages | Planned |

### IA-8: Identification and Authentication (Non-Organizational Users)

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| IA-8 | Non-Organizational Users | External IDP federation | Planned |
| IA-8(1) | Acceptance of PIV Credentials | WebAuthn/FIDO2 support | Planned |
| IA-8(2) | Acceptance of External Authenticators | OIDC federation | Planned |

### IA-11: Re-Authentication

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| IA-11 | Re-Authentication | Step-up authentication | Planned |

### IA-12: Identity Proofing

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| IA-12 | Identity Proofing | User registration flow | Planned |
| IA-12(2) | Identity Evidence | Email verification | Planned |

---

## SC - System and Communications Protection

### SC-8: Transmission Confidentiality and Integrity

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| SC-8 | Transmission Confidentiality | TLS required | Planned |
| SC-8(1) | Cryptographic Protection | TLS 1.3, modern ciphers | Planned |

### SC-12: Cryptographic Key Establishment and Management

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| SC-12 | Cryptographic Key Management | `kc-crypto` key handling | Planned |
| SC-12(1) | Availability | Key backup/recovery | Planned |

### SC-13: Cryptographic Protection

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| SC-13 | Cryptographic Protection | aws-lc-rs (FIPS capable) | Planned |

**Approved Algorithms (CNSA 2.0 Compliant):**

- Signing: RS384, RS512, ES384, ES512, PS384, PS512 (NO RS256, ES256, PS256)
- Hashing: SHA-384, SHA-512 (NO SHA-256)
- Password: Argon2id (with SHA-384/512 internally)
- Key Exchange: ECDH (P-384, P-521 only - NO P-256)
- Encryption: AES-256 only (NO AES-128)

**FORBIDDEN per CNSA 2.0:**

- SHA-256, SHA-1, MD5
- P-256/secp256r1 curves
- RSA keys < 3072 bits
- AES-128, 3DES

### SC-17: Public Key Infrastructure Certificates

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| SC-17 | PKI Certificates | JWKS management | Planned |

### SC-23: Session Authenticity

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| SC-23 | Session Authenticity | Signed session cookies | Planned |

### SC-28: Protection of Information at Rest

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| SC-28 | Protection at Rest | Encrypted credential storage | Planned |
| SC-28(1) | Cryptographic Protection | Database encryption | Planned |

---

## SI - System and Information Integrity

### SI-2: Flaw Remediation

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| SI-2 | Flaw Remediation | cargo audit in CI/CD | Planned |
| SI-2(2) | Automated Flaw Remediation | Dependabot/Renovate | Planned |

### SI-4: System Monitoring

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| SI-4 | System Monitoring | Metrics and tracing | Planned |
| SI-4(4) | Inbound and Outbound Traffic | Request logging | Planned |

### SI-7: Software, Firmware, and Information Integrity

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| SI-7 | Software Integrity | cargo audit, SBOM | Planned |
| SI-7(1) | Integrity Checks | Signature verification | Planned |

### SI-10: Information Input Validation

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| SI-10 | Input Validation | Request validation | Planned |

**Validation Requirements:**

- All user input sanitized
- SQL injection prevention (parameterized queries)
- XSS prevention (output encoding)
- CSRF protection (tokens)

### SI-11: Error Handling

| Control | Description | Implementation | Status |
| ------- | ----------- | -------------- | ------ |
| SI-11 | Error Handling | Generic error responses | Planned |

---

## Implementation Checklist

### Phase 1 (Core Infrastructure)

- [ ] AU-2: Event logging framework
- [ ] SC-12: Key management traits
- [ ] SC-13: Cryptographic provider (aws-lc-rs)

### Phase 2 (Storage Layer)

- [ ] SC-28: Encrypted storage
- [ ] SI-10: Input validation

### Phase 3 (Authentication Engine)

- [ ] IA-2: Authentication flows
- [ ] IA-5: Credential management
- [ ] AC-7: Brute force protection
- [ ] IA-6: Generic error messages

### Phase 4 (OIDC Protocol)

- [ ] AC-12: Session termination
- [ ] SC-8: TLS enforcement
- [ ] SC-23: Session authenticity

### Phase 5 (Admin API)

- [ ] AC-2: Account management
- [ ] AC-3: Access enforcement
- [ ] AC-6: Least privilege

---

## Code Annotation Format

When implementing a control, annotate the code:

```rust
/// NIST 800-53 Rev5: IA-5(1)(a) - Password Complexity
/// Enforces minimum password length of 12 characters.
pub fn validate_password_length(password: &str) -> Result<(), PasswordError> {
    if password.len() < 12 {
        return Err(PasswordError::TooShort { minimum: 12 });
    }
    Ok(())
}
```

---

## References

- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
