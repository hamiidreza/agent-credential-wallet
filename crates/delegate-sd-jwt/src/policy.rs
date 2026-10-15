//! The user's policy for an agent wallet: which claims it may prove, to which
//! verifier, and until when.
//!
//! The format is the `delegate_payload` array of a sub-credential
//! (`draft-gco-oauth-delegate-sd-jwt-00`, Section 5.1.4) before it is signed:
//! one entry per audience, each with its own allow-list and expiry. `aud` and
//! `exp` are the registered JWT claims; `allowed_claims` is this project's,
//! as the draft leaves constraint claims to the application (Section 8.2).
//!
//! ```json
//! {
//!   "delegate_payload": [
//!     {"aud": "https://wine-shop.example", "allowed_claims": ["age_over_18"], "exp": 1830297600},
//!     {"aud": "https://pharmacy.example", "allowed_claims": ["age_over_18", "birthdate"], "exp": 1830297600}
//!   ]
//! }
//! ```
//!
//! Until section F signs it into a sub-credential, the policy is a local file,
//! and only as trustworthy as the file permissions that keep the agent from
//! rewriting it.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// What the user allows for one audience: one element of `delegate_payload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// The verifier. Compared with the request's audience as an exact,
    /// case-sensitive string, as RFC 7519 compares `aud`. No wildcards.
    pub aud: String,
    /// Names of the claims this verifier may be shown.
    pub allowed_claims: Vec<String>,
    /// When the grant expires, in seconds since the Unix epoch.
    pub exp: u64,
}

/// A validated policy. The only ways to build one check the rules in
/// [`Policy::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    grants: Vec<Grant>,
}

/// The policy file. Unknown fields are rejected rather than ignored, so a
/// misspelt or unsupported rule is an error instead of a rule nobody enforces.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    delegate_payload: Vec<Grant>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// Not JSON, or not shaped like a policy: a field missing, mistyped or unknown.
    #[error("malformed policy: {0}")]
    Malformed(#[from] serde_json::Error),

    /// Well-formed, but breaks one of the rules in [`Policy::new`].
    #[error("invalid policy: {0}")]
    Invalid(&'static str),
}

impl Policy {
    /// Parses a policy file.
    pub fn from_json(json: &str) -> Result<Self, PolicyError> {
        let file: PolicyFile = serde_json::from_str(json)?;
        Self::new(file.delegate_payload)
    }

    /// Builds a policy from its grants. Rejects a policy with no grants, an
    /// empty `aud`, two grants for the same `aud`, or a grant that allows no
    /// claims: each is far more likely a mistake than an intent.
    pub fn new(grants: Vec<Grant>) -> Result<Self, PolicyError> {
        let invalid = PolicyError::Invalid;
        if grants.is_empty() {
            return Err(invalid("delegate_payload is empty"));
        }
        let mut audiences = HashSet::new();
        for grant in &grants {
            if grant.aud.is_empty() {
                return Err(invalid("an entry has an empty aud"));
            }
            if !audiences.insert(grant.aud.as_str()) {
                return Err(invalid("two entries have the same aud"));
            }
            if grant.allowed_claims.is_empty() {
                return Err(invalid("an entry allows no claims"));
            }
        }
        Ok(Self { grants })
    }

    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }
}