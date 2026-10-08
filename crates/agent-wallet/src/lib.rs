//! The agent wallet: holds one credential and the key `sk_S`, and builds
//! presentations when the agent asks for them.
//!
//! It is the only component that holds secrets and acts unattended, so what it
//! gives out is limited to two things: the names of the claims it can prove,
//! and presentations. Never claim values, Disclosures, the credential or keys.

use schemars::JsonSchema;
use sd_jwt_9901::error::Error as SdJwtError;
use sd_jwt_9901::jws::Verifier;
use sd_jwt_9901::mldsa::MlDsaSigningKey;
use sd_jwt_9901::sd_jwt::{Claims, SdJwt};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The `typ` of the credentials this wallet holds.
pub const CREDENTIAL_TYP: &str = "dc+sd-jwt";

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("credential rejected: {0}")]
    Credential(#[from] SdJwtError),

    #[error("the credential is bound to a different key than this wallet's")]
    WrongKey,

    #[error("this wallet cannot prove the claim {0:?}")]
    UnknownClaim(String),
}

/// What the agent may learn about the credential: its type and the names of
/// the claims it can ask to have proven. Never their values.
#[derive(Debug, PartialEq, Serialize, JsonSchema)]
pub struct CredentialInfo {
    /// The credential's `vct`, if it has one.
    pub credential_type: Option<String>,
    /// The claims this wallet can prove.
    pub claims: Vec<String>,
}

/// What a verifier asks for: one claim, for one verifier, for one request.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PresentationRequest {
    /// The claim the verifier asked for, e.g. "age_over_18".
    pub claim: String,
    /// The verifier's identifier, exactly as it appears in its request.
    pub audience: String,
    /// The nonce from the verifier's request.
    pub nonce: String,
}

pub struct AgentWallet {
    credential: SdJwt,
    claims: Claims,
    key: MlDsaSigningKey,
}

impl AgentWallet {
    /// Loads a credential, as RFC 9901 requires a Holder to: checks the
    /// issuer's signature and every Disclosure, and that the credential is
    /// bound to this wallet's key.
    pub fn load(
        credential: &str,
        issuer: &dyn Verifier,
        key: MlDsaSigningKey,
    ) -> Result<Self, WalletError> {
        let claims = SdJwt::verify(credential, CREDENTIAL_TYP, issuer)?;
        let bound_to = claims.get("cnf").and_then(|cnf| cnf.get("jwk"));
        if bound_to != Some(&Value::Object(key.verifying_key().to_jwk())) {
            return Err(WalletError::WrongKey);
        }
        Ok(Self {
            credential: SdJwt::parse(credential)?,
            claims,
            key,
        })
    }

    pub fn find_credential(&self) -> CredentialInfo {
        let mut claims: Vec<String> = self
            .credential
            .disclosures
            .iter()
            .filter_map(|d| d.name.clone())
            .collect();
        claims.sort();
        CredentialInfo {
            credential_type: self
                .claims
                .get("vct")
                .and_then(Value::as_str)
                .map(String::from),
            claims,
        }
    }

    /// Builds a presentation that discloses only `request.claim`, bound to
    /// `request.audience` and `request.nonce`.
    pub fn create_presentation(
        &self,
        request: &PresentationRequest,
    ) -> Result<String, WalletError> {
        let claim = request.claim.as_str();
        if !self.find_credential().claims.iter().any(|c| c == claim) {
            return Err(WalletError::UnknownClaim(claim.to_owned()));
        }
        let presentation =
            self.credential
                .present(&[claim])
                .bind(&request.audience, &request.nonce, &self.key)?;
        Ok(presentation.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sd_jwt_9901::jws::Algorithm;
    use serde_json::json;

    const SHOP: &str = "https://wine-shop.example";

    fn key() -> MlDsaSigningKey {
        MlDsaSigningKey::generate(Algorithm::MlDsa44).unwrap()
    }

    /// Stands in for the mock issuer of task 16.
    fn issue(issuer: &MlDsaSigningKey, holder: &MlDsaSigningKey) -> String {
        let claims: Claims = serde_json::from_value(json!({
            "iss": "https://issuer.example",
            "vct": "urn:example:id",
            "cnf": {"jwk": holder.verifying_key().to_jwk()},
            "given_name": "John",
            "birthdate": "1990-01-01",
            "age_over_18": true,
        }))
        .unwrap();
        let hidden = ["given_name", "birthdate", "age_over_18"];
        SdJwt::issue(claims, &hidden, CREDENTIAL_TYP, issuer)
            .unwrap()
            .to_string()
    }

    fn request(claim: &str) -> PresentationRequest {
        PresentationRequest {
            claim: claim.into(),
            audience: SHOP.into(),
            nonce: "n-1".into(),
        }
    }

    #[test]
    fn find_credential_shows_names_never_values() {
        let (issuer, holder) = (key(), key());
        let wallet =
            AgentWallet::load(&issue(&issuer, &holder), &issuer.verifying_key(), holder).unwrap();
        let info = wallet.find_credential();
        assert_eq!(info.credential_type.as_deref(), Some("urn:example:id"));
        assert_eq!(info.claims, ["age_over_18", "birthdate", "given_name"]);
        let shown = serde_json::to_string(&info).unwrap();
        assert!(!shown.contains("John") && !shown.contains("1990"));
    }

    #[test]
    fn presentation_discloses_only_the_requested_claim() {
        let (issuer, holder) = (key(), key());
        let wallet =
            AgentWallet::load(&issue(&issuer, &holder), &issuer.verifying_key(), holder).unwrap();
        let presentation = wallet.create_presentation(&request("age_over_18")).unwrap();
        let claims = SdJwt::verify_presentation(
            &presentation,
            CREDENTIAL_TYP,
            &issuer.verifying_key(),
            SHOP,
            "n-1",
        )
        .unwrap();
        assert_eq!(claims["age_over_18"], true);
        assert!(!claims.contains_key("birthdate") && !claims.contains_key("given_name"));
    }

    #[test]
    fn rejects_unknown_claims_and_foreign_credentials() {
        let (issuer, holder) = (key(), key());
        let credential = issue(&issuer, &holder);

        let wallet = AgentWallet::load(&credential, &issuer.verifying_key(), key());
        assert!(matches!(wallet, Err(WalletError::WrongKey)));

        let impostor = key().verifying_key();
        let wallet = AgentWallet::load(&credential, &impostor, holder);
        assert!(matches!(wallet, Err(WalletError::Credential(_))));

        let holder = key();
        let wallet =
            AgentWallet::load(&issue(&issuer, &holder), &issuer.verifying_key(), holder).unwrap();
        let result = wallet.create_presentation(&request("email"));
        assert!(matches!(result, Err(WalletError::UnknownClaim(_))));
    }
}
