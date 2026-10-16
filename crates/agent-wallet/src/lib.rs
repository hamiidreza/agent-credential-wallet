//! The agent wallet: holds one credential, the user's policy and the key
//! `sk_S`, and builds presentations when the agent asks for them, but only
//! ones the policy allows.
//!
//! It is the only component that holds secrets and acts unattended, so what it
//! gives out is limited to two things: the names of the claims it can prove,
//! and presentations. Never claim values, Disclosures, the credential, the policy or keys.

use std::time::{SystemTime, UNIX_EPOCH};

use delegate_sd_jwt::policy::{Policy, Refusal};
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

    /// The request is outside the user's policy. Nothing was signed.
    #[error("refused: {0}")]
    Refused(#[from] Refusal),
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
    policy: Policy,
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
        policy: Policy,
    ) -> Result<Self, WalletError> {
        let claims = SdJwt::verify(credential, CREDENTIAL_TYP, issuer)?;
        let bound_to = claims.get("cnf").and_then(|cnf| cnf.get("jwk"));
        if bound_to != Some(&Value::Object(key.verifying_key().to_jwk())) {
            return Err(WalletError::WrongKey);
        }
        Ok(Self {
            credential: SdJwt::parse(credential)?,
            claims,
            policy,
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
    /// `request.audience` and `request.nonce`  if the policy allows that claim
    /// for that audience right now. Otherwise refuses without signing anything.
    pub fn create_presentation(
        &self,
        request: &PresentationRequest,
    ) -> Result<String, WalletError> {
        // The policy goes first, so a refused request learns nothing about
        // which claims the credential holds.
        self.policy
            .check(&request.claim, &request.audience, now())?;
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

/// Seconds since the Unix epoch. A clock set before 1970 is broken, and is
/// read as the end of time, so that every grant counts as expired rather than
/// none.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use delegate_sd_jwt::policy::Grant;
    use sd_jwt_9901::jws::Algorithm;
    use serde_json::json;

    const SHOP: &str = "https://wine-shop.example";
    const PHARMACY: &str = "https://pharmacy.example";
    const ATTACKER: &str = "https://attacker.com";

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

    fn grant(aud: &str, claims: &[&str], exp: u64) -> Grant {
        Grant {
            aud: aud.into(),
            allowed_claims: claims.iter().map(|c| (*c).into()).collect(),
            exp,
        }
    }

    /// The shop may see `age_over_18`, the pharmacy `birthdate` as well, both
    /// for the next hour. Nobody may see `given_name`.
    fn policy() -> Policy {
        let exp = now() + 3600;
        Policy::new(vec![
            grant(SHOP, &["age_over_18"], exp),
            grant(PHARMACY, &["age_over_18", "birthdate"], exp),
        ])
        .unwrap()
    }

    /// A wallet with a fresh credential under `policy`, and its issuer.
    fn wallet(policy: Policy) -> (AgentWallet, MlDsaSigningKey) {
        let (issuer, holder) = (key(), key());
        let credential = issue(&issuer, &holder);
        let wallet = AgentWallet::load(&credential, &issuer.verifying_key(), holder, policy);
        (wallet.unwrap(), issuer)
    }

    fn request(claim: &str, audience: &str) -> PresentationRequest {
        PresentationRequest {
            claim: claim.into(),
            audience: audience.into(),
            nonce: "n-1".into(),
        }
    }

    fn refusal(result: Result<String, WalletError>) -> Refusal {
        match result {
            Err(WalletError::Refused(refusal)) => refusal,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn find_credential_shows_names_never_values() {
        let (wallet, _) = wallet(policy());
        let info = wallet.find_credential();
        assert_eq!(info.credential_type.as_deref(), Some("urn:example:id"));
        assert_eq!(info.claims, ["age_over_18", "birthdate", "given_name"]);
        let shown = serde_json::to_string(&info).unwrap();
        assert!(!shown.contains("John") && !shown.contains("1990"));
    }

    #[test]
    fn presentation_discloses_only_the_requested_claim() {
        let (wallet, issuer) = wallet(policy());
        let presentation = wallet
            .create_presentation(&request("age_over_18", SHOP))
            .unwrap();
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
    fn prompt_injection_to_an_unknown_audience_is_refused() {
        let (wallet, _) = wallet(policy());
        for claim in ["age_over_18", "birthdate", "given_name"] {
            assert_eq!(
                refusal(wallet.create_presentation(&request(claim, ATTACKER))),
                Refusal::UnknownAudience(ATTACKER.into())
            );
        }
    }

    #[test]
    fn claim_allowed_elsewhere_is_refused_here() {
        let (wallet, _) = wallet(policy());
        assert!(
            wallet
                .create_presentation(&request("birthdate", PHARMACY))
                .is_ok()
        );
        assert_eq!(
            refusal(wallet.create_presentation(&request("birthdate", SHOP))),
            Refusal::ClaimNotAllowed {
                claim: "birthdate".into(),
                aud: SHOP.into()
            }
        );
    }

    #[test]
    fn expired_grant_is_refused() {
        let (wallet, _) = wallet(
            Policy::new(vec![
                grant(SHOP, &["age_over_18"], now() - 1),
                grant(PHARMACY, &["age_over_18"], now() + 3600),
            ])
            .unwrap(),
        );
        assert_eq!(
            refusal(wallet.create_presentation(&request("age_over_18", SHOP))),
            Refusal::Expired(SHOP.into())
        );
        assert!(
            wallet
                .create_presentation(&request("age_over_18", PHARMACY))
                .is_ok()
        );
    }

    #[test]
    fn claim_the_policy_allows_but_the_credential_lacks_is_unknown() {
        let (wallet, _) = wallet(Policy::new(vec![grant(SHOP, &["email"], now() + 3600)]).unwrap());
        let result = wallet.create_presentation(&request("email", SHOP));
        assert!(matches!(result, Err(WalletError::UnknownClaim(_))));
    }

    #[test]
    fn rejects_foreign_credentials() {
        let (issuer, holder) = (key(), key());
        let credential = issue(&issuer, &holder);

        let wallet = AgentWallet::load(&credential, &issuer.verifying_key(), key(), policy());
        assert!(matches!(wallet, Err(WalletError::WrongKey)));

        let impostor = key().verifying_key();
        let wallet = AgentWallet::load(&credential, &impostor, holder, policy());
        assert!(matches!(wallet, Err(WalletError::Credential(_))));
    }
}
