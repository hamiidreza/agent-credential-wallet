//! Sub-credentials: the Key Binding SD-JWT+KB (KB-SD-JWT+KB) of
//! `draft-gco-oauth-delegate-sd-jwt-00`.
//!
//! The user wallet signs a sub-credential with `sk_U` as the key binding of
//! its ID credential, so the key in the credential's `cnf`, `pk_U`, is what
//! verifies it. It is an SD-JWT in its own right:
//!
//! ```text
//! header:  {"alg": "ML-DSA-44", "typ": "kb+sd-jwt+kb"}
//! payload: {
//!   "iat": 1792000000,
//!   "aud": "<the agent wallet>",
//!   "nonce": "<chosen by the agent wallet>",
//!   "issuer_jwt_hash": "<SHA-256 of the issuer-signed JWT>",
//!   "_sd_alg": "sha-256",
//!   "delegate_payload": [{"...": "<digest>"}, {"...": "<digest>"}]
//! }
//! ```
//!
//! Each element of `delegate_payload` is one [`Grant`] of the user's
//! [`Policy`] with `pk_S` added in `cnf`, hidden behind an array-element
//! Disclosure:
//!
//! ```text
//! [salt, {"aud": "https://wine-shop.example", "allowed_claims": ["age_over_18"],
//!         "exp": 1830297600, "cnf": {"jwk": <pk_S>}}]
//! ```
//!
//! The agent wallet holds every Disclosure and shows each verifier only the
//! one for that verifier, so the wine shop does not learn who else the user
//! authorised. One `sk_U` signature covers every grant.
//!
//! On the wire, the sub-credential follows the credential after an empty
//! component (Section 5.1.1), and the agent wallet's KB-JWT follows it:
//!
//! ```text
//! <issuer JWT>~<Disclosure>~...~~<KB-SD-JWT>~<delegate Disclosure>~...~<KB-JWT>
//! ```
//!
//! Where the draft leaves room, this profile chooses:
//!
//! - Binding is always `issuer_jwt_hash`, over the issuer-signed JWT alone.
//!   `sd_hash` would freeze the credential's Disclosures at delegation time,
//!   so every verifier would see every delegated claim.
//! - Every element of `delegate_payload` is a Disclosure, even when there is
//!   only one, and every element names the same `cnf`: one sub-credential
//!   delegates to one agent wallet.
//! - An element with any claim besides `aud`, `allowed_claims`, `exp` and
//!   `cnf` is rejected. An unknown claim may be a constraint the verifier
//!   doesn't understand, and ignoring a constraint is worse than refusing.
//! - `aud` and `nonce` at the top level are the claims RFC 9901 requires of a
//!   KB-JWT. They name the agent wallet that receives the delegation and a
//!   nonce it chose, so only it can check them; a verifier ignores them.
//! - `iat` is not checked for freshness. A sub-credential is meant to be used
//!   for as long as its grants last; each grant's `exp` bounds it instead.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sd_jwt_9901::disclosure::{Disclosure, random_salt, sha256_b64};
use sd_jwt_9901::error::Error as SdJwtError;
use sd_jwt_9901::jws::{self, Signer, Verifier};
use sd_jwt_9901::mldsa::MlDsaVerifyingKey;
use sd_jwt_9901::sd_jwt::{Claims, SdJwt};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::policy::{Grant, Policy, PolicyError};

/// The `typ` of a sub-credential. The draft's media type registration and
/// Sections 2 and 5.1.4 spell it this way; Section 6 spells it
/// `kb-sd-jwt+kb`, which this crate does not accept.
pub const TYP: &str = "kb+sd-jwt+kb";

#[derive(Debug, thiserror::Error)]
pub enum DelegationError {
    /// A signature, a Disclosure or the SD-JWT structure is wrong.
    #[error(transparent)]
    SdJwt(#[from] SdJwtError),

    /// The grants break one of the rules in [`Policy::new`].
    #[error(transparent)]
    Policy(#[from] PolicyError),

    /// The sub-credential breaks a rule of the draft or of this profile.
    #[error("invalid sub-credential: {0}")]
    Invalid(&'static str),
}

/// The agent wallet a sub-credential is issued to.
#[derive(Debug, Clone, Copy)]
pub struct DelegateHolder<'a> {
    /// `pk_S`. It goes in the `cnf` of every grant.
    pub key: &'a MlDsaVerifyingKey,
    /// The agent wallet's identifier: the sub-credential's `aud`.
    pub id: &'a str,
    /// A nonce the agent wallet chose: the sub-credential's `nonce`.
    pub nonce: &'a str,
}

/// One element of `delegate_payload`: a grant, and the key it is granted to.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegatePayload {
    aud: String,
    allowed_claims: Vec<String>,
    exp: u64,
    cnf: Cnf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cnf {
    jwk: Map<String, Value>,
}

/// What a verified sub-credential says.
#[derive(Debug, Clone)]
pub struct Delegation {
    /// The disclosed grants: all of them for the agent wallet, exactly one
    /// for a verifier.
    pub policy: Policy,
    /// `pk_S`, the key the grants are delegated to.
    pub delegate: MlDsaVerifyingKey,
    /// The sub-credential's `aud`: the agent wallet it was issued to.
    pub audience: String,
    /// The sub-credential's `nonce`, chosen by the agent wallet.
    pub nonce: String,
    /// When the user wallet signed it, in seconds since the Unix epoch.
    pub iat: u64,
}

impl Delegation {
    /// The single grant a presentation must carry (draft Section 6, step
    /// 3.2). A verifier calls this; the agent wallet, which holds every grant,
    /// does not.
    pub fn presented_grant(&self) -> Result<&Grant, DelegationError> {
        match self.policy.grants() {
            [grant] => Ok(grant),
            _ => Err(DelegationError::Invalid(
                "a presentation must disclose exactly one delegate payload",
            )),
        }
    }
}

/// A signed sub-credential with the Disclosures of its grants.
#[derive(Clone, Debug, PartialEq)]
pub struct SubCredential(SdJwt);

impl SubCredential {
    /// The user wallet's side: delegates every grant of `policy` to
    /// `delegate`, bound to the credential whose issuer-signed JWT is
    /// `issuer_jwt`, and signs with `user`, the key in that credential's
    /// `cnf`. `iat` is the time of signing, in seconds since the Unix epoch.
    pub fn issue(
        issuer_jwt: &str,
        policy: &Policy,
        delegate: &DelegateHolder,
        iat: u64,
        user: &dyn Signer,
    ) -> Result<Self, DelegationError> {
        let mut disclosures = Vec::new();
        for grant in policy.grants() {
            let element = DelegatePayload {
                aud: grant.aud.clone(),
                allowed_claims: grant.allowed_claims.clone(),
                exp: grant.exp,
                cnf: Cnf {
                    jwk: delegate.key.to_jwk(),
                },
            };
            let element = serde_json::to_value(element)
                .map_err(|_| SdJwtError::SigningFailed("grant is not serialisable".into()))?;
            disclosures.push(Disclosure::new(&random_salt()?, None, element));
        }
        // Sorted, so the order of the placeholders says nothing about the
        // order of the grants.
        let mut digests: Vec<String> = disclosures.iter().map(Disclosure::digest).collect();
        digests.sort();
        let placeholders: Vec<Value> = digests.into_iter().map(|d| json!({"...": d})).collect();

        let payload = json!({
            "iat": iat,
            "aud": delegate.id,
            "nonce": delegate.nonce,
            "issuer_jwt_hash": sha256_b64(issuer_jwt.as_bytes()),
            "_sd_alg": "sha-256",
            "delegate_payload": placeholders,
        });
        let mut header = Map::new();
        header.insert("typ".into(), TYP.into());
        let jwt = jws::sign(header, payload.to_string().as_bytes(), user)?;
        Ok(Self(SdJwt {
            jwt,
            disclosures,
            kb_jwt: None,
        }))
    }

    /// The agent wallet's side: keeps only the grant for `aud`, the verifier
    /// in front of it. `None` if no grant names it. The other grants'
    /// digests stay in the signed payload; their contents don't travel.
    pub fn present(&self, aud: &str) -> Option<Self> {
        let grant = self
            .0
            .disclosures
            .iter()
            .find(|d| d.value.get("aud").and_then(Value::as_str) == Some(aud))?;
        Some(Self(SdJwt {
            jwt: self.0.jwt.clone(),
            disclosures: vec![grant.clone()],
            kb_jwt: None,
        }))
    }

    /// Checks the sub-credential as the key binding of the credential whose
    /// issuer-signed JWT is `issuer_jwt`. `user` must be the key in that
    /// credential's `cnf`, which the caller has already verified.
    ///
    /// Does not check expiry: each grant has its own `exp`, which
    /// [`Policy::check`] enforces on every request.
    pub fn verify(
        &self,
        issuer_jwt: &str,
        user: &dyn Verifier,
    ) -> Result<Delegation, DelegationError> {
        let invalid = DelegationError::Invalid;
        // The signature, `typ`, and RFC 9901's rules for the Disclosures.
        let claims = SdJwt::verify(&self.to_string(), TYP, user)?;

        // Draft Section 8.1: bound to this credential and no other.
        if claims.contains_key("sd_hash") {
            return Err(invalid(
                "sd_hash is not supported; bind with issuer_jwt_hash",
            ));
        }
        let expected = sha256_b64(issuer_jwt.as_bytes());
        match claims.get("issuer_jwt_hash").and_then(Value::as_str) {
            Some(hash) if hash == expected => {}
            Some(_) => return Err(invalid("issuer_jwt_hash does not match the credential")),
            None => return Err(invalid("missing issuer_jwt_hash")),
        }

        let text = |name: &str| claims.get(name).and_then(Value::as_str).map(String::from);
        let audience = text("aud").ok_or(invalid("missing aud"))?;
        let nonce = text("nonce").ok_or(invalid("missing nonce"))?;
        let iat = claims
            .get("iat")
            .and_then(Value::as_u64)
            .ok_or(invalid("missing iat"))?;

        // Every element must have been a Disclosure. Only the signed payload
        // shows that: once processed, a plain element looks like a disclosed one.
        let signed = signed_payload(&self.0.jwt)?;
        let Some(Value::Array(elements)) = signed.get("delegate_payload") else {
            return Err(invalid("delegate_payload is missing or not an array"));
        };
        if !elements.iter().all(is_placeholder) {
            return Err(invalid(
                "every delegate_payload element must be a Disclosure",
            ));
        }

        let Some(Value::Array(disclosed)) = claims.get("delegate_payload") else {
            return Err(invalid("delegate_payload is missing or not an array"));
        };
        let mut grants = Vec::new();
        let mut delegate: Option<Map<String, Value>> = None;
        for element in disclosed {
            let payload: DelegatePayload = serde_json::from_value(element.clone())
                .map_err(|_| invalid("a delegate payload is malformed or has an unknown claim"))?;
            match &delegate {
                None => delegate = Some(payload.cnf.jwk),
                Some(jwk) if *jwk == payload.cnf.jwk => {}
                Some(_) => return Err(invalid("delegate payloads name different keys")),
            }
            grants.push(Grant {
                aud: payload.aud,
                allowed_claims: payload.allowed_claims,
                exp: payload.exp,
            });
        }
        let delegate = delegate.ok_or(invalid("no delegate payload is disclosed"))?;
        Ok(Delegation {
            policy: Policy::new(grants)?,
            delegate: MlDsaVerifyingKey::from_jwk(&delegate)?,
            audience,
            nonce,
            iat,
        })
    }

    /// Parses `<KB-SD-JWT>~<Disclosure>~...~`, with no KB-JWT after it.
    pub fn parse(s: &str) -> Result<Self, DelegationError> {
        let sd_jwt = SdJwt::parse(s)?;
        if sd_jwt.kb_jwt.is_some() {
            return Err(DelegationError::Invalid(
                "a sub-credential on its own ends in '~'",
            ));
        }
        Ok(Self(sd_jwt))
    }

    /// The signed JWT and its Disclosures, as an SD-JWT.
    pub fn as_sd_jwt(&self) -> &SdJwt {
        &self.0
    }
}

impl fmt::Display for SubCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A credential with its sub-credential: the draft's dSD-JWT, or with the
/// agent wallet's KB-JWT, its dSD-JWT+KB (Section 5.1.1).
///
/// ```text
/// <issuer JWT>~<Disclosure>~...~~<KB-SD-JWT>~<delegate Disclosure>~...~[<KB-JWT>]
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct DelegatedSdJwt {
    /// The issuer-signed credential and the Disclosures sent with it.
    pub credential: SdJwt,
    pub sub_credential: SubCredential,
    /// The agent wallet's KB-JWT, signed with `sk_S`, if this is a presentation.
    pub kb_jwt: Option<String>,
}

impl DelegatedSdJwt {
    /// Splits at the empty component that marks where the sub-credential
    /// starts. Only one delegation is supported, so a second empty component
    /// is rejected.
    pub fn parse(s: &str) -> Result<Self, DelegationError> {
        let (credential, rest) = s.split_once("~~").ok_or(DelegationError::Invalid(
            "no empty component before the sub-credential",
        ))?;
        let credential = SdJwt::parse(&format!("{credential}~"))?;
        let mut sub_credential = SdJwt::parse(rest)?;
        let kb_jwt = sub_credential.kb_jwt.take();
        Ok(Self {
            credential,
            sub_credential: SubCredential(sub_credential),
            kb_jwt,
        })
    }

    /// Verifies both signed links: the issuer's signature on the credential,
    /// whose `typ` must be `typ`, then the sub-credential against the key in
    /// the credential's `cnf`. Returns the disclosed credential claims and
    /// the delegation.
    ///
    /// The KB-JWT signed with `sk_S` is not checked here.
    pub fn verify(
        &self,
        typ: &str,
        issuer: &dyn Verifier,
    ) -> Result<(Claims, Delegation), DelegationError> {
        let credential = SdJwt {
            kb_jwt: None,
            ..self.credential.clone()
        };
        let claims = SdJwt::verify(&credential.to_string(), typ, issuer)?;
        let jwk = claims
            .get("cnf")
            .and_then(|cnf| cnf.get("jwk"))
            .and_then(Value::as_object)
            .ok_or(DelegationError::Invalid("the credential has no cnf.jwk"))?;
        let user = MlDsaVerifyingKey::from_jwk(jwk)?;
        let delegation = self.sub_credential.verify(&self.credential.jwt, &user)?;
        Ok((claims, delegation))
    }
}

impl fmt::Display for DelegatedSdJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}~", self.credential.jwt)?;
        for d in &self.credential.disclosures {
            write!(f, "{}~", d.encoded)?;
        }
        write!(f, "~{}", self.sub_credential)?;
        f.write_str(self.kb_jwt.as_deref().unwrap_or(""))
    }
}

/// The payload of a JWT whose signature has already been checked.
fn signed_payload(jwt: &str) -> Result<Map<String, Value>, DelegationError> {
    let invalid = DelegationError::Invalid;
    let payload = jwt.split('.').nth(1).ok_or(invalid("malformed JWT"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| invalid("malformed JWT"))?;
    serde_json::from_slice(&bytes).map_err(|_| invalid("malformed JWT"))
}

/// Whether `element` is `{"...": digest}`, the placeholder for a Disclosure.
fn is_placeholder(element: &Value) -> bool {
    element
        .as_object()
        .is_some_and(|obj| obj.len() == 1 && obj.get("...").is_some_and(Value::is_string))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sd_jwt_9901::jws::Algorithm;
    use sd_jwt_9901::mldsa::MlDsaSigningKey;

    const CREDENTIAL: &str = "dc+sd-jwt";
    const SHOP: &str = "https://wine-shop.example";
    const PHARMACY: &str = "https://pharmacy.example";
    const AGENT: &str = "urn:example:agent-wallet";
    const NONCE: &str = "d-nonce-1";
    const NOW: u64 = 1_800_000_000;

    fn key(alg: Algorithm) -> MlDsaSigningKey {
        MlDsaSigningKey::generate(alg).unwrap()
    }

    struct Parties {
        issuer: MlDsaSigningKey,
        user: MlDsaSigningKey,
        agent: MlDsaSigningKey,
        credential: SdJwt,
    }

    /// An issuer, a user with a credential bound to `sk_U`, and an agent
    /// wallet. `sk_U` uses `user_alg`; the others use ML-DSA-44.
    fn parties(user_alg: Algorithm) -> Parties {
        let (issuer, user, agent) = (
            key(Algorithm::MlDsa44),
            key(user_alg),
            key(Algorithm::MlDsa44),
        );
        let credential = credential(&issuer, &user);
        Parties {
            issuer,
            user,
            agent,
            credential,
        }
    }

    fn credential(issuer: &MlDsaSigningKey, user: &MlDsaSigningKey) -> SdJwt {
        let claims: Claims = serde_json::from_value(json!({
            "iss": "https://issuer.example",
            "cnf": {"jwk": user.verifying_key().to_jwk()},
            "given_name": "Erika",
            "birthdate": "1964-08-12",
            "age_over_18": true,
        }))
        .unwrap();
        let hidden = ["given_name", "birthdate", "age_over_18"];
        SdJwt::issue(claims, &hidden, CREDENTIAL, issuer).unwrap()
    }

    /// The shop may see `age_over_18`; the pharmacy `birthdate` as well.
    fn policy() -> Policy {
        let grant = |aud: &str, claims: &[&str]| Grant {
            aud: aud.into(),
            allowed_claims: claims.iter().map(|c| (*c).into()).collect(),
            exp: NOW + 3600,
        };
        Policy::new(vec![
            grant(SHOP, &["age_over_18"]),
            grant(PHARMACY, &["age_over_18", "birthdate"]),
        ])
        .unwrap()
    }

    fn delegate(p: &Parties) -> SubCredential {
        let pk_s = p.agent.verifying_key();
        let holder = DelegateHolder {
            key: &pk_s,
            id: AGENT,
            nonce: NONCE,
        };
        SubCredential::issue(&p.credential.jwt, &policy(), &holder, NOW, &p.user).unwrap()
    }

    fn invalid<T: fmt::Debug>(result: Result<T, DelegationError>) -> &'static str {
        match result {
            Err(DelegationError::Invalid(reason)) => reason,
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn the_agent_wallet_sees_every_grant() {
        let p = parties(Algorithm::MlDsa44);
        let sub = delegate(&p);
        let delegation = sub
            .verify(&p.credential.jwt, &p.user.verifying_key())
            .unwrap();
        // In digest order, which the random salts shuffle: compare as sets.
        let sorted = |policy: &Policy| {
            let mut grants = policy.grants().to_vec();
            grants.sort_by(|a, b| a.aud.cmp(&b.aud));
            grants
        };
        assert_eq!(sorted(&delegation.policy), sorted(&policy()));
        assert_eq!(
            delegation.delegate.to_jwk(),
            p.agent.verifying_key().to_jwk()
        );
        assert_eq!(delegation.audience, AGENT);
        assert_eq!(delegation.nonce, NONCE);
        assert_eq!(delegation.iat, NOW);
        assert!(delegation.presented_grant().is_err());
    }

    #[test]
    fn a_verifier_sees_only_its_own_grant() {
        let p = parties(Algorithm::MlDsa44);
        let sub = delegate(&p);
        let at_shop = sub.present(SHOP).unwrap();
        let delegation = at_shop
            .verify(&p.credential.jwt, &p.user.verifying_key())
            .unwrap();
        let grant = delegation.presented_grant().unwrap();
        assert_eq!(grant, &policy().grants()[0]);
        // The pharmacy's Disclosure does not travel; only its digest does.
        let pharmacy = sub
            .as_sd_jwt()
            .disclosures
            .iter()
            .find(|d| d.value["aud"] == PHARMACY)
            .unwrap();
        assert!(!at_shop.to_string().contains(&pharmacy.encoded));
        assert!(sub.present("https://attacker.com").is_none());
    }

    #[test]
    fn the_signed_payload_hides_the_grants() {
        let p = parties(Algorithm::MlDsa44);
        let payload = signed_payload(&delegate(&p).as_sd_jwt().jwt).unwrap();
        let elements = payload["delegate_payload"].as_array().unwrap();
        assert_eq!(elements.len(), 2);
        assert!(elements.iter().all(is_placeholder));
        assert!(!Value::Object(payload).to_string().contains("wine-shop"));
    }

    #[test]
    fn mixed_parameter_sets_verify() {
        // sk_U on ML-DSA-65, as on an iPhone; the issuer and sk_S on 44.
        let p = parties(Algorithm::MlDsa65);
        let sub = delegate(&p);
        assert!(
            sub.verify(&p.credential.jwt, &p.user.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn spliced_onto_another_credential_is_rejected() {
        // Draft Section 8.1: the same sk_U holds two credentials, and the
        // sub-credential for one is attached to the other.
        let p = parties(Algorithm::MlDsa44);
        let other = credential(&p.issuer, &p.user);
        let result = delegate(&p).verify(&other.jwt, &p.user.verifying_key());
        assert_eq!(
            invalid(result),
            "issuer_jwt_hash does not match the credential"
        );
    }

    #[test]
    fn signed_by_anyone_but_the_user_is_rejected() {
        let p = parties(Algorithm::MlDsa44);
        let impostor = key(Algorithm::MlDsa44).verifying_key();
        let result = delegate(&p).verify(&p.credential.jwt, &impostor);
        assert!(matches!(
            result,
            Err(DelegationError::SdJwt(SdJwtError::InvalidSignature))
        ));
    }

    #[test]
    fn a_forged_grant_is_rejected() {
        // A compromised agent wallet widens its own policy without sk_U.
        let p = parties(Algorithm::MlDsa44);
        let mut sub = delegate(&p).present(SHOP).unwrap();
        let forged = json!({
            "aud": SHOP, "allowed_claims": ["age_over_18", "birthdate"], "exp": u64::MAX,
            "cnf": {"jwk": p.agent.verifying_key().to_jwk()},
        });
        sub.0.disclosures = vec![Disclosure::new(&random_salt().unwrap(), None, forged)];
        let result = sub.verify(&p.credential.jwt, &p.user.verifying_key());
        assert!(matches!(
            result,
            Err(DelegationError::SdJwt(SdJwtError::InvalidSdJwt(
                "a Disclosure matches no digest in the payload"
            )))
        ));
    }

    /// Signs `payload` as a sub-credential, with `elements` as the grants,
    /// each a Disclosure unless `plain`.
    fn hand_built(
        p: &Parties,
        typ: &str,
        mut payload: Value,
        elements: Vec<Value>,
        plain: bool,
    ) -> SubCredential {
        let mut disclosures = Vec::new();
        let mut placeholders = Vec::new();
        for element in elements {
            if plain {
                placeholders.push(element);
            } else {
                let d = Disclosure::new(&random_salt().unwrap(), None, element);
                placeholders.push(json!({"...": d.digest()}));
                disclosures.push(d);
            }
        }
        payload["delegate_payload"] = placeholders.into();
        let mut header = Map::new();
        header.insert("typ".into(), typ.into());
        let jwt = jws::sign(header, payload.to_string().as_bytes(), &p.user).unwrap();
        SubCredential(SdJwt {
            jwt,
            disclosures,
            kb_jwt: None,
        })
    }

    #[test]
    fn rejects_sub_credentials_outside_the_profile() {
        let p = parties(Algorithm::MlDsa44);
        let pk_s = json!({"jwk": p.agent.verifying_key().to_jwk()});
        let shop = json!({"aud": SHOP, "allowed_claims": ["age_over_18"], "exp": NOW, "cnf": pk_s});
        let hash = sha256_b64(p.credential.jwt.as_bytes());
        let top = |remove: &str, add: Value| {
            let mut payload = json!({
                "iat": NOW, "aud": AGENT, "nonce": NONCE,
                "issuer_jwt_hash": hash, "_sd_alg": "sha-256",
            });
            payload.as_object_mut().unwrap().remove(remove);
            for (k, v) in add.as_object().unwrap() {
                payload[k] = v.clone();
            }
            payload
        };
        let with = |changes: Value| {
            let mut element = shop.clone();
            for (k, v) in changes.as_object().unwrap() {
                element[k] = v.clone();
            }
            element
        };
        let other_key = json!({"jwk": key(Algorithm::MlDsa44).verifying_key().to_jwk()});

        for (case, sub, reason) in [
            (
                "a plain element",
                hand_built(&p, TYP, top("", json!({})), vec![shop.clone()], true),
                "every delegate_payload element must be a Disclosure",
            ),
            (
                "an unknown constraint",
                hand_built(
                    &p,
                    TYP,
                    top("", json!({})),
                    vec![with(json!({"max_amount": 50}))],
                    false,
                ),
                "a delegate payload is malformed or has an unknown claim",
            ),
            (
                "no cnf",
                hand_built(
                    &p,
                    TYP,
                    top("", json!({})),
                    vec![json!({"aud": SHOP, "allowed_claims": ["age_over_18"], "exp": NOW})],
                    false,
                ),
                "a delegate payload is malformed or has an unknown claim",
            ),
            (
                "two delegates",
                hand_built(
                    &p,
                    TYP,
                    top("", json!({})),
                    vec![
                        shop.clone(),
                        with(json!({"aud": PHARMACY, "cnf": other_key})),
                    ],
                    false,
                ),
                "delegate payloads name different keys",
            ),
            (
                "sd_hash instead of issuer_jwt_hash",
                hand_built(
                    &p,
                    TYP,
                    top("issuer_jwt_hash", json!({"sd_hash": hash})),
                    vec![shop.clone()],
                    false,
                ),
                "sd_hash is not supported; bind with issuer_jwt_hash",
            ),
            (
                "no binding",
                hand_built(
                    &p,
                    TYP,
                    top("issuer_jwt_hash", json!({})),
                    vec![shop.clone()],
                    false,
                ),
                "missing issuer_jwt_hash",
            ),
            (
                "no nonce",
                hand_built(&p, TYP, top("nonce", json!({})), vec![shop.clone()], false),
                "missing nonce",
            ),
            (
                "no grants",
                hand_built(&p, TYP, top("", json!({})), vec![], false),
                "no delegate payload is disclosed",
            ),
        ] {
            let result = sub.verify(&p.credential.jwt, &p.user.verifying_key());
            assert_eq!(invalid(result), reason, "{case}");
        }

        // The other spelling of the typ, from the draft's Section 6.
        let sub = hand_built(&p, "kb-sd-jwt+kb", top("", json!({})), vec![shop], false);
        let result = sub.verify(&p.credential.jwt, &p.user.verifying_key());
        assert!(matches!(
            result,
            Err(DelegationError::SdJwt(SdJwtError::InvalidSdJwt(
                "unexpected typ"
            )))
        ));
    }

    #[test]
    fn the_credential_disclosures_can_differ_per_verifier() {
        // What issuer_jwt_hash buys: one sub-credential, a different subset of
        // the credential's Disclosures for each verifier.
        let p = parties(Algorithm::MlDsa44);
        let sub = delegate(&p);
        for (aud, reveal) in [(SHOP, vec!["age_over_18"]), (PHARMACY, vec!["birthdate"])] {
            let presented = DelegatedSdJwt {
                credential: p.credential.present(&reveal),
                sub_credential: sub.present(aud).unwrap(),
                kb_jwt: None,
            };
            let parsed = DelegatedSdJwt::parse(&presented.to_string()).unwrap();
            let (claims, delegation) = parsed
                .verify(CREDENTIAL, &p.issuer.verifying_key())
                .unwrap();
            assert!(claims.contains_key(reveal[0]));
            assert_eq!(delegation.presented_grant().unwrap().aud, aud);
        }
    }

    #[test]
    fn the_chain_needs_the_issuer_and_the_user() {
        let p = parties(Algorithm::MlDsa44);
        let chain = DelegatedSdJwt {
            credential: p.credential.clone(),
            sub_credential: delegate(&p),
            kb_jwt: None,
        };
        let impostor = key(Algorithm::MlDsa44).verifying_key();
        assert!(matches!(
            chain.verify(CREDENTIAL, &impostor),
            Err(DelegationError::SdJwt(SdJwtError::InvalidSignature))
        ));

        // A credential bound to someone else's key, carrying our sub-credential.
        let someone = key(Algorithm::MlDsa44);
        let spliced = DelegatedSdJwt {
            credential: credential(&p.issuer, &someone),
            ..chain
        };
        assert!(
            spliced
                .verify(CREDENTIAL, &p.issuer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn compact_serialisation() {
        let p = parties(Algorithm::MlDsa44);
        let sub = delegate(&p);
        let handover = DelegatedSdJwt {
            credential: p.credential.clone(),
            sub_credential: sub.clone(),
            kb_jwt: None,
        };
        let text = handover.to_string();
        // <issuer JWT>~<D>~<D>~<D>~~<KB-SD-JWT>~<DD>~<DD>~
        assert_eq!(text.split('~').count(), 1 + 3 + 1 + 1 + 2 + 1);
        assert!(text.contains(&format!("~~{}~", sub.as_sd_jwt().jwt)));
        assert!(text.ends_with('~'));
        assert_eq!(DelegatedSdJwt::parse(&text).unwrap(), handover);

        // With a KB-JWT, and with no credential Disclosures at all.
        let presented = DelegatedSdJwt {
            credential: p.credential.present(&[]),
            sub_credential: sub.present(SHOP).unwrap(),
            kb_jwt: Some("kb.jwt.here".into()),
        };
        let text = presented.to_string();
        assert!(text.starts_with(&format!("{}~~", p.credential.jwt)));
        assert!(text.ends_with("~kb.jwt.here"));
        assert_eq!(DelegatedSdJwt::parse(&text).unwrap(), presented);

        assert_eq!(SubCredential::parse(&sub.to_string()).unwrap(), sub);
        assert!(SubCredential::parse(&format!("{sub}kb.jwt.here")).is_err());
    }

    #[test]
    fn rejects_malformed_chains() {
        let p = parties(Algorithm::MlDsa44);
        let sub = delegate(&p);
        for bad in [
            // No empty component: an ordinary SD-JWT.
            p.credential.to_string(),
            // A second delegation: only one hop is supported.
            format!("{}~{sub}~{sub}", p.credential),
            String::new(),
            "~~".into(),
        ] {
            assert!(DelegatedSdJwt::parse(&bad).is_err(), "{bad:?}");
        }
    }
}
