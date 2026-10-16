//! Proof of possession of `sk_U`, for credential issuance.
//!
//! Shaped like the `jwt` proof type of OpenID for Verifiable Credential
//! Issuance 1.0 (Appendix F.1): the wallet signs the issuer's nonce with the
//! key it wants the credential bound to, and puts that key's public half in
//! the header.
//!
//! ```text
//! header:  {"alg": "ML-DSA-44", "typ": "openid4vci-proof+jwt", "jwk": <pk_U>}
//! payload: {"aud": "<issuer identifier>", "iat": 1792000000, "nonce": "<from the issuer>"}
//! ```
//!
//! The issuer checks the signature against the key in the header, then puts
//! that key in the credential's `cnf`.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sd_jwt_9901::error::Error as JwsError;
use sd_jwt_9901::jws;
use sd_jwt_9901::mldsa::{MlDsaSigningKey, MlDsaVerifyingKey};
use serde_json::{Map, Value, json};

/// The `typ` OpenID4VCI registers for this proof. A Key Binding JWT signed
/// with the same key has a different `typ`, so neither can pass for the other.
pub const TYP: &str = "openid4vci-proof+jwt";

/// How far `iat` may be from the issuer's clock, either way, in seconds.
const IAT_WINDOW: u64 = 300;

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("invalid proof: {0}")]
    Invalid(&'static str),

    #[error("invalid proof: {0}")]
    Jws(#[from] JwsError),
}

/// The wallet's side: signs `nonce` for the issuer `aud`, at time `iat`.
pub fn sign(key: &MlDsaSigningKey, aud: &str, nonce: &str, iat: u64) -> Result<String, JwsError> {
    let mut header = Map::new();
    header.insert("typ".into(), TYP.into());
    header.insert("jwk".into(), Value::Object(key.verifying_key().to_jwk()));
    let payload = json!({"aud": aud, "iat": iat, "nonce": nonce});
    jws::sign(header, payload.to_string().as_bytes(), key)
}

/// The issuer's side: checks a proof for this issuer (`aud`) and this
/// `nonce`, at time `now`, and returns the key it proves possession of.
pub fn verify(
    proof: &str,
    aud: &str,
    nonce: &str,
    now: u64,
) -> Result<MlDsaVerifyingKey, ProofError> {
    let invalid = ProofError::Invalid;
    // The key comes from the header, which the signature also covers: a proof
    // that names someone else's key fails the signature check below.
    let key = MlDsaVerifyingKey::from_jwk(&header_jwk(proof)?)?;
    let verified = jws::verify(proof, &key)?;
    if verified.header().get("typ").and_then(Value::as_str) != Some(TYP) {
        return Err(invalid("unexpected typ"));
    }
    let Ok(Value::Object(claims)) = serde_json::from_slice(verified.payload()) else {
        return Err(invalid("payload is not a JSON object"));
    };
    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    if text("aud") != Some(aud) {
        return Err(invalid("wrong aud"));
    }
    if text("nonce") != Some(nonce) {
        return Err(invalid("wrong nonce"));
    }
    let iat = claims
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(invalid("missing iat"))?;
    if iat.abs_diff(now) > IAT_WINDOW {
        return Err(invalid("iat is too far from the current time"));
    }
    Ok(key)
}

/// The `jwk` from the header, read before the signature is checked, because
/// it is the key the signature is checked with.
fn header_jwk(proof: &str) -> Result<Map<String, Value>, ProofError> {
    let invalid = ProofError::Invalid;
    let header = proof.split('.').next().ok_or(invalid("empty proof"))?;
    let header = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| invalid("header is not base64url"))?;
    let Ok(Value::Object(mut header)) = serde_json::from_slice(&header) else {
        return Err(invalid("header is not a JSON object"));
    };
    match header.remove("jwk") {
        Some(Value::Object(jwk)) => Ok(jwk),
        _ => Err(invalid("header has no jwk")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sd_jwt_9901::jws::Algorithm;

    const ISSUER: &str = "https://issuer.example";
    const NONCE: &str = "c-nonce-1";
    const NOW: u64 = 1_800_000_000;

    fn key() -> MlDsaSigningKey {
        MlDsaSigningKey::generate(Algorithm::MlDsa44).unwrap()
    }

    fn reason(result: Result<MlDsaVerifyingKey, ProofError>) -> String {
        match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected the proof to be rejected"),
        }
    }

    #[test]
    fn returns_the_key_that_signed() {
        for alg in [Algorithm::MlDsa44, Algorithm::MlDsa65] {
            let key = MlDsaSigningKey::generate(alg).unwrap();
            let proof = sign(&key, ISSUER, NONCE, NOW).unwrap();
            let proven = verify(&proof, ISSUER, NONCE, NOW).unwrap();
            assert_eq!(proven.to_jwk(), key.verifying_key().to_jwk());
        }
    }

    #[test]
    fn rejects_another_issuer_nonce_or_time() {
        let proof = sign(&key(), ISSUER, NONCE, NOW).unwrap();
        let other_issuer = verify(&proof, "https://other.example", NONCE, NOW);
        assert_eq!(reason(other_issuer), "invalid proof: wrong aud");
        let replayed = verify(&proof, ISSUER, "c-nonce-2", NOW);
        assert_eq!(reason(replayed), "invalid proof: wrong nonce");
        let stale = verify(&proof, ISSUER, NONCE, NOW + 3600);
        assert_eq!(
            reason(stale),
            "invalid proof: iat is too far from the current time"
        );
    }

    #[test]
    fn cannot_claim_someone_elses_key() {
        // Signed with our key, but naming the victim's key in the header.
        let (ours, victims) = (key(), key());
        let mut header = Map::new();
        header.insert("typ".into(), TYP.into());
        header.insert(
            "jwk".into(),
            Value::Object(victims.verifying_key().to_jwk()),
        );
        let payload = json!({"aud": ISSUER, "iat": NOW, "nonce": NONCE});
        let proof = jws::sign(header, payload.to_string().as_bytes(), &ours).unwrap();
        assert!(matches!(
            verify(&proof, ISSUER, NONCE, NOW),
            Err(ProofError::Jws(JwsError::InvalidSignature))
        ));
    }

    #[test]
    fn rejects_other_jwts_signed_with_the_same_key() {
        // A Key Binding JWT has the same claims, but must not pass as a proof.
        let key = key();
        let mut header = Map::new();
        header.insert("typ".into(), "kb+jwt".into());
        header.insert("jwk".into(), Value::Object(key.verifying_key().to_jwk()));
        let payload = json!({"aud": ISSUER, "iat": NOW, "nonce": NONCE});
        let kb_jwt = jws::sign(header, payload.to_string().as_bytes(), &key).unwrap();
        assert_eq!(
            reason(verify(&kb_jwt, ISSUER, NONCE, NOW)),
            "invalid proof: unexpected typ"
        );
    }

    #[test]
    fn rejects_malformed_proofs() {
        assert_eq!(
            reason(verify("%%%.%%%.%%%", ISSUER, NONCE, NOW)),
            "invalid proof: header is not base64url"
        );
        let no_jwk = jws::sign(Map::new(), b"{}", &key()).unwrap();
        assert_eq!(
            reason(verify(&no_jwk, ISSUER, NONCE, NOW)),
            "invalid proof: header has no jwk"
        );
    }
}
