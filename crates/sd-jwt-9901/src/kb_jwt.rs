//! Key Binding JWTs (RFC 9901): the holder's signature over one presentation.
//!
//! A KB-JWT proves that whoever sent the presentation holds the private key
//! whose public half the issuer put in `cnf`. Its payload ties that signature
//! to one verifier (`aud`), one request (`nonce`), one moment (`iat`), and the
//! exact presentation it came with (`sd_hash`).

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

use crate::disclosure::sha256_b64;
use crate::error::Error;
use crate::jws::{self, Signer, Verifier};

const TYP: &str = "kb+jwt";

/// How far `iat` may be from the verifier's clock, either way, in seconds.
const IAT_WINDOW: u64 = 300;

/// Signs a KB-JWT over `bound`: the presentation up to and including its last `~`.
pub(crate) fn sign(
    bound: &str,
    aud: &str,
    nonce: &str,
    iat: u64,
    holder: &dyn Signer,
) -> Result<String, Error> {
    let mut header = Map::new();
    header.insert("typ".into(), TYP.into());
    let payload = json!({
        "iat": iat,
        "aud": aud,
        "nonce": nonce,
        "sd_hash": sha256_b64(bound.as_bytes()),
    });
    jws::sign(header, payload.to_string().as_bytes(), holder)
}

/// Checks a KB-JWT against the holder's key, and against the `bound`
/// presentation, `aud` and `nonce` it must cover.
pub(crate) fn verify(
    kb_jwt: &str,
    bound: &str,
    aud: &str,
    nonce: &str,
    now: u64,
    holder: &dyn Verifier,
) -> Result<(), Error> {
    let invalid = Error::InvalidKeyBinding;
    let verified = jws::verify(kb_jwt, holder)?;
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
    if text("sd_hash") != Some(sha256_b64(bound.as_bytes()).as_str()) {
        return Err(invalid("sd_hash does not match the presentation"));
    }
    let iat = claims
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(invalid("missing iat"))?;
    if iat.abs_diff(now) > IAT_WINDOW {
        return Err(invalid("iat is too far from the current time"));
    }
    Ok(())
}

/// Seconds since the Unix epoch.
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::Algorithm;
    use crate::mldsa::MlDsaSigningKey;
    use crate::sd_jwt::{Claims, SdJwt};

    const CREDENTIAL: &str = "dc+sd-jwt";
    const SHOP: &str = "https://wine-shop.example";
    const NONCE: &str = "n-0S6_WzA2Mj";

    struct Parties {
        issuer: MlDsaSigningKey,
        holder: MlDsaSigningKey,
        credential: SdJwt,
    }

    /// An issuer, and a holder with a credential bound to its key through `cnf`.
    fn parties() -> Parties {
        let issuer = MlDsaSigningKey::generate(Algorithm::MlDsa44).unwrap();
        let holder = MlDsaSigningKey::generate(Algorithm::MlDsa44).unwrap();
        let claims: Claims = serde_json::from_value(json!({
            "iss": "https://issuer.example",
            "cnf": {"jwk": holder.verifying_key().to_jwk()},
            "birthdate": "1990-01-01",
            "age_over_18": true,
        }))
        .unwrap();
        let hidden = ["birthdate", "age_over_18"];
        let credential = SdJwt::issue(claims, &hidden, CREDENTIAL, &issuer).unwrap();
        Parties {
            issuer,
            holder,
            credential,
        }
    }

    /// What the wine shop runs on every presentation it receives.
    fn shop_verifies(p: &Parties, presentation: &str, aud: &str) -> Result<Claims, Error> {
        let issuer = p.issuer.verifying_key();
        SdJwt::verify_presentation(presentation, CREDENTIAL, &issuer, aud, NONCE)
    }

    fn reason(result: Result<Claims, Error>) -> &'static str {
        match result {
            Err(Error::InvalidKeyBinding(reason)) => reason,
            other => panic!("expected InvalidKeyBinding, got {other:?}"),
        }
    }

    #[test]
    fn bound_presentation_verifies() {
        let p = parties();
        let presentation = p.credential.present(&["age_over_18"]);
        let presentation = presentation
            .bind(SHOP, NONCE, &p.holder)
            .unwrap()
            .to_string();
        let claims = shop_verifies(&p, &presentation, SHOP).unwrap();
        assert_eq!(claims["age_over_18"], true);
        assert!(!claims.contains_key("birthdate"));
    }

    #[test]
    fn rejects_replay_at_another_verifier_or_request() {
        let p = parties();
        let presentation = p.credential.present(&["age_over_18"]);
        let presentation = presentation
            .bind(SHOP, NONCE, &p.holder)
            .unwrap()
            .to_string();

        let at_pharmacy = shop_verifies(&p, &presentation, "https://pharmacy.example");
        assert_eq!(reason(at_pharmacy), "wrong aud");

        let issuer = p.issuer.verifying_key();
        let next_request =
            SdJwt::verify_presentation(&presentation, CREDENTIAL, &issuer, SHOP, "a-new-nonce");
        assert_eq!(reason(next_request), "wrong nonce");
    }

    #[test]
    fn rejects_a_key_binding_without_the_holder_key() {
        let p = parties();
        let thief = MlDsaSigningKey::generate(Algorithm::MlDsa44).unwrap();
        let presentation = p.credential.present(&["age_over_18"]);
        let presentation = presentation.bind(SHOP, NONCE, &thief).unwrap().to_string();
        assert!(matches!(
            shop_verifies(&p, &presentation, SHOP),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn sd_hash_covers_the_disclosures() {
        let p = parties();
        let presentation = p.credential.present(&["age_over_18", "birthdate"]);
        let mut presentation = presentation.bind(SHOP, NONCE, &p.holder).unwrap();
        // Someone in the middle strips a Disclosure after the holder signed.
        presentation.disclosures.pop();
        let result = shop_verifies(&p, &presentation.to_string(), SHOP);
        assert_eq!(reason(result), "sd_hash does not match the presentation");
    }

    #[test]
    fn rejects_missing_and_stale_key_bindings() {
        let p = parties();
        let unbound = p.credential.present(&["age_over_18"]);
        let result = shop_verifies(&p, &unbound.to_string(), SHOP);
        assert_eq!(reason(result), "missing");

        let an_hour_ago = now() - 3600;
        let stale = sign(&unbound.to_string(), SHOP, NONCE, an_hour_ago, &p.holder).unwrap();
        let result = shop_verifies(&p, &format!("{unbound}{stale}"), SHOP);
        assert_eq!(reason(result), "iat is too far from the current time");
    }
}
