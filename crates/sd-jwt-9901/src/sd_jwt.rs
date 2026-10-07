//! SD-JWT (RFC 9901): issuing, presenting and verifying, without key binding.
//!
//! An SD-JWT is `<issuer-signed JWT>~<Disclosure>~...~<Disclosure>~<KB-JWT or empty>`.
//! The issuer's signature covers the `_sd` digests, and the digests cover the
//! Disclosures. [`SdJwt::verify`] checks the signature with [`jws::verify`],
//! then [`disclose`] checks the Disclosures against the digests.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde_json::{Map, Value};

use crate::disclosure::{Disclosure, random_salt};
use crate::error::Error;
use crate::jws::{self, Signer, Verifier};

pub type Claims = Map<String, Value>;

#[derive(Clone, Debug, PartialEq)]
pub struct SdJwt {
    pub jwt: String,
    pub disclosures: Vec<Disclosure>,
    /// The Key Binding JWT, if the holder added one.
    pub kb_jwt: Option<String>,
}

impl SdJwt {
    /// The issuer's side: hides each top-level claim named in `hidden` behind
    /// a digest in `_sd`, then signs the payload. `typ` goes in the JWT header;
    /// credentials use `dc+sd-jwt`.
    pub fn issue(
        claims: Claims,
        hidden: &[&str],
        typ: &str,
        issuer: &dyn Signer,
    ) -> Result<Self, Error> {
        let (payload, disclosures) = build_payload(claims, hidden)?;
        let mut header = Map::new();
        header.insert("typ".into(), typ.into());
        let payload = serde_json::to_vec(&payload)
            .map_err(|_| Error::SigningFailed("payload is not serialisable".into()))?;
        Ok(Self {
            jwt: jws::sign(header, &payload, issuer)?,
            disclosures,
            kb_jwt: None,
        })
    }

    /// The holder's side: keeps only the Disclosures for the claims named in
    /// `reveal`. Any old Key Binding JWT is dropped; each presentation needs a new one.
    pub fn present(&self, reveal: &[&str]) -> Self {
        let wanted = |d: &&Disclosure| d.name.as_deref().is_some_and(|n| reveal.contains(&n));
        Self {
            jwt: self.jwt.clone(),
            disclosures: self.disclosures.iter().filter(wanted).cloned().collect(),
            kb_jwt: None,
        }
    }

    /// The verifier's side: checks the issuer's signature and `typ`, then the
    /// Disclosures. Returns the payload with every disclosed claim put back
    /// and the SD-JWT syntax removed.
    pub fn verify(presentation: &str, typ: &str, issuer: &dyn Verifier) -> Result<Claims, Error> {
        let sd_jwt = Self::parse(presentation)?;
        if sd_jwt.kb_jwt.is_some() {
            return Err(Error::InvalidSdJwt("key binding not implemented yet"));
        }
        let verified = jws::verify(&sd_jwt.jwt, issuer)?;
        if verified.header().get("typ").and_then(Value::as_str) != Some(typ) {
            return Err(Error::InvalidSdJwt("unexpected typ"));
        }
        let Ok(Value::Object(payload)) = serde_json::from_slice(verified.payload()) else {
            return Err(Error::InvalidSdJwt("payload is not a JSON object"));
        };
        disclose(payload, sd_jwt.disclosures)
    }

    pub fn parse(s: &str) -> Result<Self, Error> {
        let (rest, kb_jwt) = s
            .rsplit_once('~')
            .ok_or(Error::InvalidSdJwt("no '~' separator"))?;
        let mut parts = rest.split('~');
        let jwt = parts.next().unwrap_or_default();
        if jwt.is_empty() {
            return Err(Error::InvalidSdJwt("empty JWT"));
        }
        Ok(Self {
            jwt: jwt.to_owned(),
            disclosures: parts.map(Disclosure::parse).collect::<Result<_, _>>()?,
            kb_jwt: (!kb_jwt.is_empty()).then(|| kb_jwt.to_owned()),
        })
    }
}

impl fmt::Display for SdJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}~", self.jwt)?;
        for d in &self.disclosures {
            write!(f, "{}~", d.encoded)?;
        }
        f.write_str(self.kb_jwt.as_deref().unwrap_or(""))
    }
}

/// Moves each claim named in `hidden` into a Disclosure and leaves only its
/// digest behind, in `_sd`.
fn build_payload(mut claims: Claims, hidden: &[&str]) -> Result<(Claims, Vec<Disclosure>), Error> {
    if ["_sd", "_sd_alg", "..."]
        .iter()
        .any(|k| claims.contains_key(*k))
    {
        return Err(Error::InvalidSdJwt("claims use a reserved name"));
    }
    let mut disclosures = Vec::new();
    for &name in hidden {
        let value = claims
            .remove(name)
            .ok_or(Error::InvalidSdJwt("hidden claim missing or listed twice"))?;
        disclosures.push(Disclosure::new(&random_salt()?, Some(name), value));
    }
    // Sorted, so the order of `_sd` says nothing about the order of the claims.
    let mut digests: Vec<String> = disclosures.iter().map(Disclosure::digest).collect();
    digests.sort();
    claims.insert("_sd".into(), digests.into());
    claims.insert("_sd_alg".into(), "sha-256".into());
    Ok((claims, disclosures))
}

/// Puts the disclosed claims back into a payload whose signature has already
/// been checked, and applies RFC 9901's rules for doing so. Not public: outside
/// this crate, the only way in is [`SdJwt::verify`], which checks the signature first.
pub(crate) fn disclose(mut payload: Claims, disclosures: Vec<Disclosure>) -> Result<Claims, Error> {
    match payload.remove("_sd_alg") {
        None => {}
        Some(alg) if alg == "sha-256" => {}
        Some(_) => return Err(Error::InvalidSdJwt("unsupported _sd_alg")),
    }
    let mut unused = HashMap::new();
    for d in disclosures {
        if unused.insert(d.digest(), d).is_some() {
            return Err(Error::InvalidSdJwt("the same Disclosure was sent twice"));
        }
    }
    let mut seen = HashSet::new();
    process_object(&mut payload, &mut unused, &mut seen)?;
    if !unused.is_empty() {
        return Err(Error::InvalidSdJwt(
            "a Disclosure matches no digest in the payload",
        ));
    }
    Ok(payload)
}

type Unused = HashMap<String, Disclosure>;

/// Puts back the claims whose digests are in this object's `_sd`, then
/// processes every value inside, including the ones just put back.
fn process_object(
    obj: &mut Claims,
    unused: &mut Unused,
    seen: &mut HashSet<String>,
) -> Result<(), Error> {
    if let Some(sd) = obj.remove("_sd") {
        let Value::Array(digests) = sd else {
            return Err(Error::InvalidSdJwt("_sd is not an array"));
        };
        for digest in digests {
            let Value::String(digest) = digest else {
                return Err(Error::InvalidSdJwt("_sd contains a non-string"));
            };
            if !seen.insert(digest.clone()) {
                return Err(Error::InvalidSdJwt("a digest appears twice"));
            }
            // No Disclosure for this digest: the claim stays hidden.
            let Some(d) = unused.remove(&digest) else {
                continue;
            };
            let Some(name) = d.name else {
                return Err(Error::InvalidSdJwt(
                    "an array-element Disclosure is referenced from _sd",
                ));
            };
            if obj.contains_key(&name) {
                return Err(Error::InvalidSdJwt("a disclosed claim already exists"));
            }
            obj.insert(name, d.value);
        }
    }
    for value in obj.values_mut() {
        process_value(value, unused, seen)?;
    }
    Ok(())
}

/// In arrays, each `{"...": digest}` is replaced by its disclosed value, or
/// dropped if the holder didn't disclose it.
fn process_value(
    value: &mut Value,
    unused: &mut Unused,
    seen: &mut HashSet<String>,
) -> Result<(), Error> {
    match value {
        Value::Object(obj) => process_object(obj, unused, seen),
        Value::Array(items) => {
            let mut kept = Vec::new();
            for item in items.drain(..) {
                let Some(digest) = array_digest(&item)? else {
                    kept.push(item);
                    continue;
                };
                if !seen.insert(digest.clone()) {
                    return Err(Error::InvalidSdJwt("a digest appears twice"));
                }
                match unused.remove(&digest) {
                    None => {}
                    Some(d) if d.name.is_some() => {
                        return Err(Error::InvalidSdJwt(
                            "an object-property Disclosure is referenced from an array",
                        ));
                    }
                    Some(d) => kept.push(d.value),
                }
            }
            for item in &mut kept {
                process_value(item, unused, seen)?;
            }
            *items = kept;
            Ok(())
        }
        _ => Ok(()),
    }
}

/// `Some(digest)` if `item` is `{"...": digest}`, the placeholder for a hidden array element.
fn array_digest(item: &Value) -> Result<Option<String>, Error> {
    let Value::Object(obj) = item else {
        return Ok(None);
    };
    match obj.get("...") {
        None => Ok(None),
        Some(Value::String(digest)) if obj.len() == 1 => Ok(Some(digest.clone())),
        Some(_) => Err(Error::InvalidSdJwt("malformed array-element placeholder")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::Algorithm;
    use crate::mldsa::MlDsaSigningKey;
    use serde_json::json;

    const TYP: &str = "dc+sd-jwt";

    fn claims(value: Value) -> Claims {
        let Value::Object(map) = value else {
            panic!("not an object")
        };
        map
    }

    fn issuer_key() -> MlDsaSigningKey {
        MlDsaSigningKey::generate(Algorithm::MlDsa44).unwrap()
    }

    fn credential(issuer: &MlDsaSigningKey) -> SdJwt {
        let all = claims(json!({
            "iss": "https://issuer.example",
            "given_name": "John",
            "birthdate": "1990-01-01",
            "age_over_18": true,
        }));
        SdJwt::issue(
            all,
            &["given_name", "birthdate", "age_over_18"],
            TYP,
            issuer,
        )
        .unwrap()
    }

    fn invalid(result: Result<Claims, Error>) -> &'static str {
        match result {
            Err(Error::InvalidSdJwt(reason)) => reason,
            other => panic!("expected InvalidSdJwt, got {other:?}"),
        }
    }

    #[test]
    fn present_one_claim_and_verify() {
        let issuer = issuer_key();
        let presentation = credential(&issuer).present(&["age_over_18"]).to_string();
        let disclosed = SdJwt::verify(&presentation, TYP, &issuer.verifying_key()).unwrap();
        assert_eq!(
            Value::Object(disclosed),
            json!({"iss": "https://issuer.example", "age_over_18": true})
        );
    }

    #[test]
    fn signed_payload_hides_the_values() {
        let issuer = issuer_key();
        let verified = jws::verify(&credential(&issuer).jwt, &issuer.verifying_key()).unwrap();
        assert_eq!(verified.header()["typ"], TYP);
        let payload: Value = serde_json::from_slice(verified.payload()).unwrap();
        assert_eq!(payload["_sd"].as_array().unwrap().len(), 3);
        assert_eq!(payload["_sd_alg"], "sha-256");
        let text = payload.to_string();
        assert!(!text.contains("John") && !text.contains("1990"));
    }

    #[test]
    fn serialization_round_trip() {
        let sd_jwt = credential(&issuer_key());
        assert_eq!(SdJwt::parse(&sd_jwt.to_string()).unwrap(), sd_jwt);
        assert!(sd_jwt.to_string().ends_with('~'));
    }

    #[test]
    fn rejects_wrong_key_and_typ() {
        let issuer = issuer_key();
        let presentation = credential(&issuer).present(&["age_over_18"]).to_string();
        let impostor = issuer_key().verifying_key();
        assert!(matches!(
            SdJwt::verify(&presentation, TYP, &impostor),
            Err(Error::InvalidSignature)
        ));
        let result = SdJwt::verify(&presentation, "kb+jwt", &issuer.verifying_key());
        assert_eq!(invalid(result), "unexpected typ");
    }

    #[test]
    fn rejects_forged_doubled_and_key_bound() {
        let issuer = issuer_key();
        let key = issuer.verifying_key();
        let sd_jwt = credential(&issuer).present(&["age_over_18"]);

        // A Disclosure the issuer never signed a digest for.
        let mut forged = sd_jwt.clone();
        let salt = random_salt().unwrap();
        forged.disclosures = vec![Disclosure::new(&salt, Some("age_over_18"), json!(true))];
        let result = SdJwt::verify(&forged.to_string(), TYP, &key);
        assert_eq!(
            invalid(result),
            "a Disclosure matches no digest in the payload"
        );

        let mut doubled = sd_jwt.clone();
        doubled.disclosures.push(doubled.disclosures[0].clone());
        let result = SdJwt::verify(&doubled.to_string(), TYP, &key);
        assert_eq!(invalid(result), "the same Disclosure was sent twice");

        let result = SdJwt::verify(&format!("{sd_jwt}kb.jwt.here"), TYP, &key);
        assert_eq!(invalid(result), "key binding not implemented yet");
    }

    // The rest test the processing rules alone, so they call `disclose` on
    // hand-written payloads, skipping the signature.

    #[test]
    fn nested_claims_and_array_elements() {
        let fr = Disclosure::new(&random_salt().unwrap(), None, json!("FR"));
        let de = Disclosure::new(&random_salt().unwrap(), None, json!("DE"));
        let country = Disclosure::new(&random_salt().unwrap(), Some("country"), json!("DE"));
        let payload = claims(json!({
            "nationalities": [{"...": fr.digest()}, {"...": de.digest()}],
            "address": {"_sd": [country.digest()], "locality": "Berlin"},
        }));
        // Disclose FR and the country, not DE.
        let disclosed = disclose(payload, vec![fr, country]).unwrap();
        assert_eq!(
            Value::Object(disclosed),
            json!({"nationalities": ["FR"], "address": {"locality": "Berlin", "country": "DE"}})
        );
    }

    #[test]
    fn rejects_bad_payloads() {
        let d = Disclosure::new(&random_salt().unwrap(), Some("name"), json!("Alice"));
        let cases = [
            (
                json!({"name": "Bob", "_sd": [d.digest()]}),
                "a disclosed claim already exists",
            ),
            (
                json!({"_sd": [d.digest(), d.digest()]}),
                "a digest appears twice",
            ),
            (
                json!({"list": [{"...": d.digest()}]}),
                "an object-property Disclosure is referenced from an array",
            ),
            (
                json!({"_sd_alg": "md5", "_sd": [d.digest()]}),
                "unsupported _sd_alg",
            ),
            (json!({"_sd": d.digest()}), "_sd is not an array"),
        ];
        for (payload, reason) in cases {
            let result = disclose(claims(payload), vec![d.clone()]);
            assert_eq!(invalid(result), reason);
        }
    }
}
