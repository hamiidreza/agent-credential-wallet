//! SD-JWT Disclosures (RFC 9901): `[salt, name, value]` for an object
//! property, `[salt, value]` for an array element, base64url-encoded.
//!
//! The digest is taken over the encoded string, not the JSON inside it, so a
//! parsed Disclosure keeps its string and is never re-encoded. The hash is
//! always SHA-256, the `_sd_alg` default.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::error::Error;

#[derive(Clone, Debug, PartialEq)]
pub struct Disclosure {
    pub encoded: String,
    pub salt: String,
    /// `None` for an array element.
    pub name: Option<String>,
    pub value: Value,
}

impl Disclosure {
    pub fn new(salt: &str, name: Option<&str>, value: Value) -> Self {
        let array = match name {
            Some(name) => json!([salt, name, value]),
            None => json!([salt, value]),
        };
        Self {
            encoded: URL_SAFE_NO_PAD.encode(array.to_string()),
            salt: salt.to_owned(),
            name: name.map(str::to_owned),
            value,
        }
    }

    pub fn parse(encoded: &str) -> Result<Self, Error> {
        let invalid = Error::InvalidDisclosure;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| invalid("not base64url"))?;
        let array: Vec<Value> =
            serde_json::from_slice(&bytes).map_err(|_| invalid("not a JSON array"))?;
        let (salt, name, value) = match array.as_slice() {
            [Value::String(salt), value] => (salt, None, value),
            [Value::String(salt), Value::String(name), value] => (salt, Some(name), value),
            _ => return Err(invalid("not [salt, value] or [salt, name, value]")),
        };
        if name.is_some_and(|n| n == "_sd" || n == "...") {
            return Err(invalid("reserved claim name"));
        }
        Ok(Self {
            encoded: encoded.to_owned(),
            salt: salt.clone(),
            name: name.cloned(),
            value: value.clone(),
        })
    }

    /// The digest that `_sd` or `...` uses to refer to this Disclosure.
    pub fn digest(&self) -> String {
        sha256_b64(self.encoded.as_bytes())
    }
}

/// SHA-256, base64url-encoded: the `_sd_alg` hash, used for Disclosure digests
/// and for `sd_hash` in the Key Binding JWT.
pub(crate) fn sha256_b64(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(input))
}

/// 128 random bits, base64url-encoded.
pub fn random_salt() -> Result<String, Error> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Error::SigningFailed("no system randomness".into()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9901, Sections 4.2.1 and 4.2.3.
    const MOBIUS: &str = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";
    // The same claim, encoded the three other ways Section 4.2.1 shows.
    const MOBIUS_VARIANTS: [&str; 3] = [
        "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNXHUwMGY2Yml1cyJd",
        "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd",
        "WwoiXzI2YmM0TFQtYWM2cTJLSTZjQlc1ZXMiLAoiZmFtaWx5X25hbWUiLAoiTcO2Yml1cyIKXQ",
    ];
    // RFC 9901, Sections 4.2.2 and 4.2.4.2.
    const FR: &str = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0";

    #[test]
    fn rfc_examples() {
        let d = Disclosure::parse(MOBIUS).unwrap();
        assert_eq!(d.salt, "_26bc4LT-ac6q2KI6cBW5es");
        assert_eq!(d.name.as_deref(), Some("family_name"));
        assert_eq!(d.value, json!("Möbius"));
        assert_eq!(d.digest(), "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0");

        let d = Disclosure::parse(FR).unwrap();
        assert_eq!(d.name, None);
        assert_eq!(d.value, json!("FR"));
        assert_eq!(d.digest(), "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs");
    }

    #[test]
    fn same_json_different_encoding_different_digest() {
        let original = Disclosure::parse(MOBIUS).unwrap();
        for encoded in MOBIUS_VARIANTS {
            let variant = Disclosure::parse(encoded).unwrap();
            assert_eq!(variant.value, original.value);
            assert_ne!(variant.digest(), original.digest());
        }
    }

    #[test]
    fn round_trip() {
        let salt = random_salt().unwrap();
        let d = Disclosure::new(&salt, Some("age_over_18"), json!(true));
        assert_eq!(Disclosure::parse(&d.encoded).unwrap(), d);
        let d = Disclosure::new(&salt, None, json!("DE"));
        assert_eq!(Disclosure::parse(&d.encoded).unwrap(), d);
    }

    #[test]
    fn rejects_bad_input() {
        let b64 = |s: &str| URL_SAFE_NO_PAD.encode(s);
        for bad in [
            "!!!".to_owned(),
            b64("not json"),
            b64(r#"["s"]"#),
            b64(r#"[1, "v"]"#),
            b64(r#"["s", "_sd", 1]"#),
        ] {
            assert!(Disclosure::parse(&bad).is_err(), "{bad}");
        }
    }
}
