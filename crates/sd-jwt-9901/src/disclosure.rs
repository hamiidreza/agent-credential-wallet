//! SD-JWT Disclosures (RFC 9901): `[salt, name, value]` for an object
//! property, `[salt, value]` for an array element, base64url-encoded.
//!
//! The digest is taken over the encoded string, not the JSON inside it, so a
//! parsed Disclosure keeps its string and is never re-encoded. The hash is
//! always SHA-256, the `_sd_alg` default.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

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

    pub fn parse(encoded: &str) -> Result<Self, &'static str> {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "not base64url")?;
        let array: Vec<Value> = serde_json::from_slice(&bytes).map_err(|_| "not a JSON array")?;
        let (salt, name, value) = match array.as_slice() {
            [Value::String(salt), value] => (salt, None, value),
            [Value::String(salt), Value::String(name), value] => (salt, Some(name), value),
            _ => return Err("not [salt, value] or [salt, name, value]"),
        };
        if name.is_some_and(|n| n == "_sd" || n == "...") {
            return Err("reserved claim name");
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
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.encoded.as_bytes()))
    }
}

/// 128 random bits, base64url-encoded.
pub fn random_salt() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS random number generator failed");
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Examples from RFC 9901.
    const MOBIUS: &str = "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";
    const MOBIUS_ESCAPED: &str = "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNXHUwMGY2Yml1cyJd";
    const FR: &str = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0";

    #[test]
    fn rfc_examples() {
        let d = Disclosure::parse(MOBIUS).unwrap();
        assert_eq!(d.salt, "6qMQvRL5haj");
        assert_eq!(d.name.as_deref(), Some("family_name"));
        assert_eq!(d.value, json!("Möbius"));
        assert_eq!(d.digest(), "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY");

        let d = Disclosure::parse(FR).unwrap();
        assert_eq!(d.name, None);
        assert_eq!(d.value, json!("FR"));
        assert_eq!(d.digest(), "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs");
    }

    #[test]
    fn same_json_different_encoding_different_digest() {
        let a = Disclosure::parse(MOBIUS).unwrap();
        let b = Disclosure::parse(MOBIUS_ESCAPED).unwrap();
        assert_eq!(a.value, b.value);
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn round_trip() {
        let d = Disclosure::new(&random_salt(), Some("age_over_18"), json!(true));
        assert_eq!(Disclosure::parse(&d.encoded).unwrap(), d);
        let d = Disclosure::new(&random_salt(), None, json!("DE"));
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