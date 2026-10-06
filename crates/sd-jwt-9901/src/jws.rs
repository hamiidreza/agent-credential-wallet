//! Compact JWS signing and verification ([RFC 7515]).
//!
//! The algorithm is never taken on trust from a token: the verifier says which
//! algorithm it expects, and a token naming any other is rejected before its
//! signature is looked at.
//!
//! [RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515.html

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value};

use crate::error::Error;

/// A JOSE signature algorithm supported by this crate.
///
/// Names are the ones registered for JOSE by `draft-ietf-cose-dilithium`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// ML-DSA-44 (FIPS 204).
    MlDsa44,
    /// ML-DSA-65 (FIPS 204).
    MlDsa65,
}

impl Algorithm {
    /// Return the JOSE name of this algorithm.
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::MlDsa44 => "ML-DSA-44",
            Algorithm::MlDsa65 => "ML-DSA-65",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ML-DSA-44" => Some(Self::MlDsa44),
            "ML-DSA-65" => Some(Self::MlDsa65),
            _ => None,
        }
    }
}

// Signing/verification traits
pub trait Signer {
    /// Return the algorithm that this signer implements.
    fn algorithm(&self) -> Algorithm;

    /// Sign `message` and return the raw signature bytes.
    ///
    /// `message` is the ASCII bytes of `base64url(header).base64url(payload)`,
    /// exactly as specified in RFC 7515, section 5.1.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait Verifier {
    /// Return the algorithm that this verifier implements.
    fn algorithm(&self) -> Algorithm;

    /// Verify that `signature` is a valid signature over `message`.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error>;
}

#[derive(Debug, Clone)]
pub struct VerifiedJws {
    pub header: Map<String, Value>,
    pub payload: Vec<u8>,
}

impl VerifiedJws {
    /// The protected header.
    pub fn header(&self) -> &Map<String, Value> {
        &self.header
    }

    /// The decoded payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Sign `payload` and return the compact serialisation.
///
/// `alg` is always set from `signer`, so it cannot disagree with the key;
/// any `alg` in `header` is replaced. The caller supplies everything else,
/// such as `typ` (`dc+sd-jwt`, `kb+jwt`, ...) and `kid`.
pub fn sign(
    header: Map<String, Value>,
    payload: &[u8],
    signer: &dyn Signer,
) -> Result<String, Error> {
    let mut full = Map::new();
    full.insert("alg".into(), signer.algorithm().as_str().into());
    full.extend(header.into_iter().filter(|(name, _)| name != "alg"));

    let header_json = serde_json::to_vec(&full)
        .map_err(|_| Error::SigningFailed("header is not serialisable".into()))?;

    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header_json),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = signer.sign(signing_input.as_bytes())?;

    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

/// Parse a compact JWS token and verify its signature with `verifier`.
///
/// Rejects the token if its `alg` is not the verifier's algorithm, or if it
/// uses `crit`, before the signature is checked.
pub fn verify(token: &str, verifier: &dyn Verifier) -> Result<VerifiedJws, Error> {
    let mut parts = token.split('.');

    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::MalformedToken("expected three dot-separated parts"));
    };

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| Error::MalformedToken("invalid base64url in header"))?;
    let Ok(Value::Object(header)) = serde_json::from_slice(&header_bytes) else {
        return Err(Error::MalformedToken("header is not a JSON object"));
    };

    match header.get("alg").and_then(Value::as_str) {
        Some(alg) if alg == verifier.algorithm().as_str() => {}
        Some(alg) => return Err(Error::UnexpectedAlgorithm(alg.to_string())),
        None => return Err(Error::MalformedToken("header has no alg")),
    }
    // RFC 7515 section 4.1.11: we understand no extensions, so a token
    // that marks any as critical must be rejected.
    if header.contains_key("crit") {
        return Err(Error::UnsupportedHeader("crit"));
    }

    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| Error::MalformedToken("invalid base64url in payload"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| Error::MalformedToken("invalid base64url in signature"))?;

    let signing_input_len = header_b64.len() + 1 + payload_b64.len();
    verifier.verify(&token.as_bytes()[..signing_input_len], &signature)?;

    Ok(VerifiedJws { header, payload })
}
