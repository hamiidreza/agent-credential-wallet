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
    /// Sign `message` and return the raw signature bytes.
    ///
    /// `message` is the ASCII bytes of `base64url(header).base64url(payload)`,
    /// exactly as specified in RFC 7515, section 4.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait Verifier {
    /// Verify that `signature` is a valid signature over `message`.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error>;
}

#[derive(Debug, Clone)]
pub struct CompactJws {
    /// Parsed header (always a JSON object).
    pub header: Value,
    /// Raw payload bytes (not base64-decoded further; callers parse as needed).
    pub payload: Vec<u8>,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
}

impl CompactJws {
    /// Sign `payload` with `signer` and return the compact serialisation.
    ///
    /// `alg` is the JOSE algorithm identifier that goes into the JWS header
    /// (e.g. `"MLDSA44"`). The caller supplies it because the header must be
    /// committed to before signing, and the signer trait does not carry it.
    pub fn sign(payload: &[u8], alg: &str, signer: &dyn Signer) -> Result<String, Error> {
        let header_json = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg);
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

        // RFC 7515 §4: signing input is ASCII(base64url(header) || '.' || base64url(payload))
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature = signer.sign(signing_input.as_bytes())?;
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}", signing_input, sig_b64))
    }

    /// Parse and verify a compact JWS token.
    ///
    /// Returns the decoded [`CompactJws`] if the signature is valid.
    pub fn verify(token: &str, verifier: &dyn Verifier) -> Result<Self, Error> {
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err(Error::MalformedToken("expected three dot-separated parts"));
        }
        let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| Error::MalformedToken("invalid base64url in header"))?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| Error::MalformedToken("invalid base64url in payload"))?;
        let signature = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| Error::MalformedToken("invalid base64url in signature"))?;

        let header: Value = serde_json::from_slice(&header_bytes)
            .map_err(|_| Error::MalformedToken("header is not valid JSON"))?;

        verifier.verify(signing_input.as_bytes(), &signature)?;

        Ok(Self {
            header,
            payload,
            signature,
        })
    }
}
