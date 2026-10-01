//! Error type for the sd-jwt-9901 crate.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The compact serialisation does not conform to RFC 7515.
    #[error("malformed token: {0}")]
    MalformedToken(&'static str),

    /// The signature did not verify against the supplied key.
    #[error("invalid signature")]
    InvalidSignature,

    /// A signer implementation returned an error.
    #[error("signing failed: {0}")]
    SigningFailed(String),
}