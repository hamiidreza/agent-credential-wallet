//! Error type for the sd-jwt-9901 crate.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The compact serialisation does not conform to RFC 7515.
    #[error("malformed token: {0}")]
    MalformedToken(&'static str),

    /// The token's `alg` is not the algorithm of the key it is being verified with.
    #[error("unexpected algorithm: {0:?}")]
    UnexpectedAlgorithm(String),

    /// The header uses a JOSE feature this crate deliberately does not support.
    #[error("unsupported header parameter: {0}")]
    UnsupportedHeader(&'static str),

    /// The signature did not verify against the supplied key.
    #[error("invalid signature")]
    InvalidSignature,

    /// A key, or its JWK representation, is malformed.
    #[error("invalid key: {0}")]
    InvalidKey(&'static str),

    /// A signer implementation returned an error.
    #[error("signing failed: {0}")]
    SigningFailed(String),
}
