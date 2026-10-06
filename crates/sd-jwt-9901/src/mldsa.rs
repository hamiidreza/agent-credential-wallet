//! ML-DSA ([FIPS 204]) keys for JWS, as profiled by `draft-ietf-cose-dilithium`:
//!
//! - a private key is a 32-byte seed;
//! - the context string is always empty;
//! - public keys are JWKs of key type `AKP`, with the raw key in `pub`.
//!
//! [FIPS 204]: https://doi.org/10.6028/NIST.FIPS.204

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use getrandom::SysRng;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Generate, MlDsa44, MlDsa65, MlDsaParams};
use serde_json::{Map, Value};

use crate::error::Error;
use crate::jws::{Algorithm, Signer, Verifier};

/// The draft requires the empty context string for every ML-DSA parameter set.
const CONTEXT: &[u8] = b"";

/// Length of an ML-DSA private key seed, in bytes.
pub const SEED_LEN: usize = 32;

/// How signatures are randomised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SigningMode {
    /// Fresh randomness mixed into every signature, as FIPS 204 recommends.
    #[default]
    Hedged,
    /// The same message always gives the same signature. Used to reproduce
    /// published test vectors.
    Deterministic,
}

enum SigningKeyInner {
    MlDsa44(Box<ml_dsa::SigningKey<MlDsa44>>),
    MlDsa65(Box<ml_dsa::SigningKey<MlDsa65>>),
}

/// An ML-DSA signing key.
pub struct MlDsaSigningKey {
    key: SigningKeyInner,
    mode: SigningMode,
}

impl MlDsaSigningKey {
    // wip
}