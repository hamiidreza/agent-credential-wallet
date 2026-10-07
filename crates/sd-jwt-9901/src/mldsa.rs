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
    /// Generate a fresh key from the operating system's random number generator.
    pub fn generate(alg: Algorithm) -> Result<Self, Error> {
        let failed = |_| Error::SigningFailed("no system randomness".into());
        let key = match alg {
            Algorithm::MlDsa44 => {
                SigningKeyInner::MlDsa44(Box::new(Generate::try_generate().map_err(failed)?))
            }
            Algorithm::MlDsa65 => {
                SigningKeyInner::MlDsa65(Box::new(Generate::try_generate().map_err(failed)?))
            }
        };
        Ok(Self::new(key))
    }

    fn new(key: SigningKeyInner) -> Self {
        Self {
            key,
            mode: SigningMode::default(),
        }
    }

    /// Derive a key from a 32-byte seed, the private key format of the draft.
    pub fn from_seed(algorithm: Algorithm, seed: &[u8; SEED_LEN]) -> Self {
        let seed = ml_dsa::Seed::from(*seed);
        let key = match algorithm {
            Algorithm::MlDsa44 => {
                SigningKeyInner::MlDsa44(Box::new(ml_dsa::SigningKey::from_seed(&seed)))
            }
            Algorithm::MlDsa65 => {
                SigningKeyInner::MlDsa65(Box::new(ml_dsa::SigningKey::from_seed(&seed)))
            }
        };
        Self::new(key)
    }

    /// Choose how signatures are randomised. The default is [`SigningMode::Hedged`].
    pub fn with_mode(mut self, mode: SigningMode) -> Self {
        self.mode = mode;
        self
    }

    /// The matching public key.
    pub fn verifying_key(&self) -> MlDsaVerifyingKey {
        use ml_dsa::Keypair as _;
        MlDsaVerifyingKey(match &self.key {
            SigningKeyInner::MlDsa44(key) => {
                VerifyingKeyInner::MlDsa44(Box::new(key.verifying_key()))
            }
            SigningKeyInner::MlDsa65(key) => {
                VerifyingKeyInner::MlDsa65(Box::new(key.verifying_key()))
            }
        })
    }
}

impl Signer for MlDsaSigningKey {
    fn algorithm(&self) -> Algorithm {
        match self.key {
            SigningKeyInner::MlDsa44(_) => Algorithm::MlDsa44,
            SigningKeyInner::MlDsa65(_) => Algorithm::MlDsa65,
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        match &self.key {
            SigningKeyInner::MlDsa44(key) => sign_with(key, self.mode, message),

            SigningKeyInner::MlDsa65(key) => sign_with(key, self.mode, message),
        }
    }
}

impl fmt::Debug for MlDsaSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaSigningKey")
            .field("algorithm", &self.algorithm())
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// An ML-DSA public key.
#[derive(Clone)]
pub struct MlDsaVerifyingKey(VerifyingKeyInner);

#[derive(Clone)]
enum VerifyingKeyInner {
    MlDsa44(Box<ml_dsa::VerifyingKey<MlDsa44>>),
    MlDsa65(Box<ml_dsa::VerifyingKey<MlDsa65>>),
}

impl MlDsaVerifyingKey {
    /// Decode a raw public key (FIPS 204 `pkEncode`).
    pub fn from_bytes(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, Error> {
        let wrong_length = |_| Error::InvalidKey("wrong public key length");
        Ok(Self(match algorithm {
            Algorithm::MlDsa44 => {
                VerifyingKeyInner::MlDsa44(Box::new(ml_dsa::VerifyingKey::decode(
                    &EncodedVerifyingKey::<MlDsa44>::try_from(bytes).map_err(wrong_length)?,
                )))
            }
            Algorithm::MlDsa65 => {
                VerifyingKeyInner::MlDsa65(Box::new(ml_dsa::VerifyingKey::decode(
                    &EncodedVerifyingKey::<MlDsa65>::try_from(bytes).map_err(wrong_length)?,
                )))
            }
        }))
    }

    /// The raw public key (FIPS 204 `pkEncode`).
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.0 {
            VerifyingKeyInner::MlDsa44(key) => key.encode().to_vec(),
            VerifyingKeyInner::MlDsa65(key) => key.encode().to_vec(),
        }
    }

    /// The public key as a JWK: `{"kty": "AKP", "alg": ..., "pub": ...}`.
    pub fn to_jwk(&self) -> Map<String, Value> {
        let mut jwk = Map::new();
        jwk.insert("kty".into(), "AKP".into());
        jwk.insert("alg".into(), self.algorithm().as_str().into());
        jwk.insert("pub".into(), URL_SAFE_NO_PAD.encode(self.to_bytes()).into());
        jwk
    }

    /// Read a public key from a JWK. Other members, such as `kid`, are ignored.
    ///
    /// Rejects a JWK that carries `priv`: a private key has no business in a
    /// place that expects a public one, such as a `cnf` claim.
    pub fn from_jwk(jwk: &Map<String, Value>) -> Result<Self, Error> {
        if jwk.get("kty").and_then(Value::as_str) != Some("AKP") {
            return Err(Error::InvalidKey("kty must be AKP"));
        }
        if jwk.contains_key("priv") {
            return Err(Error::InvalidKey("a public key must not contain priv"));
        }
        let algorithm = jwk
            .get("alg")
            .and_then(Value::as_str)
            .and_then(Algorithm::from_name)
            .ok_or(Error::InvalidKey("missing or unsupported alg"))?;
        let public = jwk
            .get("pub")
            .and_then(Value::as_str)
            .ok_or(Error::InvalidKey("missing pub"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(public)
            .map_err(|_| Error::InvalidKey("pub is not base64url"))?;
        Self::from_bytes(algorithm, &bytes)
    }
}

impl Verifier for MlDsaVerifyingKey {
    fn algorithm(&self) -> Algorithm {
        match self.0 {
            VerifyingKeyInner::MlDsa44(_) => Algorithm::MlDsa44,
            VerifyingKeyInner::MlDsa65(_) => Algorithm::MlDsa65,
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        match &self.0 {
            VerifyingKeyInner::MlDsa44(key) => verify_with(key, message, signature),
            VerifyingKeyInner::MlDsa65(key) => verify_with(key, message, signature),
        }
    }
}

impl fmt::Debug for MlDsaVerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsaVerifyingKey")
            .field("algorithm", &self.algorithm())
            .finish_non_exhaustive()
    }
}

fn sign_with<P: MlDsaParams>(
    key: &ml_dsa::SigningKey<P>,
    mode: SigningMode,
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    let key = key.expanded_key();
    let signature = match mode {
        SigningMode::Deterministic => key.sign_deterministic(message, CONTEXT),
        SigningMode::Hedged => key.sign_randomized(message, CONTEXT, &mut SysRng),
    }
    .map_err(|_| Error::SigningFailed("ML-DSA signing failed!".into()))?;
    Ok(signature.encode().to_vec())
}

fn verify_with<P: MlDsaParams>(
    key: &ml_dsa::VerifyingKey<P>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let encoded =
        EncodedSignature::<P>::try_from(signature).map_err(|_| Error::InvalidSignature)?;
    let signature = ml_dsa::Signature::<P>::decode(&encoded).ok_or(Error::InvalidSignature)?;
    if key.verify_with_context(message, CONTEXT, &signature) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}
