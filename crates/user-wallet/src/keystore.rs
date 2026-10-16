//! `sk_U` at rest: the ML-DSA seed, encrypted under a key derived from the
//! user's passphrase.
//!
//! Argon2id (RFC 9106) turns the passphrase into a 256-bit key, and
//! XChaCha20-Poly1305 encrypts the 32-byte seed with it. The file is JSON:
//!
//! ```json
//! {
//!   "alg": "ML-DSA-44",
//!   "kdf": {"name": "argon2id", "m_kib": 65536, "t": 3, "p": 4, "salt": "..."},
//!   "nonce": "...",
//!   "ciphertext": "..."
//! }
//! ```
//!
//! `alg` and `kdf` are authenticated as associated data, so editing either
//! makes the file fail to open rather than load a different key.

use argon2::{Argon2, Params};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sd_jwt_9901::jws::Algorithm;
use sd_jwt_9901::mldsa::{MlDsaSigningKey, SEED_LEN};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("malformed key file: {0}")]
    Malformed(String),

    #[error("wrong passphrase, or the key file was modified")]
    WrongPassphraseOrTampered,

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("no system randomness")]
    NoRandomness,
}

/// Argon2id's cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory, in KiB.
    pub m_kib: u32,
    /// Passes over the memory.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl KdfParams {
    /// RFC 9106's second recommended option, for when 2 GiB of memory per
    /// derivation is too much: 64 MiB, 3 passes, 4 lanes. The user wallet
    /// unlocks rarely, so this cost is paid rarely.
    pub const RFC_9106: Self = Self {
        m_kib: 64 * 1024,
        t: 3,
        p: 4,
    };
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    alg: String,
    kdf: Kdf,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Kdf {
    name: String,
    m_kib: u32,
    t: u32,
    p: u32,
    salt: String,
}

/// The associated data: the parts of the file that say how to use what's
/// inside. Field order is fixed, so this gives the same bytes when sealing
/// and when opening.
fn associated_data(alg: &str, kdf: &Kdf) -> Vec<u8> {
    serde_json::to_vec(&(alg, kdf)).expect("strings and integers always serialise")
}

/// Encrypts `seed` under `passphrase` and returns the key file's contents.
pub fn seal(
    seed: &[u8; SEED_LEN],
    alg: Algorithm,
    passphrase: &[u8],
    params: KdfParams,
) -> Result<String, KeystoreError> {
    let salt = random::<SALT_LEN>()?;
    let nonce = random::<NONCE_LEN>()?;
    let alg = alg.as_str().to_owned();
    let kdf = Kdf {
        name: "argon2id".to_owned(),
        m_kib: params.m_kib,
        t: params.t,
        p: params.p,
        salt: URL_SAFE_NO_PAD.encode(salt),
    };
    let key = derive_key(passphrase, &salt, params)?;
    let aad = associated_data(&alg, &kdf);
    let ciphertext = cipher(&key)
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: seed,
                aad: &aad,
            },
        )
        .map_err(|_| KeystoreError::Malformed("encryption failed".into()))?;
    let file = KeyFile {
        alg,
        kdf,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    serde_json::to_string_pretty(&file).map_err(|e| KeystoreError::Malformed(e.to_string()))
}

/// Decrypts a key file with `passphrase` and returns the signing key.
pub fn open(file: &str, passphrase: &[u8]) -> Result<MlDsaSigningKey, KeystoreError> {
    let malformed = |what: &str| KeystoreError::Malformed(what.to_owned());
    let file: KeyFile =
        serde_json::from_str(file).map_err(|e| KeystoreError::Malformed(e.to_string()))?;
    let alg = Algorithm::from_name(&file.alg)
        .ok_or_else(|| KeystoreError::Unsupported(format!("alg {:?}", file.alg)))?;
    let kdf = &file.kdf;
    if kdf.name != "argon2id" {
        return Err(KeystoreError::Unsupported(format!("kdf {:?}", kdf.name)));
    }
    let salt = decode::<SALT_LEN>(&kdf.salt).ok_or_else(|| malformed("salt"))?;
    let nonce = decode::<NONCE_LEN>(&file.nonce).ok_or_else(|| malformed("nonce"))?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&file.ciphertext)
        .map_err(|_| malformed("ciphertext"))?;

    let params = KdfParams {
        m_kib: kdf.m_kib,
        t: kdf.t,
        p: kdf.p,
    };
    let key = derive_key(passphrase, &salt, params)?;
    let aad = associated_data(&file.alg, kdf);
    let seed = Zeroizing::new(
        cipher(&key)
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| KeystoreError::WrongPassphraseOrTampered)?,
    );
    let seed: &[u8; SEED_LEN] = seed
        .as_slice()
        .try_into()
        .map_err(|_| malformed("the seed is not 32 bytes"))?;
    Ok(MlDsaSigningKey::from_seed(alg, seed))
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, KeystoreError> {
    let params = Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
        .map_err(|e| KeystoreError::Unsupported(format!("argon2 parameters: {e}")))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| KeystoreError::Unsupported(format!("argon2: {e}")))?;
    Ok(key)
}

fn cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.into())
}

fn random<const N: usize>() -> Result<[u8; N], KeystoreError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| KeystoreError::NoRandomness)?;
    Ok(bytes)
}

fn decode<const N: usize>(b64: &str) -> Option<[u8; N]> {
    URL_SAFE_NO_PAD.decode(b64).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sd_jwt_9901::jws::{Signer, Verifier};
    use serde_json::Value;

    /// Far below anything safe, so the tests run quickly in debug builds.
    const CHEAP: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };
    const PASSPHRASE: &[u8] = b"correct horse battery staple";
    const SEED: [u8; SEED_LEN] = [7; SEED_LEN];

    fn sealed(alg: Algorithm) -> String {
        seal(&SEED, alg, PASSPHRASE, CHEAP).unwrap()
    }

    #[test]
    fn opens_to_the_same_key() {
        for alg in [Algorithm::MlDsa44, Algorithm::MlDsa65] {
            let key = open(&sealed(alg), PASSPHRASE).unwrap();
            assert_eq!(key.algorithm(), alg);
            let expected = MlDsaSigningKey::from_seed(alg, &SEED).verifying_key();
            let signature = key.sign(b"message").unwrap();
            assert!(expected.verify(b"message", &signature).is_ok());
        }
    }

    #[test]
    fn the_file_does_not_contain_the_seed() {
        let file = sealed(Algorithm::MlDsa44);
        assert!(!file.contains(&URL_SAFE_NO_PAD.encode(SEED)));
        // A fresh salt and nonce every time: sealing twice gives different files.
        assert_ne!(file, sealed(Algorithm::MlDsa44));
    }

    #[test]
    fn rejects_a_wrong_passphrase() {
        let result = open(&sealed(Algorithm::MlDsa44), b"Tr0ub4dor&3");
        assert!(matches!(
            result,
            Err(KeystoreError::WrongPassphraseOrTampered)
        ));
    }

    #[test]
    fn rejects_edits_to_any_field() {
        let file: Value = serde_json::from_str(&sealed(Algorithm::MlDsa44)).unwrap();
        let other_b64 = |len| URL_SAFE_NO_PAD.encode(vec![1u8; len]);
        for (pointer, value) in [
            // Authenticated: decryption fails.
            ("/alg", Value::from("ML-DSA-65")),
            ("/kdf/t", Value::from(2)),
            ("/kdf/salt", Value::from(other_b64(SALT_LEN))),
            ("/nonce", Value::from(other_b64(NONCE_LEN))),
            ("/ciphertext", Value::from(other_b64(SEED_LEN + 16))),
        ] {
            let mut edited = file.clone();
            *edited.pointer_mut(pointer).unwrap() = value;
            let result = open(&edited.to_string(), PASSPHRASE);
            assert!(
                matches!(result, Err(KeystoreError::WrongPassphraseOrTampered)),
                "{pointer}: {result:?}"
            );
        }
    }

    #[test]
    fn rejects_malformed_and_unsupported_files() {
        let file: Value = serde_json::from_str(&sealed(Algorithm::MlDsa44)).unwrap();
        let edit = |pointer: &str, value: Value| {
            let mut edited = file.clone();
            *edited.pointer_mut(pointer).unwrap() = value;
            open(&edited.to_string(), PASSPHRASE)
        };
        assert!(matches!(
            edit("/alg", "ES256".into()),
            Err(KeystoreError::Unsupported(_))
        ));
        assert!(matches!(
            edit("/kdf/name", "pbkdf2".into()),
            Err(KeystoreError::Unsupported(_))
        ));
        assert!(matches!(
            edit("/nonce", "short".into()),
            Err(KeystoreError::Malformed(_))
        ));
        assert!(matches!(
            open("not json", PASSPHRASE),
            Err(KeystoreError::Malformed(_))
        ));
    }
}