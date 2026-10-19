//! A mock issuer. It keeps its key and its pending nonces in an issuer
//! directory, and mints one demo ID credential per request.
//!
//! - `mock-issuer init <issuer-dir>` creates the issuer key.
//! - `mock-issuer nonce <issuer-dir>` prints a fresh nonce, usable once,
//!   within five minutes.
//! - `mock-issuer issue <issuer-dir> <nonce> <holder-dir>` reads a proof of
//!   possession on standard input, checks it against the nonce, and writes a
//!   credential bound to the proven key into `<holder-dir>`, with the
//!   issuer's public key beside it.
//! - `mock-issuer direct <issuer-dir> <agent-dir>` is section D's shortcut:
//!   it binds a credential to the agent wallet's `pk_s.jwk` with no proof.
//!   It goes once the agent wallet gets its credential through delegation.
//!
//! A full issuance to the user wallet:
//!
//! ```text
//! N=$(mock-issuer nonce demo/issuer)
//! user-wallet prove demo/user https://issuer.example $N | mock-issuer issue demo/issuer $N demo/user
//! ```
//!
//! The issuer key is a plain file, as this is a mock; section G moves it into
//! an HSM.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use sd_jwt_9901::disclosure::random_salt;
use sd_jwt_9901::jws::Algorithm;
use sd_jwt_9901::mldsa::{MlDsaSigningKey, MlDsaVerifyingKey, SEED_LEN};
use sd_jwt_9901::sd_jwt::{Claims, SdJwt};
use serde_json::{Value, json};
use user_wallet::proof;

/// The issuer's identifier: the `iss` of its credentials, and the `aud` a
/// proof of possession must name.
const ISSUER: &str = "https://issuer.example";
/// How long a nonce stays usable, in seconds.
const NONCE_LIFETIME: u64 = 300;

/// Nonces handed out and not yet used, with when each was handed out.
type Nonces = BTreeMap<String, u64>;

/// Prints errors with their messages rather than their debug form.
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["init", dir] => init(Path::new(dir)),
        ["nonce", dir] => nonce(Path::new(dir)),
        ["issue", dir, nonce, holder] => issue(Path::new(dir), nonce, Path::new(holder)),
        ["direct", dir, agent] => direct(Path::new(dir), Path::new(agent)),
        _ => Err(concat!(
            "usage: mock-issuer init <issuer-dir>\n",
            "       mock-issuer nonce <issuer-dir>\n",
            "       mock-issuer issue <issuer-dir> <nonce> <holder-dir>   (proof on stdin)\n",
            "       mock-issuer direct <issuer-dir> <agent-dir>"
        )
        .into()),
    }
}

/// Creates the issuer key, and its public half for holders and verifiers.
fn init(dir: &Path) -> Result<(), Box<dyn Error>> {
    if dir.join("issuer.seed").exists() {
        return Err(format!("{} already has an issuer key", dir.display()).into());
    }
    let mut seed = [0u8; SEED_LEN];
    getrandom::fill(&mut seed)?;
    let key = MlDsaSigningKey::from_seed(Algorithm::MlDsa44, &seed);
    fs::create_dir_all(dir)?;
    fs::write(dir.join("issuer.seed"), seed)?;
    fs::write(dir.join("issuer.jwk"), public_jwk(&key))?;
    eprintln!("created the issuer key in {}", dir.display());
    Ok(())
}

/// Hands out a nonce and remembers it.
fn nonce(dir: &Path) -> Result<(), Box<dyn Error>> {
    let now = now()?;
    let mut nonces = load_nonces(dir)?;
    nonces.retain(|_, issued| !expired(*issued, now));
    // 128 random bits, base64url-encoded: the same as a Disclosure's salt.
    let nonce = random_salt()?;
    nonces.insert(nonce.clone(), now);
    save_nonces(dir, &nonces)?;
    println!("{nonce}");
    Ok(())
}

/// Checks the proof on standard input against `nonce`, and issues a
/// credential to the key it proves possession of.
fn issue(dir: &Path, nonce: &str, holder_dir: &Path) -> Result<(), Box<dyn Error>> {
    let key = load_key(dir)?;
    // Read the proof first, so the wallet piping it in never meets a closed pipe.
    let mut proof = String::new();
    io::stdin().read_to_string(&mut proof)?;

    let now = now()?;
    let mut nonces = load_nonces(dir)?;
    let taken = take_nonce(&mut nonces, nonce, now);
    // Used up whatever happens next, so a failed attempt can't be retried
    // with the same nonce.
    save_nonces(dir, &nonces)?;
    taken?;
    let holder = proof::verify(proof.trim(), ISSUER, nonce, now)?;
    write_credential(&key, &holder, holder_dir)
}

/// Section D's shortcut: binds to `pk_s.jwk` without a proof of possession.
fn direct(dir: &Path, agent_dir: &Path) -> Result<(), Box<dyn Error>> {
    let key = load_key(dir)?;
    let holder = serde_json::from_str(&read(agent_dir, "pk_s.jwk")?)?;
    write_credential(&key, &MlDsaVerifyingKey::from_jwk(&holder)?, agent_dir)
}

/// Uses up `nonce`. Valid or not, it can't be used again.
fn take_nonce(nonces: &mut Nonces, nonce: &str, now: u64) -> Result<(), &'static str> {
    let issued = nonces
        .remove(nonce)
        .ok_or("unknown nonce, or one already used")?;
    if expired(issued, now) {
        return Err("the nonce has expired");
    }
    Ok(())
}

fn expired(issued: u64, now: u64) -> bool {
    now >= issued.saturating_add(NONCE_LIFETIME)
}

/// The demo ID credential, bound to `holder` through `cnf`.
fn mint(issuer: &MlDsaSigningKey, holder: &MlDsaVerifyingKey) -> Result<SdJwt, Box<dyn Error>> {
    let claims: Claims = serde_json::from_value(json!({
        "iss": ISSUER,
        "vct": "urn:example:id",
        "cnf": {"jwk": holder.to_jwk()},
        "given_name": "Erika",
        "family_name": "Mustermann",
        "birthdate": "1964-08-12",
        "age_over_18": true,
    }))?;
    let hidden = ["given_name", "family_name", "birthdate", "age_over_18"];
    Ok(SdJwt::issue(claims, &hidden, "dc+sd-jwt", issuer)?)
}

fn write_credential(
    issuer: &MlDsaSigningKey,
    holder: &MlDsaVerifyingKey,
    dir: &Path,
) -> Result<(), Box<dyn Error>> {
    let credential = mint(issuer, holder)?;
    fs::create_dir_all(dir)?;
    fs::write(dir.join("credential.sd-jwt"), credential.to_string())?;
    fs::write(dir.join("issuer.jwk"), public_jwk(issuer))?;
    eprintln!("issued a credential to {}", dir.display());
    Ok(())
}

fn load_key(dir: &Path) -> Result<MlDsaSigningKey, Box<dyn Error>> {
    let path = dir.join("issuer.seed");
    let seed: [u8; SEED_LEN] = fs::read(&path)
        .map_err(|e| format!("{}: {e} (run `mock-issuer init` first)", path.display()))?
        .try_into()
        .map_err(|_| "issuer.seed is not 32 bytes")?;
    Ok(MlDsaSigningKey::from_seed(Algorithm::MlDsa44, &seed))
}

fn load_nonces(dir: &Path) -> Result<Nonces, Box<dyn Error>> {
    match fs::read_to_string(dir.join("nonces.json")) {
        Ok(text) => Ok(serde_json::from_str(&text)?),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Nonces::new()),
        Err(e) => Err(e.into()),
    }
}

fn save_nonces(dir: &Path, nonces: &Nonces) -> Result<(), Box<dyn Error>> {
    fs::write(dir.join("nonces.json"), serde_json::to_string(nonces)?)?;
    Ok(())
}

fn public_jwk(key: &MlDsaSigningKey) -> String {
    Value::Object(key.verifying_key().to_jwk()).to_string()
}

fn read(dir: &Path, name: &str) -> Result<String, String> {
    let path = dir.join(name);
    fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
}

fn now() -> Result<u64, Box<dyn Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn key() -> MlDsaSigningKey {
        MlDsaSigningKey::generate(Algorithm::MlDsa44).unwrap()
    }

    #[test]
    fn a_nonce_works_once_and_only_while_fresh() {
        let mut nonces = Nonces::from([("fresh".into(), NOW), ("old".into(), NOW)]);
        assert_eq!(take_nonce(&mut nonces, "fresh", NOW + 299), Ok(()));
        assert_eq!(
            take_nonce(&mut nonces, "fresh", NOW + 299),
            Err("unknown nonce, or one already used")
        );
        assert_eq!(
            take_nonce(&mut nonces, "old", NOW + NONCE_LIFETIME),
            Err("the nonce has expired")
        );
        // Used up even though it had expired.
        assert!(nonces.is_empty());
        assert_eq!(
            take_nonce(&mut nonces, "never-issued", NOW),
            Err("unknown nonce, or one already used")
        );
    }

    #[test]
    fn the_credential_is_bound_to_the_proven_key() {
        let (issuer, user) = (key(), key());
        let proof = proof::sign(&user, ISSUER, "n-1", NOW).unwrap();
        let holder = proof::verify(&proof, ISSUER, "n-1", NOW).unwrap();
        let credential = mint(&issuer, &holder).unwrap().to_string();

        let claims = SdJwt::verify(&credential, "dc+sd-jwt", &issuer.verifying_key()).unwrap();
        assert_eq!(claims["iss"], ISSUER);
        assert_eq!(
            claims["cnf"]["jwk"],
            Value::Object(user.verifying_key().to_jwk())
        );
    }
}
