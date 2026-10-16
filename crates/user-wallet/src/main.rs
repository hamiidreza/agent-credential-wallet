//! The user wallet CLI.
//!
//! - `user-wallet init <dir> [ML-DSA-44|ML-DSA-65]` creates `sk_U` and stores
//!   it in `<dir>/sk_u.json`, encrypted under a passphrase.
//!
//! The passphrase is read from the terminal. For scripted demos it can come
//! from the `USER_WALLET_PASSPHRASE` environment variable instead; other
//! processes of the same user can read a process's environment, so that is
//! for demos only.

use std::error::Error;
use std::fs;
use std::path::Path;

use sd_jwt_9901::jws::Algorithm;
use sd_jwt_9901::mldsa::SEED_LEN;
use user_wallet::keystore::{self, KdfParams};
use zeroize::Zeroizing;

const KEY_FILE: &str = "sk_u.json";
const PASSPHRASE_VAR: &str = "USER_WALLET_PASSPHRASE";

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["init", dir] => init(Path::new(dir), Algorithm::MlDsa44),
        ["init", dir, alg] => {
            let alg =
                Algorithm::from_name(alg).ok_or("unknown algorithm: use ML-DSA-44 or ML-DSA-65")?;
            init(Path::new(dir), alg)
        }
        _ => Err("usage: user-wallet init <dir> [ML-DSA-44|ML-DSA-65]".into()),
    }
}

/// Creates `sk_U` from fresh randomness and stores it, encrypted.
fn init(dir: &Path, alg: Algorithm) -> Result<(), Box<dyn Error>> {
    let path = dir.join(KEY_FILE);
    if path.exists() {
        return Err(format!("{} already exists; not overwriting a key", path.display()).into());
    }
    let passphrase = new_passphrase()?;
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    getrandom::fill(&mut *seed)?;
    let file = keystore::seal(&seed, alg, passphrase.as_bytes(), KdfParams::RFC_9106)?;
    fs::create_dir_all(dir)?;
    fs::write(&path, file)?;
    println!("created {} ({})", path.display(), alg.as_str());
    Ok(())
}

/// A new passphrase: from the environment if set, otherwise asked for twice.
fn new_passphrase() -> Result<Zeroizing<String>, Box<dyn Error>> {
    let passphrase = match std::env::var(PASSPHRASE_VAR) {
        Ok(p) => Zeroizing::new(p),
        Err(_) => {
            let first = Zeroizing::new(rpassword::prompt_password("New passphrase for sk_U: ")?);
            let second = Zeroizing::new(rpassword::prompt_password("Repeat it: ")?);
            if *first != *second {
                return Err("the passphrases differ".into());
            }
            first
        }
    };
    if passphrase.is_empty() {
        return Err("the passphrase is empty".into());
    }
    Ok(passphrase)
}
