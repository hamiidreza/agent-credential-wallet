//! A mock issuer: mints one demo ID credential, bound to a wallet's `pk_S`.
//!
//! `mock-issuer <wallet-dir>` reads the wallet's `pk_s.jwk`, and writes the
//! credential and the issuer's public key into the same directory. The issuer
//! key is new on every run, so running it again re-issues from scratch.

use std::error::Error;
use std::fs;
use std::path::Path;

use sd_jwt_9901::jws::Algorithm;
use sd_jwt_9901::mldsa::{MlDsaSigningKey, MlDsaVerifyingKey};
use sd_jwt_9901::sd_jwt::{Claims, SdJwt};
use serde_json::{Value, json};

fn main() -> Result<(), Box<dyn Error>> {
    let dir = std::env::args()
        .nth(1)
        .ok_or("usage: mock-issuer <wallet-dir>")?;
    let dir = Path::new(&dir);

    let holder = serde_json::from_str(&fs::read_to_string(dir.join("pk_s.jwk"))?)?;
    let holder = MlDsaVerifyingKey::from_jwk(&holder)?;
    let issuer = MlDsaSigningKey::generate(Algorithm::MlDsa44)?;

    let claims: Claims = serde_json::from_value(json!({
        "iss": "https://issuer.example",
        "vct": "urn:example:id",
        "cnf": {"jwk": holder.to_jwk()},
        "given_name": "Erika",
        "family_name": "Mustermann",
        "birthdate": "1964-08-12",
        "age_over_18": true,
    }))?;
    let hidden = ["given_name", "family_name", "birthdate", "age_over_18"];
    let credential = SdJwt::issue(claims, &hidden, "dc+sd-jwt", &issuer)?;

    let issuer_jwk = Value::Object(issuer.verifying_key().to_jwk());
    fs::write(dir.join("credential.sd-jwt"), credential.to_string())?;
    fs::write(dir.join("issuer.jwk"), issuer_jwk.to_string())?;
    eprintln!("issued a credential to {}", dir.display());
    Ok(())
}
