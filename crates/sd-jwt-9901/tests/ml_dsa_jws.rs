//! ML-DSA JWS tests, checked against the JOSE examples of
//! `draft-ietf-cose-dilithium` (see `tests/vectors/README.md`).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sd_jwt_9901::error::Error;
use sd_jwt_9901::jws::{self, Algorithm, Signer};
use sd_jwt_9901::mldsa::{MlDsaSigningKey, MlDsaVerifyingKey, SigningMode};
use serde_json::{Map, Value, json};

/// One JOSE example from the draft.
struct Example {
    seed: [u8; 32],
    /// The public JWK, with `priv` removed.
    public_jwk: Map<String, Value>,
    jws: String,
}

fn example(algorithm: Algorithm) -> Example {
    let file = match algorithm {
        Algorithm::MlDsa44 => "ML_DSA_44.jose.json",
        Algorithm::MlDsa65 => "ML_DSA_65.jose.json",
        _ => unreachable!(),
    };
    let path = format!("{}/tests/vectors/{file}", env!("CARGO_MANIFEST_DIR"));
    let vector: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut jwk = vector["jwk"].as_object().unwrap().clone();
    let seed = jwk.remove("priv").unwrap();
    Example {
        seed: b64(seed.as_str().unwrap()).try_into().unwrap(),
        public_jwk: jwk,
        jws: vector["jws"].as_str().unwrap().to_string(),
    }
}

fn b64(text: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(text).unwrap()
}

fn header(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

const BOTH: [Algorithm; 2] = [Algorithm::MlDsa44, Algorithm::MlDsa65];

#[test]
fn seed_derives_the_published_public_key() {
    for algorithm in BOTH {
        let ex = example(algorithm);
        let ours = MlDsaSigningKey::from_seed(algorithm, &ex.seed)
            .verifying_key()
            .to_jwk();
        assert_eq!(ours["kty"], ex.public_jwk["kty"]);
        assert_eq!(ours["alg"], ex.public_jwk["alg"]);
        assert_eq!(ours["pub"], ex.public_jwk["pub"], "{algorithm:?}");
    }
}

#[test]
fn published_jws_verifies() {
    for algorithm in BOTH {
        let ex = example(algorithm);
        let key = MlDsaVerifyingKey::from_jwk(&ex.public_jwk).unwrap();
        let verified = jws::verify(&ex.jws, &key).unwrap();
        assert_eq!(verified.header()["alg"], algorithm.as_str());
        assert_eq!(verified.header()["kid"], ex.public_jwk["kid"]);
    }
}

#[test]
fn deterministic_signing_reproduces_published_jws_byte_for_byte() {
    for algorithm in BOTH {
        let ex = example(algorithm);
        let payload = b64(ex.jws.split('.').nth(1).unwrap());
        let key =
            MlDsaSigningKey::from_seed(algorithm, &ex.seed).with_mode(SigningMode::Deterministic);
        let ours = jws::sign(
            header(json!({ "kid": ex.public_jwk["kid"] })),
            &payload,
            &key,
        )
        .unwrap();
        assert_eq!(ours, ex.jws, "{algorithm:?}");
    }
}

#[test]
fn hedged_signatures_differ_and_both_verify() {
    let key = MlDsaSigningKey::generate(Algorithm::MlDsa44).unwrap();
    assert_eq!(key.algorithm(), Algorithm::MlDsa44);
    let verifier = key.verifying_key();
    let first = jws::sign(Map::new(), b"same payload", &key).unwrap();
    let second = jws::sign(Map::new(), b"same payload", &key).unwrap();
    assert_ne!(first, second, "hedged signing should randomise");
    assert_eq!(
        jws::verify(&first, &verifier).unwrap().payload(),
        b"same payload"
    );
    assert_eq!(
        jws::verify(&second, &verifier).unwrap().payload(),
        b"same payload"
    );
}

#[test]
fn alg_comes_from_the_key_and_typ_from_the_caller() {
    let key = MlDsaSigningKey::generate(Algorithm::MlDsa44).unwrap();
    let token = jws::sign(
        header(json!({ "alg": "none", "typ": "kb+jwt" })),
        b"{}",
        &key,
    )
    .unwrap();
    let verified = jws::verify(&token, &key.verifying_key()).unwrap();
    assert_eq!(verified.header()["alg"], "ML-DSA-44");
    assert_eq!(verified.header()["typ"], "kb+jwt");
}

#[test]
fn token_for_another_algorithm_is_rejected() {
    let key_65 = MlDsaSigningKey::generate(Algorithm::MlDsa65).unwrap();
    let verifier_44 = MlDsaSigningKey::generate(Algorithm::MlDsa44)
        .unwrap()
        .verifying_key();
    let token = jws::sign(Map::new(), b"{}", &key_65).unwrap();
    assert!(matches!(
        jws::verify(&token, &verifier_44),
        Err(Error::UnexpectedAlgorithm(alg)) if alg == "ML-DSA-65"
    ));

    // A forged header claiming "none" never reaches the signature check.
    let forged = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode("{}")
    );
    assert!(matches!(
        jws::verify(&forged, &verifier_44),
        Err(Error::UnexpectedAlgorithm(alg)) if alg == "none"
    ));
}

#[test]
fn tampered_payload_is_rejected() {
    let key = MlDsaSigningKey::generate(Algorithm::MlDsa44).unwrap();
    let token = jws::sign(Map::new(), b"{\"age_over_18\":true}", &key).unwrap();
    let mut parts: Vec<String> = token.split('.').map(String::from).collect();
    parts[1] = URL_SAFE_NO_PAD.encode(b"{\"age_over_18\":false}");
    assert!(matches!(
        jws::verify(&parts.join("."), &key.verifying_key()),
        Err(Error::InvalidSignature)
    ));
}

#[test]
fn crit_header_is_rejected() {
    let key = MlDsaSigningKey::generate(Algorithm::MlDsa44).unwrap();
    let token = jws::sign(header(json!({ "crit": ["exp"], "exp": 1 })), b"{}", &key).unwrap();
    assert!(matches!(
        jws::verify(&token, &key.verifying_key()),
        Err(Error::UnsupportedHeader("crit"))
    ));
}

#[test]
fn malformed_tokens_are_rejected_without_panicking() {
    let verifier = MlDsaSigningKey::generate(Algorithm::MlDsa44)
        .unwrap()
        .verifying_key();
    let e30 = URL_SAFE_NO_PAD.encode("{}");
    let array = URL_SAFE_NO_PAD.encode("[]");
    let alg = URL_SAFE_NO_PAD.encode(r#"{"alg":"ML-DSA-44"}"#);
    for token in [
        String::new(),
        "a".into(),
        "a.b".into(),
        "a.b.c.d".into(),
        format!("!!!.{e30}.AA"),
        format!("{array}.{e30}.AA"),
        format!("{e30}.{e30}.AA"),
        format!("{alg}.!!!.AA"),
        format!("{alg}.{e30}.!!!"),
        format!("{alg}.{e30}.AA"),
    ] {
        assert!(
            jws::verify(&token, &verifier).is_err(),
            "accepted {token:?}"
        );
    }
}

#[test]
fn public_jwks_are_validated() {
    let ex = example(Algorithm::MlDsa44);
    let round_trip = MlDsaVerifyingKey::from_jwk(&ex.public_jwk)
        .unwrap()
        .to_jwk();
    assert_eq!(round_trip["pub"], ex.public_jwk["pub"]);

    let with = |name: &str, value: Value| {
        let mut jwk = ex.public_jwk.clone();
        jwk.insert(name.into(), value);
        MlDsaVerifyingKey::from_jwk(&jwk)
    };
    assert!(with("priv", json!("AAAA")).is_err(), "priv in a public key");
    assert!(with("kty", json!("EC")).is_err(), "wrong kty");
    assert!(with("alg", json!("ES256")).is_err(), "unsupported alg");
    assert!(
        with("alg", json!("ML-DSA-65")).is_err(),
        "44-sized key labelled 65"
    );
    assert!(with("pub", json!("AAAA")).is_err(), "truncated key");
}

#[test]
fn debug_output_never_shows_the_key() {
    let ex = example(Algorithm::MlDsa44);
    let key = MlDsaSigningKey::from_seed(Algorithm::MlDsa44, &ex.seed);
    assert_eq!(
        format!("{key:?}"),
        "MlDsaSigningKey { algorithm: MlDsa44, mode: Hedged, .. }"
    );
}
