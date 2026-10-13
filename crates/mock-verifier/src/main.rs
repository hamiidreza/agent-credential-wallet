//! A mock verifier: a wine shop that sells only to buyers who prove they are over 18.
//!
//! `wine-shop <issuer.jwk>` serves HTTP on localhost:
//! - `POST /order` answers with a presentation request;
//! - `POST /complete` takes `{"nonce", "presentation"}` and checks the presentation.

use std::collections::HashSet;
use std::error::Error;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::routing::post;
use sd_jwt_9901::mldsa::MlDsaVerifyingKey;
use sd_jwt_9901::sd_jwt::SdJwt;
use serde::Deserialize;
use serde_json::{Value, json};

const ADDRESS: &str = "127.0.0.1:8080";
/// The shop's identifier. Presentations must be bound to it.
const AUDIENCE: &str = "https://wine-shop.example";
/// The claim the shop asks for.
const CLAIM: &str = "age_over_18";

struct Shop {
    issuer: MlDsaVerifyingKey,
    /// Nonces handed out and not used yet.
    pending: Mutex<HashSet<String>>,
}

#[derive(Deserialize)]
struct CompleteOrder {
    nonce: String,
    presentation: String,
}

async fn order(State(shop): State<Arc<Shop>>) -> Result<Json<Value>, StatusCode> {
    let random = || getrandom::u64().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    let nonce = format!("{:016x}{:016x}", random()?, random()?);
    shop.pending.lock().unwrap().insert(nonce.clone());
    let request = json!({"claim": CLAIM, "audience": AUDIENCE, "nonce": nonce});
    Ok(Json(request))
}

async fn complete(
    State(shop): State<Arc<Shop>>,
    Json(order): Json<CompleteOrder>,
) -> Result<&'static str, (StatusCode, String)> {
    let reject = |reason: String| (StatusCode::FORBIDDEN, reason);
    // A nonce works once, whether or not the presentation checks out.
    if !shop.pending.lock().unwrap().remove(&order.nonce) {
        return Err(reject("unknown or already used nonce".into()));
    }
    let claims = SdJwt::verify_presentation(
        &order.presentation,
        "dc+sd-jwt",
        &shop.issuer,
        AUDIENCE,
        &order.nonce,
    )
    .map_err(|e| reject(format!("presentation rejected: {e}")))?;
    if claims.get(CLAIM) != Some(&Value::Bool(true)) {
        return Err(reject(format!("the presentation does not prove {CLAIM}")));
    }
    Ok("Age verified. Your wine is on its way.")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: wine-shop <issuer.jwk>")?;
    let issuer = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let shop = Shop {
        issuer: MlDsaVerifyingKey::from_jwk(&issuer)?,
        pending: Mutex::default(),
    };
    let app = Router::new()
        .route("/order", post(order))
        .route("/complete", post(complete))
        .with_state(Arc::new(shop));
    let listener = tokio::net::TcpListener::bind(ADDRESS).await?;
    println!("wine-shop: listening on http://{ADDRESS}");
    axum::serve(listener, app).await?;
    Ok(())
}
