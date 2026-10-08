//! The agent wallet as an MCP server.
//!
//! - `wallet-mcp keygen <dir>` creates `sk_S` and writes `pk_S` for the issuer.
//! - `wallet-mcp serve <dir>` loads the wallet from `dir` and serves it on stdio.

use std::error::Error;
use std::fs;
use std::path::Path;

use agent_wallet::{AgentWallet, CredentialInfo, PresentationRequest};
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::transport::stdio;
use rmcp::{ServiceExt, tool, tool_router};
use sd_jwt_9901::jws::Algorithm;
use sd_jwt_9901::mldsa::{MlDsaSigningKey, MlDsaVerifyingKey, SEED_LEN};
use serde_json::Value;

struct Server {
    wallet: AgentWallet,
}

#[tool_router(server_handler)]
impl Server {
    #[tool(
        description = "Show the type of the credential this wallet holds and the names of the claims it can prove. Never shows claim values."
    )]
    fn find_credential(&self) -> Json<CredentialInfo> {
        Json(self.wallet.find_credential())
    }

    #[tool(
        description = "Build a presentation that proves one claim to one verifier. Copy the claim, audience and nonce from the verifier's request unchanged, and send the result to that verifier."
    )]
    fn create_presentation(
        &self,
        Parameters(request): Parameters<PresentationRequest>,
    ) -> Result<String, String> {
        self.wallet
            .create_presentation(&request)
            .map_err(|e| e.to_string())
    }
}

/// Creates `sk_S` as a random seed, and writes `pk_S` for the issuer.
fn keygen(dir: &Path) -> Result<(), Box<dyn Error>> {
    let mut seed = [0u8; SEED_LEN];
    getrandom::fill(&mut seed)?;
    let pk = MlDsaSigningKey::from_seed(Algorithm::MlDsa44, &seed).verifying_key();
    fs::create_dir_all(dir)?;
    fs::write(dir.join("sk_s.seed"), seed)?;
    fs::write(dir.join("pk_s.jwk"), Value::Object(pk.to_jwk()).to_string())?;
    Ok(())
}

/// Loads `sk_S`, the trusted issuer's key and the credential, and checks them.
fn open(dir: &Path) -> Result<AgentWallet, Box<dyn Error>> {
    let seed: [u8; SEED_LEN] = read(dir, "sk_s.seed")?
        .try_into()
        .map_err(|_| "sk_s.seed is not 32 bytes")?;
    let key = MlDsaSigningKey::from_seed(Algorithm::MlDsa44, &seed);
    let issuer = serde_json::from_slice(&read(dir, "issuer.jwk")?)?;
    let issuer = MlDsaVerifyingKey::from_jwk(&issuer)?;
    let credential = String::from_utf8(read(dir, "credential.sd-jwt")?)?;
    Ok(AgentWallet::load(credential.trim(), &issuer, key)?)
}

/// Reads a file from the wallet directory, naming the file if that fails.
fn read(dir: &Path, name: &str) -> Result<Vec<u8>, String> {
    let path = dir.join(name);
    fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["keygen", dir] => keygen(Path::new(dir)),
        ["serve", dir] => {
            let server = Server {
                wallet: open(Path::new(dir))?,
            };
            // stdout carries the MCP protocol, so anything for humans goes to stderr.
            eprintln!("wallet-mcp: serving {dir}");
            server.serve(stdio()).await?.waiting().await?;
            Ok(())
        }
        _ => Err("usage: wallet-mcp keygen <dir> | wallet-mcp serve <dir>".into()),
    }
}
