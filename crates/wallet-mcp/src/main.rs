//! The MCP interface to the agent wallet. For now, a hello-world that proves
//! the plumbing: a real agent can start this process, list its tools and call one.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::transport::stdio;
use rmcp::{ServiceExt, tool, tool_router};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct HelloRequest {
    /// Who to greet.
    name: String,
}

#[derive(Debug, Clone)]
struct Wallet;

#[tool_router(server_handler)]
impl Wallet {
    #[tool(description = "Say hello. Used only to check that the MCP plumbing works.")]
    fn hello(&self, Parameters(HelloRequest { name }): Parameters<HelloRequest>) -> String {
        format!("Hello, {name}! The agent wallet is reachable.")
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // stdout carries the MCP protocol, so anything for humans goes to stderr.
    eprintln!("wallet-mcp: serving on stdio");
    let service = Wallet.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
