//! An implementation of [RFC 9901], Selective Disclosure for JSON Web Tokens.
//!
//! This crate knows nothing about wallets, agents or MCP. It is intended to be
//! useful and publishable on its own; keep it that way.
//!
//! [RFC 9901]: https://www.rfc-editor.org/rfc/rfc9901.html

pub mod disclosure;
pub mod error;
pub mod jws;
mod kb_jwt;
pub mod mldsa;
pub mod sd_jwt;
