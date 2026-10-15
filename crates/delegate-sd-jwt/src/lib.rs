//! Sub-credentials, following `draft-gco-oauth-delegate-sd-jwt-00`.
//!
//! Shared by the user wallet, which writes them, the agent wallet, which
//! enforces them, and the verifier, which checks them. So far it holds only
//! the policy format; the signed sub-credential that carries it comes later.

pub mod policy;
