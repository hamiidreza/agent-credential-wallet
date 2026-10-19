//! Sub-credentials, following `draft-gco-oauth-delegate-sd-jwt-00`.
//!
//! Shared by the user wallet, which writes them, the agent wallet, which
//! enforces them, and the verifier, which checks them.
//!
//! - [`policy`]: the user's policy, one grant per audience.
//! - [`sub_credential`]: the policy signed by the user wallet as a Key
//!   Binding SD-JWT, and the chained serialisation that carries it.

pub mod policy;
pub mod sub_credential;
