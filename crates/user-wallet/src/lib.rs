//! The user wallet: a stand-in for the wallet on the user's phone.
//!
//! It holds the user's credential and the user's root key `sk_U`, and acts
//! only with the user present. The agent wallet never sees `sk_U` or the
//! passphrase that protects it.

pub mod keystore;
