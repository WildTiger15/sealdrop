//! SealDrop crypto core. NOT AUDITED: a learning and portfolio project.
//!
//! Modules:
//! - [`xwing`]: X-Wing hybrid KEM (X25519 + ML-KEM-768), draft-connolly-cfrg-xwing-kem-11
//! - [`sign`]: ML-DSA-65 signatures (FIPS 204)
//! - [`file`]: versioned, chunked, signed file encryption format
//! - [`delegate`]: wrapping one file's key to an AI agent
//! - [`keywrap`]: wrapping a user's private keys under a passkey-derived key
//! - [`identity`]: a user's keypairs bundled together

#![forbid(unsafe_code)]

pub mod delegate;
pub mod file;
pub mod identity;
pub mod keywrap;
pub mod sign;
pub mod xwing;

mod error;
mod random;

pub use error::Error;
