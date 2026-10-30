use core::fmt;

/// Errors are deliberately coarse. A caller (or attacker) learns *that*
/// something failed, never *which secret-dependent step* failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A public key or other input had the wrong length or failed validation.
    InvalidKey,
    /// The data is not a SealDrop file / key blob, or uses an unknown version.
    InvalidFormat,
    /// Signature did not verify. Nothing has been decrypted.
    BadSignature,
    /// Authenticated decryption failed (wrong key, tampering, truncation).
    DecryptionFailed,
    /// The operating system random number generator failed.
    Randomness,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::InvalidKey => "invalid key",
            Error::InvalidFormat => "invalid or unsupported format",
            Error::BadSignature => "signature verification failed",
            Error::DecryptionFailed => "decryption failed",
            Error::Randomness => "random number generator failure",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}
