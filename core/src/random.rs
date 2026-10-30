//! One place where all randomness comes from: the operating system CSPRNG
//! (or `crypto.getRandomValues` in the browser), via the `getrandom` crate.

use crate::Error;

pub(crate) fn fill(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(|_| Error::Randomness)
}
