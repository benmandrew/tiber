//! AES (Advanced Encryption Standard) symmetric block cipher implementation.
//! AES is a symmetric block cipher. It is symmetric because it uses the same
//! key to encrypt and decrypt, and is a block cipher because it operates on
//! individual, independent blocks of data. It is typically used for encryption
//! and decryption.
//!
//! - [Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
#![deny(missing_docs)]

pub mod decrypt;
pub mod encrypt;
pub mod key;
mod sbox;
