use num_bigint::BigUint;
use thiserror::Error;

pub mod bits;
pub mod key;

pub struct RSACipher {
	pub key_pair: key::RSAKeyPair,
}

/// Returned when the input is outside the valid range [0, n).
#[derive(Debug, Error)]
#[error("RSA input too large: {input} >= {modulus} (input must be in range [0, {modulus}))")]
pub struct RSAInputTooLarge {
	pub input: BigUint,
	pub modulus: BigUint,
}

impl RSACipher {
	pub fn new(key_pair: key::RSAKeyPair) -> Self {
		Self { key_pair }
	}

	pub fn encipher(&self, plaintext: &BigUint) -> Result<BigUint, RSAInputTooLarge> {
		if plaintext >= &self.key_pair.public_key.n {
			return Err(RSAInputTooLarge {
				input: plaintext.clone(),
				modulus: self.key_pair.public_key.n.clone(),
			});
		}
		Ok(plaintext.modpow(&self.key_pair.public_key.e, &self.key_pair.public_key.n))
	}

	pub fn decipher(&self, ciphertext: &BigUint) -> Result<BigUint, RSAInputTooLarge> {
		if ciphertext >= &self.key_pair.private_key.n {
			return Err(RSAInputTooLarge {
				input: ciphertext.clone(),
				modulus: self.key_pair.private_key.n.clone(),
			});
		}
		Ok(ciphertext.modpow(&self.key_pair.private_key.d, &self.key_pair.private_key.n))
	}
}
