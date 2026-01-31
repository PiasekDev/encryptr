use num_bigint::BigUint;

pub mod key;

pub struct RSACipher {
	pub key_pair: key::RSAKeyPair,
}

impl RSACipher {
	pub fn new(key_pair: key::RSAKeyPair) -> Self {
		Self { key_pair }
	}

	pub fn encipher(&self, plaintext: &BigUint) -> BigUint {
		plaintext.modpow(&self.key_pair.public_key.e, &self.key_pair.public_key.n)
	}

	pub fn decipher(&self, ciphertext: &BigUint) -> BigUint {
		ciphertext.modpow(&self.key_pair.private_key.d, &self.key_pair.private_key.n)
	}
}
