pub mod cipher {
	pub mod affine;
	pub mod caesar;
	pub mod substitution;
	pub mod vigenere;

	pub trait Cipher {
		fn encode(&self, input: &str) -> String; // rename to encrypt?
		fn decode(&self, input: &str) -> String; // rename to decrypt?
	}
}

pub mod alphabet;
pub mod char_ext;
