pub mod cipher {
	pub mod affine;
	pub mod caesar;
	pub mod substitution;
	pub mod vigenere;

	pub trait Cipher {
		fn encode(&self, input: &str) -> String;
		fn decode(&self, input: &str) -> String;
	}
}

pub mod alphabet;
pub mod char_ext;
