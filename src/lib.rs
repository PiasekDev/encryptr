pub mod cipher {
	pub mod affine;
	pub mod caesar;
	pub mod substitution;
	pub mod vigenere;

	pub trait Cipher {
		fn encipher(&self, input: &str) -> String;
		fn decipher(&self, input: &str) -> String;
	}
}

pub mod alphabet;

pub mod extension {
	pub mod char;
}
