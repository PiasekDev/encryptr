use num_modular::ModularUnaryOps;

use crate::alphabet::{Alphabet, AlphabetIndex, AlphabetIndexable};

pub struct AffineCipher {
	a: usize,
	b: usize,
	alphabet: Alphabet<char>,
}

impl AffineCipher {
	pub fn with_params(a: usize, b: usize) -> Result<Self, AffineCipherError> {
		Self::new(Alphabet::ascii_uppercase(), a, b)
	}
}

#[derive(Debug)]
pub enum AffineCipherError {
	InvalidAValue,
}

impl AffineCipher {
	pub fn new(alphabet: Alphabet<char>, a: usize, b: usize) -> Result<Self, AffineCipherError> {
		if a.invm(&alphabet.len()).is_none() {
			return Err(AffineCipherError::InvalidAValue);
		}

		Ok(AffineCipher { a, b, alphabet })
	}

	pub fn encode(&self, input: &str) -> String {
		input
			.chars()
			.map(|c| self.encode_char(&c).unwrap_or(c))
			.collect()
	}

	fn encode_char(&self, char: &char) -> Option<char> {
		self.alphabet
			.index_of(char)
			.map(|index| self.a * index + self.b)
			.map(|new_index| new_index.get())
			.copied()
	}

	pub fn decode(&self, input: &str) -> String {
		input
			.chars()
			.map(|c| self.decode_char(&c).unwrap_or(c))
			.collect()
	}

	fn decode_char(&self, char: &char) -> Option<char> {
		self.alphabet
			.index_of(char)
			.zip(self.a.invm(&self.alphabet.len()))
			.map(|(index, inverse)| inverse * (index - self.b))
			.map(|new_index| new_index.get())
			.copied()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_default_affine_cipher() {
		let cipher = AffineCipher::with_params(5, 13).unwrap();
		let encoded = cipher.encode("The enemy knows the system.".to_uppercase().as_str());
		assert_eq!(encoded, "EWH HAHVD LAFTZ EWH ZDZEHV.");
		let decoded = cipher.decode(&encoded);
		assert_eq!(decoded, "THE ENEMY KNOWS THE SYSTEM.");
	}
}
