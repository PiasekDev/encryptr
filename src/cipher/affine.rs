use num_modular::ModularUnaryOps;

use crate::alphabet::{Alphabet, StaticAlphabet};

pub struct AffineCipher<A: Alphabet> {
	a: usize,
	b: usize,
	alphabet: A,
}

#[derive(Debug)]
pub enum AffineCipherError {
	InvalidAValue,
}

impl AffineCipher<StaticAlphabet<char, 26>> {
	pub fn with_params(a: usize, b: usize) -> Result<Self, AffineCipherError> {
		Self::new(StaticAlphabet::default(), a, b)
	}

	pub fn new(
		alphabet: StaticAlphabet<char, 26>,
		a: usize,
		b: usize,
	) -> Result<Self, AffineCipherError> {
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
			.index_of(*char)
			.map(|pos| pos * self.a + self.b)
			.map(|new_pos| *self.alphabet.char_at(new_pos))
	}

	pub fn decode(&self, input: &str) -> String {
		input
			.chars()
			.map(|c| self.decode_char(&c).unwrap_or(c))
			.collect()
	}

	fn decode_char(&self, char: &char) -> Option<char> {
		self.alphabet
			.index_of(*char)
			.map(|pos| (pos - self.b) * self.a.invm(&self.alphabet.len()).unwrap())
			.map(|new_pos| *self.alphabet.char_at(new_pos))
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
