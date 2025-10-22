use bimap::BiMap;
use num_modular::{ModularCoreOps, ModularUnaryOps};

use crate::alphabet::Alphabet;

pub struct AffineCipher {
	a: usize,
	b: usize,
	alphabet_pos: BiMap<char, usize>,
}

#[derive(Debug)]
pub enum AffineCipherError {
	InvalidAValue,
}

impl AffineCipher {
	pub fn with_params(a: usize, b: usize) -> Result<Self, AffineCipherError> {
		Self::new(Alphabet::default(), a, b)
	}

	pub fn new(alphabet: Alphabet, a: usize, b: usize) -> Result<Self, AffineCipherError> {
		let alphabet_pos: BiMap<char, usize> = alphabet.0.chars().zip(0..).collect();
		if a.invm(&alphabet_pos.len()).is_none() {
			return Err(AffineCipherError::InvalidAValue);
		}

		Ok(AffineCipher { a, b, alphabet_pos })
	}

	pub fn encode(&self, input: &str) -> String {
		input
			.chars()
			.map(|c| self.encode_char(&c).unwrap_or(c))
			.collect()
	}

	fn encode_char(&self, char: &char) -> Option<char> {
		self.alphabet_pos
			.get_by_left(char)
			.map(|pos| (self.a * pos + self.b) % self.alphabet_pos.len())
			.and_then(|new_pos| self.alphabet_pos.get_by_right(&new_pos).copied())
	}

	pub fn decode(&self, input: &str) -> String {
		input
			.chars()
			.map(|c| self.decode_char(&c).unwrap_or(c))
			.collect()
	}

	fn decode_char(&self, char: &char) -> Option<char> {
		self.alphabet_pos
			.get_by_left(char)
			.map(|pos| {
				(self.a.invm(&self.alphabet_pos.len()).unwrap()
					* pos.subm(self.b, &self.alphabet_pos.len()))
					% self.alphabet_pos.len()
			})
			.and_then(|new_pos| self.alphabet_pos.get_by_right(&new_pos).copied())
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
