use std::char;

use bimap::BiMap;
use num_modular::ModularCoreOps;

use crate::alphabet::Alphabet;

pub struct VigenereCipher {
	key: Vec<usize>,
	alphabet_pos: BiMap<char, usize>,
}

#[derive(Debug)]
pub enum VigenereCipherError {
	KeywordNotInAlphabet,
}

impl VigenereCipher {
	pub fn with_keyword(keyword: &str) -> Result<Self, VigenereCipherError> {
		Self::new(Alphabet::default(), keyword)
	}

	pub fn new(alphabet: Alphabet, keyword: &str) -> Result<Self, VigenereCipherError> {
		let alphabet_pos: BiMap<char, usize> = alphabet.0.chars().zip(0..).collect();
		let key = keyword
			.chars()
			.map(|c| alphabet_pos.get_by_left(&c).copied())
			.collect::<Option<Vec<_>>>()
			.ok_or(VigenereCipherError::KeywordNotInAlphabet)?;

		Ok(VigenereCipher { key, alphabet_pos })
	}

	pub fn encode(&self, input: &str) -> String {
		let mut key_iter = self.key.iter().cycle();
		let mut result = String::with_capacity(input.len());

		for char in input.chars() {
			let encoded_char = if let Some(position) = self.alphabet_pos.get_by_left(&char) {
				let key_offset = key_iter.next().unwrap();
				let new_pos = position.addm(key_offset, &self.alphabet_pos.len());
				*self.alphabet_pos.get_by_right(&new_pos).unwrap()
			} else {
				char
			};

			result.push(encoded_char);
		}

		result
	}

	pub fn decode(&self, input: &str) -> String {
		let mut key_iter = self.key.iter().cycle();
		let mut result = String::with_capacity(input.len());

		for char in input.chars() {
			let encoded_char = if let Some(position) = self.alphabet_pos.get_by_left(&char) {
				let key_offset = key_iter.next().unwrap();
				let new_pos = position.subm(key_offset, &self.alphabet_pos.len());
				*self.alphabet_pos.get_by_right(&new_pos).unwrap()
			} else {
				char
			};

			result.push(encoded_char);
		}

		result
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_vigenere_cipher() {
		let cipher = VigenereCipher::with_keyword("LEMON").unwrap();

		let encoded = cipher.encode("ATTACK AT DAWN");
		assert_eq!(encoded, "LXFOPV EF RNHR");

		let decoded = cipher.decode(&encoded);
		assert_eq!(decoded, "ATTACK AT DAWN");
	}
}
