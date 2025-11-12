use num_modular::ModularCoreOps;

use crate::alphabet::Alphabet;

pub struct VigenereCipher {
	key: Vec<usize>,
	alphabet: Alphabet<char>,
}

#[derive(Debug)]
pub enum VigenereCipherError {
	KeywordNotInAlphabet,
}

impl VigenereCipher {
	pub fn with_keyword(keyword: &str) -> Result<Self, VigenereCipherError> {
		Self::new(Alphabet::default(), keyword)
	}
}

impl VigenereCipher {
	pub fn new(alphabet: Alphabet<char>, keyword: &str) -> Result<Self, VigenereCipherError> {
		let key = keyword
			.chars()
			.map(|c| alphabet.position_of(c))
			.collect::<Option<Vec<_>>>()
			.ok_or(VigenereCipherError::KeywordNotInAlphabet)?;

		Ok(VigenereCipher { key, alphabet })
	}

	pub fn encode(&self, input: &str) -> String {
		let mut key_iter = self.key.iter().cycle();
		let mut result = String::with_capacity(input.len());

		for char in input.chars() {
			let encoded_char = self
				.alphabet
				.position_of(char)
				.and_then(|pos| key_iter.next().map(|offset| (pos, offset)))
				.map(|(position, key_offset)| position.addm(key_offset, &self.alphabet.len()))
				.and_then(|new_pos| self.alphabet.char_at(new_pos))
				.unwrap_or(&char);

			result.push(*encoded_char);
		}

		result
	}

	pub fn decode(&self, input: &str) -> String {
		let mut key_iter = self.key.iter().cycle();
		let mut result = String::with_capacity(input.len());

		for char in input.chars() {
			let decoded_char = self
				.alphabet
				.position_of(char)
				.and_then(|pos| key_iter.next().map(|offset| (pos, offset)))
				.map(|(position, key_offset)| position.subm(key_offset, &self.alphabet.len()))
				.and_then(|new_pos| self.alphabet.char_at(new_pos))
				.unwrap_or(&char);

			result.push(*decoded_char);
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
