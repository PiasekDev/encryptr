use bimap::BiMap;
use num_modular::ModularCoreOps;

use crate::alphabet::Alphabet;

pub struct CaesarCipher {
	alphabet_pos: BiMap<char, usize>,
	offset: usize,
}

impl CaesarCipher {
	pub fn with_offset(offset: usize) -> Self {
		CaesarCipher::new(Alphabet::default(), offset)
	}

	pub fn new(alphabet: Alphabet, offset: usize) -> Self {
		let alphabet_pos = alphabet.0.chars().zip(0..).collect();

		CaesarCipher {
			alphabet_pos,
			offset,
		}
	}

	pub fn encode(&self, input: &str) -> String {
		input
			.chars()
			.map(|c| self.encode_char(&c).unwrap_or(c))
			.collect()
	}

	fn encode_char(&self, char: &char) -> Option<char> {
		let was_uppercase = char.is_uppercase();
		let uppercase_char = char.to_uppercase().next().unwrap();

		self.alphabet_pos
			.get_by_left(&uppercase_char)
			.map(|pos| pos.addm(self.offset, &self.alphabet_pos.len()))
			.and_then(|new_pos| self.alphabet_pos.get_by_right(&new_pos))
			.map(|new_char| {
				if was_uppercase {
					new_char.to_uppercase().next().unwrap()
				} else {
					*new_char
				}
			})
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
			.map(|pos| pos.subm(self.offset, &self.alphabet_pos.len()))
			.and_then(|new_pos| self.alphabet_pos.get_by_right(&new_pos).copied())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_default_caesar_cipher() {
		let cipher = CaesarCipher::with_offset(3);
		let encoded = cipher.encode("HELLO");
		assert_eq!(encoded, "KHOOR");
		let decoded = cipher.decode(&encoded);
		assert_eq!(decoded, "HELLO");
	}

	#[test]
	fn test_caesar_cipher_with_big_offset() {
		let cipher = CaesarCipher::with_offset(29); // 29 % 26 == 3
		let encoded = cipher.encode("HELLO");
		assert_eq!(encoded, "KHOOR");
		let decoded = cipher.decode(&encoded);
		assert_eq!(decoded, "HELLO");
	}

	#[test]
	fn test_caesar_cipher_with_custom_alphabet_and_offset() {
		let alphabet = Alphabet::polish();
		let offset = 7;
		let cipher = CaesarCipher::new(alphabet, offset);
		let encoded = cipher.encode("CZEŚĆ");
		assert_eq!(encoded, "HĆKŻI");
		let decoded = cipher.decode(&encoded);
		assert_eq!(decoded, "CZEŚĆ");
	}
}
