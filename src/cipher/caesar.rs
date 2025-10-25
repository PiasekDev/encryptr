use num_modular::ModularCoreOps;

use crate::{alphabet::Alphabet, cased_alphabet::CasedAlphabet};

pub struct CaesarCipher {
	alphabet: CasedAlphabet,
	offset: usize,
}

impl CaesarCipher {
	pub fn with_offset(offset: usize) -> Self {
		CaesarCipher::new(Alphabet::default(), offset)
	}

	pub fn new(alphabet: Alphabet, offset: usize) -> Self {
		CaesarCipher {
			alphabet: CasedAlphabet::try_from(alphabet).unwrap(),
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
		self.alphabet
			.index_of(*char)
			.map(|pos| pos.with_index(pos.addm(self.offset, &self.alphabet.len())))
			.and_then(|new_pos| self.alphabet.char_at(new_pos))
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
			.map(|pos| pos.with_index(pos.subm(self.offset, &self.alphabet.len())))
			.and_then(|new_pos| self.alphabet.char_at(new_pos))
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

	#[test]
	fn test_caesar_cipher_with_mixed_case_letters() {
		let cipher = CaesarCipher::with_offset(3);
		let encoded = cipher.encode("tHe quIcK BrOwN fOx jUmPeD OvEr ThE LaZy DoG.");
		assert_eq!(encoded, "wKh txLfN EuRzQ iRa mXpShG RyHu WkH OdCb GrJ.");
		let decoded = cipher.decode(&encoded);
		assert_eq!(decoded, "tHe quIcK BrOwN fOx jUmPeD OvEr ThE LaZy DoG.");
	}
}
