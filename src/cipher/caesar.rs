use num_modular::ModularCoreOps;

use crate::{
	alphabet::{Alphabet, UncasedAlphabet},
	char_ext::CharExt,
	cipher::Cipher,
};

pub struct CaesarCipher<A> {
	alphabet: A,
	offset: usize,
}

impl CaesarCipher<UncasedAlphabet> {
	pub fn with_offset(offset: usize) -> Self {
		CaesarCipher::new(UncasedAlphabet::default(), offset)
	}
}

impl<A> CaesarCipher<A> {
	pub fn new(alphabet: A, offset: usize) -> Self {
		CaesarCipher { alphabet, offset }
	}
}

mod uncased {
	use num_modular::ModularCoreOps;

	use crate::alphabet::{Alphabet, UncasedAlphabet};

	use super::CaesarCipher;

	use crate::cipher::Cipher;

	impl Cipher for CaesarCipher<UncasedAlphabet> {
		fn encode(&self, input: &str) -> String {
			input
				.chars()
				.map(|c| encode_char(self, &c).unwrap_or(c))
				.collect()
		}

		fn decode(&self, input: &str) -> String {
			input
				.chars()
				.map(|c| decode_char(self, &c).unwrap_or(c))
				.collect()
		}
	}

	pub(crate) fn encode_char(
		this: &CaesarCipher<impl Alphabet<char>>,
		char: &char,
	) -> Option<char> {
		this.alphabet
			.index_of(*char)
			.map(|pos| pos.addm(this.offset, &this.alphabet.len()))
			.and_then(|new_pos| this.alphabet.char_at(new_pos))
	}

	pub(crate) fn decode_char(
		this: &CaesarCipher<impl Alphabet<char>>,
		char: &char,
	) -> Option<char> {
		this.alphabet
			.index_of(*char)
			.map(|pos| pos.subm(this.offset, &this.alphabet.len()))
			.and_then(|new_pos| this.alphabet.char_at(new_pos))
	}
}

mod cased {
	use num_modular::ModularCoreOps;

	use crate::alphabet::{Alphabet, CasedAlphabet, CasedChar};

	use crate::char_ext::CharExt;
	use crate::cipher::Cipher;
	use crate::cipher::caesar::CaesarCipher;

	impl Cipher for CaesarCipher<CasedAlphabet> {
		fn encode(&self, input: &str) -> String {
			input
				.chars()
				.map(|c| encode_char(self, &c).unwrap_or(c))
				.collect()
		}

		fn decode(&self, input: &str) -> String {
			input
				.chars()
				.map(|c| decode_char(self, &c).unwrap_or(c))
				.collect()
		}
	}

	pub(crate) fn encode_char(
		this: &CaesarCipher<impl Alphabet<CasedChar>>,
		char: &char,
	) -> Option<char> {
		this.alphabet
			.index_of(*char)
			.map(|pos| pos.addm(this.offset, &this.alphabet.len()))
			.and_then(|new_pos| {
				this.alphabet
					.char_at(new_pos)
					.map(|c| char.case().map(|case| c.at_case(&case)).unwrap_or(*char))
			})
	}

	pub(crate) fn decode_char(
		this: &CaesarCipher<impl Alphabet<CasedChar>>,
		char: &char,
	) -> Option<char> {
		this.alphabet
			.index_of(*char)
			.map(|pos| pos.subm(this.offset, &this.alphabet.len()))
			.and_then(|new_pos| {
				this.alphabet
					.char_at(new_pos)
					.map(|c| char.case().map(|case| c.at_case(&case)).unwrap_or(*char))
			})
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
		let alphabet = UncasedAlphabet::polish();
		let offset = 7;
		let cipher = CaesarCipher::new(alphabet, offset);
		let encoded = cipher.encode("CZEŚĆ");
		assert_eq!(encoded, "HĆKŻI");
		let decoded = cipher.decode(&encoded);
		assert_eq!(decoded, "CZEŚĆ");
	}
}
