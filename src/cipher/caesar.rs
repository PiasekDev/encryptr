use disjoint_impls::disjoint_impls;
use num_modular::ModularCoreOps;

use crate::alphabet::{Alphabet, CasedChar, StaticAlphabet};
use crate::extension::char::CharExt;

pub struct CaesarCipher<A: Alphabet> {
	alphabet: A,
	offset: usize,
}

impl CaesarCipher<StaticAlphabet<char, 26>> {
	pub fn with_offset(offset: usize) -> Self {
		CaesarCipher::new(StaticAlphabet::default(), offset)
	}
}

impl<A: Alphabet> CaesarCipher<A> {
	pub fn new(alphabet: A, offset: usize) -> Self {
		CaesarCipher { alphabet, offset }
	}
}

disjoint_impls! {
	pub trait Cipher {
		fn encipher(&self, input: &str) -> String;
		fn decipher(&self, input: &str) -> String;
	}

	impl<A: Alphabet<Character = char>> Cipher for CaesarCipher<A> {
		fn encipher(&self, input: &str) -> String {
			input
				.chars()
				.map(|c| uncased::encode_char(self, &c).unwrap_or(c))
				.collect()
		}

		fn decipher(&self, input: &str) -> String {
			input
				.chars()
				.map(|c| uncased::decode_char(self, &c).unwrap_or(c))
				.collect()
		}
	}

	impl<A: Alphabet<Character = CasedChar>> Cipher for CaesarCipher<A> {
		fn encipher(&self, input: &str) -> String {
			input
				.chars()
				.map(|c| cased::encode_char(self, &c).unwrap_or(c))
				.collect()
		}

		fn decipher(&self, input: &str) -> String {
			input
				.chars()
				.map(|c| cased::decode_char(self, &c).unwrap_or(c))
				.collect()
		}
	}
}

mod uncased {
	use super::*;

	pub(super) fn encode_char(
		this: &CaesarCipher<impl Alphabet<Character = char>>,
		char: &char,
	) -> Option<char> {
		this.alphabet
			.index_of(*char)
			.map(|pos| pos.addm(this.offset, &this.alphabet.len()))
			.and_then(|new_pos| this.alphabet.char_at(new_pos))
			.copied()
	}

	pub(super) fn decode_char(
		this: &CaesarCipher<impl Alphabet<Character = char>>,
		char: &char,
	) -> Option<char> {
		this.alphabet
			.index_of(*char)
			.map(|pos| pos.subm(this.offset, &this.alphabet.len()))
			.and_then(|new_pos| this.alphabet.char_at(new_pos))
			.copied()
	}
}

mod cased {
	use super::*;

	pub(super) fn encode_char(
		this: &CaesarCipher<impl Alphabet<Character = CasedChar>>,
		char: &char,
	) -> Option<char> {
		this.alphabet
			.index_of(*char)
			.map(|pos| pos.addm(this.offset, &this.alphabet.len()))
			.and_then(|new_pos| this.alphabet.char_at(new_pos))
			.and_then(|encoded| char.case().map(|case| encoded.at_case(&case)))
	}

	pub(super) fn decode_char(
		this: &CaesarCipher<impl Alphabet<Character = CasedChar>>,
		char: &char,
	) -> Option<char> {
		this.alphabet
			.index_of(*char)
			.map(|pos| pos.subm(this.offset, &this.alphabet.len()))
			.and_then(|new_pos| this.alphabet.char_at(new_pos))
			.and_then(|encoded| char.case().map(|case| encoded.at_case(&case)))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_default_caesar_cipher() {
		let cipher = CaesarCipher::with_offset(3);
		let encoded = cipher.encipher("HELLO");
		assert_eq!(encoded, "KHOOR");
		let decoded = cipher.decipher(&encoded);
		assert_eq!(decoded, "HELLO");
	}

	#[test]
	fn test_caesar_cipher_with_big_offset() {
		let cipher = CaesarCipher::with_offset(29); // 29 % 26 == 3
		let encoded = cipher.encipher("HELLO");
		assert_eq!(encoded, "KHOOR");
		let decoded = cipher.decipher(&encoded);
		assert_eq!(decoded, "HELLO");
	}

	#[test]
	fn test_caesar_cipher_with_custom_alphabet_and_offset() {
		let alphabet = StaticAlphabet::polish_uppercase();
		let offset = 7;
		let cipher = CaesarCipher::new(alphabet, offset);
		let encoded = cipher.encipher("CZEŚĆ");
		assert_eq!(encoded, "HĆKŻI");
		let decoded = cipher.decipher(&encoded);
		assert_eq!(decoded, "CZEŚĆ");
	}

	#[test]
	fn test_caesar_cipher_with_mixed_case_letters() {
		let alphabet = StaticAlphabet::ascii_cased();
		let offset = 3;
		let cipher = CaesarCipher::new(alphabet, offset);
		let enciphered = cipher.encipher("tHe quIcK BrOwN fOx jUmPeD OvEr ThE LaZy DoG.");
		assert_eq!(enciphered, "wKh txLfN EuRzQ iRa mXpShG RyHu WkH OdCb GrJ.");
		let deciphered = cipher.decipher(&enciphered);
		assert_eq!(deciphered, "tHe quIcK BrOwN fOx jUmPeD OvEr ThE LaZy DoG.");
	}
}
