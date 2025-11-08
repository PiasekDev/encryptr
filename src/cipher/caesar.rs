use disjoint_impls::disjoint_impls;
use num_modular::ModularCoreOps;

use crate::{
	alphabet::{Alphabet, CasedChar, StaticAlphabet},
	char_ext::CharExt,
	cipher::Cipher,
};

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
	#[disjoint_impls(remote)]
	pub trait Cipher {
		fn encode(&self, input: &str) -> String;
		fn decode(&self, input: &str) -> String;
	}

	impl<A> Cipher for CaesarCipher<A>
	where
		A: Alphabet<Character = char>,
	{
		fn encode(&self, input: &str) -> String {
			input
				.chars()
				.map(|c| uncased::encode_char(self, &c).unwrap_or(c))
				.collect()
		}

		fn decode(&self, input: &str) -> String {
			input
				.chars()
				.map(|c| uncased::decode_char(self, &c).unwrap_or(c))
				.collect()
		}
	}

	impl<A> Cipher for CaesarCipher<A>
	where
		A: Alphabet<Character = CasedChar>,
	{
		fn encode(&self, input: &str) -> String {
			input
				.chars()
				.map(|c| cased::encode_char(self, &c).unwrap_or(c))
				.collect()
		}

		fn decode(&self, input: &str) -> String {
			input
				.chars()
				.map(|c| cased::decode_char(self, &c).unwrap_or(c))
				.collect()
		}
	}
}

mod uncased {
	use super::*;

	pub(crate) fn encode_char(
		this: &CaesarCipher<impl Alphabet<Character = char>>,
		char: &char,
	) -> Option<char> {
		this.alphabet
			.index_of(*char)
			.map(|pos| pos.addm(this.offset, &this.alphabet.len()))
			.and_then(|new_pos| this.alphabet.char_at(new_pos))
			.cloned()
	}

	pub(crate) fn decode_char(
		this: &CaesarCipher<impl Alphabet<Character = char>>,
		char: &char,
	) -> Option<char> {
		this.alphabet
			.index_of(*char)
			.map(|pos| pos.subm(this.offset, &this.alphabet.len()))
			.and_then(|new_pos| this.alphabet.char_at(new_pos))
			.cloned()
	}
}

mod cased {
	use super::*;

	pub(crate) fn encode_char(
		this: &CaesarCipher<impl Alphabet<Character = CasedChar>>,
		char: &char,
	) -> Option<char> {
		this.alphabet
			.index_of(*char)
			.map(|pos| pos.addm(this.offset, &this.alphabet.len()))
			.and_then(|new_pos| {
				this.alphabet
					.char_at(new_pos)
					.and_then(|c| char.case().map(|case| c.at_case(&case)))
			})
	}

	pub(crate) fn decode_char(
		this: &CaesarCipher<impl Alphabet<Character = CasedChar>>,
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
		let alphabet = StaticAlphabet::polish();
		let offset = 7;
		let cipher = CaesarCipher::new(alphabet, offset);
		let encoded = cipher.encode("CZEŚĆ");
		assert_eq!(encoded, "HĆKŻI");
		let decoded = cipher.decode(&encoded);
		assert_eq!(decoded, "CZEŚĆ");
	}

	#[test]
	fn test_caesar_cipher_with_mixed_case_letters() {
		let cipher = CaesarCipher::new(StaticAlphabet::default_cased(), 3);
		let encoded = cipher.encode("tHe quIcK BrOwN fOx jUmPeD OvEr ThE LaZy DoG.");
		assert_eq!(encoded, "wKh txLfN EuRzQ iRa mXpShG RyHu WkH OdCb GrJ.");
		let decoded = cipher.decode(&encoded);
		assert_eq!(decoded, "tHe quIcK BrOwN fOx jUmPeD OvEr ThE LaZy DoG.");
	}
}
