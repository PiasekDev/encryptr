use num_modular::ModularCoreOps;
use std::marker::PhantomData;

use crate::{
	alphabet::{Alphabet, CasedChar, UncasedAlphabet},
	char_ext::CharExt,
};

pub struct CaesarCipher<A, C>
where
	A: Alphabet<C>,
{
	alphabet: A,
	offset: usize,
	_marker: PhantomData<C>,
}

impl CaesarCipher<UncasedAlphabet, char> {
	pub fn with_offset(offset: usize) -> Self {
		CaesarCipher::new(UncasedAlphabet::default(), offset)
	}
}

impl<A, C> CaesarCipher<A, C>
where
	A: Alphabet<C>,
{
	pub fn new(alphabet: A, offset: usize) -> Self {
		CaesarCipher { alphabet, offset, _marker: PhantomData }
	}
}

impl<A> CaesarCipher<A, char>
where
	A: Alphabet<char>,
{
	pub fn encode(&self, input: &str) -> String {
		input
			.chars()
			.map(|c| self.encode_char(&c).unwrap_or(c))
			.collect()
	}

	fn encode_char(&self, char: &char) -> Option<char> {
		self.alphabet
			.index_of(*char)
			.map(|pos| pos.addm(self.offset, &self.alphabet.len()))
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
			.map(|pos| pos.subm(self.offset, &self.alphabet.len()))
			.and_then(|new_pos| self.alphabet.char_at(new_pos))
	}
}

impl<A> CaesarCipher<A, CasedChar>
where
	A: Alphabet<CasedChar>,
{
	pub fn encode(&self, input: &str) -> String {
		input
			.chars()
			.map(|c| self.encode_char(&c).unwrap_or(c))
			.collect()
	}

	fn encode_char(&self, char: &char) -> Option<char> {
		self.alphabet
			.index_of(*char)
			.map(|pos| pos.addm(self.offset, &self.alphabet.len()))
			.and_then(|new_pos| {
				self.alphabet
					.char_at(new_pos)
					.map(|c| char.case().map(|case| c.at_case(&case)).unwrap_or(*char))
			})
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
			.map(|pos| pos.subm(self.offset, &self.alphabet.len()))
			.and_then(|new_pos| {
				self.alphabet
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
