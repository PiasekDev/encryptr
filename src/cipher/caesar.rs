use crate::alphabet::{Alphabet, AlphabetIndexable, ToChar};
use crate::cipher::Cipher;

pub struct CaesarCipher<C> {
	alphabet: Alphabet<C>,
	offset: usize,
}

impl CaesarCipher<char> {
	pub fn with_offset(offset: usize) -> Self {
		CaesarCipher::new(Alphabet::ascii_uppercase(), offset)
	}
}

impl<C> CaesarCipher<C> {
	pub fn new(alphabet: Alphabet<C>, offset: usize) -> Self {
		CaesarCipher { alphabet, offset }
	}
}

impl<C> Cipher for CaesarCipher<C>
where
	Alphabet<C>: AlphabetIndexable<C>,
	for<'a> <Alphabet<C> as AlphabetIndexable<C>>::Index<'a>: ToChar,
{
	fn encipher(&self, input: &str) -> String {
		input
			.chars()
			.map(|c| self.encode_char(&c).unwrap_or(c))
			.collect()
	}

	fn decipher(&self, input: &str) -> String {
		input
			.chars()
			.map(|c| self.decode_char(&c).unwrap_or(c))
			.collect()
	}
}

impl<C> CaesarCipher<C>
where
	Alphabet<C>: AlphabetIndexable<C>,
	for<'a> <Alphabet<C> as AlphabetIndexable<C>>::Index<'a>: ToChar,
{
	fn encode_char(&self, char: &char) -> Option<char> {
		self.alphabet
			.index_of(char)
			.map(|index| index + self.offset)
			.map(|new_index| new_index.to_char())
	}

	fn decode_char(&self, char: &char) -> Option<char> {
		self.alphabet
			.index_of(char)
			.map(|index| index - self.offset)
			.map(|new_index| new_index.to_char())
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
		let alphabet = Alphabet::polish_uppercase();
		let offset = 7;
		let cipher = CaesarCipher::new(alphabet, offset);
		let encoded = cipher.encipher("CZEŚĆ");
		assert_eq!(encoded, "HĆKŻI");
		let decoded = cipher.decipher(&encoded);
		assert_eq!(decoded, "CZEŚĆ");
	}

	#[test]
	fn test_caesar_cipher_with_mixed_case_letters() {
		let alphabet = Alphabet::ascii_cased();
		let offset = 3;
		let cipher = CaesarCipher::new(alphabet, offset);
		let enciphered = cipher.encipher("tHe quIcK BrOwN fOx jUmPeD OvEr ThE LaZy DoG.");
		assert_eq!(enciphered, "wKh txLfN EuRzQ iRa mXpShG RyHu WkH OdCb GrJ.");
		let deciphered = cipher.decipher(&enciphered);
		assert_eq!(deciphered, "tHe quIcK BrOwN fOx jUmPeD OvEr ThE LaZy DoG.");
	}
}
