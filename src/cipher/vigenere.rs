use crate::alphabet::{Alphabet, AlphabetIndex, AlphabetIndexable};

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
			.map(|c| alphabet.position_of(&c))
			.collect::<Option<Vec<_>>>()
			.ok_or(VigenereCipherError::KeywordNotInAlphabet)?;

		Ok(VigenereCipher { key, alphabet })
	}

	pub fn encode(&self, input: &str) -> String {
		let mut key_iter = self.key.iter().cycle().copied();
		input
			.chars()
			.map(|char| self.encode_char(&mut key_iter, &char).unwrap_or(char))
			.collect()
	}

	fn encode_char(&self, key_iter: &mut impl Iterator<Item = usize>, char: &char) -> Option<char> {
		self.alphabet
			.index_of(char)
			.and_then(|index| key_iter.next().map(|offset| (index, offset)))
			.map(|(index, key_offset)| index + key_offset)
			.map(|new_index| new_index.get())
			.copied()
	}

	pub fn decode(&self, input: &str) -> String {
		let mut key_iter = self.key.iter().cycle().copied();
		input
			.chars()
			.map(|char| self.decode_char(&mut key_iter, &char).unwrap_or(char))
			.collect()
	}

	fn decode_char(&self, key_iter: &mut impl Iterator<Item = usize>, char: &char) -> Option<char> {
		self.alphabet
			.index_of(char)
			.and_then(|index| key_iter.next().map(|offset| (index, offset)))
			.map(|(index, key_offset)| index - key_offset)
			.map(|new_index| new_index.get())
			.copied()
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
