use bimap::BiMap;

use crate::alphabet::Alphabet;

pub struct SubstitutionCipher {
	mapping: BiMap<char, char>,
}

#[derive(Debug)]
pub enum SubstitutionCipherError {
	InvalidMappingLength,
}

impl SubstitutionCipher {
	pub fn new<A>(alphabet: A, mapping_alphabet: A) -> Result<Self, SubstitutionCipherError>
	where
		A: Alphabet<Character = char> + IntoIterator<Item = char>,
	{
		if alphabet.len() != mapping_alphabet.len() {
			return Err(SubstitutionCipherError::InvalidMappingLength);
		}

		let mapping = alphabet.into_iter().zip(mapping_alphabet).collect();
		Ok(SubstitutionCipher { mapping })
	}

	pub fn encode(&self, input: &str) -> String {
		input
			.chars()
			.map(|c| self.mapping.get_by_left(&c).copied().unwrap_or(c))
			.collect()
	}

	pub fn decode(&self, input: &str) -> String {
		input
			.chars()
			.map(|c| self.mapping.get_by_right(&c).copied().unwrap_or(c))
			.collect()
	}
}

#[cfg(test)]
mod tests {
	use crate::alphabet::StaticAlphabet;

use super::*;

	#[test]
	fn test_substitution_cipher() {
		let alphabet = StaticAlphabet::default();
		let mapping_alphabet = StaticAlphabet::new("QWERTYUIOPASDFGHJKLZXCVBNM").expect("String length should match alphabet size");
		let cipher = SubstitutionCipher::new(alphabet, mapping_alphabet).unwrap();

		let encoded = cipher.encode("HELLO");
		assert_eq!(encoded, "ITSSG");

		let decoded = cipher.decode(&encoded);
		assert_eq!(decoded, "HELLO");
	}
}
