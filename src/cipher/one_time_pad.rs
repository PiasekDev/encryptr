use bimap::BiMap;
use num_modular::ModularCoreOps;

use crate::alphabet::Alphabet;

pub struct OneTimePad {
	alphabet_pos: BiMap<char, usize>,
}

pub enum OneTimePadEncodingError {
	KeyTooShort,
}

impl OneTimePad {
	pub fn new(alphabet: Alphabet) -> Self {
		Self {
			alphabet_pos: alphabet.to_index_bimap(),
		}
	}

	pub fn encode(&self, plaintext: &str, key: &str) -> Result<String, OneTimePadEncodingError> {
		if key.len() < plaintext.len() {
			return Err(OneTimePadEncodingError::KeyTooShort);
		}

		let mut key_pos = key.chars().flat_map(|c| self.alphabet_pos.get_by_left(&c));
		let mut ciphertext = String::new();

		for char in plaintext.chars() {
			let encoded_char = self
				.alphabet_pos
				.get_by_left(&char)
				.and_then(|p_pos| key_pos.next().map(|k_pos| (p_pos, k_pos)))
				.map(|(p_pos, k_pos)| p_pos.addm(k_pos, &self.alphabet_pos.len()))
				.and_then(|c_pos| self.alphabet_pos.get_by_right(&c_pos).copied())
				.unwrap_or(char);

			ciphertext.push(encoded_char);
		}

		// for (p_char, k_char) in plaintext.chars().zip(key_pos) {
		// 	let p_pos = self.alphabet_pos.get_by_left(&p_char).unwrap();
		// 	let k_pos = self.alphabet_pos.get_by_left(&k_char).unwrap();

		// 	let c_pos = p_pos.addm(k_pos, &self.alphabet_pos.len());
		// 	let c_char = self.alphabet_pos.get_by_right(&c_pos).unwrap();

		// 	ciphertext.push(*c_char);
		// }

		Ok(ciphertext)
	}
}
