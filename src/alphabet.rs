use std::ops::Index;

use bimap::BiMap;

pub struct Alphabet(pub String);

impl Default for Alphabet {
	fn default() -> Self {
		Self::new("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	}
}

impl Alphabet {
	pub fn new(s: &str) -> Self {
		Alphabet(s.to_owned())
	}

	pub fn polish() -> Self {
		Self::new("AĄBCĆDEĘFGHIJKLŁMNŃOÓPRSŚTUWYZŹŻ")
	}

	pub fn as_str(&self) -> &str {
		&self.0
	}

	pub fn to_index_bimap(&self) -> BiMap<char, usize> {
		self.0.chars().zip(0..).collect()
	}

	pub fn index_of(&self, c: char) -> Option<usize> {
		self.0.chars().position(|x| x == c)
	}

	pub fn char_at(&self, index: usize) -> Option<char> {
		self.0.chars().nth(index) // TODO: precompute a vector of chars and index into it
	}
}

// TODO: something like this
// impl Index<usize> for Alphabet {
// 	type Output = char;

// 	fn index(&self, index: usize) -> &Self::Output {
// 		&self.0[index..index+1]
// 	}
// }
