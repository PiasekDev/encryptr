use std::ops::Deref;

use crate::cased_alphabet::CasedCharIndex;

pub struct Alphabet(Vec<char>);

impl Default for Alphabet {
	fn default() -> Self {
		Self::new("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	}
}

impl Alphabet {
	pub fn new(s: &str) -> Self {
		Alphabet(s.chars().collect())
	}

	pub fn polish() -> Self {
		Self::new("AĄBCĆDEĘFGHIJKLŁMNŃOÓPRSŚTUWYZŹŻ")
	}

	pub fn len(&self) -> usize {
		self.0.len()
	}

	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	pub fn iter(&self) -> impl Iterator<Item = &char> {
		self.into_iter()
	}

	pub fn index_of(&self, c: char) -> Option<AlphabetIndex> {
		self.0.iter().position(|&x| x == c).map(AlphabetIndex::Simple)
	}

	pub fn char_at(&self, index: usize) -> Option<char> {
		self.0.get(index).copied()
	}
}

pub enum AlphabetIndex {
	Simple(usize),
	Cased(CasedCharIndex),
}

impl AlphabetIndex {
	pub fn index(&self) -> usize {
		match self {
			AlphabetIndex::Simple(i) => *i,
			AlphabetIndex::Cased(cased_index) => **cased_index,
		}
	}

	pub fn with_index(&self, index: usize) -> Self {
		match self {
			AlphabetIndex::Simple(_) => AlphabetIndex::Simple(index),
			AlphabetIndex::Cased(cased_index) => AlphabetIndex::Cased(cased_index.with_index(index)),
		}
	}
}

impl Deref for AlphabetIndex {
	type Target = usize;

	fn deref(&self) -> &Self::Target {
		match self {
			AlphabetIndex::Simple(i) => i,
			AlphabetIndex::Cased(cased_index) => cased_index,
		}
	}
}

impl IntoIterator for Alphabet {
	type Item = char;
	type IntoIter = std::vec::IntoIter<char>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl<'a> IntoIterator for &'a Alphabet {
	type Item = &'a char;
	type IntoIter = std::slice::Iter<'a, char>;

	#[inline]
	fn into_iter(self) -> Self::IntoIter {
		self.0.iter()
	}
}

impl FromIterator<char> for Alphabet {
	fn from_iter<T: IntoIterator<Item = char>>(iter: T) -> Self {
		Alphabet(iter.into_iter().collect())
	}
}
