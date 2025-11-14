use crate::extension::char::{CaseConversionError, CharExt};
use num_modular::VanillaInt;

mod cased_char;
pub use cased_char::*;

mod index;
pub use index::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Alphabet<T>(Vec<T>);

impl Default for Alphabet<char> {
	fn default() -> Self {
		Self::ascii_uppercase()
	}
}

impl Alphabet<char> {
	pub fn ascii_uppercase() -> Self {
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect()
	}

	pub fn polish_uppercase() -> Self {
		"AĄBCĆDEĘFGHIJKLŁMNŃOÓPRSŚTUWYZŹŻ".chars().collect()
	}
}

impl Alphabet<CasedChar> {
	pub fn ascii_cased() -> Self {
		Alphabet::ascii_uppercase()
			.try_into()
			.expect("All chars in the ASCII alphabet should be able to be cased")
	}
}

impl<T: PartialEq<char>> Alphabet<T> {
	pub fn len(&self) -> usize {
		self.0.len()
	}

	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	pub fn iter(&self) -> impl Iterator<Item = &T> {
		self.0.iter()
	}

	pub fn position_of(&self, char: &char) -> Option<usize> {
		self.0.iter().position(|x| x == char)
	}

	pub fn char_at(&self, index: usize) -> Option<&T> {
		self.0.get(index)
	}
}

pub trait AlphabetIndexable<T> {
	type Index<'a>: AlphabetIndex<'a, T>
	where
		Self: 'a;

	fn index_of(&self, char: &char) -> Option<Self::Index<'_>>;
}

impl AlphabetIndexable<char> for Alphabet<char> {
	type Index<'a> = UncasedAlphabetIndex<'a, char>;

	fn index_of(&self, char: &char) -> Option<Self::Index<'_>> {
		self.position_of(char).map(|pos| UncasedAlphabetIndex {
			alphabet: self,
			value: VanillaInt::new(pos, &self.len()),
		})
	}
}

impl AlphabetIndexable<CasedChar> for Alphabet<CasedChar> {
	type Index<'a> = CasedAlphabetIndex<'a>;

	fn index_of(&self, char: &char) -> Option<Self::Index<'_>> {
		let case = char.case()?;
		let pos = self.position_of(char)?;
		let index = UncasedAlphabetIndex {
			alphabet: self,
			value: VanillaInt::new(pos, &self.len()),
		};

		Some(CasedAlphabetIndex { case, index })
	}
}

impl<T> IntoIterator for Alphabet<T> {
	type Item = T;
	type IntoIter = std::vec::IntoIter<T>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl<'a, T> IntoIterator for &'a Alphabet<T> {
	type Item = &'a T;
	type IntoIter = std::slice::Iter<'a, T>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.iter()
	}
}

impl<T> FromIterator<T> for Alphabet<T> {
	fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
		Alphabet(iter.into_iter().collect())
	}
}

impl TryFrom<Alphabet<char>> for Alphabet<CasedChar> {
	type Error = CaseConversionError;

	fn try_from(value: Alphabet<char>) -> Result<Self, Self::Error> {
		value
			.into_iter()
			.map(CasedChar::try_from)
			.collect::<Result<Vec<_>, _>>()
			.map(Alphabet)
	}
}
