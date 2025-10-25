use std::{iter::once, ops::Deref};

use crate::alphabet::{Alphabet, AlphabetIndex};

#[derive(Debug)]
pub enum CasedAlphabetError {
	UnsupportedMultiCharacterWideCasing,
}

impl TryFrom<Alphabet> for CasedAlphabet {
	type Error = CasedAlphabetError;

	fn try_from(value: Alphabet) -> Result<Self, Self::Error> {
		let upper = value
			.iter()
			.map(|c| c.to_uppercase())
			.map(to_single_case_character)
			.collect::<Result<Alphabet, _>>()?;

		let lower = value
			.iter()
			.map(|c| c.to_lowercase())
			.map(to_single_case_character)
			.collect::<Result<Alphabet, _>>()?;

		Ok(CasedAlphabet { upper, lower })
	}
}

fn to_single_case_character(
	mut it: impl Iterator<Item = char>,
) -> Result<char, CasedAlphabetError> {
	match (it.next(), it.next()) {
		(Some(ch), None) => Ok(ch),
		_ => Err(CasedAlphabetError::UnsupportedMultiCharacterWideCasing),
	}
}

pub enum CasedChar {
	Upper(char),
	Lower(char),
}

impl CasedChar {
	pub fn char(&self) -> char {
		match self {
			CasedChar::Upper(c) => *c,
			CasedChar::Lower(c) => *c,
		}
	}
}

pub enum CasedCharIndex {
	Upper(usize),
	Lower(usize),
}

impl AlphabetIndex for CasedCharIndex {
	fn with_index(&self, index: usize) -> Self {
		match self {
			CasedCharIndex::Upper(_) => CasedCharIndex::Upper(index),
			CasedCharIndex::Lower(_) => CasedCharIndex::Lower(index),
		}
	}
}

// impl CasedCharIndex {
// 	pub fn with_index(&self, index: usize) -> Self {
// 		match self {
// 			CasedCharIndex::Upper(_) => CasedCharIndex::Upper(index),
// 			CasedCharIndex::Lower(_) => CasedCharIndex::Lower(index),
// 		}
// 	}
// }

impl Deref for CasedCharIndex {
	type Target = usize;

	fn deref(&self) -> &Self::Target {
		match self {
			CasedCharIndex::Upper(i) => i,
			CasedCharIndex::Lower(i) => i,
		}
	}
}

pub struct CasedAlphabet {
	upper: Alphabet,
	lower: Alphabet,
}

impl CasedAlphabet {
	pub fn len(&self) -> usize {
		self.upper.len()
	}

	pub fn is_empty(&self) -> bool {
		self.upper.is_empty()
	}

	pub fn iter(&self) -> impl Iterator<Item = (CasedChar, CasedChar)> {
		self.into_iter()
	}

	pub fn iter_flat(&self) -> impl Iterator<Item = CasedChar> {
		self.iter()
			.flat_map(|(upper, lower)| once(upper).chain(once(lower)))
	}

	pub fn index_of(&self, c: char) -> Option<impl AlphabetIndex> {
		self.upper
			.index_of(c)
			.map(|x| CasedCharIndex::Upper(*x))
			.or_else(|| {
				self.lower
					.index_of(c)
					.map(|x| CasedCharIndex::Lower(*x))
			})
	}

	pub fn char_at(&self, index: impl AlphabetIndex) -> Option<char> {
		match index {
			AlphabetIndex::Cased(cased_index) => match cased_index { // TODO: how to keep the information what type of index it is?
				CasedCharIndex::Upper(i) => self.upper.char_at(i),
				CasedCharIndex::Lower(i) => self.lower.char_at(i),
			},
			_ => None,
		}
	}
}

impl IntoIterator for CasedAlphabet {
	type Item = (CasedChar, CasedChar);
	type IntoIter = impl Iterator<Item = Self::Item>;

	fn into_iter(self) -> Self::IntoIter {
		self.upper
			.into_iter()
			.map(CasedChar::Upper)
			.zip(self.lower.into_iter().map(CasedChar::Lower))
	}
}

impl IntoIterator for &CasedAlphabet {
	type Item = (CasedChar, CasedChar);
	type IntoIter = impl Iterator<Item = Self::Item>;

	#[inline]
	fn into_iter(self) -> Self::IntoIter {
		self.upper
			.iter()
			.map(|&c| CasedChar::Upper(c))
			.zip(self.lower.iter().map(|&c| CasedChar::Lower(c)))
	}
}
