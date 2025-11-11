use std::str::Chars;

use itertools::Itertools;

use crate::{
	alphabet::{Alphabet, CasedChar, ModuloIndex},
	extension::char::CaseConversionError,
};

pub struct StaticAlphabet<T, const N: usize>([T; N]);

impl Default for StaticAlphabet<char, 26> {
	fn default() -> Self {
		Self::ascii_uppercase()
	}
}

impl StaticAlphabet<char, 26> {
	pub fn ascii_uppercase() -> Self {
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			.chars()
			.try_into()
			.expect("There should be 26 ASCII uppercase letters")
	}
}

impl StaticAlphabet<char, 32> {
	pub fn polish_uppercase() -> Self {
		"AĄBCĆDEĘFGHIJKLŁMNŃOÓPRSŚTUWYZŹŻ"
			.chars()
			.try_into()
			.expect("There should be 32 Polish uppercase letters")
	}
}

impl StaticAlphabet<CasedChar, 26> {
	pub fn ascii_cased() -> Self {
		StaticAlphabet::ascii_uppercase()
			.try_into()
			.expect("All chars in the ASCII alphabet should be able to be cased")
	}
}

impl<T: PartialEq + PartialEq<char>, const N: usize> Alphabet for StaticAlphabet<T, N> {
	type Character = T;

	fn len(&self) -> usize {
		N
	}

	fn is_empty(&self) -> bool {
		N == 0
	}

	fn iter(&self) -> impl Iterator<Item = &Self::Character> {
		self.0.iter()
	}

	fn index_of(&self, char: char) -> Option<usize> {
		self.0.iter().position(|x| *x == char)
	}

	fn char_at(&self, index: usize) -> Option<&Self::Character> {
		self.0.get(index)
	}
}

impl<T: PartialEq + PartialEq<char>, const N: usize> StaticAlphabet<T, N> {
	pub fn index_of(&self, char: char) -> Option<ModuloIndex<N>> {
		Alphabet::index_of(self, char).map(ModuloIndex::new)
	}

	pub fn char_at(&self, index: ModuloIndex<N>) -> &<Self as Alphabet>::Character {
		Alphabet::char_at(self, index.inner()).expect("The index value should be in array bounds")
	}
}

/// A wrapper type to help implement `TryFrom<Chars>` generically (using IntoIterator as a trait bound).
///
/// See: https://github.com/rust-lang/rust/issues/50133
pub struct TryFromInputWrapper<T>(pub T);

#[derive(Debug)]
pub enum TryFromCharIteratorError {
	TooFewElements,
	TooManyElements,
}

impl<T: IntoIterator<Item = char>, const N: usize> TryFrom<TryFromInputWrapper<T>>
	for StaticAlphabet<char, N>
{
	type Error = TryFromCharIteratorError;

	fn try_from(value: TryFromInputWrapper<T>) -> Result<Self, Self::Error> {
		let mut chars = value.0.into_iter();
		let array = core::array::from_fn(|_| chars.next());

		if array.iter().any(|x| x.is_none()) {
			return Err(TryFromCharIteratorError::TooFewElements);
		}

		if chars.next().is_some() {
			return Err(TryFromCharIteratorError::TooManyElements);
		}

		Ok(Self(
			array.map(|x| x.expect("There should be exactly N elements")),
		))
	}
}

impl<const N: usize> TryFrom<Chars<'_>> for StaticAlphabet<char, N> {
	type Error = TryFromCharIteratorError;

	fn try_from(value: Chars) -> Result<Self, Self::Error> {
		TryFromInputWrapper(value).try_into()
	}
}

impl<const N: usize> TryFrom<StaticAlphabet<char, N>> for StaticAlphabet<CasedChar, N> {
	type Error = CaseConversionError;

	fn try_from(value: StaticAlphabet<char, N>) -> Result<Self, Self::Error> {
		value
			.into_iter()
			.map(CasedChar::try_from)
			.process_results(|mut chars| {
				core::array::from_fn(|_| chars.next().expect("There should be exactly N elements"))
			})
			.map(Self)
	}
}

impl<T, const N: usize> IntoIterator for StaticAlphabet<T, N> {
	type Item = T;
	type IntoIter = std::array::IntoIter<T, N>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl<'a, T, const N: usize> IntoIterator for &'a StaticAlphabet<T, N> {
	type Item = &'a T;
	type IntoIter = core::slice::Iter<'a, T>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.iter()
	}
}
