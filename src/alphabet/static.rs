use crate::{
	alphabet::{Alphabet, CasedChar},
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
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect()
	}
}

impl StaticAlphabet<char, 32> {
	pub fn polish_uppercase() -> Self {
		"AĄBCĆDEĘFGHIJKLŁMNŃOÓPRSŚTUWYZŹŻ".chars().collect()
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

impl<const N: usize> FromIterator<char> for StaticAlphabet<char, N> {
	fn from_iter<T: IntoIterator<Item = char>>(iter: T) -> Self {
		let mut chars = iter.into_iter();
		Self(core::array::from_fn(|_| chars.next().unwrap()))
	}
}

impl<const N: usize> FromIterator<CasedChar> for StaticAlphabet<CasedChar, N> {
	fn from_iter<T: IntoIterator<Item = CasedChar>>(iter: T) -> Self {
		let mut chars = iter.into_iter();
		Self(core::array::from_fn(|_| chars.next().unwrap()))
	}
}

impl<const N: usize> TryFrom<StaticAlphabet<char, N>> for StaticAlphabet<CasedChar, N> {
	type Error = CaseConversionError;

	fn try_from(value: StaticAlphabet<char, N>) -> Result<Self, Self::Error> {
		value.into_iter().map(CasedChar::try_from).collect()
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
