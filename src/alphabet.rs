use std::ops::{Add, Mul, Sub};

use num_modular::VanillaInt;

use crate::char_ext::{CaseConversionError, CharCase, CharExt};

pub trait Alphabet: IntoIterator<Item = Self::Character> {
	type Character;

	fn len(&self) -> usize;

	fn is_empty(&self) -> bool;

	fn iter<'a>(&'a self) -> impl Iterator<Item = &'a Self::Character>
	where
		Self::Character: 'a;

	fn index_of(&self, char: char) -> Option<usize>;

	fn char_at(&self, index: usize) -> Option<&Self::Character>;
}

pub struct DynamicAlphabet<T>(Vec<T>);

impl<T> IntoIterator for DynamicAlphabet<T> {
	type Item = T;
	type IntoIter = std::vec::IntoIter<T>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl<'a, T> IntoIterator for &'a DynamicAlphabet<T> {
	type Item = &'a T;
	type IntoIter = std::slice::Iter<'a, T>;

	#[inline]
	fn into_iter(self) -> Self::IntoIter {
		self.0.iter()
	}
}

impl<T: PartialEq<char>> Alphabet for DynamicAlphabet<T> {
	type Character = T;

	fn len(&self) -> usize {
		self.0.len()
	}

	fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
	where
		T: 'a,
	{
		self.0.iter()
	}

	fn index_of(&self, c: char) -> Option<usize> {
		self.0.iter().position(|x| *x == c)
	}

	fn char_at(&self, index: usize) -> Option<&Self::Character> {
		self.0.get(index)
	}
}

pub struct StaticAlphabet<T, const N: usize>([T; N]);

impl Default for StaticAlphabet<char, 26> {
	fn default() -> Self {
		Self(
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				.chars()
				.collect::<Vec<char>>()
				.try_into()
				.expect("Alphabet length should be 26"),
		)
	}
}

impl StaticAlphabet<CasedChar, 26> {
	pub fn default_cased() -> Self {
		Self::try_from(StaticAlphabet::default()).expect("All chars in the default alphabet should be able to be cased")
	}
}

impl<const N: usize> TryFrom<StaticAlphabet<char, N>> for StaticAlphabet<CasedChar, N> {
	type Error = CaseConversionError;

	fn try_from(value: StaticAlphabet<char, N>) -> Result<Self, Self::Error> {
		let chars: Vec<CasedChar> = value
			.iter()
			.copied()
			.map(CasedChar::try_from)
			.collect::<Result<_, _>>()?;

		Ok(Self(
			chars
				.try_into()
				.expect("The length of the alphabets should match"),
		))
	}
}

impl StaticAlphabet<char, 32> {
	pub fn polish() -> Self {
		Self(
			"AĄBCĆDEĘFGHIJKLŁMNŃOÓPRSŚTUWYZŹŻ"
				.chars()
				.collect::<Vec<char>>()
				.try_into()
				.expect("Alphabet length should be 32"),
		)
	}
}

#[derive(Debug)]
pub enum StaticAlphabetError {
	LengthMismatch { expected: usize, got: usize },
}

impl<const N: usize> StaticAlphabet<char, N> {
	pub fn new(s: &str) -> Result<Self, StaticAlphabetError> {
		let chars: Vec<char> = s.chars().collect();

		if chars.len() != N {
			return Err(StaticAlphabetError::LengthMismatch {
				expected: N,
				got: chars.len(),
			});
		}

		Ok(Self(
			chars
				.try_into()
				.expect("String length should match alphabet size"),
		))
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

	#[inline]
	fn into_iter(self) -> Self::IntoIter {
		self.0.iter()
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

	fn iter<'a>(&'a self) -> impl Iterator<Item = &'a T>
	where
		T: 'a,
	{
		self.0.iter()
	}

	fn index_of(&self, c: char) -> Option<usize> {
		self.0.iter().position(|x| *x == c)
	}

	fn char_at(&self, index: usize) -> Option<&Self::Character> {
		self.0.get(index)
	}
}

pub struct ModularIndex<const N: usize>(VanillaInt<usize>);

impl<const N: usize> ModularIndex<N> {
	pub fn inner(&self) -> usize {
		*self.0.repr()
	}
}

// NOTE: Deref does not auto implement the traits, so this is therefore necessary
impl<const N: usize> Mul<usize> for ModularIndex<N> {
	type Output = ModularIndex<N>;

	fn mul(self, rhs: usize) -> Self::Output {
		ModularIndex(self.0 * rhs)
	}
}

impl<const N: usize> Add<usize> for ModularIndex<N> {
	type Output = ModularIndex<N>;

	fn add(self, rhs: usize) -> Self::Output {
		ModularIndex(self.0 + rhs)
	}
}

impl<const N: usize> Sub<usize> for ModularIndex<N> {
	type Output = ModularIndex<N>;

	fn sub(self, rhs: usize) -> Self::Output {
		ModularIndex(self.0 - rhs)
	}
}

impl<T: PartialEq + PartialEq<char>, const N: usize> StaticAlphabet<T, N> {
	pub fn index_of(&self, c: char) -> Option<ModularIndex<N>> {
		self.0
			.iter()
			.position(|x| *x == c)
			.map(|index| ModularIndex(VanillaInt::new(index, &N)))
	}

	pub fn char_at(
		&self,
		index: ModularIndex<N>,
	) -> &<StaticAlphabet<T, N> as Alphabet>::Character {
		self.0
			.get(index.inner())
			.expect("The index value should be in array bounds")
	}
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct CasedChar {
	upper: char,
	lower: char,
}

impl PartialEq<char> for CasedChar {
	fn eq(&self, other: &char) -> bool {
		self.upper == *other || self.lower == *other
	}
}

impl CasedChar {
	pub fn at_case(&self, case: &CharCase) -> char {
		match case {
			CharCase::Upper => self.upper,
			CharCase::Lower => self.lower,
		}
	}
}

impl TryFrom<char> for CasedChar {
	type Error = CaseConversionError;

	fn try_from(value: char) -> Result<Self, Self::Error> {
		let upper = value.to_uppercase_char()?;
		let lower = value.to_lowercase_char()?;

		Ok(CasedChar { upper, lower })
	}
}
