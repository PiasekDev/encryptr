use std::ops::{Add, Mul, Sub};

use crate::{
	alphabet::{AlphabetIndex, CasedChar, ToChar, UncasedAlphabetIndex},
	extension::char::CharCase,
};

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct CasedAlphabetIndex<'a> {
	pub(in crate::alphabet) case: CharCase,
	pub(in crate::alphabet) index: UncasedAlphabetIndex<'a, CasedChar>,
}

impl<'a> AlphabetIndex<'a, CasedChar> for CasedAlphabetIndex<'a> {
	fn get(&self) -> &'a CasedChar {
		self.index.get()
	}

	fn value(&self) -> usize {
		self.index.value()
	}
}

impl ToChar for CasedAlphabetIndex<'_> {
	fn to_char(&self) -> char {
		self.index.get().at_case(&self.case)
	}
}

// NOTE: Deref does not auto implement the traits, therefore these impls are necessary

impl<'a> Mul<usize> for CasedAlphabetIndex<'a> {
	type Output = CasedAlphabetIndex<'a>;

	fn mul(self, rhs: usize) -> Self::Output {
		CasedAlphabetIndex {
			case: self.case,
			index: self.index * rhs,
		}
	}
}

impl<'a> Mul<CasedAlphabetIndex<'a>> for usize {
	type Output = CasedAlphabetIndex<'a>;

	fn mul(self, rhs: CasedAlphabetIndex<'a>) -> Self::Output {
		CasedAlphabetIndex {
			case: rhs.case,
			index: rhs.index * self,
		}
	}
}

impl<'a> Add<usize> for CasedAlphabetIndex<'a> {
	type Output = CasedAlphabetIndex<'a>;

	fn add(self, rhs: usize) -> Self::Output {
		CasedAlphabetIndex {
			case: self.case,
			index: self.index + rhs,
		}
	}
}

impl<'a> Add<CasedAlphabetIndex<'a>> for usize {
	type Output = CasedAlphabetIndex<'a>;

	fn add(self, rhs: CasedAlphabetIndex<'a>) -> Self::Output {
		CasedAlphabetIndex {
			case: rhs.case,
			index: rhs.index + self,
		}
	}
}

impl<'a> Sub<usize> for CasedAlphabetIndex<'a> {
	type Output = CasedAlphabetIndex<'a>;

	fn sub(self, rhs: usize) -> Self::Output {
		CasedAlphabetIndex {
			case: self.case,
			index: self.index - rhs,
		}
	}
}

impl<'a> Sub<CasedAlphabetIndex<'a>> for usize {
	type Output = CasedAlphabetIndex<'a>;

	fn sub(self, rhs: CasedAlphabetIndex<'a>) -> Self::Output {
		CasedAlphabetIndex {
			case: rhs.case,
			index: self - rhs.index,
		}
	}
}
