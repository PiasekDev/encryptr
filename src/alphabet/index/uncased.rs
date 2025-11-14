use std::ops::{Add, Mul, Sub};

use num_modular::{ModularInteger, VanillaInt};

use crate::alphabet::{Alphabet, index::AlphabetIndex};

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct UncasedAlphabetIndex<'a, T> {
	pub(in crate::alphabet) alphabet: &'a Alphabet<T>,
	pub(in crate::alphabet) value: VanillaInt<usize>,
}

impl<'a, T> AlphabetIndex<'a, T> for UncasedAlphabetIndex<'a, T> {
	fn get(&self) -> &'a T {
		&self.alphabet.0[self.value()]
	}

	fn value(&self) -> usize {
		*self.value.repr()
	}
}

// NOTE: Deref does not auto implement the traits, therefore these impls are necessary

impl<'a, T> Mul<usize> for UncasedAlphabetIndex<'a, T> {
	type Output = UncasedAlphabetIndex<'a, T>;

	fn mul(self, rhs: usize) -> Self::Output {
		UncasedAlphabetIndex {
			alphabet: self.alphabet,
			value: self.value * rhs,
		}
	}
}

impl<'a, T> Mul<UncasedAlphabetIndex<'a, T>> for usize {
	type Output = UncasedAlphabetIndex<'a, T>;

	fn mul(self, rhs: UncasedAlphabetIndex<'a, T>) -> Self::Output {
		UncasedAlphabetIndex {
			alphabet: rhs.alphabet,
			value: rhs.value * self,
		}
	}
}

impl<'a, T> Add<usize> for UncasedAlphabetIndex<'a, T> {
	type Output = UncasedAlphabetIndex<'a, T>;

	fn add(self, rhs: usize) -> Self::Output {
		UncasedAlphabetIndex {
			alphabet: self.alphabet,
			value: self.value + rhs,
		}
	}
}

impl<'a, T> Add<UncasedAlphabetIndex<'a, T>> for usize {
	type Output = UncasedAlphabetIndex<'a, T>;

	fn add(self, rhs: UncasedAlphabetIndex<'a, T>) -> Self::Output {
		UncasedAlphabetIndex {
			alphabet: rhs.alphabet,
			value: rhs.value + self,
		}
	}
}

impl<'a, T> Sub<usize> for UncasedAlphabetIndex<'a, T> {
	type Output = UncasedAlphabetIndex<'a, T>;

	fn sub(self, rhs: usize) -> Self::Output {
		UncasedAlphabetIndex {
			alphabet: self.alphabet,
			value: self.value - rhs,
		}
	}
}

impl<'a, T> Sub<UncasedAlphabetIndex<'a, T>> for usize {
	type Output = UncasedAlphabetIndex<'a, T>;

	fn sub(self, rhs: UncasedAlphabetIndex<'a, T>) -> Self::Output {
		UncasedAlphabetIndex {
			alphabet: rhs.alphabet,
			value: VanillaInt::new(self, &rhs.value.modulus()) - rhs.value,
		}
	}
}
