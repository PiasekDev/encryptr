use std::ops::{Add, Mul, Sub};

use num_modular::{ModularInteger, VanillaInt};

use crate::alphabet::Alphabet;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct AlphabetIndex<'a, T> {
	pub(super) alphabet: &'a Alphabet<T>,
	pub(super) value: VanillaInt<usize>,
}

impl<'a, T> AlphabetIndex<'a, T> {
	pub fn get(&self) -> &'a T {
		&self.alphabet.0[self.value()]
	}

	pub fn value(&self) -> usize {
		*self.value.repr()
	}
}

// NOTE: Deref does not auto implement the traits, therefore these impls are necessary

impl<'a, T> Mul<usize> for AlphabetIndex<'a, T> {
	type Output = AlphabetIndex<'a, T>;

	fn mul(self, rhs: usize) -> Self::Output {
		AlphabetIndex {
			alphabet: self.alphabet,
			value: self.value * rhs,
		}
	}
}

impl<'a, T> Mul<AlphabetIndex<'a, T>> for usize {
	type Output = AlphabetIndex<'a, T>;

	fn mul(self, rhs: AlphabetIndex<'a, T>) -> Self::Output {
		AlphabetIndex {
			alphabet: rhs.alphabet,
			value: rhs.value * self,
		}
	}
}

impl<'a, T> Add<usize> for AlphabetIndex<'a, T> {
	type Output = AlphabetIndex<'a, T>;

	fn add(self, rhs: usize) -> Self::Output {
		AlphabetIndex {
			alphabet: self.alphabet,
			value: self.value + rhs,
		}
	}
}

impl<'a, T> Add<AlphabetIndex<'a, T>> for usize {
	type Output = AlphabetIndex<'a, T>;

	fn add(self, rhs: AlphabetIndex<'a, T>) -> Self::Output {
		AlphabetIndex {
			alphabet: rhs.alphabet,
			value: rhs.value + self,
		}
	}
}

impl<'a, T> Sub<usize> for AlphabetIndex<'a, T> {
	type Output = AlphabetIndex<'a, T>;

	fn sub(self, rhs: usize) -> Self::Output {
		AlphabetIndex {
			alphabet: self.alphabet,
			value: self.value - rhs,
		}
	}
}

impl<'a, T> Sub<AlphabetIndex<'a, T>> for usize {
	type Output = AlphabetIndex<'a, T>;

	fn sub(self, rhs: AlphabetIndex<'a, T>) -> Self::Output {
		AlphabetIndex {
			alphabet: rhs.alphabet,
			value: VanillaInt::new(self, &rhs.value.modulus()) - rhs.value,
		}
	}
}
