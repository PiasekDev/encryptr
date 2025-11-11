use std::ops::{Add, Mul, Sub};

use num_modular::VanillaInt;

pub struct ModuloIndex<const N: usize>(VanillaInt<usize>);

impl<const N: usize> ModuloIndex<N> {
	/// Creates a new ModuloIndex from a usize value.
	///
	/// The value is reduced modulo N.
	pub fn new(n: usize) -> Self {
		Self(VanillaInt::new(n, &N))
	}

	pub fn inner(&self) -> usize {
		*self.0.repr()
	}
}

// NOTE: Deref does not auto implement the traits, therefore these impls are necessary

impl<const N: usize> Mul<usize> for ModuloIndex<N> {
	type Output = ModuloIndex<N>;

	fn mul(self, rhs: usize) -> Self::Output {
		ModuloIndex(self.0 * rhs)
	}
}

impl<const N: usize> Mul<ModuloIndex<N>> for usize {
	type Output = ModuloIndex<N>;

	fn mul(self, rhs: ModuloIndex<N>) -> Self::Output {
		ModuloIndex(rhs.0 * self)
	}
}

impl<const N: usize> Add<usize> for ModuloIndex<N> {
	type Output = ModuloIndex<N>;

	fn add(self, rhs: usize) -> Self::Output {
		ModuloIndex(self.0 + rhs)
	}
}

impl<const N: usize> Add<ModuloIndex<N>> for usize {
	type Output = ModuloIndex<N>;

	fn add(self, rhs: ModuloIndex<N>) -> Self::Output {
		ModuloIndex(rhs.0 + self)
	}
}

impl<const N: usize> Sub<usize> for ModuloIndex<N> {
	type Output = ModuloIndex<N>;

	fn sub(self, rhs: usize) -> Self::Output {
		ModuloIndex(self.0 - rhs)
	}
}

impl<const N: usize> Sub<ModuloIndex<N>> for usize {
	type Output = ModuloIndex<N>;

	fn sub(self, rhs: ModuloIndex<N>) -> Self::Output {
		ModuloIndex(VanillaInt::new(self, &N) - rhs.0)
	}
}
