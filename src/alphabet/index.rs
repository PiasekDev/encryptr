use std::ops::{Add, Mul, Sub};

mod uncased;
pub use uncased::*;

pub trait AlphabetIndex<'a, T>:
	Sized + Mul<usize, Output = Self> + Add<usize, Output = Self> + Sub<usize, Output = Self>
where
	usize: Mul<Self, Output = Self>,
	usize: Add<Self, Output = Self>,
	usize: Sub<Self, Output = Self>,
{
	fn get(&self) -> &'a T;

	fn value(&self) -> usize;
}
