use sealed::sealed;
use std::ops::{Add, Mul, Sub};

mod cased;
pub use cased::*;

mod uncased;
pub use uncased::*;

pub trait AlphabetIndex<'a, T>:
	Sized
	+ Mul<usize, Output = Self>
	+ Add<usize, Output = Self>
	+ Sub<usize, Output = Self>
	+ UsizeAdd<Self>
	+ UsizeSub<Self>
	+ UsizeMul<Self>
{
	fn get(&self) -> &'a T;

	fn value(&self) -> usize;
}

#[sealed]
pub trait UsizeAdd<T> {}
#[sealed]
impl<T> UsizeAdd<T> for T where usize: Add<T, Output = T> {}

#[sealed]
pub trait UsizeSub<T> {}
#[sealed]
impl<T> UsizeSub<T> for T where usize: Sub<T, Output = T> {}

#[sealed]
pub trait UsizeMul<T> {}
#[sealed]
impl<T> UsizeMul<T> for T where usize: Mul<T, Output = T> {}
