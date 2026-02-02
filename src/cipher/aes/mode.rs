//! AES mode of operation typestate markers and KeySize trait.
//!
//! This module defines the typestate markers for AES key sizes and modes,
//! using sealed traits to prevent external implementations.

use rand::Rng;
use sealed::sealed;

// ============================================================================
// Key Size Markers
// ============================================================================

/// Marker type for AES-128 (128-bit key, 10 rounds).
#[derive(Clone, Copy, Debug, Default)]
pub struct Key128;

/// Marker type for AES-192 (192-bit key, 12 rounds).
#[derive(Clone, Copy, Debug, Default)]
pub struct Key192;

/// Marker type for AES-256 (256-bit key, 14 rounds).
#[derive(Clone, Copy, Debug, Default)]
pub struct Key256;

/// Trait defining the properties of an AES key size.
///
/// This trait is sealed to prevent external implementations.
#[sealed]
pub trait KeySize: Clone + Copy {
	/// Number of bytes in the key.
	const KEY_BYTES: usize;

	/// Number of encryption rounds.
	const ROUNDS: usize;

	/// Number of round keys (ROUNDS + 1).
	const ROUND_KEYS: usize;

	/// The concrete array type for the key.
	type KeyArray: AsRef<[u8]> + AsMut<[u8]> + Copy + Default + std::fmt::Debug;
}

#[sealed]
impl KeySize for Key128 {
	const KEY_BYTES: usize = 16;
	const ROUNDS: usize = 10;
	const ROUND_KEYS: usize = 11;
	type KeyArray = [u8; 16];
}

#[sealed]
impl KeySize for Key192 {
	const KEY_BYTES: usize = 24;
	const ROUNDS: usize = 12;
	const ROUND_KEYS: usize = 13;
	type KeyArray = [u8; 24];
}

#[sealed]
impl KeySize for Key256 {
	const KEY_BYTES: usize = 32;
	const ROUNDS: usize = 14;
	const ROUND_KEYS: usize = 15;
	type KeyArray = [u8; 32];
}

// ============================================================================
// Mode Markers
// ============================================================================

/// Electronic Codebook (ECB) mode marker.
///
/// In ECB mode, each block is encrypted independently.
/// This is the simplest mode but is not semantically secure for
/// plaintexts longer than one block.
#[derive(Clone, Copy, Debug, Default)]
pub struct ECB;

/// Cipher Block Chaining (CBC) mode.
///
/// In CBC mode, each plaintext block is XORed with the previous
/// ciphertext block before encryption. This provides better security
/// than ECB for multi-block messages.
///
/// The IV (Initialization Vector) is prepended to the ciphertext during
/// encryption and extracted from the ciphertext during decryption.
#[derive(Clone, Debug)]
pub struct CBC {
	pub(crate) iv: [u8; 16],
}

impl CBC {
	/// Create CBC mode with the specified IV.
	pub fn with_iv(iv: [u8; 16]) -> Self {
		CBC { iv }
	}

	/// Create CBC mode with a randomly generated IV.
	pub fn with_random_iv() -> Self {
		let mut iv = [0u8; 16];
		rand::thread_rng().fill(&mut iv);
		CBC { iv }
	}

	/// Get the IV.
	pub fn iv(&self) -> &[u8; 16] {
		&self.iv
	}
}

/// Trait for AES modes of operation.
///
/// This trait is sealed to prevent external implementations.
#[sealed]
pub trait Mode: Clone {}

#[sealed]
impl Mode for ECB {}

#[sealed]
impl Mode for CBC {}

// ============================================================================
// Builder Typestate Markers
// ============================================================================

/// Marker indicating no key has been set.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoKey;

/// Marker indicating a key has been set.
#[derive(Clone, Copy, Debug)]
pub struct WithKey<K: KeySize>(pub(crate) K::KeyArray);

/// Marker indicating no mode has been set.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoMode;

// ECB and CBC are used directly as mode markers in the builder
