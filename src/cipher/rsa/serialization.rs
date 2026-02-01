//! DER and PEM serialization for RSA keys.
//!
//! This module provides serialization implementations for RSA key types
//! using the `der` crate's ASN.1 encoding.
//!
//! # Format
//!
//! Keys are serialized as ASN.1 SEQUENCE structures:
//!
//! - **RSAPublicKey**: `SEQUENCE { n INTEGER, e INTEGER }`
//! - **RSAPrivateKey**: `SEQUENCE { n INTEGER, d INTEGER }`
//! - **RSAKeyPair**: `SEQUENCE { n INTEGER, e INTEGER, d INTEGER }`
//!
//! # PEM Labels
//!
//! Custom ENCRYPTR labels are used:
//! - `ENCRYPTR RSA PUBLIC KEY`
//! - `ENCRYPTR RSA PRIVATE KEY`
//! - `ENCRYPTR RSA KEY PAIR`

use der::asn1::UintRef;
use der::pem::PemLabel;
use der::{Decode, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence, Writer};
use num_bigint::BigUint;
use thiserror::Error;

use super::key::{RSAKeyPair, RSAPrivateKey, RSAPublicKey};

#[derive(Debug, Error)]
pub enum PemDecodeError {
	#[error("invalid PEM label: expected '{expected}', got '{actual}'")]
	InvalidLabel {
		expected: &'static str,
		actual: String,
	},

	#[error("PEM decode error: {0}")]
	Pem(#[from] der::pem::Error),

	#[error("DER decode error: {0}")]
	Der(#[from] der::Error),
}

impl RSAPublicKey {
	/// Decode a public key from PEM-encoded data.
	///
	/// This method handles custom PEM labels correctly, unlike the generic
	/// `DecodePem` trait which may fail with non-standard labels.
	///
	/// # Example
	///
	/// ```
	/// use encryptr::cipher::rsa::{key::{RSAPublicKey, RSAKeyPair}, bits::KeyBits, LineEnding};
	/// use der::EncodePem;
	/// use rand::SeedableRng;
	///
	/// let bits = KeyBits::try_from(512).unwrap();
	/// let mut rng = rand::rngs::StdRng::seed_from_u64(42);
	/// let key_pair = RSAKeyPair::generate(bits, &mut rng);
	///
	/// let pem = key_pair.public_key.to_pem(LineEnding::LF).unwrap();
	/// let restored = RSAPublicKey::from_pem(&pem).unwrap();
	/// assert_eq!(restored.n, key_pair.public_key.n);
	/// ```
	pub fn from_pem(pem: &str) -> Result<Self, PemDecodeError> {
		let (label, der_bytes) = der::pem::decode_vec(pem.as_bytes())?;
		if label != Self::PEM_LABEL {
			return Err(PemDecodeError::InvalidLabel {
				expected: Self::PEM_LABEL,
				actual: label.to_string(),
			});
		}
		Ok(Self::from_der(&der_bytes)?)
	}
}

impl RSAPrivateKey {
	/// Decode a private key from PEM-encoded data.
	///
	/// This method handles custom PEM labels correctly, unlike the generic
	/// `DecodePem` trait which may fail with non-standard labels.
	///
	/// # Example
	///
	/// ```
	/// use encryptr::cipher::rsa::{key::{RSAPrivateKey, RSAKeyPair}, bits::KeyBits, LineEnding};
	/// use der::EncodePem;
	/// use rand::SeedableRng;
	///
	/// let bits = KeyBits::try_from(512).unwrap();
	/// let mut rng = rand::rngs::StdRng::seed_from_u64(42);
	/// let key_pair = RSAKeyPair::generate(bits, &mut rng);
	///
	/// let pem = key_pair.private_key.to_pem(LineEnding::LF).unwrap();
	/// let restored = RSAPrivateKey::from_pem(&pem).unwrap();
	/// assert_eq!(restored.d, key_pair.private_key.d);
	/// ```
	pub fn from_pem(pem: &str) -> Result<Self, PemDecodeError> {
		let (label, der_bytes) = der::pem::decode_vec(pem.as_bytes())?;
		if label != Self::PEM_LABEL {
			return Err(PemDecodeError::InvalidLabel {
				expected: Self::PEM_LABEL,
				actual: label.to_string(),
			});
		}
		Ok(Self::from_der(&der_bytes)?)
	}
}

impl RSAKeyPair {
	/// Decode a key pair from PEM-encoded data.
	///
	/// This method handles custom PEM labels correctly, unlike the generic
	/// `DecodePem` trait which may fail with non-standard labels.
	///
	/// # Example
	///
	/// ```
	/// use encryptr::cipher::rsa::{key::RSAKeyPair, bits::KeyBits, LineEnding};
	/// use der::EncodePem;
	/// use rand::SeedableRng;
	///
	/// let bits = KeyBits::try_from(512).unwrap();
	/// let mut rng = rand::rngs::StdRng::seed_from_u64(42);
	/// let key_pair = RSAKeyPair::generate(bits, &mut rng);
	///
	/// let pem = key_pair.to_pem(LineEnding::LF).unwrap();
	/// let restored = RSAKeyPair::from_pem(&pem).unwrap();
	/// assert_eq!(restored.public_key.n, key_pair.public_key.n);
	/// ```
	pub fn from_pem(pem: &str) -> Result<Self, PemDecodeError> {
		let (label, der_bytes) = der::pem::decode_vec(pem.as_bytes())?;
		if label != Self::PEM_LABEL {
			return Err(PemDecodeError::InvalidLabel {
				expected: Self::PEM_LABEL,
				actual: label.to_string(),
			});
		}
		Ok(Self::from_der(&der_bytes)?)
	}
}

impl PemLabel for RSAPublicKey {
	const PEM_LABEL: &'static str = "ENCRYPTR RSA PUBLIC KEY";
}

impl PemLabel for RSAPrivateKey {
	const PEM_LABEL: &'static str = "ENCRYPTR RSA PRIVATE KEY";
}

impl PemLabel for RSAKeyPair {
	const PEM_LABEL: &'static str = "ENCRYPTR RSA KEY PAIR";
}

impl EncodeValue for RSAPublicKey {
	fn value_len(&self) -> der::Result<Length> {
		uint_encoded_len(&self.n)? + uint_encoded_len(&self.e)?
	}

	fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
		encode_uint(&self.n, writer)?;
		encode_uint(&self.e, writer)
	}
}

impl<'a> DecodeValue<'a> for RSAPublicKey {
	fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
		Ok(Self {
			n: decode_uint(reader)?,
			e: decode_uint(reader)?,
		})
	}
}

impl Sequence<'_> for RSAPublicKey {}

impl EncodeValue for RSAPrivateKey {
	fn value_len(&self) -> der::Result<Length> {
		uint_encoded_len(&self.n)? + uint_encoded_len(&self.d)?
	}

	fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
		encode_uint(&self.n, writer)?;
		encode_uint(&self.d, writer)
	}
}

impl<'a> DecodeValue<'a> for RSAPrivateKey {
	fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
		Ok(Self {
			n: decode_uint(reader)?,
			d: decode_uint(reader)?,
		})
	}
}

impl Sequence<'_> for RSAPrivateKey {}

impl EncodeValue for RSAKeyPair {
	fn value_len(&self) -> der::Result<Length> {
		uint_encoded_len(&self.public_key.n)?
			+ uint_encoded_len(&self.public_key.e)?
			+ uint_encoded_len(&self.private_key.d)?
	}

	fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
		encode_uint(&self.public_key.n, writer)?;
		encode_uint(&self.public_key.e, writer)?;
		encode_uint(&self.private_key.d, writer)
	}
}

impl<'a> DecodeValue<'a> for RSAKeyPair {
	fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
		let n = decode_uint(reader)?;
		let e = decode_uint(reader)?;
		let d = decode_uint(reader)?;

		Ok(Self {
			public_key: RSAPublicKey { n: n.clone(), e },
			private_key: RSAPrivateKey { n, d },
		})
	}
}

impl Sequence<'_> for RSAKeyPair {}

fn uint_encoded_len(value: &BigUint) -> der::Result<Length> {
	let bytes = value.to_bytes_be();
	let bytes = if bytes.is_empty() { &[0u8][..] } else { &bytes };
	UintRef::new(bytes)?.encoded_len()
}

fn encode_uint(value: &BigUint, writer: &mut impl Writer) -> der::Result<()> {
	let bytes = value.to_bytes_be();
	let bytes = if bytes.is_empty() { &[0u8][..] } else { &bytes };
	UintRef::new(bytes)?.encode(writer)
}

fn decode_uint<'a>(reader: &mut impl Reader<'a>) -> der::Result<BigUint> {
	let uint = reader.decode::<UintRef<'_>>()?;
	Ok(BigUint::from_bytes_be(uint.as_bytes()))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::cipher::rsa::bits::KeyBits;
	use der::{Encode, EncodePem};
	use rand::SeedableRng;
	use rand::rngs::StdRng;

	fn test_key_pair() -> RSAKeyPair {
		let bits = KeyBits::try_from(512).unwrap();
		let mut rng = StdRng::seed_from_u64(42);
		RSAKeyPair::generate(bits, &mut rng)
	}

	#[test]
	fn public_key_der_roundtrip() {
		let key_pair = test_key_pair();
		let public_key = key_pair.public_key;

		let der = public_key.to_der().unwrap();
		let decoded = RSAPublicKey::from_der(&der).unwrap();

		assert_eq!(decoded.n, public_key.n);
		assert_eq!(decoded.e, public_key.e);
	}

	#[test]
	fn private_key_der_roundtrip() {
		let key_pair = test_key_pair();
		let private_key = key_pair.private_key;

		let der = private_key.to_der().unwrap();
		let decoded = RSAPrivateKey::from_der(&der).unwrap();

		assert_eq!(decoded.n, private_key.n);
		assert_eq!(decoded.d, private_key.d);
	}

	#[test]
	fn key_pair_der_roundtrip() {
		let key_pair = test_key_pair();

		let der = key_pair.to_der().unwrap();
		let decoded = RSAKeyPair::from_der(&der).unwrap();

		assert_eq!(decoded.public_key.n, key_pair.public_key.n);
		assert_eq!(decoded.public_key.e, key_pair.public_key.e);
		assert_eq!(decoded.private_key.d, key_pair.private_key.d);
	}

	#[test]
	fn public_key_pem_roundtrip() {
		let key_pair = test_key_pair();
		let public_key = key_pair.public_key;

		let pem = public_key.to_pem(der::pem::LineEnding::LF).unwrap();
		assert!(pem.starts_with("-----BEGIN ENCRYPTR RSA PUBLIC KEY-----"));
		assert!(pem.ends_with("-----END ENCRYPTR RSA PUBLIC KEY-----\n"));

		let decoded = RSAPublicKey::from_pem(&pem).unwrap();
		assert_eq!(decoded.n, public_key.n);
		assert_eq!(decoded.e, public_key.e);
	}

	#[test]
	fn private_key_pem_roundtrip() {
		let key_pair = test_key_pair();
		let private_key = key_pair.private_key;

		let pem = private_key.to_pem(der::pem::LineEnding::LF).unwrap();
		assert!(pem.starts_with("-----BEGIN ENCRYPTR RSA PRIVATE KEY-----"));

		let decoded = RSAPrivateKey::from_pem(&pem).unwrap();
		assert_eq!(decoded.n, private_key.n);
		assert_eq!(decoded.d, private_key.d);
	}

	#[test]
	fn key_pair_pem_roundtrip() {
		let key_pair = test_key_pair();

		let pem = key_pair.to_pem(der::pem::LineEnding::LF).unwrap();
		assert!(pem.starts_with("-----BEGIN ENCRYPTR RSA KEY PAIR-----"));

		let decoded = RSAKeyPair::from_pem(&pem).unwrap();
		assert_eq!(decoded.public_key.n, key_pair.public_key.n);
		assert_eq!(decoded.public_key.e, key_pair.public_key.e);
		assert_eq!(decoded.private_key.d, key_pair.private_key.d);
	}

	#[test]
	fn from_pem_rejects_wrong_label() {
		let key_pair = test_key_pair();

		// Try to decode a public key PEM as a private key
		let public_pem = key_pair
			.public_key
			.to_pem(der::pem::LineEnding::LF)
			.unwrap();
		let err = RSAPrivateKey::from_pem(&public_pem).unwrap_err();

		assert!(matches!(err, PemDecodeError::InvalidLabel { .. }));
	}
}
