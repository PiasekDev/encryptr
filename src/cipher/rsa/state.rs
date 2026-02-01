use sealed::sealed;

use super::key::{RSAKeyPair, RSAPrivateKey, RSAPublicKey};

/// Marker type for RSACipher that can only encrypt (holds public key).
pub struct PublicOnly(pub RSAPublicKey);

/// Marker type for RSACipher that can only decrypt (holds private key).
pub struct PrivateOnly(pub RSAPrivateKey);

/// Marker type for RSACipher that can both encrypt and decrypt (holds full key pair).
pub struct KeyPair(pub RSAKeyPair);

/// Trait for types that can provide a public key for encryption.
/// This trait is sealed and cannot be implemented outside this module.
#[sealed]
pub trait CanEncrypt {
	fn public_key(&self) -> &RSAPublicKey;
}

/// Trait for types that can provide a private key for decryption.
/// This trait is sealed and cannot be implemented outside this module.
#[sealed]
pub trait CanDecrypt {
	fn private_key(&self) -> &RSAPrivateKey;
}

#[sealed]
impl CanEncrypt for PublicOnly {
	fn public_key(&self) -> &RSAPublicKey {
		&self.0
	}
}

#[sealed]
impl CanEncrypt for KeyPair {
	fn public_key(&self) -> &RSAPublicKey {
		&self.0.public_key
	}
}

#[sealed]
impl CanDecrypt for PrivateOnly {
	fn private_key(&self) -> &RSAPrivateKey {
		&self.0
	}
}

#[sealed]
impl CanDecrypt for KeyPair {
	fn private_key(&self) -> &RSAPrivateKey {
		&self.0.private_key
	}
}
