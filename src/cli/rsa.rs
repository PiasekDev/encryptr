//! RSA cipher CLI command
//!
//! Implements the `encryptr rsa` subcommand for RSA key generation, encryption, and decryption.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use der::EncodePem;
use rand::SeedableRng;

use super::input;
use super::output::{self, Encoding};
use encryptr::cipher::rsa::bits::KeyBits;
use encryptr::cipher::rsa::key::{RSAKeyPair, RSAPrivateKey, RSAPublicKey};
use encryptr::cipher::rsa::{LineEnding, PKCS1v15, RSACipher};

/// RSA cipher actions
#[derive(Subcommand)]
pub enum RsaAction {
	/// Generate a new RSA key pair
	Generate(GenerateArgs),
	/// Encrypt a message with a public key
	Encrypt(EncryptArgs),
	/// Decrypt a message with a private key
	Decrypt(DecryptArgs),
	/// Export public key from a key pair
	ExportPublic(ExportPublicArgs),
}

/// Arguments for RSA key generation
#[derive(Args)]
pub struct GenerateArgs {
	/// Key size in bits (minimum 5, recommended 2048+)
	#[arg(short, long)]
	pub bits: u64,

	/// Output file (stdout if not specified)
	#[arg(short, long, value_name = "FILE")]
	pub output: Option<PathBuf>,

	/// Output format
	#[arg(short, long, default_value = "pem")]
	pub format: KeyFormat,
}

/// Arguments for RSA encryption
#[derive(Args)]
pub struct EncryptArgs {
	/// Path to public key or key pair PEM file
	#[arg(long, value_name = "FILE")]
	pub public_key: PathBuf,

	/// Padding scheme
	#[arg(short, long, default_value = "pkcs1v15")]
	pub padding: PaddingType,

	/// Message to encrypt
	pub message: Option<String>,

	/// Read message from file
	#[arg(long, value_name = "FILE")]
	pub input_file: Option<PathBuf>,

	/// Write ciphertext to file (binary)
	#[arg(long, value_name = "FILE")]
	pub output_file: Option<PathBuf>,

	/// Output encoding (for stdout, ignored if --output-file is used)
	#[arg(short, long, default_value = "base64")]
	pub encoding: Encoding,
}

/// Arguments for RSA decryption
#[derive(Args)]
pub struct DecryptArgs {
	/// Path to private key or key pair PEM file
	#[arg(long, value_name = "FILE")]
	pub private_key: PathBuf,

	/// Padding scheme
	#[arg(short, long, default_value = "pkcs1v15")]
	pub padding: PaddingType,

	/// Ciphertext to decrypt (encoded as hex or base64)
	pub ciphertext: Option<String>,

	/// Read ciphertext from file (binary)
	#[arg(long, value_name = "FILE")]
	pub input_file: Option<PathBuf>,

	/// Write plaintext to file
	#[arg(long, value_name = "FILE")]
	pub output_file: Option<PathBuf>,

	/// Input encoding (for CIPHERTEXT argument, ignored if --input-file is used)
	#[arg(short, long, default_value = "base64")]
	pub encoding: Encoding,
}

/// Arguments for exporting public key
#[derive(Args)]
pub struct ExportPublicArgs {
	/// Path to key pair PEM file
	#[arg(long, value_name = "FILE")]
	pub key_pair: PathBuf,

	/// Output file (stdout if not specified)
	#[arg(short, long, value_name = "FILE")]
	pub output: Option<PathBuf>,

	/// Output format
	#[arg(short, long, default_value = "pem")]
	pub format: KeyFormat,
}

/// Padding scheme for RSA operations
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaddingType {
	/// No padding (textbook RSA, not recommended)
	None,
	/// PKCS#1 v1.5 padding (recommended)
	Pkcs1v15,
}

/// Output format for keys
#[derive(ValueEnum, Clone, Copy, Default, Debug, PartialEq, Eq)]
pub enum KeyFormat {
	/// PEM format (base64 with headers)
	#[default]
	Pem,
	/// DER format (raw binary ASN.1)
	Der,
}

/// Run the RSA command
pub fn run(action: RsaAction) -> Result<()> {
	match action {
		RsaAction::Generate(args) => generate(args),
		RsaAction::Encrypt(args) => encrypt(args),
		RsaAction::Decrypt(args) => decrypt(args),
		RsaAction::ExportPublic(args) => export_public(args),
	}
}

fn generate(args: GenerateArgs) -> Result<()> {
	let bits = KeyBits::try_from(args.bits)
		.map_err(|_| anyhow::anyhow!("Key size must be at least 5 bits, got {}", args.bits))?;

	eprintln!("Generating {}-bit RSA key pair...", args.bits);

	let mut rng = rand::rngs::StdRng::from_entropy();
	let key_pair = RSAKeyPair::generate(bits, &mut rng);

	match args.format {
		KeyFormat::Pem => {
			let pem = key_pair
				.to_pem(LineEnding::LF)
				.context("Failed to encode key pair as PEM")?;
			output::write_text(&pem, args.output.as_ref())?;
		}
		KeyFormat::Der => {
			use der::Encode;
			let der = key_pair
				.to_der()
				.context("Failed to encode key pair as DER")?;
			output::write_binary(&der, args.output.as_ref())?;
		}
	}

	eprintln!("Key pair generated successfully.");
	Ok(())
}

fn encrypt(args: EncryptArgs) -> Result<()> {
	// Load the public key (try key pair first, then public key)
	let public_key = load_public_key(&args.public_key)?;

	// Get the message
	let message = if args.input_file.is_some() {
		input::get_binary(
			args.message.as_deref(),
			args.input_file.as_ref(),
			args.encoding,
		)?
	} else {
		input::get_text(args.message.as_deref(), args.input_file.as_ref())?.into_bytes()
	};

	let ciphertext = match args.padding {
		PaddingType::None => {
			// Use BigUint API for no-padding mode
			use num_bigint::BigUint;
			let cipher = RSACipher::with_public_key(public_key.clone());
			let plaintext = BigUint::from_bytes_be(&message);

			// Check that message fits
			if plaintext >= public_key.n {
				anyhow::bail!(
					"Message too large for key. Max {} bytes, got {} bytes",
					public_key.byte_length() - 1,
					message.len()
				);
			}

			let ciphertext_int = cipher
				.encipher(&plaintext)
				.map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

			// Pad to key length
			let key_bytes = public_key.byte_length();
			let mut result = ciphertext_int.to_bytes_be();
			while result.len() < key_bytes {
				result.insert(0, 0);
			}
			result
		}
		PaddingType::Pkcs1v15 => {
			let rng = rand::rngs::StdRng::from_entropy();
			let padding = PKCS1v15::new(rng);
			let mut cipher = RSACipher::with_public_key_and_padding(public_key, padding);

			cipher
				.encrypt(&message)
				.map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?
		}
	};

	// Output
	if args.output_file.is_some() {
		output::write_binary(&ciphertext, args.output_file.as_ref())
	} else {
		output::write_encoded(&ciphertext, args.encoding, None)
	}
}

fn decrypt(args: DecryptArgs) -> Result<()> {
	// Load the private key (try key pair first, then private key)
	let private_key = load_private_key(&args.private_key)?;

	// Get the ciphertext
	let ciphertext = if args.input_file.is_some() {
		input::get_binary(None, args.input_file.as_ref(), args.encoding)?
	} else {
		input::get_encoded_binary(args.ciphertext.as_deref(), None, args.encoding)?
	};

	let plaintext = match args.padding {
		PaddingType::None => {
			// Use BigUint API for no-padding mode
			use num_bigint::BigUint;
			let cipher = RSACipher::with_private_key(private_key);
			let ciphertext_int = BigUint::from_bytes_be(&ciphertext);

			let plaintext_int = cipher
				.decipher(&ciphertext_int)
				.map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

			plaintext_int.to_bytes_be()
		}
		PaddingType::Pkcs1v15 => {
			let rng = rand::rngs::StdRng::from_entropy();
			let padding = PKCS1v15::new(rng);
			let cipher = RSACipher::with_private_key_and_padding(private_key, padding);

			cipher
				.decrypt(&ciphertext)
				.map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?
		}
	};

	// Output
	if args.output_file.is_some() {
		output::write_binary(&plaintext, args.output_file.as_ref())
	} else {
		let text = String::from_utf8_lossy(&plaintext);
		output::write_text(&text, None)
	}
}

fn export_public(args: ExportPublicArgs) -> Result<()> {
	let pem_content = std::fs::read_to_string(&args.key_pair)
		.with_context(|| format!("Failed to read key pair: {}", args.key_pair.display()))?;

	let key_pair = RSAKeyPair::from_pem(&pem_content).context("Failed to parse key pair PEM")?;

	match args.format {
		KeyFormat::Pem => {
			let pem = key_pair
				.public_key
				.to_pem(LineEnding::LF)
				.context("Failed to encode public key as PEM")?;
			output::write_text(&pem, args.output.as_ref())?;
		}
		KeyFormat::Der => {
			use der::Encode;
			let der = key_pair
				.public_key
				.to_der()
				.context("Failed to encode public key as DER")?;
			output::write_binary(&der, args.output.as_ref())?;
		}
	}

	Ok(())
}

/// Load a public key from a file, trying key pair format first, then public key format
fn load_public_key(path: &PathBuf) -> Result<RSAPublicKey> {
	let pem_content = std::fs::read_to_string(path)
		.with_context(|| format!("Failed to read key file: {}", path.display()))?;

	// Try key pair first
	if let Ok(key_pair) = RSAKeyPair::from_pem(&pem_content) {
		return Ok(key_pair.public_key);
	}

	// Try public key
	RSAPublicKey::from_pem(&pem_content)
		.context("Failed to parse public key PEM. Expected public key or key pair.")
}

/// Load a private key from a file, trying key pair format first, then private key format
fn load_private_key(path: &PathBuf) -> Result<RSAPrivateKey> {
	let pem_content = std::fs::read_to_string(path)
		.with_context(|| format!("Failed to read key file: {}", path.display()))?;

	// Try key pair first
	if let Ok(key_pair) = RSAKeyPair::from_pem(&pem_content) {
		return Ok(key_pair.private_key);
	}

	// Try private key
	RSAPrivateKey::from_pem(&pem_content)
		.context("Failed to parse private key PEM. Expected private key or key pair.")
}
