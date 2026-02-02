//! RSA cipher CLI command
//!
//! Implements the `encryptr rsa` subcommand for RSA key generation, encryption, and decryption.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use der::{Decode, EncodePem};
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
	/// Export private key from a key pair
	ExportPrivate(ExportPrivateArgs),
	/// Split a key pair into separate public and private key files
	Split(SplitArgs),
	/// Inspect the contents of a key file
	Inspect(InspectArgs),
}

/// Arguments for RSA key generation
#[derive(Args)]
pub struct GenerateArgs {
	/// Key size in bits (minimum 5, recommended 2048+)
	#[arg(short, long)]
	pub bits: u64,

	/// Output file for combined key pair (stdout if not specified)
	/// Cannot be used with --public-key or --private-key
	#[arg(short, long, value_name = "FILE", conflicts_with_all = ["public_key", "private_key"])]
	pub output: Option<PathBuf>,

	/// Write public key to separate file (omit to skip public key output)
	#[arg(long, value_name = "FILE")]
	pub public_key: Option<PathBuf>,

	/// Write private key to separate file (omit to skip private key output)
	#[arg(long, value_name = "FILE")]
	pub private_key: Option<PathBuf>,

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

/// Arguments for exporting private key
#[derive(Args)]
pub struct ExportPrivateArgs {
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

/// Arguments for splitting a key pair into separate files
#[derive(Args)]
pub struct SplitArgs {
	/// Path to key pair PEM file
	#[arg(long, value_name = "FILE")]
	pub key_pair: PathBuf,

	/// Output file for public key (auto-derived from key-pair if not specified)
	#[arg(long, value_name = "FILE")]
	pub public_key: Option<PathBuf>,

	/// Output file for private key (auto-derived from key-pair if not specified)
	#[arg(long, value_name = "FILE")]
	pub private_key: Option<PathBuf>,

	/// Output format
	#[arg(short, long, default_value = "pem")]
	pub format: KeyFormat,
}

/// Arguments for inspecting a key file
#[derive(Args)]
pub struct InspectArgs {
	/// Path to key file (public key, private key, or key pair)
	#[arg(value_name = "FILE")]
	pub key: PathBuf,
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
		RsaAction::ExportPrivate(args) => export_private(args),
		RsaAction::Split(args) => split(args),
		RsaAction::Inspect(args) => inspect(args),
	}
}

fn generate(args: GenerateArgs) -> Result<()> {
	let bits = KeyBits::try_from(args.bits)
		.map_err(|_| anyhow::anyhow!("Key size must be at least 5 bits, got {}", args.bits))?;

	eprintln!("Generating {}-bit RSA key pair...", args.bits);

	let mut rng = rand::rngs::StdRng::from_entropy();
	let key_pair = RSAKeyPair::generate(bits, &mut rng);

	// Determine output mode: combined key pair vs separate files
	let separate_output = args.public_key.is_some() || args.private_key.is_some();

	if separate_output {
		// Output to separate files
		if let Some(ref pub_path) = args.public_key {
			write_public_key(&key_pair.public_key, Some(pub_path), args.format)?;
			eprintln!("Public key written to: {}", pub_path.display());
		}

		if let Some(ref priv_path) = args.private_key {
			write_private_key(&key_pair.private_key, Some(priv_path), args.format)?;
			eprintln!("Private key written to: {}", priv_path.display());
		}
	} else {
		// Output combined key pair (original behavior)
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
	let key_pair = load_key_pair(&args.key_pair)?;

	write_public_key(&key_pair.public_key, args.output.as_ref(), args.format)?;

	Ok(())
}

fn export_private(args: ExportPrivateArgs) -> Result<()> {
	let key_pair = load_key_pair(&args.key_pair)?;

	write_private_key(&key_pair.private_key, args.output.as_ref(), args.format)?;

	Ok(())
}

fn split(args: SplitArgs) -> Result<()> {
	let key_pair = load_key_pair(&args.key_pair)?;

	// Determine output paths (use provided or auto-derive)
	let extension = match args.format {
		KeyFormat::Pem => "pem",
		KeyFormat::Der => "der",
	};

	let public_path = args
		.public_key
		.unwrap_or_else(|| derive_output_path(&args.key_pair, "pub", extension));
	let private_path = args
		.private_key
		.unwrap_or_else(|| derive_output_path(&args.key_pair, "priv", extension));

	// Write both keys
	write_public_key(&key_pair.public_key, Some(&public_path), args.format)?;
	eprintln!("Public key written to: {}", public_path.display());

	write_private_key(&key_pair.private_key, Some(&private_path), args.format)?;
	eprintln!("Private key written to: {}", private_path.display());

	Ok(())
}

/// Derive an output path from a key pair path by inserting a suffix before the extension
///
/// Example: `keys.pem` with suffix `pub` and extension `pem` -> `keys.pub.pem`
fn derive_output_path(key_pair_path: &std::path::Path, suffix: &str, extension: &str) -> PathBuf {
	let stem = key_pair_path
		.file_stem()
		.and_then(|s| s.to_str())
		.unwrap_or("key");
	let parent = key_pair_path.parent().unwrap_or(std::path::Path::new("."));

	parent.join(format!("{}.{}.{}", stem, suffix, extension))
}

/// Write a public key to a file or stdout
fn write_public_key(key: &RSAPublicKey, path: Option<&PathBuf>, format: KeyFormat) -> Result<()> {
	match format {
		KeyFormat::Pem => {
			let pem = key
				.to_pem(LineEnding::LF)
				.context("Failed to encode public key as PEM")?;
			output::write_text(&pem, path)?;
		}
		KeyFormat::Der => {
			use der::Encode;
			let der = key.to_der().context("Failed to encode public key as DER")?;
			output::write_binary(&der, path)?;
		}
	}
	Ok(())
}

/// Write a private key to a file or stdout
fn write_private_key(key: &RSAPrivateKey, path: Option<&PathBuf>, format: KeyFormat) -> Result<()> {
	match format {
		KeyFormat::Pem => {
			let pem = key
				.to_pem(LineEnding::LF)
				.context("Failed to encode private key as PEM")?;
			output::write_text(&pem, path)?;
		}
		KeyFormat::Der => {
			use der::Encode;
			let der = key
				.to_der()
				.context("Failed to encode private key as DER")?;
			output::write_binary(&der, path)?;
		}
	}
	Ok(())
}

/// Check if file content looks like PEM (starts with "-----BEGIN")
fn is_pem_format(data: &[u8]) -> bool {
	data.starts_with(b"-----BEGIN")
}

/// Load a key pair from a file (supports both PEM and DER formats)
fn load_key_pair(path: &Path) -> Result<RSAKeyPair> {
	let data = std::fs::read(path)
		.with_context(|| format!("Failed to read key file: {}", path.display()))?;

	if is_pem_format(&data) {
		let pem_content =
			String::from_utf8(data).context("Key file contains invalid UTF-8 for PEM format")?;
		RSAKeyPair::from_pem(&pem_content).context("Failed to parse key pair PEM")
	} else {
		RSAKeyPair::from_der(&data).context("Failed to parse key pair DER")
	}
}

/// Load a public key from a file, trying key pair format first, then public key format.
/// Supports both PEM and DER formats.
fn load_public_key(path: &Path) -> Result<RSAPublicKey> {
	let data = std::fs::read(path)
		.with_context(|| format!("Failed to read key file: {}", path.display()))?;

	if is_pem_format(&data) {
		let pem_content =
			String::from_utf8(data).context("Key file contains invalid UTF-8 for PEM format")?;

		// Try key pair first
		if let Ok(key_pair) = RSAKeyPair::from_pem(&pem_content) {
			return Ok(key_pair.public_key);
		}

		// Try public key
		RSAPublicKey::from_pem(&pem_content)
			.context("Failed to parse PEM. Expected public key or key pair.")
	} else {
		// Try key pair first (DER)
		if let Ok(key_pair) = RSAKeyPair::from_der(&data) {
			return Ok(key_pair.public_key);
		}

		// Try public key (DER)
		RSAPublicKey::from_der(&data)
			.context("Failed to parse DER. Expected public key or key pair.")
	}
}

/// Load a private key from a file, trying key pair format first, then private key format.
/// Supports both PEM and DER formats.
fn load_private_key(path: &Path) -> Result<RSAPrivateKey> {
	let data = std::fs::read(path)
		.with_context(|| format!("Failed to read key file: {}", path.display()))?;

	if is_pem_format(&data) {
		let pem_content =
			String::from_utf8(data).context("Key file contains invalid UTF-8 for PEM format")?;

		// Try key pair first
		if let Ok(key_pair) = RSAKeyPair::from_pem(&pem_content) {
			return Ok(key_pair.private_key);
		}

		// Try private key
		RSAPrivateKey::from_pem(&pem_content)
			.context("Failed to parse PEM. Expected private key or key pair.")
	} else {
		// Try key pair first (DER)
		if let Ok(key_pair) = RSAKeyPair::from_der(&data) {
			return Ok(key_pair.private_key);
		}

		// Try private key (DER)
		RSAPrivateKey::from_der(&data)
			.context("Failed to parse DER. Expected private key or key pair.")
	}
}

/// Parsed key type for inspection
enum ParsedKey {
	KeyPair(RSAKeyPair),
	PublicKey(RSAPublicKey),
	PrivateKey(RSAPrivateKey),
}

/// Detected file format
enum DetectedFormat {
	Pem,
	Der,
}

/// Common public exponents used in RSA.
/// If the second integer in a DER-encoded key matches one of these, it's likely a public key.
const COMMON_PUBLIC_EXPONENTS: [u64; 5] = [3, 5, 17, 257, 65537];

/// Check if a value looks like a public exponent (small and commonly used).
fn is_likely_public_exponent(e: &num_bigint::BigUint) -> bool {
	// Public exponents are typically small (< 2^32) and often one of the common values
	if e.bits() > 32 {
		return false;
	}

	// Try to convert to u64 and check against common values
	let e_u64: Option<u64> = e.try_into().ok();
	match e_u64 {
		Some(val) => COMMON_PUBLIC_EXPONENTS.contains(&val),
		None => false,
	}
}

/// Load any key type from a file for inspection.
/// Supports both PEM and DER formats.
///
/// For DER format, since public and private keys have the same structure (two integers),
/// we use heuristics to distinguish them: if the second integer is a common public
/// exponent (3, 5, 17, 257, 65537), it's treated as a public key.
///
/// Returns the parsed key and the detected format.
fn load_any_key(path: &Path) -> Result<(ParsedKey, DetectedFormat)> {
	let data = std::fs::read(path)
		.with_context(|| format!("Failed to read key file: {}", path.display()))?;

	if is_pem_format(&data) {
		let pem_content =
			String::from_utf8(data).context("Key file contains invalid UTF-8 for PEM format")?;

		if let Ok(key_pair) = RSAKeyPair::from_pem(&pem_content) {
			return Ok((ParsedKey::KeyPair(key_pair), DetectedFormat::Pem));
		}
		if let Ok(public_key) = RSAPublicKey::from_pem(&pem_content) {
			return Ok((ParsedKey::PublicKey(public_key), DetectedFormat::Pem));
		}
		if let Ok(private_key) = RSAPrivateKey::from_pem(&pem_content) {
			return Ok((ParsedKey::PrivateKey(private_key), DetectedFormat::Pem));
		}

		anyhow::bail!(
			"Failed to parse key file. Expected PEM-encoded public key, private key, or key pair."
		);
	} else {
		// DER format - try key pair first (has 3 integers, so it's unambiguous)
		if let Ok(key_pair) = RSAKeyPair::from_der(&data) {
			return Ok((ParsedKey::KeyPair(key_pair), DetectedFormat::Der));
		}

		// For two-integer keys, we need to use heuristics since public (n, e) and
		// private (n, d) keys have the same structure.
		// Parse as public key and check if e looks like a public exponent.
		if let Ok(public_key) = RSAPublicKey::from_der(&data) {
			if is_likely_public_exponent(&public_key.e) {
				return Ok((ParsedKey::PublicKey(public_key), DetectedFormat::Der));
			} else {
				// e is too large to be a public exponent, so this is actually a private key
				// where e is really d
				let private_key = RSAPrivateKey {
					n: public_key.n,
					d: public_key.e,
				};
				return Ok((ParsedKey::PrivateKey(private_key), DetectedFormat::Der));
			}
		}

		anyhow::bail!(
			"Failed to parse key file. Expected DER-encoded public key, private key, or key pair."
		);
	}
}

fn inspect(args: InspectArgs) -> Result<()> {
	let (key, format) = load_any_key(&args.key)?;
	let format_str = match format {
		DetectedFormat::Pem => "PEM",
		DetectedFormat::Der => "DER",
	};

	match key {
		ParsedKey::KeyPair(key_pair) => print_key_pair_info(&key_pair, format_str),
		ParsedKey::PublicKey(public_key) => print_public_key_info(&public_key, format_str),
		ParsedKey::PrivateKey(private_key) => print_private_key_info(&private_key, format_str),
	}

	Ok(())
}

/// Print information about an RSA key pair
fn print_key_pair_info(key_pair: &RSAKeyPair, format: &str) {
	let bit_length = key_pair.public_key.n.bits();
	let byte_length = key_pair.public_key.byte_length();

	println!("Key Type:            Key Pair");
	println!("Format:              {}", format);
	println!("Bit Length:          {} bits", bit_length);
	println!(
		"Modulus (n):         {} ({} bytes)",
		format_biguint_hex(&key_pair.public_key.n),
		byte_length
	);
	println!("Public Exponent (e): {}", key_pair.public_key.e);
	println!(
		"Private Exponent (d): {} ({} bytes)",
		format_biguint_hex(&key_pair.private_key.d),
		byte_length
	);
}

/// Print information about an RSA public key
fn print_public_key_info(public_key: &RSAPublicKey, format: &str) {
	let bit_length = public_key.n.bits();
	let byte_length = public_key.byte_length();

	println!("Key Type:            Public Key");
	println!("Format:              {}", format);
	println!("Bit Length:          {} bits", bit_length);
	println!(
		"Modulus (n):         {} ({} bytes)",
		format_biguint_hex(&public_key.n),
		byte_length
	);
	println!("Public Exponent (e): {}", public_key.e);
}

/// Print information about an RSA private key
fn print_private_key_info(private_key: &RSAPrivateKey, format: &str) {
	let bit_length = private_key.n.bits();
	let byte_length = private_key.byte_length();

	println!("Key Type:            Private Key");
	println!("Format:              {}", format);
	println!("Bit Length:          {} bits", bit_length);
	println!(
		"Modulus (n):         {} ({} bytes)",
		format_biguint_hex(&private_key.n),
		byte_length
	);
	println!(
		"Private Exponent (d): {} ({} bytes)",
		format_biguint_hex(&private_key.d),
		byte_length
	);
}

/// Format a BigUint as a hexadecimal string with 0x prefix
///
/// For large values (> 64 hex chars), truncates to show first 16 and last 16 chars
/// with "..." in between.
fn format_biguint_hex(value: &num_bigint::BigUint) -> String {
	let hex = value.to_str_radix(16);

	if hex.len() <= 64 {
		format!("0x{}", hex)
	} else {
		format!("0x{}...{}", &hex[..16], &hex[hex.len() - 16..])
	}
}
