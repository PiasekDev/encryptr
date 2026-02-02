//! DES cipher CLI command
//!
//! Implements the `encryptr des` subcommand for encoding/decoding with the DES block cipher.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use super::input;
use super::output::{self, Encoding};
use encryptr::cipher::des::DESCipher;

/// DES cipher actions
#[derive(Subcommand)]
pub enum DesAction {
	/// Encode (encrypt) data using DES
	Encode(DesArgs),
	/// Decode (decrypt) data using DES
	Decode(DesDecodeArgs),
}

/// Arguments for DES encode operation
#[derive(Args)]
pub struct DesArgs {
	/// 64-bit key in hex (16 hex characters, e.g., "0123456789ABCDEF")
	#[arg(short, long)]
	pub key: String,

	/// Data to encrypt (reads from stdin if not provided)
	pub text: Option<String>,

	/// Read input from file (binary)
	#[arg(long, value_name = "FILE")]
	pub input_file: Option<PathBuf>,

	/// Write output to file (binary)
	#[arg(long, value_name = "FILE")]
	pub output_file: Option<PathBuf>,

	/// Output encoding format (for stdout, ignored if --output-file is used)
	#[arg(short, long, default_value = "base64")]
	pub encoding: Encoding,
}

/// Arguments for DES decode operation
#[derive(Args)]
pub struct DesDecodeArgs {
	/// 64-bit key in hex (16 hex characters, e.g., "0123456789ABCDEF")
	#[arg(short, long)]
	pub key: String,

	/// Ciphertext to decrypt (encoded as hex or base64)
	pub text: Option<String>,

	/// Read input from file (binary)
	#[arg(long, value_name = "FILE")]
	pub input_file: Option<PathBuf>,

	/// Write output to file
	#[arg(long, value_name = "FILE")]
	pub output_file: Option<PathBuf>,

	/// Input encoding format (for TEXT argument, ignored if --input-file is used)
	#[arg(short, long, default_value = "base64")]
	pub encoding: Encoding,
}

/// Run the DES cipher command
pub fn run(action: DesAction) -> Result<()> {
	match action {
		DesAction::Encode(args) => encode(args),
		DesAction::Decode(args) => decode(args),
	}
}

fn parse_key(key_str: &str) -> Result<[u8; 8]> {
	let key_bytes = hex::decode(key_str).context("Invalid key: must be valid hexadecimal")?;

	key_bytes.try_into().map_err(|v: Vec<u8>| {
		anyhow::anyhow!(
			"Invalid key length: expected 8 bytes (16 hex chars), got {}",
			v.len()
		)
	})
}

fn encode(args: DesArgs) -> Result<()> {
	let key = parse_key(&args.key)?;
	let cipher = DESCipher::new(key);

	// For encode, read raw bytes (text is treated as UTF-8 bytes)
	let input = if args.input_file.is_some() {
		input::get_binary(
			args.text.as_deref(),
			args.input_file.as_ref(),
			args.encoding,
		)?
	} else {
		// If text argument provided, use it as raw bytes
		input::get_text(args.text.as_deref(), args.input_file.as_ref())?.into_bytes()
	};

	let encrypted = cipher.encode(&input);

	// Output: binary to file, encoded to stdout
	if args.output_file.is_some() {
		output::write_binary(&encrypted, args.output_file.as_ref())
	} else {
		output::write_encoded(&encrypted, args.encoding, None)
	}
}

fn decode(args: DesDecodeArgs) -> Result<()> {
	let key = parse_key(&args.key)?;
	let cipher = DESCipher::new(key);

	// For decode: from file read binary, from text read encoded
	let input = if args.input_file.is_some() {
		input::get_binary(None, args.input_file.as_ref(), args.encoding)?
	} else {
		input::get_encoded_binary(args.text.as_deref(), None, args.encoding)?
	};

	let decrypted = cipher
		.decode(&input)
		.map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

	// Output: to file write binary, to stdout write as text (lossy UTF-8)
	if args.output_file.is_some() {
		output::write_binary(&decrypted, args.output_file.as_ref())
	} else {
		let text = String::from_utf8_lossy(&decrypted);
		output::write_text(&text, None)
	}
}
