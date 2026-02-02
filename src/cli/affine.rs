//! Affine cipher CLI command
//!
//! Implements the `encryptr affine` subcommand for encoding/decoding with the Affine cipher.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use super::alphabet::AlphabetType;
use super::input;
use super::output;
use encryptr::cipher::affine::AffineCipher;

/// Affine cipher actions
#[derive(Subcommand)]
pub enum AffineAction {
	/// Encode (encipher) text using Affine cipher
	Encode(AffineArgs),
	/// Decode (decipher) text using Affine cipher
	Decode(AffineArgs),
}

/// Arguments for Affine cipher operations
#[derive(Args)]
pub struct AffineArgs {
	/// Multiplicative key 'a' (must be coprime with alphabet length)
	#[arg(long)]
	pub a: usize,

	/// Additive key 'b' (shift value)
	#[arg(long)]
	pub b: usize,

	/// Alphabet to use (note: cased alphabet not supported for Affine)
	#[arg(short = 'A', long, default_value = "ascii")]
	pub alphabet: AlphabetType,

	/// Text to process (reads from stdin if not provided)
	pub text: Option<String>,

	/// Read input from file
	#[arg(long, value_name = "FILE")]
	pub input_file: Option<PathBuf>,

	/// Write output to file
	#[arg(long, value_name = "FILE")]
	pub output_file: Option<PathBuf>,
}

/// Run the Affine cipher command
pub fn run(action: AffineAction) -> Result<()> {
	match action {
		AffineAction::Encode(args) => encode(args),
		AffineAction::Decode(args) => decode(args),
	}
}

fn create_cipher(args: &AffineArgs) -> Result<AffineCipher> {
	if args.alphabet.is_cased() {
		anyhow::bail!(
			"Affine cipher does not support case-preserving alphabet. Use 'ascii' or 'polish'."
		);
	}

	let alphabet = args.alphabet.to_char_alphabet();
	let alphabet_len = alphabet.len();

	AffineCipher::new(alphabet, args.a, args.b).map_err(|_| {
		anyhow::anyhow!(
			"Invalid 'a' value: {} is not coprime with alphabet length {}",
			args.a,
			alphabet_len
		)
	})
}

fn encode(args: AffineArgs) -> Result<()> {
	let input = input::get_text(args.text.as_deref(), args.input_file.as_ref())?;
	let cipher = create_cipher(&args)?;
	let result = cipher.encode(&input);
	output::write_text(&result, args.output_file.as_ref())
}

fn decode(args: AffineArgs) -> Result<()> {
	let input = input::get_text(args.text.as_deref(), args.input_file.as_ref())?;
	let cipher = create_cipher(&args)?;
	let result = cipher.decode(&input);
	output::write_text(&result, args.output_file.as_ref())
}
