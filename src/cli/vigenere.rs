//! Vigenere cipher CLI command
//!
//! Implements the `encryptr vigenere` subcommand for encoding/decoding with the Vigenere cipher.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use super::alphabet::AlphabetType;
use super::input;
use super::output;
use encryptr::cipher::vigenere::VigenereCipher;

/// Vigenere cipher actions
#[derive(Subcommand)]
pub enum VigenereAction {
	/// Encode (encipher) text using Vigenere cipher
	Encode(VigenereArgs),
	/// Decode (decipher) text using Vigenere cipher
	Decode(VigenereArgs),
}

/// Arguments for Vigenere cipher operations
#[derive(Args)]
pub struct VigenereArgs {
	/// Keyword for the cipher (must contain only characters from the alphabet)
	#[arg(short, long)]
	pub keyword: String,

	/// Alphabet to use (note: cased alphabet not supported for Vigenere)
	#[arg(short, long, default_value = "ascii")]
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

/// Run the Vigenere cipher command
pub fn run(action: VigenereAction) -> Result<()> {
	match action {
		VigenereAction::Encode(args) => encode(args),
		VigenereAction::Decode(args) => decode(args),
	}
}

fn create_cipher(args: &VigenereArgs) -> Result<VigenereCipher> {
	if args.alphabet.is_cased() {
		anyhow::bail!(
			"Vigenere cipher does not support case-preserving alphabet. Use 'ascii' or 'polish'."
		);
	}

	VigenereCipher::new(args.alphabet.to_char_alphabet(), &args.keyword)
		.map_err(|_| anyhow::anyhow!("Invalid keyword: contains characters not in the alphabet"))
}

fn encode(args: VigenereArgs) -> Result<()> {
	let input = input::get_text(args.text.as_deref(), args.input_file.as_ref())?;
	let cipher = create_cipher(&args)?;
	let result = cipher.encode(&input);
	output::write_text(&result, args.output_file.as_ref())
}

fn decode(args: VigenereArgs) -> Result<()> {
	let input = input::get_text(args.text.as_deref(), args.input_file.as_ref())?;
	let cipher = create_cipher(&args)?;
	let result = cipher.decode(&input);
	output::write_text(&result, args.output_file.as_ref())
}
