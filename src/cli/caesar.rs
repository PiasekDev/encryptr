//! Caesar cipher CLI command
//!
//! Implements the `encryptr caesar` subcommand for encoding/decoding with the Caesar cipher.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use super::alphabet::AlphabetType;
use super::input;
use super::output;
use encryptr::cipher::Cipher;
use encryptr::cipher::caesar::CaesarCipher;

/// Caesar cipher actions
#[derive(Subcommand)]
pub enum CaesarAction {
	/// Encode (encipher) text using Caesar cipher
	Encode(CaesarArgs),
	/// Decode (decipher) text using Caesar cipher
	Decode(CaesarArgs),
}

/// Arguments for Caesar cipher operations
#[derive(Args)]
pub struct CaesarArgs {
	/// Shift offset (e.g., 3 for classic ROT3, 13 for ROT13)
	#[arg(short, long)]
	pub offset: usize,

	/// Alphabet to use
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

/// Run the Caesar cipher command
pub fn run(action: CaesarAction) -> Result<()> {
	match action {
		CaesarAction::Encode(args) => encode(args),
		CaesarAction::Decode(args) => decode(args),
	}
}

fn encode(args: CaesarArgs) -> Result<()> {
	let input = input::get_text(args.text.as_deref(), args.input_file.as_ref())?;

	let result = if args.alphabet.is_cased() {
		let cipher = CaesarCipher::new(args.alphabet.to_cased_alphabet(), args.offset);
		cipher.encipher(&input)
	} else {
		let cipher = CaesarCipher::new(args.alphabet.to_char_alphabet(), args.offset);
		cipher.encipher(&input)
	};

	output::write_text(&result, args.output_file.as_ref())
}

fn decode(args: CaesarArgs) -> Result<()> {
	let input = input::get_text(args.text.as_deref(), args.input_file.as_ref())?;

	let result = if args.alphabet.is_cased() {
		let cipher = CaesarCipher::new(args.alphabet.to_cased_alphabet(), args.offset);
		cipher.decipher(&input)
	} else {
		let cipher = CaesarCipher::new(args.alphabet.to_char_alphabet(), args.offset);
		cipher.decipher(&input)
	};

	output::write_text(&result, args.output_file.as_ref())
}
