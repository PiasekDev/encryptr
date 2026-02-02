//! CLI module for encryptr
//!
//! This module provides a command-line interface for the encryptr cryptography library.

pub mod affine;
pub mod alphabet;
pub mod caesar;
pub mod completions;
pub mod crack;
pub mod des;
pub mod input;
pub mod manpages;
pub mod output;
pub mod rsa;
pub mod substitution;
pub mod vigenere;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use clap_complete::Shell;

/// PiasekDev's cryptography toolkit
#[derive(Parser)]
#[command(name = "encryptr")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
	#[command(subcommand)]
	pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
	/// Caesar cipher (shift cipher)
	Caesar {
		#[command(subcommand)]
		action: caesar::CaesarAction,
	},
	/// Vigenere cipher (polyalphabetic substitution)
	Vigenere {
		#[command(subcommand)]
		action: vigenere::VigenereAction,
	},
	/// Affine cipher (ax + b mod m)
	Affine {
		#[command(subcommand)]
		action: affine::AffineAction,
	},
	/// Simple substitution cipher
	Substitution {
		#[command(subcommand)]
		action: substitution::SubstitutionAction,
	},
	/// DES block cipher
	Des {
		#[command(subcommand)]
		action: des::DesAction,
	},
	/// RSA asymmetric encryption
	Rsa {
		#[command(subcommand)]
		action: rsa::RsaAction,
	},
	/// Cryptanalysis tools (crack ciphers)
	Crack {
		#[command(subcommand)]
		action: crack::CrackAction,
	},
	/// Generate shell completions
	Completions {
		/// Shell to generate completions for
		#[arg(value_enum)]
		shell: Shell,
	},
	/// Generate man pages
	Manpages {
		/// Output directory for man pages
		#[arg(short, long, default_value = "man")]
		output: PathBuf,
	},
}

/// Run the CLI with the parsed arguments
pub fn run(cli: Cli) -> anyhow::Result<()> {
	match cli.command {
		Commands::Caesar { action } => caesar::run(action),
		Commands::Vigenere { action } => vigenere::run(action),
		Commands::Affine { action } => affine::run(action),
		Commands::Substitution { action } => substitution::run(action),
		Commands::Des { action } => des::run(action),
		Commands::Rsa { action } => rsa::run(action),
		Commands::Crack { action } => crack::run(action),
		Commands::Completions { shell } => {
			completions::generate_completions(shell);
			Ok(())
		}
		Commands::Manpages { output } => manpages::generate_manpages(&output),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use clap::CommandFactory;

	#[test]
	fn verify_cli() {
		Cli::command().debug_assert();
	}
}
