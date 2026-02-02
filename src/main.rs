//! Encryptr CLI - PiasekDev's cryptography toolkit
//!
//! A command-line interface for the encryptr cryptography library.

mod cli;

use clap::Parser;

fn main() -> anyhow::Result<()> {
	let cli = cli::Cli::parse();
	cli::run(cli)
}
