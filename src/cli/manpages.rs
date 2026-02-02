//! Man page generation for encryptr CLI

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use clap::CommandFactory;
use clap_mangen::Man;

use super::Cli;

/// Generate man pages to the specified output directory
pub fn generate_manpages(out_dir: &Path) -> Result<()> {
	let cmd = Cli::command();

	// Create output directory if it doesn't exist
	fs::create_dir_all(out_dir)
		.with_context(|| format!("Failed to create directory: {}", out_dir.display()))?;

	// Generate main man page
	let main_man = Man::new(cmd.clone());
	let main_path = out_dir.join("encryptr.1");
	let mut main_file = fs::File::create(&main_path)
		.with_context(|| format!("Failed to create file: {}", main_path.display()))?;
	main_man
		.render(&mut main_file)
		.context("Failed to render main man page")?;
	println!("Generated: {}", main_path.display());

	// Generate man pages for subcommands
	for subcommand in cmd.get_subcommands() {
		if subcommand.get_name() == "help" {
			continue;
		}

		let sub_man = Man::new(subcommand.clone());
		let sub_path = out_dir.join(format!("encryptr-{}.1", subcommand.get_name()));
		let mut sub_file = fs::File::create(&sub_path)
			.with_context(|| format!("Failed to create file: {}", sub_path.display()))?;
		sub_man
			.render(&mut sub_file)
			.context("Failed to render subcommand man page")?;
		println!("Generated: {}", sub_path.display());

		// Generate man pages for nested subcommands (encode/decode actions)
		for nested in subcommand.get_subcommands() {
			if nested.get_name() == "help" {
				continue;
			}

			let nested_man = Man::new(nested.clone());
			let nested_path = out_dir.join(format!(
				"encryptr-{}-{}.1",
				subcommand.get_name(),
				nested.get_name()
			));
			let mut nested_file = fs::File::create(&nested_path)
				.with_context(|| format!("Failed to create file: {}", nested_path.display()))?;
			nested_man
				.render(&mut nested_file)
				.context("Failed to render nested man page")?;
			println!("Generated: {}", nested_path.display());
		}
	}

	Ok(())
}
