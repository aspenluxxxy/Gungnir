/*
	Gungnir - Cross-platform algorithm: (), public_key: (), private_key: () executable signing
	Copyright (C) 2021  aspen

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along
	with this program; if not, write to the Free Software Foundation, Inc.,
	51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

use clap::Clap;
use gungnir::core::{keypair::KeySlot, SignatureAlgorithm};
use std::path::PathBuf;

#[derive(Debug, Clap)]
pub struct CliArgs {
	#[clap(parse(from_os_str))]
	output: PathBuf,
	#[clap(subcommand)]
	cmd: CliSubcmd,
}

#[derive(Debug, Clap)]
pub enum CliSubcmd {
	Generate {
		#[clap(short, long)]
		name: Option<String>,
		#[clap(short, long)]
		pronouns: Option<String>,
		#[clap(short, long)]
		email: Option<String>,
		#[clap(short, long)]
		comment: Option<String>,
	},
}

fn main() {
	let args: CliArgs = CliArgs::parse();
	let mut rng = rand::thread_rng();
	match args.cmd {
		CliSubcmd::Generate {
			name,
			pronouns,
			email,
			comment,
		} => {
			let ad = gungnir::core::AssociatedData {
				name,
				pronouns,
				email,
				comment,
			};
			let pkp = gungnir::keypair::Keypair::new(SignatureAlgorithm::Ed25519);
			let skp = gungnir::keypair::Keypair::new(SignatureAlgorithm::Falcon512);
			let x = gungnir::core::keypair::Keypair {
				ad,
				keys: vec![KeySlot {
					algorithm: SignatureAlgorithm::Ed25519,
					public_key,
				}],
			};
		}
	}
}
