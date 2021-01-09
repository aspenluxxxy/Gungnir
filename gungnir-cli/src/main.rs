/*
   Gungnir - Cross-platform executable signing
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
use std::path::PathBuf;

#[derive(Debug, Clap)]
pub struct CliArgs {
	#[clap(parse(from_os_str))]
	input: PathBuf,
	#[clap(parse(from_os_str))]
	output: PathBuf,
}

fn main() {
	let args: CliArgs = CliArgs::parse();
}
